"""Scan pipeline: manifests -> graph -> OSV -> risk -> AI explanations."""
from __future__ import annotations

import logging
import re

import httpx

from . import graph as G
from . import llm, osv_client, risk
from .config import settings
from .db import SessionLocal
from .models import Finding, Scan
from .parsers import Dep, is_manifest_path, parse_manifests

log = logging.getLogger("depshield.scanner")

LEVELS = ("critical", "high", "medium", "low")
GH_RE = re.compile(r"github\.com[/:]([\w.\-]+)/([\w.\-]+?)(?:\.git)?(?:/tree/([^/]+))?/?$")
SKIP_DIRS = {"test", "tests", "fixtures", "examples", "vendor", "docs", "node_modules"}


# ------------------------------------------------------------------ GitHub

def fetch_github_manifests(url: str, max_files: int = 12) -> dict[str, str]:
    m = GH_RE.search(url.strip())
    if not m:
        raise ValueError("That does not look like a GitHub repository URL.")
    owner, repo, branch = m.groups()
    headers = {"Accept": "application/vnd.github+json"}
    if settings.github_token:
        headers["Authorization"] = f"Bearer {settings.github_token}"

    with httpx.Client(timeout=30, headers=headers, follow_redirects=True) as c:
        if not branch:
            r = c.get(f"https://api.github.com/repos/{owner}/{repo}")
            if r.status_code == 404:
                raise ValueError("Repository not found. Private repos need GITHUB_TOKEN.")
            r.raise_for_status()
            branch = r.json()["default_branch"]
        tree = c.get(f"https://api.github.com/repos/{owner}/{repo}/git/trees/{branch}", params={"recursive": "1"})
        tree.raise_for_status()
        paths = [
            t["path"]
            for t in tree.json().get("tree", [])
            if t["type"] == "blob"
            and is_manifest_path(t["path"])
            and t["path"].count("/") <= 3
            and not (set(t["path"].split("/")[:-1]) & SKIP_DIRS)
        ]
        paths.sort(key=lambda p: (p.count("/"), p))
        files: dict[str, str] = {}
        for p in paths[:max_files]:
            raw = c.get(f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{p}")
            if raw.status_code == 200 and len(raw.text) < 8_000_000:
                files[p] = raw.text
    return files


# ------------------------------------------------------------------ analysis

def analyze(
    nodes: dict[str, Dep],
    roots: set[str],
    user_id: int,
    app_name: str,
    sensitive: bool,
    sync_neo4j: bool = True,
) -> dict:
    vuln_ids_by_key = osv_client.query_batch(list(nodes.values()))
    vuln_data = osv_client.fetch_vulns({v for ids in vuln_ids_by_key.values() for v in ids})

    if sync_neo4j:
        G.sync_app(user_id, app_name, sensitive, nodes)
    apps_map = G.apps_using(user_id, list(vuln_ids_by_key))

    reachable = G.prod_reachable(nodes, roots)
    depth, parent = G.bfs_paths(nodes, roots)
    dependents = G.dependents_count(nodes)

    infos: dict[str, list[osv_client.VulnInfo]] = {}
    for key, ids in vuln_ids_by_key.items():
        for vid in ids:
            if vid in vuln_data:
                infos.setdefault(key, []).append(osv_client.normalize(vuln_data[vid], nodes[key]))

    features = {
        k: [
            dependents[k],
            len(d.depends_on),
            depth.get(k, 0),
            len(infos.get(k, [])),
            max((i.cvss for i in infos.get(k, [])), default=0.0),
        ]
        for k, d in nodes.items()
    }
    anomalies = risk.detect_anomalies(features)

    findings: list[dict] = []
    for key, vulns in infos.items():
        dep = nodes[key]
        apps = list(apps_map.get(key) or [])
        if not any(a["name"] == app_name for a in apps):
            apps.append({"name": app_name, "sensitive": sensitive})
        sensitive_apps = sum(1 for a in apps if a.get("sensitive"))
        for info in vulns:
            fix = osv_client.pick_fix(dep.version, info.fixed_versions)
            score, level, reasons = risk.score_risk(
                risk.RiskInput(
                    cvss=info.cvss,
                    direct=dep.direct,
                    dev=dep.dev,
                    reachable=key in reachable,
                    app_count=len(apps),
                    sensitive_apps=sensitive_apps,
                    anomaly=key in anomalies,
                    fix_available=fix is not None,
                )
            )
            findings.append(
                {
                    "package_key": key,
                    "package": dep.name,
                    "version": dep.version,
                    "ecosystem": dep.ecosystem,
                    "vuln_id": info.id,
                    "aliases": info.aliases,
                    "summary": info.summary,
                    "cvss": info.cvss,
                    "severity": info.severity,
                    "fixed_versions": info.fixed_versions,
                    "recommended_fix": fix,
                    "is_direct": dep.direct,
                    "is_dev": dep.dev,
                    "reachable": key in reachable,
                    "path": G.path_to(key, parent) if key in parent else [G.APP_NODE, key],
                    "apps": [a["name"] for a in apps],
                    "anomaly": key in anomalies,
                    "risk_score": score,
                    "risk_level": level,
                    "reasons": reasons,
                    "ai_explanation": None,
                }
            )
    findings.sort(key=lambda f: -f["risk_score"])
    return {
        "findings": findings,
        "summary": summarize(findings, nodes),
        "depth": depth,
        "warnings": [],
    }


def summarize(findings: list[dict], nodes: dict[str, Dep]) -> dict:
    counts = {lvl: 0 for lvl in LEVELS}
    for f in findings:
        counts[f["risk_level"]] += 1
    return {
        "counts": counts,
        "total_packages": len(nodes),
        "direct_packages": sum(1 for d in nodes.values() if d.direct),
        "vulnerable_packages": len({f["package_key"] for f in findings}),
        "total_findings": len(findings),
        "overall_score": risk.overall_score([f["risk_score"] for f in findings]),
    }


def graph_json(nodes: dict[str, Dep], roots: set[str], findings: list[dict], depth: dict[str, int]) -> dict:
    best: dict[str, dict] = {}
    for f in findings:  # findings are sorted, so the first hit per package is its worst
        best.setdefault(f["package_key"], f)
    out = []
    for k, d in nodes.items():
        b = best.get(k)
        out.append(
            {
                "key": k,
                "name": d.name,
                "version": d.version,
                "ecosystem": d.ecosystem,
                "direct": d.direct,
                "dev": d.dev,
                "depth": depth.get(k, 0),
                "depends_on": sorted(d.depends_on),
                "risk": b["risk_score"] if b else 0,
                "level": b["risk_level"] if b else None,
                "vuln_count": sum(1 for f in findings if f["package_key"] == k) if b else 0,
            }
        )
    return {"roots": sorted(roots), "nodes": out}


def nodes_from_graph(g: dict) -> tuple[dict[str, Dep], set[str]]:
    nodes = {
        n["key"]: Dep(n["name"], n["version"], n["ecosystem"], n["direct"], n["dev"], set(n["depends_on"]))
        for n in g["nodes"]
    }
    return nodes, set(g["roots"])


# ------------------------------------------------------------------ job entry point

def run_scan(scan_id: int) -> None:
    db = SessionLocal()
    scan = db.get(Scan, scan_id)
    if scan is None:
        db.close()
        return
    try:
        scan.status, scan.error = "running", None
        db.commit()

        if scan.source_type == "github":
            scan.manifests = fetch_github_manifests(scan.repo_url or "")
            db.commit()

        parsed = parse_manifests(scan.manifests or {})
        if not parsed.nodes:
            raise ValueError(" ".join(parsed.warnings) or "No dependencies found.")

        result = analyze(parsed.nodes, parsed.roots, scan.user_id, scan.name, scan.sensitive)
        findings = result["findings"]

        top = findings[: settings.ai_explain_top_n]
        for f, text in zip(top, llm.explain_findings(top)):
            f["ai_explanation"] = text
        for f in findings[settings.ai_explain_top_n :]:
            f["ai_explanation"] = llm.template_explanation(f)

        summary = result["summary"]
        summary["headline"] = llm.headline(summary, findings[0] if findings else None)
        summary["warnings"] = parsed.warnings

        scan.findings = [Finding(**f) for f in findings]
        scan.graph = graph_json(parsed.nodes, parsed.roots, findings, result["depth"])
        scan.summary = summary
        scan.status = "done"
        db.commit()
    except Exception as exc:
        log.exception("scan %s failed", scan_id)
        db.rollback()
        scan = db.get(Scan, scan_id)
        scan.status, scan.error = "failed", str(exc)[:500]
        db.commit()
    finally:
        db.close()


# ------------------------------------------------------------------ what-if

def simulate_fix(scan: Scan, upgrades: list[dict]) -> dict:
    """Re-score the app as if the given packages were upgraded. Nothing is persisted.

    Limitation: an upgraded package keeps its old dependency list, because the
    real dependency tree of the new version is only known after re-locking.
    """
    nodes, roots = nodes_from_graph(scan.graph)
    key_map: dict[str, str] = {}
    replaced: dict[str, Dep] = {}
    for u in upgrades:
        old = nodes.get(u["key"])
        if not old:
            continue
        new = Dep(old.name, u["version"], old.ecosystem, old.direct, old.dev, set(old.depends_on))
        replaced[u["key"]] = new
        key_map[u["key"]] = new.key

    new_nodes: dict[str, Dep] = {}
    for k, d in nodes.items():
        d2 = replaced.get(k) or Dep(d.name, d.version, d.ecosystem, d.direct, d.dev, set(d.depends_on))
        d2.depends_on = {key_map.get(c, c) for c in d2.depends_on}
        if d2.key in new_nodes:
            new_nodes[d2.key].depends_on |= d2.depends_on
        else:
            new_nodes[d2.key] = d2
    new_roots = {key_map.get(r, r) for r in roots}

    result = analyze(new_nodes, new_roots, scan.user_id, scan.name, scan.sensitive, sync_neo4j=False)
    before = {(f.package, f.vuln_id) for f in scan.findings}
    after = {(f["package"], f["vuln_id"]) for f in result["findings"]}
    return {
        "before": {k: scan.summary[k] for k in ("counts", "overall_score", "total_findings")},
        "after": {k: result["summary"][k] for k in ("counts", "overall_score", "total_findings")},
        "resolved": sorted(f"{p}: {v}" for p, v in before - after),
        "introduced": sorted(f"{p}: {v}" for p, v in after - before),
    }
