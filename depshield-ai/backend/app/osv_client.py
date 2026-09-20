"""Vulnerability lookup against OSV.dev (primary) and NVD (CVSS fallback)."""
from __future__ import annotations

import json
import logging
import math
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

import httpx

from .config import settings
from .parsers import Dep

log = logging.getLogger("depshield.osv")

OSV_URL = "https://api.osv.dev/v1"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_TTL = 60 * 60 * 24

_LABEL_TO_CVSS = {"LOW": 3.1, "MODERATE": 5.5, "MEDIUM": 5.5, "HIGH": 7.8, "CRITICAL": 9.5}
_mem_cache: dict[str, str] = {}
_redis = None


def _cache():
    global _redis
    if _redis is None:
        try:
            import redis

            _redis = redis.Redis.from_url(settings.redis_url, socket_connect_timeout=1, decode_responses=True)
            _redis.ping()
        except Exception:
            _redis = False
    return _redis or None


def _cache_get(key: str):
    r = _cache()
    raw = r.get(key) if r else _mem_cache.get(key)
    return json.loads(raw) if raw else None


def _cache_set(key: str, value) -> None:
    raw = json.dumps(value)
    r = _cache()
    if r:
        r.setex(key, CACHE_TTL, raw)
    else:
        _mem_cache[key] = raw


# ------------------------------------------------------------------- CVSS v3 base score

def cvss3_score(vector: str) -> float | None:
    """CVSS v3.x base score from a vector string. Returns None for other versions."""
    if not vector.startswith("CVSS:3"):
        return None
    try:
        m = dict(part.split(":") for part in vector.split("/")[1:])
        scope_changed = m["S"] == "C"
        av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[m["AV"]]
        ac = {"L": 0.77, "H": 0.44}[m["AC"]]
        pr = {"N": 0.85, "L": 0.68 if scope_changed else 0.62, "H": 0.5 if scope_changed else 0.27}[m["PR"]]
        ui = {"N": 0.85, "R": 0.62}[m["UI"]]
        cia = {"H": 0.56, "L": 0.22, "N": 0.0}
        iss = 1 - (1 - cia[m["C"]]) * (1 - cia[m["I"]]) * (1 - cia[m["A"]])
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if scope_changed else 6.42 * iss
        if impact <= 0:
            return 0.0
        expl = 8.22 * av * ac * pr * ui
        base = min(1.08 * (impact + expl), 10) if scope_changed else min(impact + expl, 10)
        return math.ceil(base * 10) / 10
    except (KeyError, ValueError):
        return None


def severity_label(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


# ------------------------------------------------------------------- OSV

@dataclass
class VulnInfo:
    id: str
    aliases: list[str] = field(default_factory=list)
    summary: str = ""
    cvss: float = 0.0
    severity: str = "MEDIUM"
    fixed_versions: list[str] = field(default_factory=list)


def query_batch(deps: list[Dep]) -> dict[str, list[str]]:
    """Returns {dep.key: [vuln ids]} using OSV's querybatch endpoint."""
    out: dict[str, list[str]] = {}
    with httpx.Client(timeout=60) as client:
        for i in range(0, len(deps), 500):
            chunk = deps[i : i + 500]
            payload = {"queries": [{"package": {"name": d.name, "ecosystem": d.ecosystem}, "version": d.version} for d in chunk]}
            resp = client.post(f"{OSV_URL}/querybatch", json=payload)
            resp.raise_for_status()
            for dep, result in zip(chunk, resp.json().get("results", [])):
                ids = [v["id"] for v in result.get("vulns", [])]
                if ids:
                    out[dep.key] = ids
    return out


def _fetch_vuln(vuln_id: str) -> dict:
    cached = _cache_get(f"osv:{vuln_id}")
    if cached:
        return cached
    resp = httpx.get(f"{OSV_URL}/vulns/{vuln_id}", timeout=30)
    resp.raise_for_status()
    data = resp.json()
    _cache_set(f"osv:{vuln_id}", data)
    return data


def fetch_vulns(vuln_ids: set[str]) -> dict[str, dict]:
    def one(vid: str):
        try:
            return vid, _fetch_vuln(vid)
        except Exception as exc:  # network hiccup: skip this advisory, keep scanning
            log.warning("OSV fetch failed for %s: %s", vid, exc)
            return vid, None

    with ThreadPoolExecutor(max_workers=8) as pool:
        return {vid: data for vid, data in pool.map(one, vuln_ids) if data}


def _nvd_cvss(cve_id: str) -> float | None:
    cached = _cache_get(f"nvd:{cve_id}")
    if cached is not None:
        return cached or None
    headers = {"apiKey": settings.nvd_api_key} if settings.nvd_api_key else {}
    try:
        resp = httpx.get(NVD_URL, params={"cveId": cve_id}, headers=headers, timeout=20)
        resp.raise_for_status()
        metrics = resp.json()["vulnerabilities"][0]["cve"]["metrics"]
        for k in ("cvssMetricV31", "cvssMetricV30"):
            if k in metrics:
                score = float(metrics[k][0]["cvssData"]["baseScore"])
                _cache_set(f"nvd:{cve_id}", score)
                return score
    except Exception as exc:
        log.info("NVD lookup skipped for %s: %s", cve_id, exc)
    _cache_set(f"nvd:{cve_id}", 0)
    return None


def normalize(vuln: dict, dep: Dep, use_nvd: bool = True) -> VulnInfo:
    aliases = [a for a in vuln.get("aliases", []) if a != vuln["id"]]
    cvss = None
    for sev in vuln.get("severity", []):
        score = cvss3_score(sev.get("score", ""))
        if score is not None:
            cvss = max(cvss or 0.0, score)
    if cvss is None:
        label = str((vuln.get("database_specific") or {}).get("severity", "")).upper()
        cvss = _LABEL_TO_CVSS.get(label)
    if cvss is None and use_nvd:
        for cve in [vuln["id"], *aliases]:
            if cve.startswith("CVE-"):
                cvss = _nvd_cvss(cve)
                if cvss is not None:
                    break
    if cvss is None:
        cvss = 5.5  # unknown severity: assume medium rather than hide it

    fixed: set[str] = set()
    for aff in vuln.get("affected", []):
        pkg = aff.get("package", {})
        if pkg.get("ecosystem", "").split(":")[0] != dep.ecosystem or pkg.get("name", "").lower() != dep.name.lower():
            continue
        for rng in aff.get("ranges", []):
            for ev in rng.get("events", []):
                if "fixed" in ev:
                    fixed.add(ev["fixed"])

    return VulnInfo(
        id=vuln["id"],
        aliases=aliases,
        summary=(vuln.get("summary") or (vuln.get("details") or "")[:200]).strip(),
        cvss=cvss,
        severity=severity_label(cvss),
        fixed_versions=sorted(fixed),
    )


def pick_fix(current: str, fixed_versions: list[str]) -> str | None:
    """Smallest fixed version that is newer than the one in use."""
    from packaging.version import InvalidVersion, Version

    try:
        cur = Version(current)
    except InvalidVersion:
        return fixed_versions[0] if fixed_versions else None
    newer = []
    for f in fixed_versions:
        try:
            v = Version(f)
        except InvalidVersion:
            continue
        if v > cur:
            newer.append(v)
    return str(min(newer)) if newer else (fixed_versions[-1] if fixed_versions else None)
