"""End-to-end check of the analysis pipeline with OSV and Neo4j mocked out."""
import json

from app import graph as G
from app import osv_client, scanner
from app.parsers import parse_package_lock

LOCK = {
    "lockfileVersion": 3,
    "packages": {
        "": {"dependencies": {"lodash": "4.17.15", "express": "^4.17.1"}},
        "node_modules/lodash": {"version": "4.17.15"},
        "node_modules/express": {"version": "4.17.1", "dependencies": {"qs": "6.7.0"}},
        "node_modules/qs": {"version": "6.7.0"},
    },
}

VULNS = {
    "GHSA-lodash": {
        "id": "GHSA-lodash",
        "aliases": ["CVE-2021-23337"],
        "summary": "Command injection in lodash",
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"}],
        "affected": [{"package": {"name": "lodash", "ecosystem": "npm"}, "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]}],
    },
    "GHSA-qs": {
        "id": "GHSA-qs",
        "summary": "Prototype pollution in qs",
        "database_specific": {"severity": "HIGH"},
        "affected": [{"package": {"name": "qs", "ecosystem": "npm"}, "ranges": [{"type": "SEMVER", "events": [{"fixed": "6.7.3"}]}]}],
    },
}


def fake_query_batch(deps):
    out = {}
    for d in deps:
        if d.name == "lodash" and d.version == "4.17.15":
            out[d.key] = ["GHSA-lodash"]
        if d.name == "qs" and d.version == "6.7.0":
            out[d.key] = ["GHSA-qs"]
    return out


def test_pipeline_ranks_sensitive_direct_dependency_first(monkeypatch):
    monkeypatch.setattr(osv_client, "query_batch", fake_query_batch)
    monkeypatch.setattr(osv_client, "fetch_vulns", lambda ids: {i: VULNS[i] for i in ids})
    monkeypatch.setattr(G, "sync_app", lambda *a, **k: False)
    monkeypatch.setattr(G, "apps_using", lambda *a, **k: {})

    parsed = parse_package_lock(json.dumps(LOCK))
    result = scanner.analyze(parsed.nodes, parsed.roots, user_id=1, app_name="payments", sensitive=True)

    top, second = result["findings"]
    assert top["package"] == "lodash" and top["recommended_fix"] == "4.17.21"
    assert top["risk_score"] > second["risk_score"]
    assert second["path"] == ["app", "npm:express@4.17.1", "npm:qs@6.7.0"]
    assert result["summary"]["total_findings"] == 2

    # what-if: upgrading lodash removes its finding and lowers the overall score
    class FakeScan:
        user_id, name, sensitive = 1, "payments", True
        graph = scanner.graph_json(parsed.nodes, parsed.roots, result["findings"], result["depth"])
        summary = result["summary"]
        findings = [type("F", (), {"package": f["package"], "vuln_id": f["vuln_id"]}) for f in result["findings"]]

    sim = scanner.simulate_fix(FakeScan, [{"key": "npm:lodash@4.17.15", "version": "4.17.21"}])
    assert sim["resolved"] == ["lodash: GHSA-lodash"]
    assert sim["after"]["overall_score"] < sim["before"]["overall_score"]
