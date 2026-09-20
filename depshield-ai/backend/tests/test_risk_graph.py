from app import graph as G
from app.osv_client import cvss3_score, pick_fix
from app.parsers import Dep
from app.risk import RiskInput, detect_anomalies, level_for, overall_score, score_risk


def dep(name, version="1.0.0", direct=False, dev=False, children=()):
    return Dep(name, version, "npm", direct, dev, {f"npm:{c}@1.0.0" for c in children})


def test_cvss3_known_vectors():
    assert cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8
    assert cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N") == 7.2
    assert cvss3_score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N") is None


def test_pick_fix_chooses_smallest_newer_version():
    assert pick_fix("4.17.15", ["4.17.19", "4.17.21", "3.0.0"]) == "4.17.19"
    assert pick_fix("1.0.0", []) is None


def test_production_reachable_critical_outranks_dev_only():
    prod, *_ = score_risk(RiskInput(cvss=9.8, direct=True, dev=False, reachable=True, app_count=3, sensitive_apps=1))
    dev, *_ = score_risk(RiskInput(cvss=9.8, direct=True, dev=True, reachable=False))
    assert prod > dev and prod >= 80
    assert level_for(prod) == "critical"


def test_blast_radius_and_sensitivity_raise_score():
    base, *_ = score_risk(RiskInput(cvss=7.5, direct=False, dev=False, reachable=True))
    wider, *_ = score_risk(RiskInput(cvss=7.5, direct=False, dev=False, reachable=True, app_count=3, sensitive_apps=1))
    assert wider > base


def test_score_is_clamped():
    s, *_ = score_risk(RiskInput(cvss=10, direct=True, dev=False, reachable=True, app_count=10, sensitive_apps=5, anomaly=True))
    assert s == 100.0


def test_overall_score_uses_worst_and_top5():
    assert overall_score([]) == 0.0
    assert overall_score([90, 10]) > overall_score([50, 50])


def test_graph_reachability_depth_and_attack_subgraph():
    nodes = {
        "npm:a@1.0.0": dep("a", direct=True, children=["b"]),
        "npm:b@1.0.0": dep("b", children=["c"]),
        "npm:c@1.0.0": dep("c"),
        "npm:d@1.0.0": dep("d", direct=True),
        "npm:t@1.0.0": dep("t", direct=True, dev=True, children=["c"]),
    }
    roots = {"npm:a@1.0.0", "npm:d@1.0.0", "npm:t@1.0.0"}
    assert G.prod_reachable(nodes, roots) == {"npm:a@1.0.0", "npm:b@1.0.0", "npm:c@1.0.0", "npm:d@1.0.0"}
    depth, parent = G.bfs_paths(nodes, roots)
    assert depth["npm:c@1.0.0"] == 3
    assert G.path_to("npm:c@1.0.0", parent) == ["app", "npm:a@1.0.0", "npm:b@1.0.0", "npm:c@1.0.0"]
    keep, edges = G.attack_subgraph(nodes, roots, {"npm:c@1.0.0"})
    assert keep == {"npm:a@1.0.0", "npm:b@1.0.0", "npm:c@1.0.0", "npm:t@1.0.0"}
    assert ("app", "npm:d@1.0.0") not in edges and ("app", "npm:a@1.0.0") in edges


def test_anomaly_detection_needs_enough_samples():
    assert detect_anomalies({"x": [1, 1, 1, 0, 0]}) == set()
