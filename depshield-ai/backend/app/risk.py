"""Risk prioritisation.

The score is deliberately transparent: every point comes from a named signal, and
each signal produces a human-readable reason. The LLM later turns these reasons
into prose; it never invents the score.

Signals: CVSS severity, exposure (prod vs dev, reachable), direct vs transitive,
blast radius (how many of your apps use it), sensitive downstream apps, and a
structural anomaly flag from an IsolationForest over graph features.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class RiskInput:
    cvss: float
    direct: bool
    dev: bool
    reachable: bool
    app_count: int = 1
    sensitive_apps: int = 0
    anomaly: bool = False
    fix_available: bool = True


def level_for(score: float) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 35:
        return "medium"
    return "low"


def score_risk(r: RiskInput) -> tuple[float, str, list[str]]:
    reasons: list[str] = []
    score = r.cvss * 6  # up to 60 points from severity
    reasons.append(f"CVSS {r.cvss:.1f}")

    if r.dev:
        score -= 20
        reasons.append("development-only dependency (not shipped to production)")
    elif not r.reachable:
        score -= 10
        reasons.append("not reachable from production dependencies")
    else:
        score += 15
        reasons.append("production dependency reachable from the app")

    if r.direct:
        score += 5
        reasons.append("direct dependency (you control the upgrade)")
    else:
        reasons.append("transitive dependency")

    if r.app_count > 1:
        score += min(10, 3 * r.app_count)
        reasons.append(f"used by {r.app_count} of your applications")

    if r.sensitive_apps:
        score += 10
        reasons.append(f"used by {r.sensitive_apps} sensitive service(s) such as payments or auth")

    if r.anomaly:
        score += 5
        reasons.append("unusual position in the dependency graph")

    if not r.fix_available:
        reasons.append("no patched version published yet")

    score = max(0.0, min(100.0, score))
    return round(score, 1), level_for(score), reasons


def detect_anomalies(features: dict[str, list[float]], min_samples: int = 20) -> set[str]:
    """IsolationForest over [dependents, dependencies, depth, vuln_count, max_cvss].

    Flags packages whose graph position is statistically unusual in this scan
    (for example a deep package with very high fan-in and known vulnerabilities).
    Needs enough packages to be meaningful, so small graphs return an empty set.
    """
    if len(features) < min_samples:
        return set()
    try:
        import numpy as np
        from sklearn.ensemble import IsolationForest
    except ImportError:
        return set()

    keys = list(features)
    X = np.array([features[k] for k in keys], dtype=float)
    model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
    labels = model.fit_predict(X)
    return {k for k, label in zip(keys, labels) if label == -1}


def overall_score(scores: list[float]) -> float:
    """Single number for the whole scan: worst finding weighted with the top five average."""
    if not scores:
        return 0.0
    top = sorted(scores, reverse=True)[:5]
    return round(0.6 * top[0] + 0.4 * (sum(top) / len(top)), 1)
