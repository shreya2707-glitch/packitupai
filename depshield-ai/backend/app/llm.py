"""Plain-language explanations. Uses OpenAI when OPENAI_API_KEY is set, otherwise a
deterministic template, so the demo never breaks without a key."""
from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor

from .config import settings

log = logging.getLogger("depshield.llm")

SYSTEM = (
    "You are an application-security engineer writing triage notes for developers. "
    "Use only the facts provided. Do not invent CVEs, versions or exploit details. "
    "Write 2-3 short sentences: why this dependency should be fixed at its priority, "
    "then the exact action. No headings, no markdown."
)


def _client():
    if not settings.openai_api_key:
        return None
    from openai import OpenAI

    return OpenAI(api_key=settings.openai_api_key)


def template_explanation(f: dict) -> str:
    fix = f"Upgrade {f['package']} to {f['recommended_fix']}." if f.get("recommended_fix") else "No patched version is listed yet; consider replacing or pinning the package and monitor the advisory."
    why = "; ".join(f["reasons"][:4])
    return f"{f['risk_level'].capitalize()} priority ({f['risk_score']}/100): {why}. {fix}"


def _explain_one(client, f: dict) -> str:
    facts = (
        f"Package: {f['package']}@{f['version']} ({f['ecosystem']})\n"
        f"Advisory: {f['vuln_id']} - {f['summary']}\n"
        f"Risk: {f['risk_level']} ({f['risk_score']}/100)\n"
        f"Signals: {'; '.join(f['reasons'])}\n"
        f"Dependency path: {' > '.join(f['path'])}\n"
        f"Recommended fix version: {f.get('recommended_fix') or 'none published'}"
    )
    try:
        resp = client.chat.completions.create(
            model=settings.openai_model,
            messages=[{"role": "system", "content": SYSTEM}, {"role": "user", "content": facts}],
            temperature=0.2,
            max_tokens=160,
        )
        return (resp.choices[0].message.content or "").strip() or template_explanation(f)
    except Exception as exc:
        log.warning("LLM call failed, using template: %s", exc)
        return template_explanation(f)


def explain_findings(findings: list[dict]) -> list[str]:
    """Explanations aligned with `findings` (already sorted by risk, highest first)."""
    client = _client()
    if not client:
        return [template_explanation(f) for f in findings]
    with ThreadPoolExecutor(max_workers=4) as pool:
        return list(pool.map(lambda f: _explain_one(client, f), findings))


def headline(summary: dict, top: dict | None) -> str:
    if not top:
        return "No known vulnerabilities found in the scanned dependencies."
    base = (
        f"Fix {top['package']} first: {top['risk_level']} risk, "
        f"{summary['counts'].get('critical', 0)} critical and {summary['counts'].get('high', 0)} high findings in total."
    )
    client = _client()
    if not client:
        return base
    try:
        resp = client.chat.completions.create(
            model=settings.openai_model,
            messages=[
                {"role": "system", "content": "Write one sentence (max 30 words) telling a developer what to fix first and why. Use only the facts given."},
                {"role": "user", "content": f"Counts: {summary['counts']}. Top finding: {top['package']}@{top['version']}, reasons: {'; '.join(top['reasons'])}, fix: {top.get('recommended_fix')}"},
            ],
            temperature=0.2,
            max_tokens=80,
        )
        return (resp.choices[0].message.content or base).strip()
    except Exception as exc:
        log.warning("LLM headline failed: %s", exc)
        return base
