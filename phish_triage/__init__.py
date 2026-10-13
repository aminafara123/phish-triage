"""phish-triage: deterministic phishing triage for .eml files, LLM only for prose.

    from phish_triage import analyze
    result = analyze("samples/obvious-phish.eml")
    print(result["verdict"], result["score"])
"""
from __future__ import annotations

from . import llm, parse, report
from . import score as _score
from . import signals as _signals

__all__ = ["analyze"]


def analyze(path: str, with_llm: bool = True) -> dict:
    """Parse one .eml, run the deterministic checks, score, and (optionally)
    attach an AI narrative. Returns everything the CLI/MCP need."""
    email = parse.parse_eml(path)
    sigs = _signals.evaluate(email)
    score, verdict = _score.score_signals(sigs)
    narrative = (llm.narrate(report.llm_context(email, sigs, score, verdict))
                 if with_llm else "")
    markdown, data = report.build(email, sigs, score, verdict, narrative)
    return {
        "path": path,
        "email": email,
        "signals": sigs,
        "score": score,
        "verdict": verdict,
        "narrative": narrative,
        "markdown": markdown,
        "json": data,
    }
