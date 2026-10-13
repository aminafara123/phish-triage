"""Render a triage result as report.md and a JSON dict.

All URLs/domains leave here defanged. The AI narrative is labelled as such and
carries a human-review disclaimer, as the deterministic verdict does not.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone

from . import parse
from .signals import Signal

DISCLAIMER = (
    "This is an automated triage aid, not a verdict of record. The score and "
    "verdict are produced by deterministic heuristics; the narrative is "
    "AI-generated. A human analyst must review before acting."
)


def llm_context(e: parse.ParsedEmail, signals: list[Signal], score: int,
                verdict: str) -> dict:
    return {
        "subject": e.subject,
        "from": parse.defang(e.from_addr),
        "score": score,
        "verdict": verdict,
        "signals": [s.__dict__ for s in signals],
    }


def _iocs(e: parse.ParsedEmail) -> dict:
    sender_domains = sorted({
        parse.defang(parse.registered_domain(a))
        for a in (e.from_addr, e.reply_to, e.return_path) if a
    })
    return {
        "urls": [parse.defang(u) for u in e.urls],
        "sender_domains": [d for d in sender_domains if d],
        "attachments": [a["filename"] for a in e.attachments],
    }


def build(e: parse.ParsedEmail, signals: list[Signal], score: int,
          verdict: str, narrative: str) -> tuple[str, dict]:
    iocs = _iocs(e)
    data = {
        "file": os.path.basename(e.path),
        "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "verdict": verdict,
        "score": score,
        "subject": e.subject,
        "from": parse.defang(e.from_addr),
        "from_name": e.from_name,
        "reply_to": parse.defang(e.reply_to),
        "signals": [s.__dict__ for s in signals],
        "iocs": iocs,
        "ai_narrative": narrative,
        "disclaimer": DISCLAIMER,
    }
    return _markdown(data, signals), data


def _markdown(d: dict, signals: list[Signal]) -> str:
    L = [
        f"# Phishing triage — `{d['file']}`",
        "",
        f"**Verdict: {d['verdict']}**  |  **Risk score: {d['score']}/100**",
        "",
        f"- Subject: {d['subject'] or '(none)'}",
        f"- From: {d['from_name']} <{d['from']}>",
        f"- Reply-To: {d['reply_to'] or '(none)'}",
        f"- Generated: {d['generated_utc']}",
        "",
        "## Signals",
        "",
        "| Signal | Status | Pts | Why |",
        "| --- | --- | ---: | --- |",
    ]
    for s in signals:
        status = "FLAG" if s.triggered else "ok"
        L.append(f"| {s.name} | {status} | {s.weight if s.triggered else 0} "
                 f"| {s.detail} |")

    iocs = d["iocs"]
    L += ["", "## Indicators (defanged)", ""]
    L.append("**URLs:**")
    L += ([f"- `{u}`" for u in iocs["urls"]] or ["- (none)"])
    L.append("")
    L.append(f"**Sender domains:** {', '.join(iocs['sender_domains']) or '(none)'}")
    L.append(f"**Attachments:** {', '.join(iocs['attachments']) or '(none)'}")

    L += ["", "## Analyst narrative (AI-generated)", "",
          "> AI-generated summary. The verdict and score above are "
          "deterministic, not model-decided.", "",
          d["ai_narrative"], "",
          "---", f"_{d['disclaimer']}_", ""]
    return "\n".join(L)
