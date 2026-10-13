"""Thin LLM narrative layer.

One function, one OpenAI-compatible /chat/completions call, configured only by
env (defaults to local Ollama). The verdict and score are decided before this
runs; the model only writes an analyst-style paragraph about findings it is
handed. Never raises and never blocks the tool: if the endpoint is unreachable
it degrades to a clear notice.
"""
from __future__ import annotations

import json
import os
import urllib.request

LLM_BASE_URL = os.environ.get("LLM_BASE_URL", "http://127.0.0.1:11434/v1")
LLM_MODEL = os.environ.get("LLM_MODEL", "qwen3:30b-a3b-instruct-2507-q4_K_M")
LLM_API_KEY = os.environ.get("LLM_API_KEY", "ollama")

SYSTEM = (
    "You are a SOC analyst assistant. You are given the deterministic findings "
    "of a phishing-triage tool (a verdict, a score, and a list of signals). "
    "Write a concise 3-5 sentence summary for another analyst: what the "
    "evidence suggests and the most important signals, in plain language. "
    "Do NOT invent facts beyond the findings. Do NOT change or restate the "
    "numeric score as your own judgement. Do NOT give an all-clear. End with a "
    "one-line recommended next action."
)


def _prompt(ctx: dict) -> str:
    lines = [
        f"Verdict: {ctx['verdict']}  Score: {ctx['score']}/100",
        f"Subject: {ctx.get('subject', '')}",
        f"From: {ctx.get('from', '')}",
        "Triggered signals:",
    ]
    fired = [s for s in ctx["signals"] if s["triggered"]]
    if not fired:
        lines.append("  (none triggered)")
    for s in fired:
        lines.append(f"  - {s['name']} (+{s['weight']}): {s['detail']}")
    return "\n".join(lines)


def _fallback(reason: str) -> str:
    return ("_LLM narrative unavailable; the deterministic findings above stand "
            f"on their own._ (reason: {reason})")


def narrate(ctx: dict, timeout: int = 60) -> str:
    """Return a short analyst narrative, or a graceful notice on any failure."""
    try:
        body = json.dumps({
            "model": LLM_MODEL,
            "messages": [
                {"role": "system", "content": SYSTEM},
                {"role": "user", "content": _prompt(ctx)},
            ],
            "temperature": 0.2,
            "stream": False,
        }).encode()
        req = urllib.request.Request(
            LLM_BASE_URL.rstrip("/") + "/chat/completions",
            data=body,
            headers={"Content-Type": "application/json",
                     "Authorization": f"Bearer {LLM_API_KEY}"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read())
        text = (data["choices"][0]["message"]["content"] or "").strip()
        return text or _fallback("empty response from model")
    except Exception as exc:  # unreachable endpoint, bad response, timeout, ...
        return _fallback(f"{type(exc).__name__}: {exc}")
