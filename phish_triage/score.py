"""Combine signals into a 0-100 risk score and a verdict.

Deterministic and model-free on purpose: the LLM writes prose, it never moves
the number. Score is the capped sum of triggered signal weights.
"""
from __future__ import annotations

from .signals import Signal

LIKELY_PHISHING = 60
SUSPICIOUS = 25


def score_signals(signals: list[Signal]) -> tuple[int, str]:
    score = min(100, sum(s.weight for s in signals if s.triggered))
    if score >= LIKELY_PHISHING:
        verdict = "Likely Phishing"
    elif score >= SUSPICIOUS:
        verdict = "Suspicious"
    else:
        verdict = "Benign"
    return score, verdict
