#!/usr/bin/env python3
"""phish-triage MCP: expose the email analyzer as one tool any MCP client can call.

Optional bonus layer over the CLI. The heuristics and scoring are unchanged and
deterministic; the model client just gets to ask "analyze this .eml". Needs the
`mcp` package (pip install mcp); nothing else in this repo imports it, so the
test gate stays stdlib-only.

Run (stdio):            python -m phish_triage.mcp_server
Wire into Claude Code:  claude mcp add phish-triage -- python -m phish_triage.mcp_server
"""
from __future__ import annotations

import os
import tempfile

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

from . import analyze

server = MCPServer(
    "phish-triage",
    instructions=(
        "Analyze a suspicious email (.eml) and return a deterministic phishing "
        "verdict, a 0-100 risk score, the per-signal breakdown, and defanged "
        "indicators. The score/verdict are heuristic, not model-decided; a human "
        "analyst must review before acting."
    ),
)

# Reads a file / caller-supplied text and computes; never sends or mutates mail.
READ_ONLY = ToolAnnotations(read_only_hint=True, destructive_hint=False,
                            idempotent_hint=True, open_world_hint=False)


@server.tool(annotations=READ_ONLY)
def analyze_email(eml_path: str = "", eml_text: str = "",
                  with_narrative: bool = False) -> str:
    """Triage one email. Pass eml_path (a .eml file) OR eml_text (raw message
    source). Set with_narrative=true to add the AI analyst summary (needs a
    reachable LLM; falls back to a notice if not). Returns the markdown report
    with a deterministic verdict, score, signal table and defanged IOCs."""
    if not eml_path and not eml_text:
        return "Provide eml_path (a .eml file) or eml_text (raw message source)."
    tmp = None
    try:
        if eml_text and not eml_path:
            fd, tmp = tempfile.mkstemp(suffix=".eml")
            with os.fdopen(fd, "w") as fh:
                fh.write(eml_text)
            eml_path = tmp
        if not os.path.isfile(eml_path):
            return f"Not a file: {eml_path}"
        return analyze(eml_path, with_llm=with_narrative)["markdown"]
    finally:
        if tmp:
            os.unlink(tmp)


def main():
    server.run()


if __name__ == "__main__":
    main()
