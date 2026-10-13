"""CLI:  python -m phish_triage samples/*.eml

Writes out/<name>.report.md and out/<name>.json per email, prints a one-line
verdict for each. --no-llm skips the narrative (useful offline / in CI).
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import sys

from . import analyze


def _expand(patterns: list[str]) -> list[str]:
    files: list[str] = []
    for p in patterns:
        hits = glob.glob(p)
        files.extend(hits if hits else [p])  # keep literal if no glob match
    return files


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="phish_triage",
        description="Score .eml files for phishing with deterministic signals.")
    ap.add_argument("emls", nargs="+", help="one or more .eml files or globs")
    ap.add_argument("-o", "--out", default="out", help="output dir (default: out)")
    ap.add_argument("--no-llm", action="store_true",
                    help="skip the AI narrative (no LLM call)")
    args = ap.parse_args(argv)

    os.makedirs(args.out, exist_ok=True)
    rc = 0
    for path in _expand(args.emls):
        if not os.path.isfile(path):
            print(f"skip: {path} (not a file)", file=sys.stderr)
            rc = 1
            continue
        res = analyze(path, with_llm=not args.no_llm)
        stem = os.path.splitext(os.path.basename(path))[0]
        md_path = os.path.join(args.out, f"{stem}.report.md")
        json_path = os.path.join(args.out, f"{stem}.json")
        with open(md_path, "w") as fh:
            fh.write(res["markdown"])
        with open(json_path, "w") as fh:
            json.dump(res["json"], fh, indent=2)
        print(f"{res['verdict']:<16} {res['score']:>3}/100  {stem}  "
              f"-> {md_path}")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
