# 60-second demo script

Goal: show a deterministic phishing verdict with a defensible reason, and prove the LLM only writes prose.

## Setup (before recording)

```bash
make install
clear
```

## Recording (about 60 seconds)

1) Say the one-liner: "phish-triage reads a raw .eml and scores it like a SOC analyst would, same way every time."

2) Show the samples (2s):
```bash
ls samples/
```

3) Run the whole set (5s). Point at the four verdicts:
```bash
python -m phish_triage --no-llm samples/*.eml
```
Call out: obvious-phish 100 Likely Phishing, benign-newsletter 0 Benign, and the Google alert staying Benign despite "Security alert" wording.

4) Open the phishing report and scroll the signal table (15s):
```bash
sed -n '1,30p' out/obvious-phish.report.md
```
Say: "Every FLAG has a reason. Reply-To mismatch, display-name spoof, DMARC fail, a lookalike link, anchor text that hides a different host. The score is the sum of those weights, not a guess."

5) Point at the defanged IOCs section: "No live links anywhere in the repo or the output."

6) Add the AI narrative (10s), to show the model is additive, not deciding:
```bash
python -m phish_triage samples/obvious-phish.eml
sed -n '/Analyst narrative/,$p' out/obvious-phish.report.md
```
Say: "The local LLM writes the summary. It is labelled AI-generated and it never moves the score. The verdict is still 100, Likely Phishing."

7) Close on the tests (5s):
```bash
pytest -q
```
Say: "Offline, no network, no API key. The deterministic core is what the tests lock down."
