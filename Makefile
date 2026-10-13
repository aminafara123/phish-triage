.PHONY: install test run clean mcp

install:
	python3 -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt

test:
	python3 -m pytest -q

run:
	python3 -m phish_triage samples/*.eml

mcp:
	python3 -m phish_triage.mcp_server

clean:
	rm -rf out .pytest_cache && find . -name __pycache__ -type d -exec rm -rf {} +
