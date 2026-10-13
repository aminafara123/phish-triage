"""Offline tests for the deterministic core. No network, no live model.

Run: pytest -q
"""
from pathlib import Path

import pytest

from phish_triage import analyze, llm, parse, report
from phish_triage.score import score_signals
from phish_triage.signals import Signal, evaluate

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def _sigmap(email):
    return {s.id: s for s in evaluate(email)}


# --- defang / refang / domain parsing --------------------------------------

def test_defang_refang_roundtrip():
    assert parse.defang("http://evil.com/a") == "hxxp://evil[.]com/a"
    assert parse.defang("https://a.b.com") == "hxxps://a[.]b[.]com"
    assert parse.refang("hxxps://paypal[.]com/x") == "https://paypal.com/x"
    # refang(defang(x)) == x for a plain URL
    url = "https://sub.example.co.uk/path"
    assert parse.refang(parse.defang(url)) == url


def test_registered_domain():
    assert parse.registered_domain("https://a.b.paypa1-secure.com/x") == "paypa1-secure.com"
    assert parse.registered_domain("mail.google.co.uk") == "google.co.uk"
    assert parse.registered_domain("noreply@github.com") == "github.com"
    assert parse.registered_domain("http://203.0.113.9/login") == "203.0.113.9"


def test_extract_urls_handles_defanged_text():
    urls = parse.extract_urls("click hxxps://paypa1-secure[.]com/verify now and hxxp://x[.]io")
    assert "https://paypa1-secure.com/verify" in urls
    assert "http://x.io" in urls


# --- parsing ---------------------------------------------------------------

def test_parse_eml_fields():
    e = parse.parse_eml(str(SAMPLES / "obvious-phish.eml"))
    assert e.from_addr == "service@paypa1-secure.com"
    assert e.from_name == "PayPal Security"
    assert e.reply_to == "recover@secure-refund.net"
    assert e.return_path == "bounce@mailer-paypa1.com"
    # defanged header did not truncate the domain
    assert parse.registered_domain(e.from_addr) == "paypa1-secure.com"
    # attachment + urls + anchors extracted
    assert any(a["filename"] == "PayPal_Invoice.html" for a in e.attachments)
    assert any(u.startswith("https://paypa1-secure.com/verify") for u in e.urls)
    assert e.anchors and e.anchors[0][0].startswith("https://paypa1-secure.com")


# --- header-mismatch detection ---------------------------------------------

def test_header_mismatch_flags_phish_not_benign():
    phish = _sigmap(parse.parse_eml(str(SAMPLES / "obvious-phish.eml")))
    assert phish["reply_to_mismatch"].triggered
    assert phish["return_path_mismatch"].triggered
    assert phish["display_name_spoof"].triggered

    benign = _sigmap(parse.parse_eml(str(SAMPLES / "benign-newsletter.eml")))
    assert not benign["reply_to_mismatch"].triggered
    assert not benign["return_path_mismatch"].triggered
    # "GitHub" from github.com must NOT be read as brand spoofing
    assert not benign["display_name_spoof"].triggered


def test_auth_results_fail_detected():
    phish = _sigmap(parse.parse_eml(str(SAMPLES / "obvious-phish.eml")))
    assert phish["spf_fail"].triggered
    assert phish["dkim_fail"].triggered
    assert phish["dmarc_fail"].triggered
    benign = _sigmap(parse.parse_eml(str(SAMPLES / "benign-newsletter.eml")))
    assert not benign["dmarc_fail"].triggered


# --- URL signals: lookalike / ip / shortener / punycode --------------------

def test_url_signal_flags():
    e = parse.ParsedEmail(urls=[
        "https://paypa1-secure.com/login",   # lookalike (1->l homoglyph)
        "http://203.0.113.5/verify",         # ip-literal
        "https://bit.ly/abc",                # shortener
        "https://xn--pypl-53d.com/",         # punycode
    ])
    s = {x.id: x for x in evaluate(e)}
    assert s["url_lookalike"].triggered
    assert s["url_ip_literal"].triggered
    assert s["url_shortener"].triggered
    assert s["url_punycode"].triggered
    # details are defanged (no live links in the report)
    assert "hxxp" in s["url_ip_literal"].detail and "[.]" in s["url_ip_literal"].detail


def test_anchor_mismatch_detected():
    phish = _sigmap(parse.parse_eml(str(SAMPLES / "obvious-phish.eml")))
    assert phish["anchor_mismatch"].triggered


# --- scoring / verdicts ----------------------------------------------------

def test_score_thresholds():
    assert score_signals([Signal("a", "a", 70, True, "")]) == (70, "Likely Phishing")
    assert score_signals([Signal("a", "a", 30, True, "")]) == (30, "Suspicious")
    assert score_signals([Signal("a", "a", 10, True, "")]) == (10, "Benign")
    # score is capped at 100
    big = [Signal(str(i), "x", 50, True, "") for i in range(4)]
    assert score_signals(big)[0] == 100


@pytest.mark.parametrize("name,verdict,lo,hi", [
    ("obvious-phish", "Likely Phishing", 60, 100),
    ("subtle-bec", "Suspicious", 25, 59),
    ("benign-newsletter", "Benign", 0, 24),
    ("benign-google-alert", "Benign", 0, 24),
])
def test_pipeline_verdicts(name, verdict, lo, hi):
    r = analyze(str(SAMPLES / f"{name}.eml"), with_llm=False)
    assert r["verdict"] == verdict
    assert lo <= r["score"] <= hi


# --- LLM is mocked / degrades; verdict stays deterministic -----------------

def test_llm_narrative_is_mocked_into_report(monkeypatch):
    monkeypatch.setattr(llm, "narrate", lambda ctx, timeout=60: "MOCK-NARRATIVE")
    r = analyze(str(SAMPLES / "subtle-bec.eml"), with_llm=True)
    assert r["narrative"] == "MOCK-NARRATIVE"
    assert "MOCK-NARRATIVE" in r["markdown"]
    # verdict is unchanged by the model
    assert r["verdict"] == "Suspicious"


def test_llm_degrades_without_network(monkeypatch):
    def boom(*a, **k):
        raise OSError("no network")
    monkeypatch.setattr(llm.urllib.request, "urlopen", boom)
    out = llm.narrate({"verdict": "Benign", "score": 0, "signals": []})
    assert "LLM narrative unavailable" in out


def test_report_labels_ai_and_disclaimer():
    r = analyze(str(SAMPLES / "obvious-phish.eml"), with_llm=False)
    md = r["markdown"]
    assert "AI-generated" in md
    assert "human analyst must review" in md
    # IOCs in the report are defanged, never a live link
    assert "http://" not in md and "https://" not in md
    assert r["json"]["verdict"] == "Likely Phishing"
