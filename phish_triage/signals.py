"""Deterministic phishing signals.

Each check returns a Signal whether it fired or not, so the report can show the
full checklist (not just the hits). Only `triggered` signals add to the score.
Everything here is pure and offline: no model, no network.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from . import parse

# --- reference data ---------------------------------------------------------

# brand token -> the domains that legitimately belong to it
BRANDS = {
    "paypal": {"paypal.com"},
    "microsoft": {"microsoft.com", "outlook.com", "office.com", "office365.com",
                  "live.com", "microsoftonline.com"},
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com", "amazon.co.uk", "amazonses.com"},
    "google": {"google.com", "gmail.com", "accounts.google.com"},
    "netflix": {"netflix.com"},
    "docusign": {"docusign.com", "docusign.net"},
    "dhl": {"dhl.com"},
    "fedex": {"fedex.com"},
    "ups": {"ups.com"},
    "chase": {"chase.com"},
    "wellsfargo": {"wellsfargo.com"},
    "bankofamerica": {"bankofamerica.com"},
    "linkedin": {"linkedin.com"},
    "facebook": {"facebook.com", "meta.com"},
    "instagram": {"instagram.com"},
    "whatsapp": {"whatsapp.com"},
    "coinbase": {"coinbase.com"},
    "github": {"github.com"},
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rb.gy", "cutt.ly", "rebrand.ly", "shorturl.at", "tiny.cc", "t.ly",
}

FREEMAIL = {"gmail.com", "outlook.com", "hotmail.com", "yahoo.com",
            "aol.com", "icloud.com", "proton.me", "gmx.com", "mail.com"}

# very-risky (executables/scripts) vs risky (macros/archives/active content)
EXT_EXEC = {"exe", "scr", "com", "pif", "bat", "cmd", "js", "jse", "vbs",
            "vbe", "wsf", "hta", "lnk", "ps1", "msi", "jar", "jnlp", "reg"}
EXT_RISKY = {"zip", "rar", "7z", "gz", "iso", "img", "docm", "xlsm", "pptm",
             "dotm", "html", "htm", "svg", "ace", "cab", "one"}

# homoglyph fold: digits/symbols commonly swapped for letters in lookalikes
_HOMOGLYPH = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s",
                            "7": "t", "$": "s", "@": "a"})

URGENCY_PATTERNS = [
    r"urgent", r"immediate(?:ly)?", r"within \d+ ?h(?:ou)?rs?", r"act now",
    r"as soon as possible", r"asap", r"final (?:notice|warning|reminder)",
    r"account (?:has been )?(?:suspend|lock|limit|restrict|disabl)",
    r"suspend(?:ed|ing)?", r"will be (?:closed|terminated|deleted|deactivated)",
    r"verify (?:your )?(?:account|identity|information|details)",
    r"confirm (?:your )?(?:account|identity|password|payment|details)",
    r"update (?:your )?(?:password|payment|billing|bank|account)",
    r"unusual (?:activity|sign[- ]?in|login)", r"security alert",
    r"click (?:here|the link|below)", r"log ?in to (?:verify|confirm|secure)",
    r"re-?activate", r"re-?validate", r"validate your",
    r"wire (?:transfer|the funds|payment)", r"gift ?cards?",
    r"keep this confidential", r"are you (?:at your desk|available)",
    r"bank (?:details|account) (?:have|has) changed", r"remittance",
]


@dataclass
class Signal:
    id: str
    name: str
    weight: int
    triggered: bool
    detail: str


def _sig(id, name, weight, triggered, detail):
    return Signal(id, name, weight if triggered else 0, triggered, detail)


# --- individual checks ------------------------------------------------------

def _header_mismatch(e: parse.ParsedEmail) -> list[Signal]:
    out = []
    from_dom = parse.registered_domain(e.from_addr)
    rt_dom = parse.registered_domain(e.reply_to) if e.reply_to else ""
    rp_dom = parse.registered_domain(e.return_path) if e.return_path else ""

    out.append(_sig(
        "reply_to_mismatch", "Reply-To differs from From", 15,
        bool(rt_dom and from_dom and rt_dom != from_dom),
        f"Reply-To {parse.defang(rt_dom)} vs From {parse.defang(from_dom)}"
        if rt_dom and rt_dom != from_dom
        else ("Reply-To matches From" if rt_dom else "no Reply-To header")))

    out.append(_sig(
        "return_path_mismatch", "Return-Path differs from From", 10,
        bool(rp_dom and from_dom and rp_dom != from_dom),
        f"Return-Path {parse.defang(rp_dom)} vs From {parse.defang(from_dom)}"
        if rp_dom and rp_dom != from_dom
        else ("Return-Path matches From" if rp_dom else "no Return-Path header")))
    return out


def _display_name_spoof(e: parse.ParsedEmail) -> Signal:
    name = e.from_name.lower()
    from_dom = parse.registered_domain(e.from_addr)
    folded = name.translate(_HOMOGLYPH)
    # brand named in display name but From domain is not that brand's
    for brand, domains in BRANDS.items():
        if brand in folded and from_dom not in domains:
            return _sig(
                "display_name_spoof", "Display-name brand spoofing", 20, True,
                f"display name claims '{e.from_name}' but From domain is "
                f"{parse.defang(from_dom) or '(none)'}")
    # display name contains a domain/email that disagrees with the real From
    m = re.search(r"[\w.-]+\.[a-z]{2,}", name)
    if m and from_dom and parse.registered_domain(m.group(0)) != from_dom:
        return _sig(
            "display_name_spoof", "Display-name brand spoofing", 20, True,
            f"display name shows {parse.defang(m.group(0))} but From domain is "
            f"{parse.defang(from_dom)}")
    return _sig("display_name_spoof", "Display-name brand spoofing", 20, False,
                "display name consistent with From domain")


def _auth_results(e: parse.ParsedEmail) -> list[Signal]:
    text = e.auth_results.lower()
    specs = [("spf", "SPF", 15), ("dkim", "DKIM", 12), ("dmarc", "DMARC", 15)]
    out = []
    for key, label, weight in specs:
        m = re.search(rf"\b{key}\s*=\s*([a-z]+)", text)
        result = m.group(1) if m else ""
        failed = result in {"fail", "softfail", "permerror", "temperror"}
        if not result:
            detail = f"{label} result not present in headers"
        else:
            detail = f"{label}={result}"
        out.append(_sig(f"{key}_fail", f"{label} authentication", weight,
                        failed, detail))
    return out


def _received_chain(e: parse.ParsedEmail) -> Signal:
    # ponytail: counts hops only; deeper HELO/claimed-domain analysis is the
    # upgrade path if false-negatives show up.
    hops = len(e.received)
    return _sig("received_chain", "Received-chain sanity", 8, hops == 0,
                "no Received headers (unusual for delivered mail)" if hops == 0
                else f"{hops} Received hop(s) present")


def _url_signals(e: parse.ParsedEmail) -> list[Signal]:
    hosts = [(u, parse.host_of(u)) for u in e.urls]
    puny, ipl, short, look = [], [], [], []
    for url, host in hosts:
        if not host:
            continue
        rd = parse.registered_domain(host)
        if any(lbl.startswith("xn--") for lbl in host.split(".")):
            puny.append(url)
        if parse.is_ip(host):
            ipl.append(url)
        if rd in SHORTENERS:
            short.append(url)
        folded = host.translate(_HOMOGLYPH)
        for brand, domains in BRANDS.items():
            if brand in folded and rd not in domains:
                look.append(url)
                break

    def joined(urls):
        return ", ".join(parse.defang(u) for u in urls[:4])

    return [
        _sig("url_punycode", "Punycode / IDN-homograph URL", 20, bool(puny),
             joined(puny) if puny else "no punycode (xn--) hosts"),
        _sig("url_ip_literal", "IP-literal URL", 15, bool(ipl),
             joined(ipl) if ipl else "no IP-literal URLs"),
        _sig("url_shortener", "URL-shortener link", 10, bool(short),
             joined(short) if short else "no link-shortener URLs"),
        _sig("url_lookalike", "Brand-lookalike / typosquat URL", 20, bool(look),
             joined(look) if look else "no brand-lookalike URLs"),
    ]


def _anchor_mismatch(e: parse.ParsedEmail) -> Signal:
    bad = []
    for href, text in e.anchors:
        m = re.search(r"[\w.-]+\.[a-z]{2,}", text.lower())
        if not m:
            continue
        shown = parse.registered_domain(m.group(0))
        real = parse.registered_domain(parse.host_of(href))
        if shown and real and shown != real:
            bad.append(f"text '{parse.defang(m.group(0))}' -> "
                       f"{parse.defang(parse.host_of(href))}")
    return _sig("anchor_mismatch", "Link text hides a different host", 15,
                bool(bad), "; ".join(bad[:3]) if bad
                else "no deceptive link text")


def _attachments(e: parse.ParsedEmail) -> Signal:
    exec_hits, risky_hits = [], []
    for att in e.attachments:
        ext = att["filename"].rsplit(".", 1)[-1].lower() if "." in att["filename"] else ""
        if ext in EXT_EXEC:
            exec_hits.append(f"{att['filename']} ({ext})")
        elif ext in EXT_RISKY:
            risky_hits.append(f"{att['filename']} ({ext})")
    if exec_hits:
        return _sig("attachment_risk", "Risky attachment type", 25, True,
                    "executable/script: " + ", ".join(exec_hits))
    if risky_hits:
        return _sig("attachment_risk", "Risky attachment type", 12, True,
                    "macro/archive/active: " + ", ".join(risky_hits))
    n = len(e.attachments)
    return _sig("attachment_risk", "Risky attachment type", 12, False,
                f"{n} attachment(s), none high-risk" if n else "no attachments")


def _urgency(e: parse.ParsedEmail) -> Signal:
    blob = f"{e.subject}\n{e.body_text}".lower()
    hits = sorted({m.group(0) for pat in URGENCY_PATTERNS
                   for m in re.finditer(pat, blob)})
    weight = min(15, len(hits) * 4)
    return Signal("urgency_language", "Urgency / credential-harvest language",
                  weight, len(hits) >= 1,
                  (", ".join(hits[:6]) + (" ..." if len(hits) > 6 else ""))
                  if hits else "no urgency/credential-harvest phrasing")


def evaluate(e: parse.ParsedEmail) -> list[Signal]:
    """Run every deterministic check. Order = report order."""
    sigs: list[Signal] = []
    sigs += _header_mismatch(e)
    sigs.append(_display_name_spoof(e))
    sigs += _auth_results(e)
    sigs.append(_received_chain(e))
    sigs += _url_signals(e)
    sigs.append(_anchor_mismatch(e))
    sigs.append(_attachments(e))
    sigs.append(_urgency(e))
    return sigs
