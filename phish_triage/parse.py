"""Parse a .eml file into the fields the deterministic checks need.

Stdlib `email` does the heavy lifting. The only non-obvious bit is defang /
refang: samples and reports keep URLs/domains defanged (hxxp, [.]) so the repo
holds no live clickable links, but the checks need real hosts, so the parser
refangs on the way in and the report defangs on the way out.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr
from urllib.parse import urlparse

# --- defang / refang --------------------------------------------------------

_URL_RE = re.compile(r"""https?://[^\s<>"')\]}]+""", re.IGNORECASE)
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

# eTLD+1 is approximated by "last two labels", with a small set of known
# two-part public suffixes handled explicitly.
# ponytail: naive public-suffix list; swap for `tldextract` if co.uk-style
# domains ever need to be exact.
_MULTI_TLD = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "co.jp", "com.au", "net.au",
    "org.au", "co.nz", "co.in", "co.za", "com.br", "com.cn", "com.mx",
    "com.sg", "co.kr", "com.tr",
}


def defang(s: str) -> str:
    """Make a URL/host safe to paste into a report (no live link)."""
    if not s:
        return s
    s = re.sub(r"https(?=://)", "hxxps", s, flags=re.IGNORECASE)
    s = re.sub(r"http(?=://)", "hxxp", s, flags=re.IGNORECASE)
    return s.replace(".", "[.]")


def refang(s: str) -> str:
    """Reverse common defanging so the string parses as a real URL/host."""
    if not s:
        return s
    s = (s.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".")
          .replace("[:]", ":").replace("[://]", "://"))
    s = re.sub(r"hxxps", "https", s, flags=re.IGNORECASE)
    s = re.sub(r"hxxp", "http", s, flags=re.IGNORECASE)
    return s


def host_of(url_or_addr: str) -> str:
    """Hostname from a URL or the domain from an email address."""
    s = refang(url_or_addr or "").strip()
    if "://" in s:
        return (urlparse(s).hostname or "").lower()
    if "@" in s:
        return s.rsplit("@", 1)[-1].strip(" <>").lower()
    return s.strip(" <>").lower()


def registered_domain(host_or_url: str) -> str:
    host = host_of(host_or_url).strip(".")
    if not host or is_ip(host):
        return host
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    last2 = ".".join(parts[-2:])
    if last2 in _MULTI_TLD and len(parts) >= 3:
        return ".".join(parts[-3:])
    return last2


def is_ip(host: str) -> bool:
    host = (host or "").strip("[]")
    return bool(_IPV4_RE.match(host)) or (":" in host and host.count(":") >= 2)


def extract_urls(text: str) -> list[str]:
    """Refanged, de-duplicated http(s) URLs in order of first appearance."""
    out, seen = [], set()
    for m in _URL_RE.finditer(refang(text or "")):
        url = m.group(0).rstrip(".,);]'\"")
        if url not in seen:
            seen.add(url)
            out.append(url)
    return out


# --- model ------------------------------------------------------------------

@dataclass
class ParsedEmail:
    path: str = ""
    subject: str = ""
    from_name: str = ""
    from_addr: str = ""
    reply_to: str = ""
    return_path: str = ""
    to: str = ""
    date: str = ""
    auth_results: str = ""
    received: list[str] = field(default_factory=list)
    body_text: str = ""
    html: str = ""
    urls: list[str] = field(default_factory=list)
    anchors: list[tuple[str, str]] = field(default_factory=list)
    attachments: list[dict] = field(default_factory=list)


_ANCHOR_RE = re.compile(
    r"""<a\b[^>]*\bhref\s*=\s*["']([^"']+)["'][^>]*>(.*?)</a>""",
    re.IGNORECASE | re.DOTALL,
)
_TAG_RE = re.compile(r"<[^>]+>")


def _strip_html(html: str) -> str:
    return re.sub(r"\s+", " ", _TAG_RE.sub(" ", html or "")).strip()


def _first_addr(values: list[str]) -> str:
    # refang BEFORE parseaddr: a defanged "[.]" looks like a domain-literal and
    # makes the stdlib parser truncate the address.
    for _, addr in getaddresses([refang(v) for v in (values or [])]):
        if addr:
            return addr.lower()
    return ""


def _refang_header_bytes(raw: bytes) -> bytes:
    # policy.default parses address headers at parse time, so a defanged "[.]"
    # must be undone BEFORE parsing or the address gets truncated. Only the
    # header block is touched; the body is left alone (base64 never contains
    # "[.]", and body URLs are refanged later by extract_urls).
    for sep in (b"\r\n\r\n", b"\n\n"):
        i = raw.find(sep)
        if i != -1:
            return refang(raw[:i].decode("latin-1")).encode("latin-1") + raw[i:]
    return refang(raw.decode("latin-1")).encode("latin-1")


def parse_eml(path: str) -> ParsedEmail:
    with open(path, "rb") as fh:
        msg = BytesParser(policy=policy.default).parsebytes(
            _refang_header_bytes(fh.read()))

    name, addr = parseaddr(refang(msg.get("from", "")))
    e = ParsedEmail(
        path=str(path),
        subject=(msg.get("subject", "") or "").strip(),
        from_name=name.strip(),
        from_addr=addr.lower(),
        reply_to=_first_addr(msg.get_all("reply-to", [])),
        return_path=parseaddr(refang(msg.get("return-path", "")))[1].lower(),
        to=msg.get("to", "") or "",
        date=msg.get("date", "") or "",
        received=[str(r) for r in msg.get_all("received", [])],
    )
    auth = msg.get_all("authentication-results", []) + \
        msg.get_all("received-spf", []) + \
        msg.get_all("arc-authentication-results", [])
    e.auth_results = "\n".join(str(a) for a in auth)

    plain, html = [], []
    for part in msg.walk():
        if part.is_multipart():
            continue
        ctype = part.get_content_type()
        filename = part.get_filename()
        disp = part.get_content_disposition()
        if disp == "attachment" or (filename and disp != "inline"):
            e.attachments.append({"filename": filename or "(unnamed)",
                                  "content_type": ctype})
            continue
        try:
            content = part.get_content()
        except Exception:
            continue
        if not isinstance(content, str):
            continue
        if ctype == "text/plain":
            plain.append(content)
        elif ctype == "text/html":
            html.append(content)

    e.html = "\n".join(html)
    e.body_text = "\n".join(plain) or _strip_html(e.html)
    e.anchors = [(refang(h), _strip_html(t)) for h, t in _ANCHOR_RE.findall(e.html)]
    e.urls = extract_urls("\n".join(plain + html))
    return e


if __name__ == "__main__":  # tiny self-check
    assert registered_domain("https://a.b.paypa1-secure.com/x") == "paypa1-secure.com"
    assert registered_domain("mail.google.co.uk") == "google.co.uk"
    assert refang("hxxps://paypal[.]com/x") == "https://paypal.com/x"
    assert defang("http://evil.com") == "hxxp://evil[.]com"
    assert extract_urls("go hxxp://evil[.]com/a now") == ["http://evil.com/a"]
    assert is_ip("203.0.113.9") and not is_ip("example.com")
    print("parse self-check OK")
