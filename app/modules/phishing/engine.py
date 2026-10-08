"""Module 1 - phishing & malicious-URL heuristics.

Purely offline: the URL is parsed and scored, never fetched (no SSRF surface).
The "NLP" intent check is a transparent lexicon/pattern matcher, not a trained model.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

from app.shared.models import Finding, ModuleResult


class InvalidURLError(ValueError):
    """Raised when the input cannot be treated as an http(s) URL."""


_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://")
_NUMERIC_HOST_RE = re.compile(r"(0x[0-9a-f]+|\d+)(\.(0x[0-9a-f]+|\d+)){0,3}")

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy", "ow.ly",
    "shorturl.at", "tiny.cc",
}  # fmt: skip
RISKY_TLDS = {
    "zip", "mov", "tk", "ml", "ga", "cf", "gq", "xyz", "top", "click", "work", "support",
    "country", "loan", "men", "icu", "buzz", "rest", "fit", "cam",
}  # fmt: skip
KEYWORDS = (
    "login", "signin", "verify", "update", "banking", "secure", "account", "confirm",
    "password", "kyc", "otp", "wallet", "suspend",
)  # fmt: skip
MULTI_SUFFIX = {
    "co.in", "org.in", "net.in", "gov.in", "ac.in", "nic.in", "res.in", "co.uk", "org.uk",
    "com.au", "co.jp", "com.br",
}  # fmt: skip

# brand token -> official registered domains
BRANDS: dict[str, set[str]] = {
    "sbi": {"sbi.co.in", "onlinesbi.sbi", "onlinesbi.com", "sbicard.com"},
    "hdfcbank": {"hdfcbank.com"},
    "icicibank": {"icicibank.com"},
    "axisbank": {"axisbank.com"},
    "paytm": {"paytm.com"},
    "phonepe": {"phonepe.com"},
    "npci": {"npci.org.in"},
    "irctc": {"irctc.co.in"},
    "incometax": {"incometax.gov.in"},
    "uidai": {"uidai.gov.in"},
    "paypal": {"paypal.com"},
    "google": {"google.com", "google.co.in", "googleusercontent.com"},
    "microsoft": {"microsoft.com", "microsoftonline.com", "live.com", "office.com"},
    "amazon": {"amazon.com", "amazon.in", "amazonaws.com"},
    "flipkart": {"flipkart.com"},
    "apple": {"apple.com", "icloud.com"},
    "facebook": {"facebook.com"},
    "instagram": {"instagram.com"},
    "whatsapp": {"whatsapp.com", "whatsapp.net"},
    "netflix": {"netflix.com"},
}
_OFFICIAL = set().union(*BRANDS.values())

URGENCY_PATTERNS = [
    r"\bwithin\s+\d+\s*(?:hours?|hrs?|minutes?|mins?)\b",
    r"\b(?:immediately|urgent(?:ly)?|act now|right away|asap)\b",
    r"\b(?:final|last)\s+(?:notice|warning|reminder)\b",
    r"\baccount\s+(?:will\s+be\s+)?(?:suspended|blocked|locked|closed|deactivated)\b",
    r"\b(?:expires?|expiring)\s+(?:today|soon|tonight|in\s+\d+)",
    r"\bunauthori[sz]ed\s+(?:access|login|transaction)\b",
    r"\blegal action\b",
]
CREDENTIAL_PATTERNS = [
    r"\b(?:verify|confirm|validate|update)\s+(?:your\s+)?(?:account|identity|details|"
    r"information|kyc|pan|aadhaar|password|card)\b",
    r"\b(?:enter|share|provide|send|submit)\s+(?:your\s+)?(?:otp|pin|password|cvv|"
    r"card number|aadhaar|pan|upi pin|login)\b",
    r"\bkyc\s+(?:update|verification|expired|pending)\b",
    r"\b(?:click|tap)\s+(?:the\s+)?(?:link|here|below)\s+to\s+(?:verify|confirm|update|"
    r"log\s?in|unlock|restore)\b",
    r"\bone[- ]time\s+password\b",
    r"\bnet\s?banking\s+(?:password|credentials)\b",
]
_URGENCY_RE = [re.compile(p, re.IGNORECASE) for p in URGENCY_PATTERNS]
_CREDENTIAL_RE = [re.compile(p, re.IGNORECASE) for p in CREDENTIAL_PATTERNS]

_HOMOGLYPHS = str.maketrans({"0": "o", "3": "e", "5": "s", "4": "a", "$": "s"})


def parse_url(url: str):
    raw = url.strip()
    if not raw or len(raw) > 2048:
        raise InvalidURLError("URL is empty or longer than 2048 characters")
    if any(ord(c) < 32 or c.isspace() for c in raw):
        raise InvalidURLError("URL must not contain whitespace or control characters")
    assumed = False
    if not _SCHEME_RE.match(raw):
        raw = ("https:" + raw) if raw.startswith("//") else ("https://" + raw)
        assumed = True
    try:
        parts = urlsplit(raw)
        host = parts.hostname
        port = parts.port
    except ValueError as exc:
        raise InvalidURLError("Malformed URL") from exc
    if parts.scheme.lower() not in {"http", "https"}:
        raise InvalidURLError("Only http and https URLs are supported")
    if not host:
        raise InvalidURLError("URL has no host")
    return parts, host.rstrip(".").lower(), port, assumed


def _is_ip_host(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(_NUMERIC_HOST_RE.fullmatch(host))


def registered_domain(labels: list[str]) -> str:
    if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_SUFFIX:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:]) if len(labels) >= 2 else ".".join(labels)


def _levenshtein(a: str, b: str) -> int:
    if abs(len(a) - len(b)) > 3:
        return 99
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _variants(label: str) -> set[str]:
    base = label.translate(_HOMOGLYPHS).replace("rn", "m").replace("vv", "w")
    return {base.replace("1", "l"), base.replace("1", "i")}


def _brand_finding(host: str, reg: str, reg_label: str, path: str) -> Finding | None:
    if reg in _OFFICIAL:
        return None
    variants = _variants(reg_label)
    for brand in BRANDS:
        if reg_label == brand:
            continue
        close = len(brand) >= 6 and 0 < _levenshtein(reg_label, brand) <= (
            2 if len(brand) >= 9 else 1
        )
        if brand in variants or close:
            return Finding("typosquat", 35, {"domain": reg, "brand": brand})
    host_tokens = set(re.split(r"[.\-]", host))
    for brand in BRANDS:
        if brand in host_tokens or (len(brand) >= 5 and brand in reg_label):
            return Finding("brand_misplaced", 25, {"brand": brand, "domain": reg})
    path_tokens = set(re.split(r"[^a-z0-9]+", path.lower()))
    for brand in BRANDS:
        if brand in path_tokens:
            return Finding("brand_misplaced", 15, {"brand": brand, "domain": reg})
    return None


def _intent_findings(text: str) -> list[Finding]:
    out: list[Finding] = []
    urgency = [m.group(0) for rx in _URGENCY_RE if (m := rx.search(text))]
    cred = [m.group(0) for rx in _CREDENTIAL_RE if (m := rx.search(text))]
    if urgency:
        out.append(Finding("intent_urgency", min(15, 6 * len(urgency)), {"phrases": urgency[:3]}))
    if cred:
        out.append(Finding("intent_credential", min(25, 10 * len(cred)), {"phrases": cred[:3]}))
    return out


def analyze(url: str, text: str | None = None) -> ModuleResult:
    parts, host, port, assumed = parse_url(url)
    findings: list[Finding] = []
    length = len(url.strip())
    is_ip = _is_ip_host(host)

    if is_ip:
        findings.append(Finding("ip_host", 30, {"host": host}))
    if "@" in parts.netloc:
        findings.append(Finding("at_symbol", 20))
    if parts.scheme == "http" and not assumed:
        findings.append(Finding("no_https", 10))
    if length > 120:
        findings.append(Finding("long_url", 15, {"length": length}))
    elif length > 75:
        findings.append(Finding("long_url", 8, {"length": length}))
    if port not in (None, 80, 443):
        findings.append(Finding("nonstandard_port", 8, {"port": port}))

    haystack = (host + parts.path + "?" + parts.query).lower()
    hits = [k for k in KEYWORDS if k in haystack]
    if hits:
        findings.append(Finding("suspicious_keywords", min(16, 4 * len(hits)), {"keywords": hits}))

    evidence: dict = {
        "host": host,
        "scheme": parts.scheme,
        "url_length": length,
        "is_ip_host": is_ip,
    }

    if not is_ip:
        try:
            ascii_host = host.encode("idna").decode()
        except UnicodeError:
            ascii_host = host
        labels = ascii_host.split(".")
        reg = registered_domain(labels)
        reg_label = reg.split(".")[0]
        tld = labels[-1]
        sub_depth = len(labels) - len(reg.split("."))
        evidence.update({"registered_domain": reg, "tld": tld, "subdomain_depth": sub_depth})

        if ascii_host in SHORTENERS:
            findings.append(Finding("url_shortener", 10, {"host": ascii_host}))
        if tld in RISKY_TLDS:
            findings.append(Finding("risky_tld", 15, {"tld": tld}))
        if sub_depth > 3:
            findings.append(Finding("deep_subdomains", 10, {"count": sub_depth}))
        if host.count("-") >= 3:
            findings.append(Finding("many_hyphens", 8, {"count": host.count("-")}))
        if any(label.startswith("xn--") for label in labels) or ascii_host != host:
            findings.append(Finding("punycode", 20))
        brand = _brand_finding(ascii_host, reg, reg_label, parts.path)
        if brand:
            findings.append(brand)

    notes: list[str] = []
    if text:
        findings.extend(_intent_findings(text))
        evidence["text_analysed"] = True
    if assumed:
        notes.append("No scheme was given; https was assumed and the HTTP check was skipped.")
    notes.append("Offline analysis only: the URL was not fetched and reputation was not checked.")
    return ModuleResult("phishing", findings, evidence, notes)
