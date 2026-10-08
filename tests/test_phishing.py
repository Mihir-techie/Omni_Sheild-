import pytest

from app.modules.phishing.engine import InvalidURLError, analyze


def codes(result):
    return {f.code for f in result.findings}


def test_benign_url_scores_safe():
    r = analyze("https://example.com/login")
    assert r.score < 20
    assert not codes(r) - {"suspicious_keywords"}


def test_raw_ip_and_http_flagged():
    r = analyze("http://192.168.4.7/verify/account")
    assert {"ip_host", "no_https", "suspicious_keywords"} <= codes(r)


def test_obfuscated_numeric_ip_flagged():
    assert "ip_host" in codes(analyze("http://3232235777/login"))


def test_userinfo_trick_flagged_and_real_host_used():
    r = analyze("https://paypal.com@evil.example.xyz/login")
    assert "at_symbol" in codes(r)
    assert r.evidence["host"] == "evil.example.xyz"


def test_homoglyph_typosquat():
    r = analyze("https://paypa1.com/signin")
    assert "typosquat" in codes(r)


def test_brand_in_wrong_domain():
    r = analyze("https://sbi-secure-login.xyz/netbanking")
    assert "brand_misplaced" in codes(r)
    assert "risky_tld" in codes(r)


@pytest.mark.parametrize(
    "url",
    [
        "https://www.paypal.com/signin",
        "https://login.microsoftonline.com/common",
        "https://retail.onlinesbi.sbi/",
        "https://www.sbi.co.in/",
    ],
)
def test_official_domains_not_flagged_as_brand_abuse(url):
    assert not codes(analyze(url)) & {"typosquat", "brand_misplaced"}


def test_punycode_flagged():
    assert "punycode" in codes(analyze("https://xn--pypal-4ve.com/"))


def test_missing_scheme_is_accepted_without_http_penalty():
    r = analyze("example.com/path")
    assert "no_https" not in codes(r)


def test_text_intent_check():
    text = "URGENT: your account will be suspended within 24 hours. Verify your account and enter your OTP."
    c = codes(analyze("https://example.com", text))
    assert {"intent_urgency", "intent_credential"} <= c


@pytest.mark.parametrize("bad", ["", "ftp://example.com", "javascript:alert(1)", "http://", "a b.com"])
def test_invalid_urls_rejected(bad):
    with pytest.raises(InvalidURLError):
        analyze(bad)
