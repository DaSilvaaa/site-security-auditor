import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from siteaudit import checks, cli, fetch  # noqa: E402
from siteaudit.report import build_pdf  # noqa: E402

GOOD_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'; object-src 'none'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=()",
}
NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)
GOOD_TLS = {"protocol": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384", "issuer": "Let's Encrypt",
            "not_after": NOW + timedelta(days=60), "verify_error": None}


def failed_ids(findings):
    return {f.id for f in findings if not f.passed}


def test_good_headers_all_pass():
    assert failed_ids(checks.analyze_headers(GOOD_HEADERS)) == set()


def test_empty_headers_flag_everything():
    assert {"HDR-HSTS", "HDR-CSP", "HDR-FRAME", "HDR-XCTO", "HDR-REFERRER", "HDR-PERMS"} <= failed_ids(
        checks.analyze_headers({}))


def test_header_names_are_case_insensitive():
    lowered = {k.lower(): v for k, v in GOOD_HEADERS.items()}
    assert failed_ids(checks.analyze_headers(lowered)) == set()


def test_short_hsts_fails():
    h = {**GOOD_HEADERS, "Strict-Transport-Security": "max-age=300"}
    assert "HDR-HSTS" in failed_ids(checks.analyze_headers(h))


def test_unsafe_csp_fails():
    h = {**GOOD_HEADERS, "Content-Security-Policy": "default-src 'self' 'unsafe-inline'"}
    assert "HDR-CSP" in failed_ids(checks.analyze_headers(h))


def test_frame_ancestors_replaces_xfo():
    h = {k: v for k, v in GOOD_HEADERS.items() if k != "X-Frame-Options"}
    h["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'"
    assert "HDR-FRAME" not in failed_ids(checks.analyze_headers(h))


def test_version_leak_detected():
    assert "HDR-LEAK" in failed_ids(checks.analyze_headers({**GOOD_HEADERS, "Server": "nginx/1.18.0"}))
    assert "HDR-LEAK" not in failed_ids(checks.analyze_headers({**GOOD_HEADERS, "Server": "nginx"}))


def test_cookie_flags():
    bad = checks.analyze_cookies(["sid=abc; Path=/"])
    assert "Secure" in bad[0].detail and "HttpOnly" in bad[0].detail and "SameSite" in bad[0].detail
    assert checks.analyze_cookies(["sid=abc; Secure; HttpOnly; SameSite=Lax"])[0].passed


def test_redirect_checks():
    assert checks.analyze_redirect(301, "https://x.com/")[0].passed
    assert not checks.analyze_redirect(200, None)[0].passed
    assert not checks.analyze_redirect(301, "http://x.com/")[0].passed


def test_good_tls_passes():
    assert failed_ids(checks.analyze_tls(GOOD_TLS, now=NOW)) == set()


def test_expired_and_soon_expiring_cert():
    expired = {**GOOD_TLS, "not_after": NOW - timedelta(days=1)}
    soon = {**GOOD_TLS, "not_after": NOW + timedelta(days=5)}
    assert "TLS-EXPIRY" in failed_ids(checks.analyze_tls(expired, now=NOW))
    f = [x for x in checks.analyze_tls(soon, now=NOW) if x.id == "TLS-EXPIRY"][0]
    assert not f.passed and f.severity == "high"


def test_old_protocol_and_weak_cipher():
    ids = failed_ids(checks.analyze_tls({**GOOD_TLS, "protocol": "TLSv1", "cipher": "RC4-SHA"}, now=NOW))
    assert {"TLS-PROTO", "TLS-CIPHER"} <= ids


def test_untrusted_cert_is_critical():
    f = checks.analyze_tls({**GOOD_TLS, "verify_error": "self signed"}, now=NOW)[0]
    assert not f.passed and f.severity == "critical"


def test_score_and_grade():
    assert checks.score([checks.Finding("a", "a", "high", True, "")]) == (100, "A")
    bad = [checks.Finding(str(i), "x", "high", False, "") for i in range(4)]
    assert checks.score(bad) == (20, "F")


def test_parse_target():
    assert fetch.parse_target("exemplo.com") == ("exemplo.com", 443)
    assert fetch.parse_target("https://exemplo.com:8443/x") == ("exemplo.com", 8443)
    with pytest.raises(ValueError):
        fetch.parse_target("http://exemplo.com")


def test_pdf_generated_and_escapes_html(tmp_path):
    findings = checks.analyze_headers({}) + [checks.Finding("X", "<b>inj</b>", "low", False, "a & b", "fix")]
    out = tmp_path / "r.pdf"
    build_pdf(str(out), "exemplo.com", findings)
    assert out.read_bytes().startswith(b"%PDF")


def test_cli_requires_confirmation(capsys):
    assert cli.main(["exemplo.com"]) == 2
    assert "autorização" in capsys.readouterr().out


def test_cli_end_to_end_with_mocked_network(monkeypatch, tmp_path):
    monkeypatch.setattr(fetch, "fetch_https", lambda h, p: (200, GOOD_HEADERS, []))
    monkeypatch.setattr(fetch, "fetch_tls", lambda h, p: {**GOOD_TLS, "not_after": datetime.now(timezone.utc) + timedelta(days=90)})
    monkeypatch.setattr(fetch, "fetch_http_redirect", lambda h: (301, "https://exemplo.com/"))
    out = tmp_path / "r.pdf"
    assert cli.main(["https://exemplo.com", "--yes", "-o", str(out)]) == 0
    assert out.read_bytes().startswith(b"%PDF")
