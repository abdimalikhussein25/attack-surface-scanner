from asm_scanner.checks import check_hostname, check_http, check_tls, check_exposures, sort_findings
from asm_scanner.discovery import parse_crtsh
from asm_scanner.probe import HttpResult, TlsResult, extract_title
from asm_scanner.report import to_markdown

SECURE_HEADERS = {
    "strict-transport-security": "max-age=31536000",
    "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
    "x-content-type-options": "nosniff",
}


def titles(findings):
    return {f.title for f in findings}


def test_parse_crtsh_filters_and_dedupes():
    entries = [
        {"name_value": "*.example.com\nwww.example.com"},
        {"name_value": "API.Example.com"},
        {"name_value": "evil.com\nnotexample.com"},
        {"name_value": "bad_host.example.com"},
    ]
    assert parse_crtsh(entries, "example.com") == {"example.com", "www.example.com", "api.example.com"}


def test_secure_site_has_no_header_findings():
    http = HttpResult(url="https://a/", status=200, headers=SECURE_HEADERS, redirect_to_https=True)
    assert check_http("a", http) == []


def test_missing_headers_and_no_redirect():
    http = HttpResult(url="https://a/", status=200, headers={"server": "nginx/1.18.0"}, redirect_to_https=False)
    t = titles(check_http("a", http))
    assert "HTTP does not redirect to HTTPS" in t
    assert any("HSTS" in x for x in t)
    assert "Version disclosed in server header" in t
    assert any("clickjacking" in x for x in t)


def test_unreachable_host_yields_nothing():
    assert check_http("a", HttpResult(url="https://a/", error="URLError")) == []


def test_tls_checks():
    assert check_tls("a", TlsResult("a", days_left=90, hostname_ok=True, protocol="TLSv1.3")) == []
    assert "TLS certificate expires soon" in titles(check_tls("a", TlsResult("a", days_left=5, hostname_ok=True)))
    assert "TLS certificate expired" in titles(check_tls("a", TlsResult("a", days_left=-3, hostname_ok=True)))
    assert check_tls("a", TlsResult("a", hostname_ok=False, error="hostname mismatch"))[0].severity == "high"


def test_hostname_keywords():
    assert check_hostname("staging.example.com")[0].detail == "staging"
    assert check_hostname("api-dev.example.com")[0].detail == "dev"
    assert check_hostname("developer.example.com") == []  # not a false positive


def test_sorting_puts_high_first():
    findings = check_hostname("dev.x.com") + check_exposures("x.com", ["/.env"])
    assert sort_findings(findings)[0].severity == "high"


def test_extract_title():
    assert extract_title(b"<html><TITLE>\n Login  Portal </TITLE>") == "Login Portal"
    assert extract_title(b"no title") is None


def test_markdown_report_renders():
    md = to_markdown("x.com", [{"host": "x.com", "ips": ["1.2.3.4"], "status": 200, "title": "Home", "server": "nginx", "tls_days_left": 50}],
                     check_exposures("x.com", ["/.git/HEAD"]))
    assert "# Attack surface report — x.com" in md
    assert "🔴 1 high" in md
    assert "`x.com`" in md
