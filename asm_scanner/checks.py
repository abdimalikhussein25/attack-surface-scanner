"""Turn raw probe results into prioritised findings. Pure functions — no network."""

from __future__ import annotations

from dataclasses import dataclass

from .probe import HttpResult, TlsResult

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}

# Hostname fragments that usually indicate non-production or admin surfaces.
INTERESTING_KEYWORDS = ("dev", "staging", "stage", "test", "uat", "admin", "internal", "old", "backup", "jenkins", "grafana", "phpmyadmin")

SECURITY_HEADERS = {
    "strict-transport-security": ("medium", "HSTS missing — browsers may be downgraded to HTTP"),
    "content-security-policy": ("low", "No Content-Security-Policy — weaker defence against XSS"),
    "x-content-type-options": ("low", "X-Content-Type-Options missing — MIME sniffing possible"),
}


@dataclass
class Finding:
    host: str
    severity: str
    title: str
    detail: str = ""


def check_http(host: str, http: HttpResult) -> list[Finding]:
    findings: list[Finding] = []
    if http.status is None:
        return findings

    for header, (sev, title) in SECURITY_HEADERS.items():
        if header not in http.headers:
            findings.append(Finding(host, sev, title))

    frame_ok = "x-frame-options" in http.headers or "frame-ancestors" in http.headers.get("content-security-policy", "")
    if not frame_ok:
        findings.append(Finding(host, "low", "No clickjacking protection (X-Frame-Options / frame-ancestors)"))

    if http.redirect_to_https is False:
        findings.append(Finding(host, "medium", "HTTP does not redirect to HTTPS"))

    for header in ("server", "x-powered-by", "x-aspnet-version"):
        value = http.headers.get(header, "")
        if any(ch.isdigit() for ch in value):
            findings.append(Finding(host, "low", f"Version disclosed in {header} header", value))

    if http.status >= 500:
        findings.append(Finding(host, "info", f"Server error on homepage (HTTP {http.status})"))
    return findings


def check_tls(host: str, tls: TlsResult) -> list[Finding]:
    if tls.hostname_ok is False:
        return [Finding(host, "high", "Invalid TLS certificate", tls.error or "")]
    findings: list[Finding] = []
    if tls.days_left is not None:
        if tls.days_left < 0:
            findings.append(Finding(host, "high", "TLS certificate expired", f"{-tls.days_left} days ago"))
        elif tls.days_left <= 14:
            findings.append(Finding(host, "medium", "TLS certificate expires soon", f"{tls.days_left} days left"))
    if tls.protocol in ("TLSv1", "TLSv1.1"):
        findings.append(Finding(host, "medium", f"Outdated TLS protocol negotiated ({tls.protocol})"))
    return findings


def check_exposures(host: str, paths: list[str]) -> list[Finding]:
    return [Finding(host, "high", f"Sensitive file exposed: {p}") for p in paths]


def check_hostname(host: str) -> list[Finding]:
    labels = host.split(".")
    hits = [k for k in INTERESTING_KEYWORDS if any(k == part or part.startswith(k + "-") or part.endswith("-" + k) for part in labels)]
    if hits:
        return [Finding(host, "info", "Potential non-production/admin host exposed", ", ".join(hits))]
    return []


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.host, f.title))
