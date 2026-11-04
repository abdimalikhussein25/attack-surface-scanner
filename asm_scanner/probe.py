"""Light-touch probing of discovered hosts: HTTP(S) response and TLS certificate."""

from __future__ import annotations

import re
import socket
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .discovery import USER_AGENT

# Paths whose presence is almost always an exposure.
SENSITIVE_PATHS = ["/.git/HEAD", "/.env", "/server-status", "/.DS_Store", "/backup.zip"]


@dataclass
class HttpResult:
    url: str
    status: int | None = None
    title: str | None = None
    server: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    redirect_to_https: bool | None = None
    error: str | None = None


@dataclass
class TlsResult:
    host: str
    issuer: str | None = None
    not_after: datetime | None = None
    days_left: int | None = None
    hostname_ok: bool | None = None
    protocol: str | None = None
    error: str | None = None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # noqa: D401
        return None


_opener = urllib.request.build_opener(_NoRedirect)
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)


def fetch(url: str, timeout: float = 10, read_bytes: int = 65536) -> tuple[int, dict[str, str], bytes]:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        resp = _opener.open(req, timeout=timeout)
    except urllib.error.HTTPError as e:  # 3xx/4xx/5xx still carry useful info
        return e.code, {k.lower(): v for k, v in e.headers.items()}, e.read(read_bytes) if e.fp else b""
    with resp:
        return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read(read_bytes)


def extract_title(body: bytes) -> str | None:
    m = _TITLE_RE.search(body.decode("utf-8", "replace"))
    return re.sub(r"\s+", " ", m.group(1)).strip()[:120] if m else None


def probe_http(host: str, timeout: float = 10) -> HttpResult:
    url = f"https://{host}/"
    result = HttpResult(url=url)
    try:
        status, headers, body = fetch(url, timeout)
        result.status, result.headers = status, headers
        result.server = headers.get("server")
        result.title = extract_title(body)
    except Exception as e:  # noqa: BLE001 — record, don't crash the scan
        result.error = type(e).__name__ + (f": {e.reason}" if hasattr(e, "reason") else "")

    try:
        status, headers, _ = fetch(f"http://{host}/", timeout, read_bytes=0)
        location = headers.get("location", "")
        result.redirect_to_https = status in (301, 302, 307, 308) and location.startswith("https://")
    except Exception:  # noqa: BLE001
        result.redirect_to_https = None
    return result


def probe_sensitive_paths(host: str, timeout: float = 8) -> list[str]:
    """Return sensitive paths that answer 200 with plausible content."""
    exposed = []
    for path in SENSITIVE_PATHS:
        try:
            status, headers, body = fetch(f"https://{host}{path}", timeout, read_bytes=512)
        except Exception:  # noqa: BLE001
            continue
        if status != 200 or "text/html" in headers.get("content-type", ""):
            continue  # soft-404 pages are usually HTML
        if path == "/.git/HEAD" and not body.startswith(b"ref:"):
            continue
        exposed.append(path)
    return exposed


def probe_tls(host: str, port: int = 443, timeout: float = 10) -> TlsResult:
    result = TlsResult(host=host)
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
                result.protocol = tls.version()
                result.hostname_ok = True
    except ssl.SSLCertVerificationError as e:
        result.hostname_ok = False
        result.error = e.verify_message
        return result
    except Exception as e:  # noqa: BLE001
        result.error = type(e).__name__
        return result

    issuer = dict(x[0] for x in cert.get("issuer", ()))
    result.issuer = issuer.get("organizationName") or issuer.get("commonName")
    result.not_after = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), tz=timezone.utc)
    result.days_left = (result.not_after - datetime.now(timezone.utc)).days
    return result
