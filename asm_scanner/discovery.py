"""Asset discovery: passive subdomain enumeration and DNS resolution."""

from __future__ import annotations

import json
import re
import socket
import urllib.request
from concurrent.futures import ThreadPoolExecutor

USER_AGENT = "asm-scanner/0.1 (+https://github.com/abdimalikhussein25/attack-surface-scanner)"
_HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def parse_crtsh(entries: list[dict], domain: str) -> set[str]:
    """Extract unique, valid hostnames under `domain` from crt.sh JSON."""
    domain = domain.lower().strip(".")
    hosts: set[str] = set()
    for entry in entries:
        for name in str(entry.get("name_value", "")).splitlines():
            name = name.strip().lower().lstrip("*.").rstrip(".")
            if (name == domain or name.endswith("." + domain)) and _HOST_RE.match(name):
                hosts.add(name)
    return hosts


def crtsh_subdomains(domain: str, timeout: float = 30) -> set[str]:
    """Query certificate-transparency logs via crt.sh (passive, no contact with the target)."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return parse_crtsh(json.loads(resp.read().decode() or "[]"), domain)


def resolve(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return []
    return sorted({info[4][0] for info in infos})


def resolve_all(hosts: set[str], workers: int = 32) -> dict[str, list[str]]:
    """Resolve hosts concurrently; drop the ones that no longer exist."""
    ordered = sorted(hosts)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = pool.map(resolve, ordered)
    return {h: ips for h, ips in zip(ordered, results) if ips}
