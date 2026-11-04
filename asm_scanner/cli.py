"""Command-line entry point: `asm-scan example.com`."""

from __future__ import annotations

import argparse
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from . import __version__
from .checks import check_exposures, check_hostname, check_http, check_tls, sort_findings
from .discovery import crtsh_subdomains, resolve_all
from .probe import probe_http, probe_sensitive_paths, probe_tls
from .report import to_json, to_markdown

BANNER = "Only scan domains you own or are explicitly authorised to test."


def scan_host(host: str, ips: list[str], deep: bool):
    http = probe_http(host)
    tls = probe_tls(host)
    findings = check_hostname(host) + check_http(host, http) + check_tls(host, tls)
    if deep and http.status is not None:
        findings += check_exposures(host, probe_sensitive_paths(host))
    asset = {
        "host": host,
        "ips": ips,
        "status": http.status,
        "title": http.title,
        "server": http.server,
        "tls_issuer": tls.issuer,
        "tls_days_left": tls.days_left,
    }
    return asset, findings


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="asm-scan", description="External attack surface scanner. " + BANNER)
    p.add_argument("domain", help="root domain, e.g. example.com")
    p.add_argument("-o", "--out", default="reports", help="output directory (default: reports)")
    p.add_argument("--extra", nargs="*", default=[], help="additional hostnames to include")
    p.add_argument("--deep", action="store_true", help="also check for exposed sensitive files (.git, .env, ...)")
    p.add_argument("--workers", type=int, default=16)
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = p.parse_args(argv)

    domain = args.domain.lower().strip().strip(".")
    print(f"⚠️  {BANNER}\n", file=sys.stderr)

    print(f"[1/3] Discovering subdomains of {domain} (certificate transparency)…", file=sys.stderr)
    try:
        hosts = crtsh_subdomains(domain)
    except Exception as e:  # noqa: BLE001
        print(f"      crt.sh unavailable ({type(e).__name__}); continuing with the root domain only", file=sys.stderr)
        hosts = set()
    hosts |= {domain, *[h.lower() for h in args.extra]}

    resolved = resolve_all(hosts)
    print(f"      {len(hosts)} names found, {len(resolved)} resolve", file=sys.stderr)

    print("[2/3] Probing live hosts…", file=sys.stderr)
    assets, findings = [], []
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        for asset, host_findings in pool.map(lambda kv: scan_host(kv[0], kv[1], args.deep), resolved.items()):
            assets.append(asset)
            findings.extend(host_findings)
    assets.sort(key=lambda a: a["host"])
    findings = sort_findings(findings)

    print("[3/3] Writing report…", file=sys.stderr)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    md_path, json_path = out / f"{domain}.md", out / f"{domain}.json"
    md_path.write_text(to_markdown(domain, assets, findings), encoding="utf-8")
    json_path.write_text(to_json(domain, assets, findings), encoding="utf-8")

    high = sum(f.severity == "high" for f in findings)
    print(f"\n✅ {len(assets)} hosts, {len(findings)} findings ({high} high)\n   {md_path}\n   {json_path}", file=sys.stderr)
    return 1 if high else 0


if __name__ == "__main__":
    sys.exit(main())
