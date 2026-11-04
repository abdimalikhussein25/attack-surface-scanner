# attack-surface-scanner

**Find what your organisation exposes to the internet, in one command.**

`asm-scan` discovers your subdomains from certificate-transparency logs, checks which ones are alive, and flags the things attackers look for first: expired or invalid certificates, sites that don't force HTTPS, missing security headers, version leaks, forgotten `dev`/`staging`/`admin` hosts, and exposed `.git` or `.env` files. You get a clean Markdown report for management and JSON for your pipeline.

![Python](https://img.shields.io/badge/python-3.10%2B-3776AB?logo=python&logoColor=white)
![Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)
![License](https://img.shields.io/badge/license-MIT-blue)

> ⚠️ **Only scan domains you own or are explicitly authorised to test.** Discovery is passive, but probing contacts the hosts.

## Install

```bash
pip install git+https://github.com/abdimalikhussein25/attack-surface-scanner
```

## Usage

```bash
asm-scan example.com                 # discovery + HTTPS/TLS/header checks
asm-scan example.com --deep          # also look for exposed .git, .env, server-status …
asm-scan example.com --extra vpn.example.com mail.example.com -o reports/
```

```
[1/3] Discovering subdomains of example.com (certificate transparency)…
      84 names found, 31 resolve
[2/3] Probing live hosts…
[3/3] Writing report…

✅ 31 hosts, 47 findings (3 high)
   reports/example.com.md
   reports/example.com.json
```

The exit code is `1` when there are high-severity findings, so you can fail a scheduled CI job and get alerted.

## What it checks

| Severity | Check |
|---|---|
| 🔴 High | Invalid or expired TLS certificate · exposed `.git/`, `.env`, backups, `server-status` |
| 🟠 Medium | No HTTP → HTTPS redirect · missing HSTS · certificate expiring within 14 days · TLS 1.0/1.1 |
| 🟡 Low | Missing CSP, `X-Content-Type-Options`, clickjacking protection · version numbers in `Server`/`X-Powered-By` |
| 🔵 Info | Hosts named like `dev`, `staging`, `admin`, `jenkins`, `phpmyadmin` … · 5xx on homepage |

## Sample report

| Severity | Host | Finding | Detail |
|---|---|---|---|
| 🔴 high | `old.example.com` | TLS certificate expired | 212 days ago |
| 🔴 high | `staging.example.com` | Sensitive file exposed: /.env | |
| 🟠 medium | `portal.example.com` | HTTP does not redirect to HTTPS | |
| 🟡 low | `www.example.com` | Version disclosed in server header | nginx/1.18.0 |
| 🔵 info | `staging.example.com` | Potential non-production/admin host exposed | staging |

## How it works

```
crt.sh (CT logs) ──► subdomains ──► DNS resolve ──► HTTPS / HTTP / TLS probe ──► checks ──► report.md + report.json
```

- `asm_scanner/discovery.py`: passive enumeration and concurrent DNS resolution
- `asm_scanner/probe.py`: HTTP(S) and TLS probing, no redirects followed
- `asm_scanner/checks.py`: pure functions that turn probe results into findings (fully unit-tested)
- `asm_scanner/report.py`: Markdown and JSON output

Pure Python standard library: nothing to install beyond Python itself, which makes it easy to run on a locked-down server.

## Roadmap

- [ ] Port scanning of common admin/database ports
- [ ] Subdomain-takeover detection (dangling CNAMEs)
- [ ] Diff mode: alert only on what changed since the last scan
- [ ] Email (SPF / DMARC) posture

## Development

```bash
pip install -e ".[dev]"
pytest
```

## License

MIT © Abdimalik Salad Hussein · [Fiddo Technology](https://fiddotechnology.com)
