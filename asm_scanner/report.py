"""Markdown and JSON report rendering."""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import asdict
from datetime import datetime, timezone

from .checks import Finding

ICON = {"high": "🔴", "medium": "🟠", "low": "🟡", "info": "🔵"}


def to_markdown(domain: str, assets: list[dict], findings: list[Finding]) -> str:
    counts = Counter(f.severity for f in findings)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    out = [
        f"# Attack surface report — {domain}",
        "",
        f"_Generated {now}_",
        "",
        "## Summary",
        "",
        f"- **Live hosts:** {len(assets)}",
        "- **Findings:** "
        + ", ".join(f"{ICON[s]} {counts.get(s, 0)} {s}" for s in ("high", "medium", "low", "info")),
        "",
        "## Findings",
        "",
    ]
    if findings:
        out += ["| Severity | Host | Finding | Detail |", "|---|---|---|---|"]
        out += [f"| {ICON[f.severity]} {f.severity} | `{f.host}` | {f.title} | {f.detail} |" for f in findings]
    else:
        out.append("No findings. 🎉")

    out += ["", "## Assets", "", "| Host | IPs | HTTPS | Title | Server | TLS expires |", "|---|---|---|---|---|---|"]
    for a in assets:
        out.append(
            f"| `{a['host']}` | {', '.join(a['ips'])} | {a.get('status') or '—'} | "
            f"{(a.get('title') or '').replace('|', '/')} | {a.get('server') or ''} | {a.get('tls_days_left', '—')} days |"
        )
    return "\n".join(out) + "\n"


def to_json(domain: str, assets: list[dict], findings: list[Finding]) -> str:
    return json.dumps(
        {
            "domain": domain,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "assets": assets,
            "findings": [asdict(f) for f in findings],
        },
        indent=2,
        default=str,
    )
