#!/usr/bin/env python3
"""
EPSS Enterprise Dashboard Renderer
- Consumes epss-findings.json
- Produces epss-dashboard.md (rich Markdown report)
"""

import os
import json
import math
from datetime import datetime


def load_json(path: str) -> dict[str, object]:
    """Load EPSS JSON safely."""
    if not os.path.exists(path):
        raise SystemExit(f"[ERROR] EPSS findings file not found: {path}")

    with open(path) as f:  # UP015 FIX: remove mode + encoding
        return json.load(f)


def fmt_pct(x: float) -> str:
    """Convert decimal to percent."""
    try:
        return f"{x * 100:.1f}%"
    except Exception:
        return "-"


def fmt_cvss(x: float) -> str:
    try:
        return f"{x:.1f}"
    except Exception:
        return "-"


def build_stats(data: dict[str, object]) -> dict[str, object]:
    """Compute high-level EPSS metrics."""
    high_risk: list[dict[str, object]] = data.get("high_risk", [])
    threshold = float(data.get("threshold", 0.5))

    total_unique = int(data.get("total_unique_cves", 0))
    high_risk_count = len(high_risk)

    return {
        "threshold": threshold,
        "total_unique": total_unique,
        "high_risk_count": high_risk_count,
        "high_risk": high_risk,
    }


def table_high_risk(items: list[dict[str, object]]) -> str:
    if not items:
        return "> No high-risk CVEs detected."

    rows = [
        "| CVE | Package | Severity | CVSS | EPSS | KEV | Reason |",
        "|------|---------|----------|------|------|-----|--------|",
    ]

    for x in items:
        cve = x.get("cve", "-")
        pkg = x.get("pkg_name", "-")
        sev = x.get("severity", "-")
        cvss = fmt_cvss(x.get("cvss") or 0)
        epss = fmt_pct(x.get("epss") or 0)
        kev = "YES" if x.get("is_kev") else "NO"
        reason = ", ".join(x.get("reasons", []))

        rows.append(
            f"| {cve} | {pkg} | {sev} | {cvss} | {epss} | {kev} | {reason} |"
        )

    return "\n".join(rows)


def render_markdown(data: dict[str, object]) -> str:
    stats = build_stats(data)
    high_risk = stats["high_risk"]
    threshold = stats["threshold"]
    total = stats["total_unique"]
    high_cnt = stats["high_risk_count"]

    generated_at = data.get("generated_at") or datetime.utcnow().isoformat() + "Z"

    lines: list[str] = []

    lines.append("# 🛡 EPSS Security Dashboard (Enterprise)\n")
    lines.append(f"Generated: **{generated_at}**\n")

    lines.append("## Summary\n")
    lines.append(f"- Total Unique CVEs Analyzed: **{total}**")
    lines.append(f"- High-Risk EPSS Threshold: **EPSS ≥ {threshold}**")
    lines.append(f"- High-Risk CVEs Detected: **{high_cnt}**\n")

    lines.append("## High-Risk CVEs\n")
    lines.append(table_high_risk(high_risk))

    return "\n".join(lines)


def main():
    epss_file = os.environ.get("EPSS_FINDINGS", "security-reports/epss-findings.json")
    out_file = os.environ.get("EPSS_OUT", "security-reports/epss-dashboard.md")

    data = load_json(epss_file)
    md = render_markdown(data)

    os.makedirs(os.path.dirname(out_file), exist_ok=True)

    with open(out_file, "w") as f:  # UP015 FIX
        f.write(md)

    print(f"[OK] EPSS dashboard generated → {out_file}")


if __name__ == "__main__":
    main()
