#!/usr/bin/env python3
"""
Render OWASP ASVS scorecard → Markdown dashboard.

Input : security-reports/asvs-scorecard.json
Output: security-reports/asvs-scorecard.md
"""

import json
from pathlib import Path

SRC = Path("security-reports/asvs-scorecard.json")
DST = Path("security-reports/asvs-scorecard.md")


def safe_int(v, default=0):
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def main():
    if not SRC.exists():
        raise SystemExit(f"[ERR] ASVS scorecard not found: {SRC}")

    data = json.loads(SRC.read_text())

    meta = data.get("meta", {}) or {}
    categories = data.get("categories", {}) or {}

    total_req = safe_int(meta.get("total_requirements"))
    implemented = safe_int(meta.get("implemented"))
    partial = safe_int(meta.get("partial"))
    not_impl = safe_int(meta.get("not_implemented"))

    overall_pct = (implemented / total_req * 100) if total_req else 0.0

    lines = []

    # Header
    lines.append(f"# OWASP ASVS Scorecard – {meta.get('app_name', 'Application')}")
    lines.append("")
    lines.append(f"- **Profile**: {meta.get('profile', 'N/A')}")
    lines.append(f"- **Total Requirements**: {total_req}")
    lines.append(
        f"- **Implemented**: {implemented} ({overall_pct:.1f}%)"
    )
    lines.append(f"- **Partial**: {partial}")
    lines.append(f"- **Not Implemented**: {not_impl}")
    lines.append("")

    # Simple badge (bisa kamu taruh di README)
    if overall_pct >= 80:
        grade = "🟢 Strong"
    elif overall_pct >= 50:
        grade = "🟡 Medium"
    else:
        grade = "🔴 Weak"

    lines.append(f"> **Overall ASVS posture**: {grade} ({overall_pct:.1f}% implemented)")
    lines.append("")

    # Table per category
    lines.append("## Per-Category Summary")
    lines.append("")
    lines.append("| Category | Name | Total | Implemented | Partial | Not Impl. | Coverage |")
    lines.append("|----------|------|-------|-------------|---------|-----------|----------|")

    for cat_id, value in categories.items():
        # value bisa dict, bisa string, jadi hati2
        if isinstance(value, dict):
            name = value.get("name", cat_id)
            t = safe_int(value.get("total"))
            i = safe_int(value.get("implemented"))
            p = safe_int(value.get("partial"))
            n = safe_int(value.get("not_implemented"))
        else:
            # fallback kalo cuma string → semua unknown
            name = str(value)
            t = i = p = n = 0

        pct = (i / t * 100) if t else 0.0
        lines.append(
            f"| {cat_id} | {name} | {t} | {i} | {p} | {n} | {pct:.1f}% |"
        )

    DST.write_text("\n".join(lines), encoding="utf-8")
    print(f"[OK] ASVS markdown written to {DST}")


if __name__ == "__main__":
    main()
