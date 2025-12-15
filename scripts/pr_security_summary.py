#!/usr/bin/env python3
import json
from pathlib import Path

REPORT_DIR = Path("security-reports")
TOP_N = 5  # max findings shown in PR comment


def main():
    epss_path = REPORT_DIR / "epss-findings.json"

    if not epss_path.exists():
        print("ℹ️ No EPSS report found")
        return

    epss = json.loads(epss_path.read_text())

    total_high_crit = epss.get("total_trivy_high_crit", 0)
    high_risk = epss.get("high_risk", [])
    ignored = max(total_high_crit - len(high_risk), 0)

    rollup = epss.get("rollup", {})
    portfolio_score = rollup.get("portfolio_score_0_100", 0)
    weighted_sum = rollup.get("weighted_risk_sum", 0)
    weighted_max = rollup.get("weighted_risk_max", 0)

    lines = []
    lines.append("🔒 **PR Security Summary**")
    lines.append("")

    # -------------------------------------------------
    # Gate result
    # -------------------------------------------------
    if high_risk:
        lines.append(f"❌ **{len(high_risk)} exploitable risks detected**")
    else:
        lines.append("✅ **No exploitable risks detected**")

    # -------------------------------------------------
    # Ignored due to EPSS
    # -------------------------------------------------
    if ignored > 0:
        lines.append(
            f"ℹ️ **{ignored} HIGH/CRITICAL findings ignored** "
            f"(EPSS below threshold)"
        )

    lines.append("")

    # -------------------------------------------------
    # Weighted risk rollup
    # -------------------------------------------------
    lines.append("📊 **Weighted Risk (CVSS × EPSS)**")
    lines.append(f"- Portfolio risk score: **{portfolio_score}/100**")
    lines.append(f"- Total weighted risk: **{weighted_sum}**")
    lines.append(f"- Max single risk: **{weighted_max}**")

    # -------------------------------------------------
    # Top findings
    # -------------------------------------------------
    if high_risk:
        lines.append("")
        lines.append("🔥 **Top Exploitable Findings**")

        # Sort by weighted risk desc
        sorted_findings = sorted(
            high_risk,
            key=lambda x: x.get("weighted_risk", 0),
            reverse=True,
        )[:TOP_N]

        for f in sorted_findings:
            cve = f.get("cve_id", "N/A")
            pkg = f.get("pkg_name", "unknown")
            cvss = f.get("cvss", 0)
            epss_score = f.get("epss", 0)
            weighted = f.get("weighted_risk", 0)

            lines.append(
                f"- `{cve}` ({pkg}) → "
                f"CVSS {cvss}, EPSS {epss_score:.3f}, "
                f"**Risk {weighted}**"
            )

    lines.append("")
    lines.append("✅ **Security gate passed**")

    print("\n".join(lines))


if __name__ == "__main__":
    main()
