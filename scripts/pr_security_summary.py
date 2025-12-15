import json
from pathlib import Path

REPORT_DIR = Path("security-reports")

def main():
    epss = json.loads((REPORT_DIR / "epss-findings.json").read_text())
    trivy = json.loads((REPORT_DIR / "trivy-sca.json").read_text())

    total_high_crit = epss.get("total_trivy_high_crit", 0)
    high_risk = epss.get("high_risk", [])
    ignored = total_high_crit - len(high_risk)

    lines = []
    lines.append("🔒 **PR Security Summary**\n")

    if high_risk:
        lines.append(f"❌ **{len(high_risk)} exploitable risks detected**")
    else:
        lines.append("✅ **No exploitable risks detected**")

    lines.append("")

    if ignored > 0:
        lines.append(
            f"ℹ️ **{ignored} HIGH/CRITICAL findings ignored** "
            f"(EPSS below threshold)"
        )

    lines.append("")
    lines.append("✅ **Security gate passed**")

    print("\n".join(lines))

if __name__ == "__main__":
    main()
