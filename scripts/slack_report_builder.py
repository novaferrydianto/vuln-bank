#!/usr/bin/env python3
import json
import argparse
import os
from typing import Any, Dict, List


# ============================================================
# Helper Functions
# ============================================================

def safe_load(path: str) -> Any:
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return None


def emoji_heatmap(crit, high, med, low):
    return (
        f"🟥 Critical: {'█' * crit or '—'}  ({crit})\n"
        f"🟧 High    : {'█' * high or '—'}  ({high})\n"
        f"🟨 Medium  : {'█' * med or '—'}  ({med})\n"
        f"🟦 Low     : {'█' * low or '—'}  ({low})"
    )


def top5_list(vulns: List[Dict[str, Any]]) -> str:
    if not vulns:
        return "_No high-risk CVEs detected._"

    sorted_items = sorted(vulns, key=lambda x: x.get("epss", 0), reverse=True)
    top = sorted_items[:5]

    lines = []
    for i, v in enumerate(top, start=1):
        cve = v.get("cve")
        epss = v.get("epss")
        sev = v.get("severity")
        pkg = v.get("pkg")

        epss_fmt = f"{epss:.2f}" if epss is not None else "0.00"
        lines.append(f"{i}. *{cve}* — EPSS `{epss_fmt}` — {sev} — `{pkg}`")

    return "\n".join(lines)


def compute_severity_counts(vulns: List[Dict[str, Any]]):
    crit = sum(1 for v in vulns if v.get("severity") == "CRITICAL")
    high = sum(1 for v in vulns if v.get("severity") == "HIGH")
    med = sum(1 for v in vulns if v.get("severity") == "MEDIUM")
    low = sum(1 for v in vulns if v.get("severity") == "LOW")
    return crit, high, med, low


def compute_epss_counts(vulns: List[Dict[str, Any]], threshold: float):
    epss_count = sum(1 for v in vulns if v.get("epss", 0) >= threshold)
    kev_count = sum(1 for v in vulns if v.get("is_kev") is True)
    return epss_count, kev_count


def avg_epss_top5(vulns: List[Dict[str, Any]]) -> float:
    if not vulns:
        return 0.0
    sorted_items = sorted(vulns, key=lambda x: x.get("epss", 0), reverse=True)
    top = sorted_items[:5]
    scores = [v.get("epss", 0) for v in top]
    return round(sum(scores) / len(scores), 3) if scores else 0.0


# ============================================================
# Main Slack Payload Builder
# ============================================================

def build_payload(repo: str,
                  env: str,
                  pipeline: str,
                  deploy_status: str,
                  epss_data: Dict[str, Any],
                  summary_data: Dict[str, Any]) -> Dict[str, Any]:

    high_risk = epss_data.get("high_risk", [])
    threshold = epss_data.get("threshold", 0.5)

    crit, high, med, low = compute_severity_counts(high_risk)
    epss_count, kev_count = compute_epss_counts(high_risk, threshold)
    avg_top5 = avg_epss_top5(high_risk)

    top5 = top5_list(high_risk)
    heatmap = emoji_heatmap(crit, high, med, low)

    # Weekly trends (if summary data exists)
    new_findings = summary_data.get("new_findings", 0)
    solved = summary_data.get("solved", 0)

    # -----------------------------------------
    # Build Slack JSON Block Kit structure
    # -----------------------------------------
    payload = {
        "text": "🔐 Vuln Bank – Enhanced Security Recap",
        "blocks": [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": "🔐 Vuln Bank — Enhanced Security Recap"}
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"*Repository:* `{repo}`\n"
                        f"*Environment:* `{env}`\n"
                        f"*Pipeline:* `{pipeline}`"
                    )
                }
            },
            {"type": "divider"},

            # Severity + Weekly Activity
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": (
                            "*Open Issues by Severity:*\n"
                            f"• 🔴 Critical: *{crit}*\n"
                            f"• 🟠 High: *{high}*\n"
                            f"• 🟡 Medium: *{med}*\n"
                            f"• 🔵 Low: *{low}*"
                        )
                    },
                    {
                        "type": "mrkdwn",
                        "text": (
                            "*Activity This Week:*\n"
                            f"• ➕ New findings: *{new_findings}*\n"
                            f"• ✔️ Resolved: *{solved}*"
                        )
                    }
                ]
            },

            {"type": "divider"},

            # EPSS & KEV
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        "*EPSS & KEV Breakdown:*\n"
                        f"• 🔥 High-EPSS (≥ {threshold}): *{epss_count}*\n"
                        f"• 🛑 KEV-listed CVEs: *{kev_count}*\n"
                        f"• 📈 Avg EPSS (Top 5): *{avg_top5}*"
                    )
                }
            },

            # Top 5 CVEs
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Top 5 Highest Risk CVEs:*\n{top5}"}
            },

            {"type": "divider"},

            # Heatmap
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Risk Heatmap:*\n{heatmap}"}
            },

            {"type": "divider"},

            # Deployment Status
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Deployment Status:*\n{deploy_status}"}
            },

            # Footer
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": (
                            "Generated by *Vuln Bank DevSecOps Pipeline* using "
                            "Trivy, Snyk, Semgrep, Checkov, ZAP, EPSS, KEV, Cosign, SBOM."
                        )
                    }
                ]
            }
        ]
    }

    return payload


# ============================================================
# CLI Entrypoint
# ============================================================

def main():
    parser = argparse.ArgumentParser(description="Slack Enhanced Security Report Builder")
    parser.add_argument("--repo", default="vuln-bank")
    parser.add_argument("--env", default="production")
    parser.add_argument("--pipeline", default="DevSecOps Pipeline")
    parser.add_argument("--deploy-status", required=True)
    parser.add_argument("--epss", required=True)
    parser.add_argument("--summary", required=False)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    epss_data = safe_load(args.epss) or {"high_risk": []}
    summary_data = safe_load(args.summary) or {"new_findings": 0, "solved": 0}

    payload = build_payload(
        repo=args.repo,
        env=args.env,
        pipeline=args.pipeline,
        deploy_status=args.deploy_status,
        epss_data=epss_data,
        summary_data=summary_data
    )

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(payload, f, indent=2)

    print(f"Slack report generated: {args.output}")


if __name__ == "__main__":
    main()
