#!/usr/bin/env python3
"""
Slack Report Builder (Ruff-Clean + SonarQube-Clean)
Generates a structured Slack payload summarizing:
- Pipeline metadata
- EPSS/KEV high-risk vulnerabilities
- Static/DAST/SCA summary
"""

import json
import argparse
from typing import Any, Dict, List


# =========================
# Helpers
# =========================

def load_json(path: str) -> Any:
    """Safely load JSON; return None on failure."""
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def safe_len(value: Any) -> int:
    """Return len(value) if value is list-like, else 0."""
    return len(value) if isinstance(value, list) else 0


def field(text: str) -> Dict[str, Any]:
    """Slack markdown field."""
    return {"type": "mrkdwn", "text": text}


def section(text: str) -> Dict[str, Any]:
    return {"type": "section", "text": {"type": "mrkdwn", "text": text}}


def header(text: str) -> Dict[str, Any]:
    return {"type": "header", "text": {"type": "plain_text", "text": text}}


def divider() -> Dict[str, Any]:
    return {"type": "divider"}


def build_epss_details(epss_list: List[Dict[str, Any]]) -> str:
    """Format EPSS/KEV detailed items."""
    if not epss_list:
        return "No EPSS/KEV high-risk vulnerabilities."

    lines = []
    for item in epss_list:
        cve = item.get("cve")
        epss = item.get("epss")
        kev_flag = item.get("is_kev")
        lines.append(f"- `{cve}` (EPSS={epss}, KEV={kev_flag})")
    return "\n".join(lines)


def build_summary_cells(summary: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Create Slack fields for scan summary."""
    new_findings = summary.get("new_findings", 0)
    solved = summary.get("solved", 0)
    return [
        field(f"*New Findings:*\n{new_findings}"),
        field(f"*Solved Issues:*\n{solved}"),
    ]


def build_top_metadata(repo: str, env: str, pipeline: str, deploy: str) -> List[Dict[str, Any]]:
    return [
        field(f"*Repository:*\n`{repo}`"),
        field(f"*Environment:*\n`{env}`"),
        field(f"*Pipeline:*\n`{pipeline}`"),
        field(f"*Status:*\n`{deploy}`"),
    ]


def build_epss_block(epss_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Block summarizing EPSS/KEV aggregated results."""
    epss_list = epss_data.get("high_risk", [])
    high_count = safe_len(epss_list)
    threshold = epss_data.get("threshold", "?")
    mode = epss_data.get("mode", "?")

    cells = [
        field(f"*EPSS High-Risk:*\n{high_count}"),
        field(f"*Threshold:*\n{threshold}"),
        field(f"*Mode:*\n{mode}"),
    ]

    details_text = build_epss_details(epss_list)

    return [
        section("*EPSS/KEV Summary*"),
        {"type": "section", "fields": cells},
        divider(),
        section(details_text),
    ]


def build_slack_payload(
    repo: str,
    env: str,
    pipeline: str,
    deploy_status: str,
    epss_data: Dict[str, Any],
    summary: Dict[str, Any],
) -> Dict[str, Any]:
    """Construct final Slack payload."""
    blocks: List[Dict[str, Any]] = []

    # Header
    blocks.append(header("🔐 Vuln Bank – Security Summary Report"))
    blocks.append(divider())

    # Metadata
    blocks.append(section("*Pipeline Metadata*"))
    blocks.append({"type": "section", "fields": build_top_metadata(repo, env, pipeline, deploy_status)})
    blocks.append(divider())

    # Summary
    blocks.append(section("*Scan Summary*"))
    blocks.append({"type": "section", "fields": build_summary_cells(summary)})
    blocks.append(divider())

    # EPSS/KEV
    blocks.extend(build_epss_block(epss_data))

    return {"blocks": blocks}


# =========================
# MAIN
# =========================

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Slack Report Builder")
    parser.add_argument("--repo", required=True)
    parser.add_argument("--env", required=True)
    parser.add_argument("--pipeline", required=True)
    parser.add_argument("--deploy-status", required=True)
    parser.add_argument("--epss", required=True)
    parser.add_argument("--summary", required=True)
    parser.add_argument("--output", required=True)
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    epss_data = load_json(args.epss) or {}
    summary_data = load_json(args.summary) or {}

    payload = build_slack_payload(
        repo=args.repo,
        env=args.env,
        pipeline=args.pipeline,
        deploy_status=args.deploy_status,
        epss_data=epss_data,
        summary=summary_data,
    )

    out_path = args.output
    out_dir = out_path.rsplit("/", 1)[0] if "/" in out_path else "."
    try:
        import os
        os.makedirs(out_dir, exist_ok=True)
    except Exception:
        pass

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

    print(f"[OK] Slack report generated → {out_path}")


if __name__ == "__main__":
    main()
