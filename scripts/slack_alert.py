#!/usr/bin/env python3
"""
Slack Rich Security Alert (Incoming Webhook)
Triggers when:
- Trivy has HIGH/CRITICAL CVE findings, OR
- EPSS high_risk list is non-empty
"""

from __future__ import annotations

import argparse
import json
import os
import re
import urllib.request
from typing import Any

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")


def _load_json(path: str) -> Any:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _load_text(path: str) -> str:
    try:
        with open(path, encoding="utf-8") as f:
            return f.read()
    except Exception:
        return ""


def _as_results(trivy_json: Any) -> list[dict[str, Any]]:
    if isinstance(trivy_json, dict) and isinstance(trivy_json.get("Results"), list):
        return trivy_json["Results"]
    if isinstance(trivy_json, list):
        return [x for x in trivy_json if isinstance(x, dict)]
    return []


def _top_trivy_high_crit(trivy_json: Any, limit: int = 8) -> tuple[int, list[dict[str, Any]]]:
    results = _as_results(trivy_json)
    items: list[dict[str, Any]] = []
    count = 0

    for r in results:
        vulns = r.get("Vulnerabilities") or []
        if not isinstance(vulns, list):
            continue
        for v in vulns:
            if not isinstance(v, dict):
                continue
            vid = str(v.get("VulnerabilityID", "")).strip()
            sev = str(v.get("Severity", "")).strip().upper()
            if CVE_RE.match(vid) and sev in {"HIGH", "CRITICAL"}:
                count += 1
                if len(items) < limit:
                    items.append(
                        {
                            "cve": vid,
                            "severity": sev,
                            "pkg": v.get("PkgName") or "",
                            "installed": v.get("InstalledVersion") or "",
                            "fixed": v.get("FixedVersion") or "",
                            "title": v.get("Title") or "",
                        }
                    )

    return count, items


def _post_webhook(url: str, payload: dict[str, Any], timeout: int = 15) -> None:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        resp.read()


def _mk_blocks(
    *,
    repo: str,
    ref: str,
    sha: str,
    run_url: str,
    trivy_count: int,
    trivy_top: list[dict[str, Any]],
    epss_threshold: float,
    epss_high: list[dict[str, Any]],
    hadolint_text: str,
    checkov_json: Any,
) -> list[dict[str, Any]]:
    risk_title = "Security Gate Triggered"
    env_line = f"Repo: {repo} | Ref: {ref} | SHA: {sha[:7]}"
    run_line = f"Run: {run_url}"

    summary = (
        f"*High/Critical CVEs (Trivy)*: {trivy_count}\n"
        f"*EPSS-high (>= {epss_threshold})*: {len(epss_high)}"
    )

    blocks: list[dict[str, Any]] = [
        {"type": "header", "text": {"type": "plain_text", "text": risk_title}},
        {"type": "section", "text": {"type": "mrkdwn", "text": env_line}},
        {"type": "section", "text": {"type": "mrkdwn", "text": run_line}},
        {"type": "divider"},
        {"type": "section", "text": {"type": "mrkdwn", "text": summary}},
    ]

    if trivy_top:
        lines = [
            f"• `{it['severity']}` `{it['cve']}` {it['pkg']} {it['installed']} → {it['fixed'] or 'n/a'}"
            for it in trivy_top
        ]
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": "*Top Trivy Findings*\n" + "\n".join(lines)}})

    if epss_high:
        lines = [
            f"• `EPSS {it.get('epss', 0)}` `{it.get('cve','')}` {it.get('pkg_name','')} {it.get('installed_version','')}"
            for it in epss_high[:8]
        ]
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": "*Top EPSS-high Findings*\n" + "\n".join(lines)}})

    hadolint_hits = len([ln for ln in hadolint_text.splitlines() if ln.strip()]) if hadolint_text.strip() else 0

    checkov_hits = 0
    if isinstance(checkov_json, dict):
        summary_obj = checkov_json.get("summary") or {}
        if isinstance(summary_obj, dict) and isinstance(summary_obj.get("failed"), int):
            checkov_hits = int(summary_obj["failed"])

    blocks.extend(
        [
            {"type": "divider"},
            {
                "type": "context",
                "elements": [{"type": "mrkdwn", "text": f"Hadolint lines: {hadolint_hits} | Checkov failed: {checkov_hits}"}],
            },
        ]
    )

    return blocks


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--webhook", required=True, help="Slack incoming webhook URL")
    ap.add_argument("--run-url", required=True, help="GitHub Actions run URL")
    ap.add_argument("--trivy", required=True, help="Path to trivy-sca.json")
    ap.add_argument("--epss", required=True, help="Path to epss-findings.json")
    ap.add_argument("--hadolint", default="", help="Path to hadolint.txt (optional)")
    ap.add_argument("--checkov", default="", help="Path to checkov.json (optional)")
    ap.add_argument("--timeout", type=int, default=15, help="HTTP timeout seconds")
    args = ap.parse_args()

    repo = os.environ.get("GITHUB_REPOSITORY", "unknown/unknown")
    ref = os.environ.get("GITHUB_REF_NAME") or os.environ.get("GITHUB_REF") or "unknown"
    sha = os.environ.get("GITHUB_SHA", "unknown")

    trivy = _load_json(args.trivy)
    epss = _load_json(args.epss)

    trivy_count, trivy_top = _top_trivy_high_crit(trivy, limit=8)

    epss_threshold = float((epss or {}).get("threshold", 0.0) or 0.0)
    epss_high = (epss or {}).get("high_risk", []) or []
    if not isinstance(epss_high, list):
        epss_high = []

    triggered = (trivy_count > 0) or (len(epss_high) > 0)
    if not triggered:
        print("SLACK_SKIP: no High/Critical or EPSS-high findings")
        return 0

    hadolint_text = _load_text(args.hadolint) if args.hadolint else ""
    checkov_json: Any = {}
    if args.checkov:
        try:
            checkov_json = _load_json(args.checkov)
        except Exception:
            checkov_json = {}

    blocks = _mk_blocks(
        repo=repo,
        ref=ref,
        sha=sha,
        run_url=args.run_url,
        trivy_count=trivy_count,
        trivy_top=trivy_top,
        epss_threshold=epss_threshold,
        epss_high=epss_high,
        hadolint_text=hadolint_text,
        checkov_json=checkov_json,
    )

    payload = {"text": "Vuln Bank security gate triggered.", "blocks": blocks}
    _post_webhook(args.webhook, payload, timeout=args.timeout)

    print("SLACK_SENT")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
