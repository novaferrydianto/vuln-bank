#!/usr/bin/env python3
"""
ASVS Export – Tool-Mapped (Deterministic, Schema-Compliant)

Consumes:
- schemas/asvs-tool-map.json
- Semgrep / Bandit / ZAP / Trivy / Gitleaks outputs

Produces:
- security-reports/governance/asvs-coverage.json

Design:
- Schema-first (audit-ready)
- Deterministic scoring
- CI / Slack / Pages compatible
"""

import json
import argparse
import os
from pathlib import Path
from datetime import datetime
from collections import defaultdict

# --------------------------------------------------
# Utils
# --------------------------------------------------
def load_json(path):
    if not path:
        return {}
    p = Path(path)
    if not p.exists():
        return {}
    return json.loads(p.read_text(encoding="utf-8"))

# --------------------------------------------------
# Tool adapters (normalize signals)
# --------------------------------------------------
def semgrep_findings(data):
    return {r.get("check_id") for r in data.get("results", [])}

def bandit_findings(data):
    return {r.get("test_id") for r in data.get("results", [])}

def zap_findings(data):
    rules = set()
    for site in data.get("site", []):
        for alert in site.get("alerts", []):
            rules.add(alert.get("name"))
    return rules

def gitleaks_findings(data):
    runs = data.get("runs", [])
    if not runs:
        return set()
    return {r.get("ruleId") for r in runs[0].get("results", [])}

def trivy_findings(data):
    vulns = []
    for r in data.get("Results", []):
        vulns.extend(r.get("Vulnerabilities", []))
    return vulns

# --------------------------------------------------
# ASVS evaluation logic
# --------------------------------------------------
def evaluate_control(control, signals):
    decision = control.get("decision", {})
    hits = []

    for tool in control.get("tools", []):
        tool_name = tool["tool"]
        rule_ids = set(tool.get("rules", []))
        findings = signals.get(tool_name, set())

        # Trivy special handling (severity + KEV)
        if tool_name == "trivy":
            for v in findings:
                if v.get("Severity") in tool.get("severity_fail", []):
                    if tool.get("kev_block") and v.get("KEV", False):
                        return "FAIL", ["KEV detected"]
        else:
            matched = rule_ids & findings
            if matched:
                hits.extend(sorted(matched))

    if decision.get("immediate_fail") and hits:
        return "FAIL", hits

    if decision.get("fail_if_any") and hits:
        return "FAIL", hits

    if hits:
        return "PARTIAL", hits

    if control.get("automation") == "manual":
        return "MANUAL", []

    return "PASS", []

# --------------------------------------------------
# Main
# --------------------------------------------------
def main(args):
    tool_map = load_json(args.tool_map)

    signals = {
        "semgrep": semgrep_findings(load_json(args.semgrep)),
        "bandit": bandit_findings(load_json(args.bandit)),
        "zap": zap_findings(load_json(args.zap)),
        "gitleaks": gitleaks_findings(load_json(args.gitleaks)),
        "trivy": trivy_findings(load_json(args.trivy)),
    }

    results = []
    summary_counts = defaultdict(int)

    score = 0
    max_score = 0

    scoring = tool_map.get("scoring", {})

    for ctrl in tool_map.get("controls", []):
        status, evidence = evaluate_control(ctrl, signals)

        summary_counts[status] += 1

        if status != "MANUAL":
            max_score += 1
            score += scoring.get(status.lower(), 0)

        results.append({
            "id": ctrl["id"],
            "title": ctrl["title"],
            "level": ctrl["level"],
            "owasp": ctrl.get("owasp", []),
            "status": status,
            "evidence": evidence
        })

    pass_percent = round((score / max_score) * 100, 2) if max_score else 0

    output = {
        "meta": {
            "asvs_version": tool_map.get("asvs_version", "4.x"),
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "repo": os.getenv("GITHUB_REPOSITORY", "local"),
        },
        "summary": {
            "total": len(results),
            "pass": summary_counts.get("PASS", 0),
            "fail": summary_counts.get("FAIL", 0),
            "partial": summary_counts.get("PARTIAL", 0),
            "manual": summary_counts.get("MANUAL", 0),
            "pass_percent": pass_percent,
        },
        "controls": results,
    }

    out = Path(args.out_json)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(output, indent=2), encoding="utf-8")

    print(f"[OK] ASVS coverage written → {out}")

# --------------------------------------------------
if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--tool-map", default="schemas/asvs-tool-map.json")
    p.add_argument("--semgrep")
    p.add_argument("--bandit")
    p.add_argument("--zap")
    p.add_argument("--trivy")
    p.add_argument("--gitleaks")
    p.add_argument("--out-json", required=True)
    args = p.parse_args()
    main(args)
