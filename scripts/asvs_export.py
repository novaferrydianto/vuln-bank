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
    owners = set()

    for tool in control.get("tools", []):
        tool_name = tool["tool"]
        rule_ids = set(tool.get("rules", []))
        findings = signals.get(tool_name, set())

        if tool_name == "trivy":
            for v in findings:
                if v.get("Severity") in tool.get("severity_fail", []):
                    owners.add("trivy")
                    if tool.get("kev_block") and v.get("KEV", False):
                        return "FAIL", ["KEV detected"], ["trivy"]
        else:
            matched = rule_ids & findings
            if matched:
                hits.extend(sorted(matched))
                owners.add(tool_name)

    if decision.get("immediate_fail") and hits:
        return "FAIL", hits, sorted(owners)

    if decision.get("fail_if_any") and hits:
        return "FAIL", hits, sorted(owners)

    if hits:
        return "FAIL", hits, sorted(owners)

    if control.get("automation") == "manual":
        return "NOT_APPLICABLE", [], []

    return "PASS", [], []

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
    status_counts = defaultdict(int)
    family_summary = defaultdict(lambda: defaultdict(int))

    for ctrl in tool_map.get("controls", []):
        status, evidence, owners = evaluate_control(ctrl, signals)

        status_counts[status] += 1

        family = ctrl["id"].split(".")[0]  # V1, V2, ...
        family_summary[family][status] += 1

        results.append({
            "id": ctrl["id"],
            "title": ctrl["title"],
            "level": ctrl["level"],
            "owasp": ctrl.get("owasp", []),
            "status": status,
            "evidence": evidence,
            "owners": owners,
        })

    passed = status_counts.get("PASS", 0)
    failed = status_counts.get("FAIL", 0)
    not_applicable = status_counts.get("NOT_APPLICABLE", 0)

    effective_total = passed + failed
    coverage_percent = round(
        (passed / effective_total) * 100, 2
    ) if effective_total else 0.0

    output = {
        "meta": {
            "asvs_version": tool_map.get("asvs_version", "4.x"),
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "repo": os.getenv("GITHUB_REPOSITORY", "local"),
        },
        "summary": {
            # ✅ REQUIRED BY SCHEMA
            "total": effective_total,
            "passed": passed,
            "failed": failed,
            "coverage_percent": coverage_percent,

            # ➕ EXTENSIONS (allowed)
            "not_applicable": not_applicable,
            "families": family_summary,
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
