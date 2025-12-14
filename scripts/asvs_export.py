#!/usr/bin/env python3
"""
ASVS Export – Tool-Mapped (Deterministic)

Consumes:
- schemas/asvs-tool-map.json
- Semgrep / Bandit / ZAP / Trivy / Gitleaks outputs

Produces:
- governance/asvs-coverage.json
- governance/asvs-coverage.md
"""

import json
import argparse
from pathlib import Path
from collections import defaultdict

# --------------------------------------------------
# Loaders
# --------------------------------------------------
def load_json(path):
    if not path or not Path(path).exists():
        return {}
    return json.loads(Path(path).read_text())

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
    return {r.get("ruleId") for r in data.get("runs", [{}])[0].get("results", [])}

def trivy_findings(data):
    vulns = []
    for r in data.get("Results", []):
        vulns.extend(r.get("Vulnerabilities", []))
    return vulns

# --------------------------------------------------
# ASVS Evaluation
# --------------------------------------------------
def evaluate_control(control, signals):
    decision = control.get("decision", {})
    hits = []

    for tool in control.get("tools", []):
        tool_name = tool["tool"]
        rule_ids = set(tool.get("rules", []))
        findings = signals.get(tool_name, set())

        if tool_name == "trivy":
            for v in findings:
                if v.get("Severity") in tool.get("severity_fail", []):
                    if tool.get("kev_block") and v.get("KEV", False):
                        return "FAIL", ["KEV detected"]
        else:
            matched = rule_ids & findings
            if matched:
                hits.extend(list(matched))

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
        "trivy": trivy_findings(load_json(args.trivy))
    }

    results = []
    score = 0
    max_score = 0

    for ctrl in tool_map["controls"]:
        status, evidence = evaluate_control(ctrl, signals)

        weight = tool_map["scoring"].get(
            status.lower(), 0
        )

        if status != "MANUAL":
            max_score += 1
            score += weight

        results.append({
            "id": ctrl["id"],
            "title": ctrl["title"],
            "level": ctrl["level"],
            "owasp": ctrl.get("owasp", []),
            "status": status,
            "evidence": evidence
        })

    coverage = {
        "summary": {
            "controls": len(results),
            "pass_percent": round((score / max_score) * 100, 2) if max_score else 0
        },
        "controls": results
    }

    Path(args.out_json).write_text(json.dumps(coverage, indent=2))
    print(f"[OK] ASVS coverage written → {args.out_json}")

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
