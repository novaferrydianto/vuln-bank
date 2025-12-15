#!/usr/bin/env python3
"""
ASVS Export – Tool-Mapped (Deterministic, Schema-Compliant)

Consumes:
- schemas/asvs-tool-map.json
- Semgrep / Bandit / ZAP / Trivy / Gitleaks outputs
- (optional) security-metrics/weekly/risk-trend.json  -> burn-down velocity KPI

Produces:
- security-reports/governance/asvs-coverage.json

Design:
- Schema-first (audit-ready)
- Deterministic evaluation
- CI / Slack / Pages compatible
"""

import json
import argparse
import os
from pathlib import Path
from datetime import datetime
from collections import defaultdict
from typing import Any, Dict, List, Optional

# --------------------------------------------------
# Risk model (level-weighted, non-linear)
# --------------------------------------------------
LEVEL_WEIGHTS = {
    1: 1,  # L1
    2: 2,  # L2
    3: 4,  # L3 (non-linear, executive risk)
}

# Optional trend input for burn-down KPI
RISK_TREND_PATH = os.getenv("RISK_TREND_PATH", "security-metrics/weekly/risk-trend.json")

# --------------------------------------------------
# Utils
# --------------------------------------------------
def utc_week_id(dt: Optional[datetime] = None) -> str:
    dt = dt or datetime.utcnow()
    # ISO week is generally best for exec reporting
    iso_year, iso_week, _ = dt.isocalendar()
    return f"{iso_year}-W{iso_week:02d}"

def load_json(path: Any) -> Dict[str, Any]:
    if not path:
        return {}
    p = Path(path)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}

def write_json(path: Path, obj: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2), encoding="utf-8")

def normalize_level(raw):
    """
    Accepts: 'L1','L2','L3', 1,2,3
    Returns: int 1|2|3
    """
    if isinstance(raw, int) and raw in (1, 2, 3):
        return raw
    if isinstance(raw, str):
        raw = raw.strip().upper()
        if raw.startswith("L") and raw[1:].isdigit():
            v = int(raw[1:])
            if v in (1, 2, 3):
                return v
    raise ValueError(f"Invalid ASVS level: {raw}")

def safe_int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except Exception:
        return default

# --------------------------------------------------
# Tool adapters (normalize signals)
# --------------------------------------------------
def semgrep_findings(data):
    return {r.get("check_id") for r in data.get("results", []) if r.get("check_id")}

def bandit_findings(data):
    return {r.get("test_id") for r in data.get("results", []) if r.get("test_id")}

def zap_findings(data):
    rules = set()
    for site in data.get("site", []) or []:
        for alert in site.get("alerts", []) or []:
            name = alert.get("name")
            if name:
                rules.add(name)
    return rules

def gitleaks_findings(data):
    runs = data.get("runs", []) or []
    if not runs:
        return set()
    results = runs[0].get("results", []) or []
    out = set()
    for r in results:
        rid = r.get("ruleId")
        if rid:
            out.add(rid)
    return out

def trivy_findings(data):
    vulns = []
    for r in data.get("Results", []) or []:
        vulns.extend(r.get("Vulnerabilities", []) or [])
    return vulns

# --------------------------------------------------
# Burn-down KPI helpers
# --------------------------------------------------
def compute_burn_down(current_raw: int, trend_doc: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Uses latest point in risk-trend.json as 'previous' baseline.
    Expected:
      { "points": [ {"week":"2025-W50","risk_raw": 26}, ... ] }
    """
    points = trend_doc.get("points", []) or []
    if not points:
        return None

    last = points[-1]
    prev_raw = safe_int(last.get("risk_raw"), default=0)

    delta = current_raw - prev_raw
    if delta < 0:
        direction = "DOWN"
    elif delta > 0:
        direction = "UP"
    else:
        direction = "FLAT"

    return {
        "previous_raw": prev_raw,
        "delta": delta,
        "velocity": delta,   # per-week delta (simple and exec-readable)
        "direction": direction,
        "week": utc_week_id(),
    }

# --------------------------------------------------
# ASVS evaluation logic
# --------------------------------------------------
def evaluate_control(control, signals):
    """
    Returns:
      status: PASS | FAIL | NOT_APPLICABLE
      evidence: list[str]
      owners: list[str]
    """
    decision = control.get("decision", {}) or {}
    hits: List[str] = []
    owners = set()

    for tool in control.get("tools", []) or []:
        tool_name = tool.get("tool")
        if not tool_name:
            continue

        rule_ids = set(tool.get("rules", []) or [])
        findings = signals.get(tool_name, set())

        # Trivy: severity + KEV logic
        if tool_name == "trivy":
            for v in findings:
                if v.get("Severity") in (tool.get("severity_fail", []) or []):
                    owners.add("trivy")
                    if tool.get("kev_block") and bool(v.get("KEV", False)):
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
        # Schema does NOT allow PARTIAL → collapse to FAIL
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

    # Risk accumulators
    risk_raw = 0
    risk_max = 0
    risk_by_level = defaultdict(int)    # "L3" -> points
    risk_by_family = defaultdict(int)   # "V14" -> points

    for ctrl in tool_map.get("controls", []) or []:
        status, evidence, owners = evaluate_control(ctrl, signals)

        level = normalize_level(ctrl.get("level"))
        cid = ctrl.get("id", "")
        if not cid:
            # Skip invalid entries rather than crashing schema output
            continue

        family = cid.split(".")[0]  # V1..V14

        status_counts[status] += 1
        family_summary[family][status] += 1

        weight = LEVEL_WEIGHTS[level]

        # Risk model excludes NOT_APPLICABLE
        if status in ("PASS", "FAIL"):
            risk_max += weight
            if status == "FAIL":
                risk_raw += weight
                risk_by_level[f"L{level}"] += weight
                risk_by_family[family] += weight

        results.append({
            "id": cid,
            "title": ctrl.get("title", ""),
            "level": level,                   # integer (schema)
            "owasp": ctrl.get("owasp", []) or [],
            "status": status,                 # PASS | FAIL | NOT_APPLICABLE
            "evidence": evidence,
            "owners": owners,                 # tool ownership
        })

    passed = status_counts.get("PASS", 0)
    failed = status_counts.get("FAIL", 0)
    not_applicable = status_counts.get("NOT_APPLICABLE", 0)

    effective_total = passed + failed

    coverage_percent = round(
        (passed / effective_total) * 100, 2
    ) if effective_total else 0.0

    risk_percent = round(
        (risk_raw / risk_max) * 100, 2
    ) if risk_max else 0.0

    worst_families = sorted(
        [{"family": f, "risk_points": pts} for f, pts in risk_by_family.items() if pts > 0],
        key=lambda x: x["risk_points"],
        reverse=True,
    )

    # --------------------------------------------------
    # Burn-down KPI (optional, non-fatal)
    # --------------------------------------------------
    trend_doc = load_json(RISK_TREND_PATH)
    burn_down = compute_burn_down(risk_raw, trend_doc)

    output = {
        "meta": {
            "asvs_version": tool_map.get("asvs_version", "4.x"),
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "repo": os.getenv("GITHUB_REPOSITORY", "local"),
        },
        "summary": {
            # REQUIRED BY SCHEMA
            "total": effective_total,
            "passed": passed,
            "failed": failed,
            "coverage_percent": coverage_percent,

            # EXTENSIONS (allowed)
            "not_applicable": not_applicable,
            "families": family_summary,

            # Level-weighted risk model
            "risk": {
                "model": {
                    "L1": LEVEL_WEIGHTS[1],
                    "L2": LEVEL_WEIGHTS[2],
                    "L3": LEVEL_WEIGHTS[3],
                },
                "raw_score": risk_raw,
                "max_score": risk_max,
                "risk_percent": risk_percent,
                "by_level": dict(risk_by_level),
                "by_family": dict(risk_by_family),
                "worst_families": worst_families[:10],
            },
        },
        "controls": results,
    }

    if burn_down:
        output["summary"]["risk"]["burn_down"] = burn_down

    out = Path(args.out_json)
    write_json(out, output)

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
