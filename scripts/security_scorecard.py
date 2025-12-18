#!/usr/bin/env python3
"""
Security Scorecard Generator (Refactored, Low Cognitive Complexity)

Inputs:
- OWASP latest results (JSON)
- EPSS findings (JSON)
- DefectDojo SLA weekly stats (JSON)

Output:
- Consolidated security scorecard JSON for the board report
"""

import json
import os
from typing import Dict, Any


# =========================================================
# Helpers
# =========================================================

def load_json(path: str) -> dict:
    if not os.path.exists(path):
        return {}
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return {}


def normalize_number(v, default=0.0):
    try:
        return float(v)
    except Exception:
        return float(default)


# =========================================================
# Domain-specific extractors
# =========================================================

def extract_owasp_score(data: Dict[str, Any]) -> float:
    """
    Expected structure:
    { "total_pass": X, "total_fail": Y }
    """
    if not data:
        return 0.0
    passed = normalize_number(data.get("total_pass", 0))
    failed = normalize_number(data.get("total_fail", 0))
    total = passed + failed
    if total == 0:
        return 0.0
    return round(passed / total, 4)


def extract_epss_score(data: Dict[str, Any]) -> float:
    """
    Uses weighted EPSS high-risk count.
    Expected structure:
    { "total_high_risk": N, ... }
    """
    if not data:
        return 0.0
    count = normalize_number(data.get("total_high_risk", 0))
    if count == 0:
        return 1.0  # perfect score
    # decay model (the more high-risk CVEs, the worse)
    score = max(0.0, 1.0 - (count * 0.1))
    return round(score, 4)


def extract_sla_score(data: Dict[str, Any]) -> float:
    """
    Expected structure:
    { "on_time": X, "late": Y }
    """
    if not data:
        return 0.0
    on_time = normalize_number(data.get("on_time", 0))
    late = normalize_number(data.get("late", 0))
    total = on_time + late
    if total == 0:
        return 1.0
    return round(on_time / total, 4)


# =========================================================
# Weighted aggregation
# =========================================================

def compute_weighted_score(owasp: float, epss: float, sla: float) -> float:
    """
    Global weighting:
      - OWASP: 0.40
      - EPSS:  0.35
      - SLA:   0.25
    """
    return round(
        (owasp * 0.40) +
        (epss * 0.35) +
        (sla * 0.25),
        4
    )


# =========================================================
# Main scorecard builder
# =========================================================

def build_scorecard(
    owasp_json: str,
    epss_json: str,
    sla_json: str
) -> Dict[str, Any]:
    owasp_data = load_json(owasp_json)
    epss_data = load_json(epss_json)
    sla_data = load_json(sla_json)

    owasp_score = extract_owasp_score(owasp_data)
    epss_score = extract_epss_score(epss_data)
    sla_score = extract_sla_score(sla_data)

    final_score = compute_weighted_score(
        owasp_score, epss_score, sla_score
    )

    return {
        "owasp_score": owasp_score,
        "epss_score": epss_score,
        "sla_score": sla_score,
        "final_score": final_score,
        "total_high_risk": epss_data.get("total_high_risk", 0),
        "owasp_fail": owasp_data.get("total_fail", 0),
    }


# =========================================================
# CLI
# =========================================================

def main():
    owasp = os.environ.get("OWASP_LATEST", "docs/data/owasp-latest.json")
    epss = os.environ.get("EPSS_FINDINGS", "security-reports/epss-findings.json")
    sla = os.environ.get("SLA_WEEKLY", "docs/data/defectdojo-sla-weekly.json")

    scorecard = build_scorecard(owasp, epss, sla)
    print(json.dumps(scorecard, indent=2))


if __name__ == "__main__":
    main()
