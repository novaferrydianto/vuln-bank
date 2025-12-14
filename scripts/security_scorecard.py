#!/usr/bin/env python3
"""
Security Scorecard Generator (Schema-Compliant, Board-Ready)

Inputs (best-effort):
- docs/data/owasp-latest.json
- security-reports/epss-findings.json
- docs/data/defectdojo-sla-weekly.json

Output:
- docs/data/security-scorecard.json
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List


# ----------------------------
# Paths / Env
# ----------------------------
REPO = os.getenv("GITHUB_REPOSITORY", "unknown/repo")

OWASP_FILE = Path("docs/data/owasp-latest.json")
EPSS_FILE = Path("security-reports/epss-findings.json")
SLA_FILE = Path("docs/data/defectdojo-sla-weekly.json")

OUT_FILE = Path("docs/data/security-scorecard.json")

VERSION = "v1.0"


# ----------------------------
# Helpers
# ----------------------------
def load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def clamp(score: int) -> int:
    return max(0, min(100, score))


def grade_from_score(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


# ----------------------------
# Component Scoring
# ----------------------------
def score_owasp(data: Dict[str, Any]) -> int:
    """
    Simple heuristic:
    - More open high-risk OWASP issues → lower score
    """
    counts = data.get("counts", {})
    high = counts.get("A01", 0) + counts.get("A02", 0)
    return clamp(100 - (high * 10))


def score_epss(data: Dict[str, Any]) -> int:
    """
    EPSS score based on count of high-risk CVEs
    """
    high_risk = data.get("high_risk", [])
    return clamp(100 - (len(high_risk) * 15))


def score_sla(data: Dict[str, Any]) -> int:
    """
    SLA score based on breached findings
    """
    breaches = data.get("summary", {}).get("breached", 0)
    return clamp(100 - (breaches * 20))


# ----------------------------
# Main
# ----------------------------
def main() -> None:
    OUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    owasp = load_json(OWASP_FILE, {})
    epss = load_json(EPSS_FILE, {"high_risk": [], "threshold": None})
    sla = load_json(SLA_FILE, {"summary": {"breached": 0}})

    # Component scores
    owasp_score = score_owasp(owasp)
    epss_score = score_epss(epss)
    sla_score = score_sla(sla)

    # Weights
    weights = {
        "overall": {"owasp": 0.4, "epss": 0.35, "sla": 0.25},
        "asset": {}
    }

    overall = clamp(
        int(
            owasp_score * weights["overall"]["owasp"]
            + epss_score * weights["overall"]["epss"]
            + sla_score * weights["overall"]["sla"]
        )
    )

    grade = grade_from_score(overall)

    # ----------------------------
    # Schema-Compliant Output
    # ----------------------------
    scorecard: Dict[str, Any] = {
        "meta": {
            "repo": REPO,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "version": VERSION,
            "description": "Automated security posture scorecard"
        },

        "weights": weights,

        "score": {
            "overall": overall,
            "grade": grade,
            "components": {
                "owasp": owasp_score,
                "epss": epss_score,
                "sla": sla_score
            }
        },

        "grade_policy": {
            "A": "Strong security posture",
            "B": "Good posture with manageable risk",
            "C": "Moderate risk; remediation required",
            "D": "High risk; urgent action required",
            "F": "Critical security posture"
        },

        "management_summary": {
            "grade_rationale": (
                f"Overall grade {grade} driven by OWASP={owasp_score}, "
                f"EPSS={epss_score}, SLA={sla_score}."
            ),
            "deployment_posture": (
                "Acceptable for controlled deployment"
                if grade in ("A", "B")
                else "Deployment requires remediation"
            ),
            "key_risks": [
                "High-risk vulnerabilities with exploit potential"
                if epss_score < 80 else "No dominant exploit risks identified"
            ],
            "recommended_actions": [
                "Prioritize remediation of EPSS-high CVEs",
                "Reduce SLA breaches through faster patching",
                "Track OWASP A01/A02 trends weekly"
            ]
        },

        "owasp": {
            "global": owasp.get("counts", {}),
            "score": owasp_score
        },

        "epss": {
            "threshold": epss.get("threshold"),
            "high_risk_count": len(epss.get("high_risk", [])),
            "score": epss_score,
            "top_cves": epss.get("high_risk", [])[:5]
        },

        "sla": {
            "summary": sla.get("summary", {}),
            "breaches": sla.get("breaches", {}),
            "breaches_by_severity": sla.get("breaches_by_severity", {}),
            "breaches_by_asset": sla.get("breaches_by_asset", {}),
            "score": sla_score
        },

        "assets": [
            {
                "name": "global",
                "type": "application",
                "score": {
                    "overall": overall,
                    "owasp": owasp_score,
                    "epss": epss_score,
                    "sla": sla_score
                }
            }
        ]
    }

    OUT_FILE.write_text(json.dumps(scorecard, indent=2), encoding="utf-8")
    print(f"[OK] Security scorecard written → {OUT_FILE}")


if __name__ == "__main__":
    main()
