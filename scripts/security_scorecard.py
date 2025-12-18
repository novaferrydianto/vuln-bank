#!/usr/bin/env python3
"""
Security Scorecard Builder for Vuln Bank

- Input:
  - OWASP_LATEST  (env): docs/data/owasp-latest.json
  - EPSS_FINDINGS (env): security-reports/epss-findings.json
  - SLA_WEEKLY    (env): docs/data/defectdojo-sla-weekly.json

- Output:
  - JSON to stdout (redirected by pipeline to docs/data/security-scorecard.json)

Weight default:
  W_OWASP=0.40, W_EPSS=0.35, W_SLA=0.25
"""

import json
import os
import sys
from datetime import datetime


def safe_load_json(path: str):
    """Load JSON file defensively; return None on error/missing."""
    if not path or not os.path.exists(path):
        return None
    try:
        with open(path) as f:
            return json.load(f)
    except Exception as exc:  # noqa: BLE001
        print(f"[WARN] Failed to load JSON from {path}: {exc}", file=sys.stderr)
        return None


def clamp01(value: float) -> float:
    """Clamp numeric value into [0, 1]."""
    try:
        v = float(value)
    except Exception:  # noqa: BLE001
        return 0.0
    if v < 0.0:
        return 0.0
    if v > 1.0:
        return 1.0
    return v


def compute_owasp_component(data: dict | None) -> dict:
    """
    Compute normalized OWASP/ASVS score.

    Expected example shape (tolerant to missing keys):
    {
      "overall_score": 0-100,
      "summary": {"coverage": 0-1, "fulfilled_ratio": 0-1, ...},
      "by_category": [...]
    }
    """
    details: dict = {}
    if not data:
        score_norm = 0.0
        details["note"] = "No OWASP/ASVS data available."
    else:
        overall = data.get("overall_score")
        if overall is not None:
            score_norm = clamp01(overall / 100.0)
        else:
            coverage = None
            summary = data.get("summary") or {}
            if "coverage" in summary:
                coverage = summary.get("coverage")
            if coverage is None and "fulfilled_ratio" in summary:
                coverage = summary.get("fulfilled_ratio")
            if coverage is not None:
                score_norm = clamp01(coverage)
            else:
                score_norm = 0.0
                details["note"] = "OWASP data present but overall_score/coverage missing."

        details["raw"] = data

    score = round(score_norm * 100)
    return {
        "score": score,
        "normalized": score_norm,
        "details": details,
    }


def compute_epss_component(data: dict | None) -> dict:
    """
    EPSS findings from epss_gate.py.

    Example shape:
    {
      "mode": "C",
      "threshold": 0.5,
      "total_findings": N,
      "high_risk": [
        {
          "cve": "...",
          "epss": 0.91,
          "percentile": 0.99,
          "is_kev": true,
          "severity": "CRITICAL",
          "cvss": 9.8,
          ...
        },
        ...
      ]
    }
    """
    details: dict = {}
    if not data:
        details["note"] = "No EPSS data available."
        return {
            "score": 100,
            "normalized": 1.0,
            "details": details,
        }

    high_risk = data.get("high_risk", []) or []
    mode = data.get("mode")
    threshold = data.get("threshold")

    high_risk_count = len(high_risk)
    kev_count = sum(1 for item in high_risk if item.get("is_kev"))
    max_penalty_items = 20

    # Fewer high-risk items => higher score
    base = max(0.0, 1.0 - min(high_risk_count, max_penalty_items) / float(max_penalty_items))

    # Extra penalty for KEV items
    kev_penalty = kev_count * 0.05
    score_norm = max(0.0, base - kev_penalty)

    details["mode"] = mode
    details["threshold"] = threshold
    details["high_risk_count"] = high_risk_count
    details["kev_count"] = kev_count

    score = round(score_norm * 100)
    return {
        "score": score,
        "normalized": score_norm,
        "details": details,
    }


def _get_or(data: dict | None, *keys: str, default: int | float = 0) -> int | float:
    """Get first existing key from dict; otherwise default."""
    if not isinstance(data, dict):
        return default
    for key in keys:
        if key in data:
            return data.get(key, default)
    return default


def compute_sla_component(data: dict | None) -> dict:
    """
    SLA / aging data from DefectDojo export.

    Example shape (flexible):
    {
      "open_critical": 3,
      "open_high": 10,
      "near_sla_breach": 5,
      "breached": 2,
      ...
    }
    """
    details: dict = {}
    if not data:
        details["note"] = "No SLA/aging data available."
        return {
            "score": 50,
            "normalized": 0.5,
            "details": details,
        }

    open_critical = _get_or(
        data,
        "open_critical",
        "critical_open",
        "crit_open",
        default=0,
    )
    open_high = _get_or(
        data,
        "open_high",
        "high_open",
        default=0,
    )
    breached = _get_or(
        data,
        "breached",
        "sla_breached",
        "overdue",
        default=0,
    )
    near_breach = _get_or(
        data,
        "near_sla_breach",
        "near_breach",
        "aging_risk",
        default=0,
    )

    # Weighted "risk points"
    risk_points = (
        open_critical * 3
        + open_high * 2
        + breached * 4
        + near_breach * 1
    )

    # Normalize: 0 points => 1.0, >=50 points => 0.0
    score_norm = max(0.0, 1.0 - risk_points / 50.0)

    details.update(
        {
            "open_critical": open_critical,
            "open_high": open_high,
            "breached": breached,
            "near_breach": near_breach,
            "risk_points": risk_points,
        },
    )

    score = round(score_norm * 100)
    return {
        "score": score,
        "normalized": score_norm,
        "details": details,
    }


def traffic_light(score: int) -> str:
    if score >= 85:
        return "green"
    if score >= 70:
        return "yellow"
    return "red"


def letter_grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "E"


def main() -> None:
    app = os.environ.get("APP_NAME", "vuln-bank")
    owasp_path = os.environ.get("OWASP_LATEST", "docs/data/owasp-latest.json")
    epss_path = os.environ.get("EPSS_FINDINGS", "security-reports/epss-findings.json")
    sla_path = os.environ.get("SLA_WEEKLY", "docs/data/defectdojo-sla-weekly.json")

    w_owasp = float(os.environ.get("W_OWASP", "0.40"))
    w_epss = float(os.environ.get("W_EPSS", "0.35"))
    w_sla = float(os.environ.get("W_SLA", "0.25"))

    # Normalize weights
    w_sum = w_owasp + w_epss + w_sla
    if w_sum <= 0:
        w_owasp = 0.4
        w_epss = 0.35
        w_sla = 0.25
        w_sum = 1.0

    w_owasp /= w_sum
    w_epss /= w_sum
    w_sla /= w_sum

    owasp_data = safe_load_json(owasp_path)
    epss_data = safe_load_json(epss_path)
    sla_data = safe_load_json(sla_path)

    comp_owasp = compute_owasp_component(owasp_data)
    comp_epss = compute_epss_component(epss_data)
    comp_sla = compute_sla_component(sla_data)

    # Weighted overall
    overall_norm = (
        comp_owasp["normalized"] * w_owasp
        + comp_epss["normalized"] * w_epss
        + comp_sla["normalized"] * w_sla
    )
    overall_score = round(overall_norm * 100)
    grade = letter_grade(overall_score)
    signal = traffic_light(overall_score)

    summary_en = (
        f"Overall security posture score for {app} is {overall_score} "
        f"({grade}, {signal}). OWASP/ASVS={comp_owasp['score']}, "
        f"EPSS/KEV risk={comp_epss['score']}, SLA/Aging={comp_sla['score']}."
    )
    summary_id = (
        f"Skor posture keamanan keseluruhan untuk {app} adalah {overall_score} "
        f"({grade}, {signal}). OWASP/ASVS={comp_owasp['score']}, "
        f"risiko EPSS/KEV={comp_epss['score']}, SLA/aging={comp_sla['score']}."
    )

    out = {
        "metadata": {
            "app_name": app,
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "weights": {
                "owasp": w_owasp,
                "epss": w_epss,
                "sla": w_sla,
            },
        },
        "components": {
            "owasp": comp_owasp,
            "epss": comp_epss,
            "sla": comp_sla,
        },
        "overall": {
            "score": overall_score,
            "normalized": overall_norm,
            "grade": grade,
            "traffic_light": signal,
            "summary_en": summary_en,
            "summary_id": summary_id,
        },
    }

    json.dump(out, sys.stdout, indent=2)


if __name__ == "__main__":
    main()
