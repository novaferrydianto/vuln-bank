#!/usr/bin/env python3
import json
from pathlib import Path

SCORECARD = Path("docs/data/security-scorecard.json")

def clamp(x, lo, hi):
    return max(lo, min(hi, x))

def compute(scorecard: dict) -> dict:
    owasp = scorecard.get("owasp", {}) if isinstance(scorecard, dict) else {}
    asvs  = scorecard.get("asvs", {}) if isinstance(scorecard, dict) else {}
    epss  = scorecard.get("epss", {}) if isinstance(scorecard, dict) else {}
    sla   = scorecard.get("sla", {}) if isinstance(scorecard, dict) else {}

    owasp_cov = float(owasp.get("coverage_percent") or 0)
    asvs_cov  = float(asvs.get("coverage_percent") or 0)

    high_risk = int(epss.get("high_risk_count") or 0)
    breaches  = int(sla.get("breaches") or 0)

    epss_component = clamp(100 - high_risk * 15, 40, 100)
    sla_component  = clamp(100 - breaches  * 15, 40, 100)

    W = {"owasp": 30, "asvs": 30, "epss": 25, "sla": 15}
    score = (
        owasp_cov * W["owasp"] +
        asvs_cov  * W["asvs"] +
        epss_component * W["epss"] +
        sla_component  * W["sla"]
    ) / 100.0

    return {
        "maturity_score": int(round(clamp(score, 0, 100))),
        "maturity_breakdown": {
            "owasp_coverage": round(owasp_cov, 2),
            "asvs_coverage": round(asvs_cov, 2),
            "epss_component": int(epss_component),
            "sla_component": int(sla_component),
            "weights": W
        }
    }

def main():
    data = json.loads(SCORECARD.read_text(encoding="utf-8"))
    data.update(compute(data))
    SCORECARD.write_text(json.dumps(data, indent=2), encoding="utf-8")
    print("[OK] maturity_score added to security-scorecard.json")

if __name__ == "__main__":
    main()
