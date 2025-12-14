#!/usr/bin/env python3
import json, os, datetime

def load(path, default):
    if not os.path.exists(path):
        return default
    with open(path) as f:
        return json.load(f)

# -------------------------
# Load inputs
# -------------------------
owasp = load("docs/data/owasp-latest.json", {})
epss = load("docs/data/epss-weekly.json", {})
sla  = load("docs/data/defectdojo-sla-weekly.json", {})

# -------------------------
# OWASP score
# -------------------------
OWASP_MAX = 50
total_owasp = sum(owasp.get("counts", {}).values())
owasp_score = max(0, 100 - min((total_owasp / OWASP_MAX) * 100, 100))

# -------------------------
# EPSS score
# -------------------------
high_epss = epss.get("high_risk", [])
if high_epss:
    avg_epss = sum(v["epss"] for v in high_epss) / len(high_epss)
    epss_score = max(0, 100 - avg_epss * 100)
else:
    epss_score = 100

# -------------------------
# SLA score
# -------------------------
total = sla.get("total_findings", 0)
breached = sla.get("sla_breached", 0)
if total > 0:
    sla_score = max(0, 100 - (breached / total) * 100)
else:
    sla_score = 100

# -------------------------
# Final weighted score
# -------------------------
final_score = round(
    (owasp_score * 0.4) +
    (epss_score * 0.4) +
    (sla_score * 0.2),
    2
)

result = {
    "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
    "components": {
        "owasp": round(owasp_score, 2),
        "epss": round(epss_score, 2),
        "sla": round(sla_score, 2),
    },
    "final_score": final_score,
    "grade": (
        "A" if final_score >= 90 else
        "B" if final_score >= 80 else
        "C" if final_score >= 70 else
        "D"
    )
}

os.makedirs("docs/data", exist_ok=True)
with open("docs/data/security-scorecard.json", "w") as f:
    json.dump(result, f, indent=2)

print("[OK] Security scorecard generated:", final_score)
