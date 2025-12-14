#!/usr/bin/env python3
import os, json, datetime, pathlib, re

NOW = datetime.datetime.utcnow()

def load_json(path, default=None):
  p = pathlib.Path(path)
  if not p.exists():
    return default
  return json.loads(p.read_text(encoding="utf-8"))

def append_jsonl(path, obj):
  pathlib.Path(path).parent.mkdir(parents=True, exist_ok=True)
  with open(path, "a", encoding="utf-8") as f:
    f.write(json.dumps(obj) + "\n")

# Inputs
owasp = load_json("docs/data/owasp-latest.json", {"counts": {}})
sla = load_json("docs/data/sla-latest.json", {"summary": {}, "breaches_top": [], "breach_count": 0})
assets_cfg = load_json("security-assets.json", {"assets": {}})

assets = assets_cfg.get("assets", {}) or {}
if not assets:
  # fallback weights
  assets = {
    "frontend": {"weight": 0.35, "tags_any": [], "title_keywords_any": []},
    "backend": {"weight": 0.45, "tags_any": [], "title_keywords_any": []},
    "db": {"weight": 0.20, "tags_any": [], "title_keywords_any": []},
  }

# --- scoring knobs (editable) ---
SEV_POINTS = {"Critical": 10, "High": 7, "Medium": 4, "Low": 2, "Info": 1}

# EPSS points: if epss >= threshold => extra risk
EPSS_THRESHOLD = float(os.environ.get("EPSS_THRESHOLD", "0.50"))
def epss_points(epss):
  try:
    e = float(epss or 0.0)
  except Exception:
    e = 0.0
  if e >= 0.90: return 6
  if e >= 0.70: return 4
  if e >= EPSS_THRESHOLD: return 2
  return 0

# SLA breach multiplier
def sla_multiplier(is_breach: bool):
  return 1.5 if is_breach else 1.0

# Asset classification heuristic (title keywords)
def classify_asset(title: str):
  t = (title or "").lower()
  hits = {}
  for aname, acfg in assets.items():
    kws = [k.lower() for k in (acfg.get("title_keywords_any") or [])]
    score = 0
    for k in kws:
      if k and k in t:
        score += 1
    hits[aname] = score
  # pick max hit; if all zero => backend default
  best = max(hits.items(), key=lambda x: x[1])[0] if hits else "backend"
  if hits.get(best, 0) == 0:
    return "backend"
  return best

# --- compute SLA-based risk per asset ---
breaches = sla.get("breaches_top", []) or []
asset_risk = {a: {"open_risk": 0.0, "breach_risk": 0.0, "breach_count": 0, "top": []} for a in assets.keys()}
total_open_risk = 0.0

for b in breaches:
  title = b.get("title","")
  sev = b.get("severity","Medium")
  age_days = int(b.get("age_days", 0) or 0)
  sla_days = int(b.get("sla_days", 30) or 30)
  is_breach = age_days > sla_days

  a = classify_asset(title)
  base = float(SEV_POINTS.get(sev, 4))
  extra = float(epss_points(b.get("epss")))
  risk = (base + extra) * sla_multiplier(is_breach)

  asset_risk[a]["open_risk"] += (base + extra)
  if is_breach:
    asset_risk[a]["breach_risk"] += risk
    asset_risk[a]["breach_count"] += 1
    asset_risk[a]["top"].append({
      "title": title,
      "severity": sev,
      "age_days": age_days,
      "sla_days": sla_days,
      "epss": b.get("epss"),
      "url": b.get("url"),
      "risk": round(risk, 2),
    })

  total_open_risk += (base + extra)

for a in asset_risk:
  asset_risk[a]["top"] = sorted(asset_risk[a]["top"], key=lambda x: -x["risk"])[:10]
  asset_risk[a]["open_risk"] = round(asset_risk[a]["open_risk"], 2)
  asset_risk[a]["breach_risk"] = round(asset_risk[a]["breach_risk"], 2)

# --- OWASP label pressure (global) ---
owasp_counts = (owasp.get("counts") or owasp.get("owasp_counts") or {})
owasp_pressure = 0.0
# simple: A01/A02 heavier
for k, v in (owasp_counts or {}).items():
  k = str(k)
  n = int(v or 0)
  if k in ("A01","A02"): owasp_pressure += n * 2.0
  elif k in ("A03","A04","A05"): owasp_pressure += n * 1.5
  else: owasp_pressure += n * 1.0

# --- score normalization ---
# Score = 100 - normalized_risk (clamped)
# risk = weighted(asset breach risk + open risk) + owasp pressure
weighted_asset_risk = 0.0
for a, acfg in assets.items():
  w = float(acfg.get("weight", 0.0))
  weighted_asset_risk += w * (asset_risk[a]["breach_risk"] + 0.25 * asset_risk[a]["open_risk"])

risk_total = weighted_asset_risk + 0.5 * owasp_pressure
score = max(0.0, 100.0 - min(100.0, risk_total))  # clamp

result = {
  "generated_at": NOW.isoformat() + "Z",
  "inputs": {
    "owasp_counts": owasp_counts,
    "sla_breach_count": int(sla.get("breach_count", 0) or 0),
    "epss_threshold": EPSS_THRESHOLD,
  },
  "weights": {
    "assets": {a: float(assets[a].get("weight",0.0)) for a in assets},
    "owasp_pressure_factor": 0.5,
    "open_risk_factor": 0.25,
    "sla_breach_multiplier": 1.5,
  },
  "risk": {
    "owasp_pressure": round(owasp_pressure, 2),
    "weighted_asset_risk": round(weighted_asset_risk, 2),
    "risk_total": round(risk_total, 2)
  },
  "score": round(score, 2),
  "assets": asset_risk,
}

pathlib.Path("docs/data").mkdir(parents=True, exist_ok=True)
pathlib.Path("security-metrics/weekly").mkdir(parents=True, exist_ok=True)

pathlib.Path("docs/data/scorecard-latest.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
append_jsonl("docs/data/scorecard-history.jsonl", result)
pathlib.Path("security-metrics/weekly/scorecard-latest.json").write_text(json.dumps(result, indent=2), encoding="utf-8")

print("[OK] Scorecard generated. Score:", result["score"])
