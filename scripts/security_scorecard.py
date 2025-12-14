#!/usr/bin/env python3
import os, json, datetime, urllib.request, urllib.parse, math, re
from typing import Dict, Any, List, Tuple

REPO = os.environ.get("GITHUB_REPOSITORY") or os.environ.get("REPO") or ""
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")

# Inputs
OWASP_LATEST = os.environ.get("OWASP_LATEST", "docs/data/owasp-latest.json")
EPSS_FINDINGS = os.environ.get("EPSS_FINDINGS", "security-reports/epss-findings.json")
SLA_WEEKLY = os.environ.get("SLA_WEEKLY", "docs/data/defectdojo-sla-weekly.json")

OUT_SCORECARD = os.environ.get("OUT_SCORECARD", "docs/data/security-scorecard.json")

# Weighting (overall)
W_OWASP = float(os.environ.get("W_OWASP", "0.40"))
W_EPSS = float(os.environ.get("W_EPSS", "0.35"))
W_SLA  = float(os.environ.get("W_SLA",  "0.25"))

# Per-asset weights (tunable)
ASSET_WEIGHTS = {
    "frontend": {"owasp": 0.35, "epss": 0.30, "sla": 0.35},
    "backend":  {"owasp": 0.40, "epss": 0.35, "sla": 0.25},
    "db":       {"owasp": 0.30, "epss": 0.45, "sla": 0.25},
}

NOW = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc)

OWASP_KEYS = [f"A{i:02}" for i in range(1, 11)]
ASSETS = ["frontend", "backend", "db"]

# ---------------------------
# Utilities
# ---------------------------
def read_json(path: str):
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def safe_int(x, default=0):
    try:
        return int(x)
    except Exception:
        return default

def safe_float(x, default=0.0):
    try:
        return float(x)
    except Exception:
        return default

def clamp(v, lo=0, hi=100):
    return max(lo, min(hi, v))

def grade_from_score(score: int):
    if score >= 90: return "A"
    if score >= 80: return "B"
    if score >= 70: return "C"
    if score >= 60: return "D"
    return "F"

def github_headers():
    return {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "vuln-bank-scorecard"
    }

def norm_asset(a: str) -> str:
    a = (a or "").strip().lower()
    if a in ("frontend", "backend", "db"):
        return a
    return "backend"

# ---------------------------
# Asset detection (labels + path fallback)
# ---------------------------
FRONT_HINTS = [
    r"\bui\b", r"\bux\b", r"\bfrontend\b", r"\btemplates?\b", r"\bstatic\b", r"\bcss\b", r"\bjs\b",
    r"\bhtml\b", r"templates/", r"static/", r"docs/"
]
DB_HINTS = [
    r"\bdb\b", r"\bdatabase\b", r"\bpostgres\b", r"\bpgsql\b", r"\bmysql\b", r"\bsql\b",
    r"database\.py", r"migrations?/", r"schema", r"seed"
]

def detect_asset_from_text(text: str) -> str:
    t = (text or "").lower()
    for p in DB_HINTS:
        if re.search(p, t):
            return "db"
    for p in FRONT_HINTS:
        if re.search(p, t):
            return "frontend"
    return "backend"

# ---------------------------
# OWASP (global + per-asset)
# ---------------------------
OWASP_PENALTY_WEIGHTS = {
    "A01": 10, "A02": 9, "A03": 8, "A04": 7, "A05": 7,
    "A06": 6, "A07": 6, "A08": 5, "A09": 5, "A10": 4
}

def score_owasp_from_counts(counts: Dict[str, int]) -> int:
    penalty = 0.0
    for k, c in (counts or {}).items():
        kk = (k or "").upper()
        w = OWASP_PENALTY_WEIGHTS.get(kk, 4)
        penalty += w * safe_int(c)
    score = 100 * math.exp(-penalty / 30.0)
    return int(clamp(round(score)))

def get_owasp_counts_global():
    data = read_json(OWASP_LATEST)
    if data and isinstance(data.get("counts"), dict):
        # weekly job output
        return {k: safe_int(v) for k, v in data["counts"].items()}
    # fallback: compute from GitHub issues
    return fetch_owasp_counts_from_github(per_asset=False)["global"]

def fetch_owasp_counts_from_github(per_asset: bool = True) -> Dict[str, Any]:
    """
    Count OWASP labels from GitHub issues and (optionally) split per asset using:
    - asset:* labels, else fallback from text hints (title+body)
    """
    out = {
        "global": {k: 0 for k in OWASP_KEYS},
        "by_asset": {a: {k: 0 for k in OWASP_KEYS} for a in ASSETS}
    }
    if not REPO or not GITHUB_TOKEN:
        return out

    # Pull up to 500 issues (5 pages)
    for page in range(1, 6):
        url = f"https://api.github.com/repos/{REPO}/issues?state=all&per_page=100&page={page}"
        req = urllib.request.Request(url, headers=github_headers())
        with urllib.request.urlopen(req, timeout=30) as resp:
            issues = json.load(resp)
        if not issues:
            break

        for issue in issues:
            labels = issue.get("labels", []) or []
            label_names = [(l.get("name") or "") for l in labels]
            label_upper = [n.upper() for n in label_names]

            # extract OWASP label(s)
            owasp_hits = []
            for name_u in label_upper:
                if name_u.startswith("OWASP:A"):
                    key = name_u.replace("OWASP:", "")
                    if key in out["global"]:
                        owasp_hits.append(key)

            if not owasp_hits:
                continue

            # global counts
            for k in owasp_hits:
                out["global"][k] += 1

            if not per_asset:
                continue

            # asset label
            asset = None
            for n in label_names:
                nn = (n or "").strip().lower()
                if nn.startswith("asset:"):
                    asset = norm_asset(nn.split("asset:", 1)[1])
                    break

            # fallback asset detection from title+body
            if not asset:
                blob = (issue.get("title") or "") + "\n" + (issue.get("body") or "")
                asset = detect_asset_from_text(blob)

            for k in owasp_hits:
                out["by_asset"][asset][k] += 1

    return out

# ---------------------------
# EPSS (global + per-asset)
# ---------------------------
def score_epss(high_risk_count: int) -> int:
    score = 100 * math.exp(-high_risk_count / 2.5)
    return int(clamp(round(score)))

def parse_epss_findings() -> Dict[str, Any]:
    d = read_json(EPSS_FINDINGS)
    if not d:
        return {"high_risk": [], "threshold": None}

    high_risk = d.get("high_risk") or d.get("high_risk_findings") or []
    threshold = d.get("threshold") or d.get("epss_threshold")
    return {"high_risk": high_risk, "threshold": threshold}

def epss_top_cves(high_risk: List[Dict[str, Any]], limit: int = 5):
    out = []
    for x in (high_risk or [])[:10]:
        out.append({
            "cve": x.get("cve") or x.get("CVE"),
            "epss": x.get("epss") or x.get("EPSS"),
            "package": x.get("package") or x.get("pkg") or x.get("dependency")
        })
    # sort by epss desc if numeric
    out.sort(key=lambda z: safe_float(z.get("epss"), 0.0), reverse=True)
    return out[:limit]

def detect_asset_from_epss_item(item: Dict[str, Any]) -> str:
    # Try multiple hints
    fields = [
        str(item.get("file") or ""),
        str(item.get("path") or ""),
        str(item.get("target") or ""),
        str(item.get("component") or ""),
        str(item.get("package") or ""),
        str(item.get("pkg") or ""),
        str(item.get("dependency") or "")
    ]
    blob = "\n".join([f for f in fields if f])
    return detect_asset_from_text(blob)

def epss_by_asset(high_risk: List[Dict[str, Any]]) -> Dict[str, int]:
    counts = {a: 0 for a in ASSETS}
    for item in high_risk or []:
        a = detect_asset_from_epss_item(item)
        counts[a] += 1
    return counts

# ---------------------------
# SLA weekly (DefectDojo)
# ---------------------------
def get_sla_weekly():
    d = read_json(SLA_WEEKLY)
    if not d:
        return {
            "breaches": {"Critical": 0, "High": 0},
            "breaches_by_asset": {a: {"Critical": 0, "High": 0} for a in ASSETS},
            "sla_days": {"Critical": None, "High": None},
            "top_breaches": []
        }

    breaches = (d.get("counts") or {}).get("breaches") or d.get("breaches") or {}
    breaches_by_asset = (d.get("counts") or {}).get("breaches_by_asset") or d.get("breaches_by_asset") or {}

    norm = {a: {"Critical": 0, "High": 0} for a in ASSETS}
    for a, sv in (breaches_by_asset or {}).items():
        aa = norm_asset(a)
        norm[aa]["Critical"] += safe_int((sv or {}).get("Critical"))
        norm[aa]["High"] += safe_int((sv or {}).get("High"))

    return {
        "breaches": {"Critical": safe_int(breaches.get("Critical")), "High": safe_int(breaches.get("High"))},
        "breaches_by_asset": norm,
        "sla_days": d.get("sla_days") or {},
        "top_breaches": d.get("top_breaches") or []
    }

def score_sla(breaches_critical: int, breaches_high: int) -> int:
    penalty = breaches_critical * 18 + breaches_high * 8
    score = 100 * math.exp(-penalty / 30.0)
    return int(clamp(round(score)))

# ---------------------------
# Per-asset scoring (REAL)
# ---------------------------
def compute_asset_scores(owasp_by_asset: Dict[str, Dict[str, int]],
                         epss_asset_counts: Dict[str, int],
                         sla_obj: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    out = {}

    for a in ASSETS:
        w = ASSET_WEIGHTS[a]

        owasp_counts = owasp_by_asset.get(a) or {k: 0 for k in OWASP_KEYS}
        owasp_s = score_owasp_from_counts(owasp_counts)

        epss_cnt = safe_int(epss_asset_counts.get(a))
        epss_s = score_epss(epss_cnt)

        bre_c = safe_int(sla_obj["breaches_by_asset"][a].get("Critical"))
        bre_h = safe_int(sla_obj["breaches_by_asset"][a].get("High"))
        sla_s = score_sla(bre_c, bre_h)

        overall = int(clamp(round(
            w["owasp"] * owasp_s +
            w["epss"]  * epss_s +
            w["sla"]   * sla_s
        )))

        out[a] = {
            "owasp": owasp_s,
            "epss": epss_s,
            "sla": sla_s,
            "overall": overall,
            "inputs": {
                "owasp_counts": owasp_counts,
                "epss_high_risk_count": epss_cnt,
                "sla_breaches": {"Critical": bre_c, "High": bre_h}
            }
        }

    return out

def main():
    os.makedirs("docs/data", exist_ok=True)

    # OWASP per-asset: prefer GitHub issues labels (asset:* + OWASP:Ax)
    owasp_github = fetch_owasp_counts_from_github(per_asset=True)
    owasp_global = get_owasp_counts_global()

    # If weekly file exists but per-asset is empty, we still use GitHub split.
    owasp_by_asset = owasp_github["by_asset"]

    # EPSS
    epss_parsed = parse_epss_findings()
    high_risk = epss_parsed["high_risk"]
    epss_asset_counts = epss_by_asset(high_risk)
    epss_obj = {
        "high_risk_count": len(high_risk),
        "top_cves": epss_top_cves(high_risk, limit=5),
        "threshold": epss_parsed["threshold"]
    }

    # SLA
    sla_obj = get_sla_weekly()

    # Global scores
    s_owasp = score_owasp_from_counts(owasp_global)
    s_epss = score_epss(epss_obj["high_risk_count"])
    s_sla  = score_sla(safe_int(sla_obj["breaches"]["Critical"]), safe_int(sla_obj["breaches"]["High"]))

    overall = int(clamp(round(
        W_OWASP * s_owasp +
        W_EPSS  * s_epss +
        W_SLA   * s_sla
    )))

    # Per-asset scores (real)
    assets = compute_asset_scores(owasp_by_asset, epss_asset_counts, sla_obj)

    out = {
        "repo": REPO or "unknown",
        "generated_at": NOW.isoformat().replace("+00:00", "Z"),

        "owasp": owasp_global,
        "owasp_by_asset": owasp_by_asset,

        "epss": {
            "high_risk_count": epss_obj["high_risk_count"],
            "top_cves": epss_obj["top_cves"],
            "threshold": epss_obj.get("threshold"),
            "by_asset": epss_asset_counts
        },

        "sla": {
            "breaches": sla_obj.get("breaches", {"Critical": 0, "High": 0}),
            "breaches_by_asset": sla_obj.get("breaches_by_asset", {}),
            "sla_days": sla_obj.get("sla_days", {}),
            "top_breaches": (sla_obj.get("top_breaches") or [])[:5]
        },

        "score": {
            "owasp": s_owasp,
            "epss": s_epss,
            "sla": s_sla,
            "overall": overall
        },
        "grade": grade_from_score(overall),

        # Dashboard expects: assets[a].overall etc.
        "assets": {a: {"owasp": v["owasp"], "epss": v["epss"], "sla": v["sla"], "overall": v["overall"]} for a, v in assets.items()},

        "weights": {
            "overall": {"owasp": W_OWASP, "epss": W_EPSS, "sla": W_SLA},
            "asset": ASSET_WEIGHTS
        },

        # Debug-friendly: can be removed later
        "explain": {
            "asset_detection": "asset:* labels preferred; fallback uses path/title/body hints",
            "owasp_source": "docs/data/owasp-latest.json if present for global; per-asset from GitHub issue labels",
            "epss_source": EPSS_FINDINGS,
            "sla_source": SLA_WEEKLY
        }
    }

    os.makedirs(os.path.dirname(OUT_SCORECARD), exist_ok=True)
    with open(OUT_SCORECARD, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)

    os.makedirs("security-metrics/weekly", exist_ok=True)
    with open("security-metrics/weekly/security-scorecard.json", "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)

    print("[OK] security scorecard generated")
    print(f" - {OUT_SCORECARD}")
    print(" - security-metrics/weekly/security-scorecard.json")

if __name__ == "__main__":
    main()
