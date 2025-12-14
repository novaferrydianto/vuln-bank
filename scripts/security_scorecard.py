#!/usr/bin/env python3
import os
import json
import datetime
from typing import Dict, Any, List

# -----------------------------
# Helpers
# -----------------------------
def utc_now_iso() -> str:
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

def safe_read_json(path: str, default: Any) -> Any:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default

def safe_write_json(path: str, obj: Any) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2)

def append_jsonl(path: str, obj: Any) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(obj) + "\n")

def clamp(v: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, v))

# -----------------------------
# Scoring model (bank-grade)
# -----------------------------
OWASP_PENALTIES = {
    # heavier penalty for A01/A02
    "A01": 15,
    "A02": 12,
    "A03": 10,
    "A04": 9,
    "A05": 8,
    "A06": 8,
    "A07": 7,
    "A08": 7,
    "A09": 6,
    "A10": 6,
}

SLA_PENALTIES = {
    "Critical": 30,
    "High": 15,
    "Medium": 7,
    "Low": 3,
}

WEIGHTS = {
    "owasp": 0.4,
    "epss": 0.4,
    "sla": 0.2,
}

def score_owasp(owasp_counts: Dict[str, int]) -> int:
    penalty = 0
    for k, c in owasp_counts.items():
        p = OWASP_PENALTIES.get(k, 5)
        penalty += int(c) * int(p)
    return int(clamp(100 - penalty, 0, 100))

def score_epss(high_risk_count: int) -> int:
    # strong penalty per high-risk EPSS/KEV finding
    return int(clamp(100 - (high_risk_count * 15), 0, 100))

def score_sla(breaches: Dict[str, int]) -> int:
    penalty = 0
    for sev, c in breaches.items():
        penalty += int(c) * int(SLA_PENALTIES.get(sev, 5))
    return int(clamp(100 - penalty, 0, 100))

def overall_score(s_owasp: int, s_epss: int, s_sla: int) -> int:
    v = (
        s_owasp * WEIGHTS["owasp"] +
        s_epss  * WEIGHTS["epss"] +
        s_sla   * WEIGHTS["sla"]
    )
    return int(round(clamp(v, 0, 100)))

def grade_from_score(score: int) -> str:
    if score >= 90: return "A"
    if score >= 80: return "B"
    if score >= 65: return "C"
    if score >= 50: return "D"
    return "F"

# -----------------------------
# Per-asset logic
# -----------------------------
DEFAULT_ASSETS = {
    "frontend": {
        "label": "asset:frontend",
        # optional: package hints if you later enrich epss-findings with package paths
        "package_hints": ["nuxt", "next", "react", "vue", "webpack", "vite"],
    },
    "backend": {
        "label": "asset:backend",
        "package_hints": ["flask", "django", "fastapi", "requests", "gunicorn"],
    },
    "db": {
        "label": "asset:db",
        "package_hints": ["postgres", "psql", "pg", "mysql", "sqlite"],
    },
}

def split_owasp_by_asset(issue_rows: List[Dict[str, Any]], assets_cfg: Dict[str, Any]) -> Dict[str, Dict[str, int]]:
    # issue_rows = [{"labels": ["OWASP:A01", "asset:backend", ...]}, ...]
    keys = [f"A{i:02}" for i in range(1, 11)]
    out = {a: {k: 0 for k in keys} for a in assets_cfg.keys()}

    for row in issue_rows:
        labels = [str(x).lower() for x in row.get("labels", [])]
        for asset, cfg in assets_cfg.items():
            if cfg["label"].lower() in labels:
                for l in labels:
                    u = l.upper()
                    if u.startswith("OWASP:A"):
                        k = u.replace("OWASP:", "")
                        if k in out[asset]:
                            out[asset][k] += 1
    return out

def split_epss_by_asset(epss_findings: Dict[str, Any], assets_cfg: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """
    Expect epss_findings.json format similar to:
      { "high_risk": [ {"cve": "...", "epss": 0.92, "package": "xz-utils", ...}, ... ] }
    If no explicit asset field exists, we infer by package keywords (best effort).
    """
    high = epss_findings.get("high_risk", []) or []
    out = {a: {"high_risk_count": 0, "top_cves": []} for a in assets_cfg.keys()}

    for item in high:
        pkg = str(item.get("package") or "").lower()
        cve = item.get("cve")
        epss = item.get("epss", 0)
        placed = False

        for asset, cfg in assets_cfg.items():
            hints = [h.lower() for h in cfg.get("package_hints", [])]
            if any(h in pkg for h in hints):
                out[asset]["high_risk_count"] += 1
                out[asset]["top_cves"].append({"cve": cve, "epss": epss, "package": item.get("package")})
                placed = True
                break

        # if we can't infer, keep unassigned (ignored) to avoid lying
        if not placed:
            pass

    # cap top_cves length
    for a in out:
        out[a]["top_cves"] = out[a]["top_cves"][:5]
    return out

def split_sla_by_asset(sla_weekly: Dict[str, Any], assets_cfg: Dict[str, Any]) -> Dict[str, Dict[str, int]]:
    """
    If your DefectDojo SLA weekly output includes components/engagement tags per asset,
    you can populate this properly later.
    For now: fallback to global breaches for every asset = 0 (safe, not misleading).
    """
    return {a: {"Critical": 0, "High": 0, "Medium": 0, "Low": 0} for a in assets_cfg.keys()}

# -----------------------------
# Main
# -----------------------------
def main():
    repo = os.environ.get("GITHUB_REPOSITORY") or os.environ.get("REPO") or "unknown/unknown"
    generated_at = utc_now_iso()

    # Inputs
    owasp_latest = safe_read_json("docs/data/owasp-latest.json", {})
    owasp_counts = (owasp_latest.get("counts") or owasp_latest.get("owasp_counts") or {}) if isinstance(owasp_latest, dict) else {}
    # normalize keys to A01..A10
    norm_owasp = {f"A{i:02}": int(owasp_counts.get(f"A{i:02}", 0)) for i in range(1, 11)}

    epss_in = safe_read_json("security-reports/epss-findings.json", safe_read_json("docs/data/epss-weekly.json", {}))
    high_risk = epss_in.get("high_risk", []) if isinstance(epss_in, dict) else []
    high_risk_count = int(len(high_risk))
    top_cves = []
    for it in (high_risk[:5] if isinstance(high_risk, list) else []):
        top_cves.append({
            "cve": it.get("cve"),
            "epss": it.get("epss"),
            "package": it.get("package"),
        })

    sla_weekly = safe_read_json("docs/data/defectdojo-sla-weekly.json", {})
    breaches = ((sla_weekly.get("breaches") or {}) if isinstance(sla_weekly, dict) else {})
    norm_breaches = {k: int(breaches.get(k, 0)) for k in ["Critical", "High", "Medium", "Low"]}

    # Scores
    s_owasp = score_owasp(norm_owasp)
    s_epss  = score_epss(high_risk_count)
    s_sla   = score_sla(norm_breaches)
    overall = overall_score(s_owasp, s_epss, s_sla)
    grade = grade_from_score(overall)

    # Per-asset (requires issue label export file; optional)
    # If you want true per-asset OWASP counts, generate docs/data/issues-labels.json in your weekly job.
    issue_rows = safe_read_json("docs/data/issues-labels.json", [])
    assets_cfg = DEFAULT_ASSETS
    owasp_by_asset = split_owasp_by_asset(issue_rows if isinstance(issue_rows, list) else [], assets_cfg)
    epss_by_asset = split_epss_by_asset(epss_in if isinstance(epss_in, dict) else {}, assets_cfg)
    sla_by_asset = split_sla_by_asset(sla_weekly if isinstance(sla_weekly, dict) else {}, assets_cfg)

    assets_scorecard = {}
    for asset in assets_cfg.keys():
        a_owasp = score_owasp(owasp_by_asset.get(asset, {}))
        a_epss  = score_epss(int(epss_by_asset.get(asset, {}).get("high_risk_count", 0)))
        a_sla   = score_sla(sla_by_asset.get(asset, {}))
        a_overall = overall_score(a_owasp, a_epss, a_sla)
        assets_scorecard[asset] = {
            "owasp": a_owasp,
            "epss": a_epss,
            "sla": a_sla,
            "overall": a_overall,
            "grade": grade_from_score(a_overall),
            "raw": {
                "owasp_counts": owasp_by_asset.get(asset, {}),
                "epss": epss_by_asset.get(asset, {"high_risk_count": 0, "top_cves": []}),
                "sla_breaches": sla_by_asset.get(asset, {}),
            }
        }

    # Output (matches your sample JSON)
    out = {
        "repo": repo,
        "generated_at": generated_at,
        "owasp": {k: v for k, v in norm_owasp.items() if v > 0},
        "epss": {
            "high_risk_count": high_risk_count,
            "top_cves": top_cves,
        },
        "sla": {
            "breaches": {k: v for k, v in norm_breaches.items() if v > 0},
        },
        "score": {
            "owasp": s_owasp,
            "epss": s_epss,
            "sla": s_sla,
            "overall": overall,
        },
        "grade": grade,
    }

    safe_write_json("docs/data/security-scorecard.json", out)
    append_jsonl("docs/data/security-scorecard-history.jsonl", out)
    safe_write_json("docs/data/security-scorecard-assets.json", {"repo": repo, "generated_at": generated_at, "assets": assets_scorecard})

    print("[OK] security scorecard generated:")
    print(" - docs/data/security-scorecard.json")
    print(" - docs/data/security-scorecard-history.jsonl")
    print(" - docs/data/security-scorecard-assets.json")

if __name__ == "__main__":
    main()
