#!/usr/bin/env python3
"""
Slack Notification – Governance Enriched (Enterprise)

Signals:
- Gate decision
- ASVS PASS% + delta
- Failed ASVS controls (top-N)
- ASCII sparkline fallback
- EPSS / KEV high-risk correlation (+ KEV weekly trend)
- ZAP severity summary
- ASVS family summary (V1–V14 counts)

Design goals:
- Explainable security decision
- Executive-readable
- PR & main safe
"""

import json
import os
from pathlib import Path
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

# --------------------------------------------------
# Environment
# --------------------------------------------------
SLACK_WEBHOOK = os.getenv("SLACK_WEBHOOK_URL")
REPO = os.getenv("GITHUB_REPOSITORY", "unknown")
RUN_ID = os.getenv("GITHUB_RUN_ID", os.getenv("GITHUB_RUN_ID", "manual"))
PR = os.getenv("PR_NUMBER")  # optional

BASE = Path("security-reports")

ASVS_LABELS = BASE / "governance/asvs-labels.json"
ASVS_COVERAGE = BASE / "governance/asvs-coverage.json"

# Pages trend data (should be written ONLY on main by a dedicated job)
PASS_TREND = Path("security-metrics/weekly/pass-trend.json")

# NEW: KEV trend (weekly). Expected shape:
# { "points":[ {"week":"2025-W50","kev_count":2}, ... ] }
KEV_TREND = Path("security-metrics/weekly/kev-trend.json")

EPSS = BASE / "epss-findings.json"
ZAP = BASE / "zap/zap_alerts.json"
GATE = BASE / "gate_failed"

# Tune these if desired
TOP_FAILED_ASVS = int(os.getenv("TOP_FAILED_ASVS", "6"))
PASS_TREND_WINDOW = int(os.getenv("PASS_TREND_WINDOW", "10"))
KEV_TREND_WINDOW = int(os.getenv("KEV_TREND_WINDOW", "10"))

# --------------------------------------------------
# Helpers
# --------------------------------------------------
def load_json(path: Path, default=None) -> Any:
    try:
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"[WARN] Failed to load {path}: {e}")
    return default if default is not None else {}

def safe_float(v: Any, default: float = 0.0) -> float:
    try:
        return float(v)
    except Exception:
        return default

def ascii_sparkline(values: List[float]) -> str:
    """Compact sparkline using unicode blocks (safe for Slack text)."""
    if not values:
        return "n/a"
    blocks = "▁▂▃▄▅▆▇█"
    mn, mx = min(values), max(values)
    if mx == mn:
        return blocks[4] * len(values)
    out = []
    for v in values:
        idx = int((v - mn) / (mx - mn) * (len(blocks) - 1))
        idx = max(0, min(len(blocks) - 1, idx))
        out.append(blocks[idx])
    return "".join(out)

def fmt_delta(delta: Optional[float]) -> str:
    if delta is None:
        return "n/a"
    if delta > 0:
        return f"▲ +{delta:.2f}%"
    if delta < 0:
        return f"▼ {delta:.2f}%"
    return "– 0.00%"

# --------------------------------------------------
# ASVS helpers
# --------------------------------------------------
def load_failed_asvs(limit: int = TOP_FAILED_ASVS) -> List[Dict[str, Any]]:
    data = load_json(ASVS_COVERAGE, {})
    controls = data.get("controls", []) or []
    failed = [c for c in controls if c.get("status") == "FAIL"]
    # best-effort stable ordering: by id
    failed.sort(key=lambda x: str(x.get("id", "")))
    return failed[:limit]

def load_pass_metrics() -> Tuple[Optional[float], Optional[float], str]:
    """
    Returns:
      (current_pass_percent_from_coverage, delta_from_trend, sparkline_from_trend)
    """
    coverage = load_json(ASVS_COVERAGE, {})
    summary = coverage.get("summary", {}) or {}
    current_pass_pct = summary.get("pass_percent")

    trend_doc = load_json(PASS_TREND, {})
    points = trend_doc.get("points", []) or []
    # normalize to floats
    series = [safe_float(p.get("pass_percent")) for p in points if "pass_percent" in p]
    series_tail = series[-PASS_TREND_WINDOW:]

    delta = None
    if len(series) >= 2:
        delta = round(series[-1] - series[-2], 2)

    spark = ascii_sparkline(series_tail)
    return current_pass_pct, delta, spark

def asvs_family_summary() -> List[Tuple[str, int, int]]:
    """
    Returns list of tuples: [(family, pass_count, total_count), ...]
    Covers V1..V14 if present.
    """
    data = load_json(ASVS_COVERAGE, {})
    controls = data.get("controls", []) or []

    fam: Dict[str, Dict[str, int]] = {}
    for c in controls:
        cid = str(c.get("id", ""))
        family = cid.split(".")[0] if cid else ""
        if not (family.startswith("V") and family[1:].isdigit()):
            continue

        fam.setdefault(family, {"pass": 0, "total": 0})
        fam[family]["total"] += 1
        if c.get("status") == "PASS":
            fam[family]["pass"] += 1

    # Sort V1..V14 numerically where possible
    def fam_key(k: str) -> int:
        try:
            return int(k[1:])
        except Exception:
            return 999

    out = [(k, v["pass"], v["total"]) for k, v in fam.items()]
    out.sort(key=lambda x: fam_key(x[0]))
    return out

# --------------------------------------------------
# KEV helpers
# --------------------------------------------------
def load_kev_trend() -> Tuple[int, str]:
    """
    Returns:
      (latest_kev_count, kev_sparkline)
    """
    trend_doc = load_json(KEV_TREND, {})
    points = trend_doc.get("points", []) or []
    series = [int(p.get("kev_count", 0) or 0) for p in points]
    series_tail = series[-KEV_TREND_WINDOW:]
    latest = series[-1] if series else 0
    # sparkline expects floats; ints are fine
    spark = ascii_sparkline([float(x) for x in series_tail])
    return latest, spark

# --------------------------------------------------
# Main
# --------------------------------------------------
def main():
    if not SLACK_WEBHOOK:
        print("[SKIP] SLACK_WEBHOOK_URL not set")
        return

    asvs_labels = load_json(ASVS_LABELS, {})
    epss = load_json(EPSS, {})
    zap = load_json(ZAP, {})

    risk_labels = set(asvs_labels.get("risk_labels", []) or [])
    owasp_labels = set(asvs_labels.get("owasp_labels", []) or [])
    asvs_delta = asvs_labels.get("asvs_delta", []) or []

    # --------------------------------------------------
    # EPSS / KEV summary
    # --------------------------------------------------
    high_risk = epss.get("high_risk", []) or []
    epss_max = max((safe_float(v.get("epss", 0)) for v in high_risk), default=0.0)
    kev_count_in_highrisk = sum(1 for v in high_risk if bool(v.get("kev")))

    kev_latest, kev_spark = load_kev_trend()

    # --------------------------------------------------
    # ZAP summary
    # --------------------------------------------------
    zap_high = 0
    zap_counts: Dict[str, int] = {}

    for site in zap.get("site", []) or []:
        for alert in site.get("alerts", []) or []:
            risk = alert.get("riskdesc") or alert.get("risk") or "Unknown"
            zap_counts[risk] = zap_counts.get(risk, 0) + 1
            if str(alert.get("riskcode")) == "3":
                zap_high += 1

    # --------------------------------------------------
    # Decision logic
    # --------------------------------------------------
    gate_failed = GATE.exists()
    high_risk_flag = "risk:high" in risk_labels
    medium_risk_flag = "risk:medium" in risk_labels

    incident = any(
        str(o).startswith("OWASP-A01") or str(o).startswith("OWASP-A02")
        for o in owasp_labels
    )

    should_notify = (
        gate_failed
        or incident
        or high_risk_flag
        or epss_max >= 0.5
        or zap_high > 0
        or len(asvs_delta) > 0
        or kev_count_in_highrisk > 0
        or kev_latest > 0
    )

    if not should_notify:
        print("[OK] No Slack notification required")
        return

    # --------------------------------------------------
    # Headline
    # --------------------------------------------------
    if gate_failed or incident:
        headline = "🚨 *SECURITY INCIDENT DETECTED*"
    elif high_risk_flag:
        headline = "🔴 *HIGH SECURITY RISK DETECTED*"
    elif medium_risk_flag:
        headline = "🟠 *MEDIUM SECURITY RISK DETECTED*"
    else:
        headline = "⚠️ *SECURITY SIGNAL DETECTED*"

    lines: List[str] = [
        headline,
        f"*Repository:* `{REPO}`",
        f"*Run ID:* `{RUN_ID}`",
    ]
    if PR:
        lines.append(f"*PR:* `#{PR}`")

    lines.append("")

    # --------------------------------------------------
    # PASS% + trend
    # --------------------------------------------------
    pass_pct, pass_delta, pass_spark = load_pass_metrics()
    if pass_pct is not None:
        lines.extend([
            "*ASVS PASS%:*",
            f"• Current: `{pass_pct}%` ({fmt_delta(pass_delta)})",
            f"• Trend: `{pass_spark}`",
        ])
    else:
        lines.extend([
            "*ASVS PASS%:*",
            "• Current: `n/a`",
            f"• Trend: `{pass_spark}`",
        ])

    # --------------------------------------------------
    # ASVS family summary (V1–V14)
    # --------------------------------------------------
    fam = asvs_family_summary()
    if fam:
        lines.append("")
        lines.append("*ASVS Family Coverage (PASS/TOTAL):*")
        # Keep it executive-readable; show up to 14 families if present
        for family, p, t in fam[:14]:
            lines.append(f"• `{family}`: `{p}/{t}`")

    # --------------------------------------------------
    # Failed ASVS controls (top-N)
    # --------------------------------------------------
    failed = load_failed_asvs()
    if failed:
        lines.append("")
        lines.append(f"*❌ Failed ASVS Controls (top {len(failed)}):*")
        for c in failed:
            cid = c.get("id", "unknown")
            lvl = c.get("level", "n/a")
            title = c.get("title", "").strip()
            if title:
                lines.append(f"• `{cid}` ({lvl}) – {title}")
            else:
                lines.append(f"• `{cid}` ({lvl})")

    # --------------------------------------------------
    # OWASP impact
    # --------------------------------------------------
    if owasp_labels:
        lines.append("")
        lines.append("*OWASP Top 10 Impact:*")
        for o in sorted(owasp_labels):
            lines.append(f"• `{o}`")

    # --------------------------------------------------
    # EPSS / KEV correlation + KEV trend
    # --------------------------------------------------
    if high_risk or kev_latest > 0:
        lines.append("")
        lines.append(f"*EPSS/KEV:* EPSS max `{epss_max:.2f}` | KEV-in-highrisk `{kev_count_in_highrisk}`")
        lines.append(f"*KEV Weekly Trend:* `{kev_spark}` (latest `{kev_latest}`)")
        for v in high_risk[:3]:
            cve = v.get("cve", "n/a")
            e = safe_float(v.get("epss", 0))
            kev = "KEV" if v.get("kev") else "non-KEV"
            lines.append(f"• `{cve}` | EPSS `{e:.2f}` | `{kev}`")

    # --------------------------------------------------
    # ZAP summary
    # --------------------------------------------------
    if zap_counts:
        lines.append("")
        lines.append("*ZAP Alerts (by severity):*")
        # Stable, readable ordering
        for k in sorted(zap_counts.keys()):
            lines.append(f"• {k}: `{zap_counts[k]}`")

    # --------------------------------------------------
    # Send Slack
    # --------------------------------------------------
    payload = {"text": "\n".join(lines)}

    req = urllib.request.Request(
        SLACK_WEBHOOK,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    urllib.request.urlopen(req, timeout=10)
    print("[OK] Slack notification sent")


if __name__ == "__main__":
    main()
