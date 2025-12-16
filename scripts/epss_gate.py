#!/usr/bin/env python3
import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional

import requests
from requests.adapters import HTTPAdapter, Retry

EPSS_API_URL = "https://api.first.org/data/v1/epss"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
BATCH_SIZE = 50


# -----------------------------
# Args
# -----------------------------
def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--input", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--threshold", type=float, required=True)
    return p.parse_args()


# -----------------------------
# HTTP session
# -----------------------------
def session():
    s = requests.Session()
    retries = Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
    s.mount("https://", HTTPAdapter(max_retries=retries))
    return s


# -----------------------------
# CVSS extractor (py38 safe)
# -----------------------------
def extract_cvss(v: Dict[str, Any]) -> Optional[float]:
    cvss = v.get("CVSS")
    if not isinstance(cvss, dict):
        return None
    for src in ("nvd", "redhat", "github", "ghsa", "vendor"):
        s = cvss.get(src)
        if isinstance(s, dict) and s.get("V3Score") is not None:
            try:
                return float(s["V3Score"])
            except Exception:
                pass
    return None


# -----------------------------
# Load Trivy HIGH/CRITICAL
# -----------------------------
def load_trivy(path: Path) -> List[Dict[str, Any]]:
    data = json.loads(path.read_text())
    vulns = []

    for r in data.get("Results", []):
        for v in r.get("Vulnerabilities") or []:
            sev = (v.get("Severity") or "").upper()
            if sev not in ("HIGH", "CRITICAL"):
                continue

            vulns.append(
                {
                    "cve": v.get("VulnerabilityID"),
                    "pkg_name": v.get("PkgName"),
                    "severity": sev,
                    "installed_version": v.get("InstalledVersion"),
                    "fixed_version": v.get("FixedVersion") or "N/A",
                    "cvss": extract_cvss(v),
                }
            )
    return vulns


# -----------------------------
# EPSS
# -----------------------------
def fetch_epss(cves: List[str]) -> Dict[str, Dict[str, float]]:
    s = session()
    out = {}

    for i in range(0, len(cves), BATCH_SIZE):
        batch = ",".join(cves[i : i + BATCH_SIZE])
        try:
            r = s.get(EPSS_API_URL, params={"cve": batch}, timeout=20)
            r.raise_for_status()
            for d in r.json().get("data", []):
                out[d["cve"]] = {
                    "epss": float(d.get("epss", 0)),
                    "percentile": float(d.get("percentile", 0)),
                }
        except Exception as e:
            print(f"[WARN] EPSS fetch failed: {e}")
    return out


# -----------------------------
# CISA KEV
# -----------------------------
def fetch_kev() -> Dict[str, bool]:
    try:
        r = session().get(CISA_KEV_URL, timeout=30)
        r.raise_for_status()
        return {v["cveID"]: True for v in r.json().get("vulnerabilities", [])}
    except Exception:
        return {}


# -----------------------------
# Main
# -----------------------------
def main():
    args = parse_args()
    threshold = args.threshold

    input_path = Path(args.input)
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    vulns = load_trivy(input_path)
    total = len(vulns)

    if not vulns:
        output_path.write_text(
            json.dumps(
                {
                    "threshold": threshold,
                    "total_trivy_high_crit": 0,
                    "ignored_high_crit": 0,
                    "rollup": {
                        "portfolio_score_0_100": 0,
                        "weighted_risk_sum": 0,
                        "weighted_risk_max": 0,
                        "epss_above_threshold": 0,
                        "kev_hits": 0,
                    },
                    "high_risk": [],
                    "all_findings": [],
                },
                indent=2,
            )
        )
        print("[GATE] ✅ PASSED (no vulnerabilities)")
        return

    epss_map = fetch_epss(sorted({v["cve"] for v in vulns}))
    kev_map = fetch_kev()

    high_risk = []
    all_findings = []
    weighted_sum = 0.0
    weighted_max = 0.0
    kev_hits = 0

    for v in vulns:
        epss = epss_map.get(v["cve"], {}).get("epss", 0.0)
        percentile = epss_map.get(v["cve"], {}).get("percentile", 0.0)
        cvss = v.get("cvss") or 0.0
        weighted = round(cvss * epss, 3)
        is_kev = kev_map.get(v["cve"], False)

        decision = "IGNORE_LOW_EPSS"
        reasons = []

        if epss >= threshold:
            decision = "BLOCK"
            reasons.append(f"EPSS>={threshold}")

        if is_kev:
            decision = "BLOCK"
            reasons.append("CISA_KEV")
            kev_hits += 1

        all_findings.append(
            {
                **v,
                "epss": epss,
                "percentile": percentile,
                "weighted_risk": weighted,
                "decision": decision,
            }
        )

        if decision == "BLOCK":
            weighted_sum += weighted
            weighted_max = max(weighted_max, weighted)
            high_risk.append(
                {
                    **v,
                    "epss": epss,
                    "percentile": percentile,
                    "weighted_risk": weighted,
                    "is_kev": is_kev,
                    "reasons": reasons,
                }
            )

    ignored = total - len(high_risk)
    portfolio_score = min(100, int(weighted_sum * 10))

    result = {
        "threshold": threshold,
        "total_trivy_high_crit": total,
        "ignored_high_crit": ignored,
        "rollup": {
            "portfolio_score_0_100": portfolio_score,
            "weighted_risk_sum": round(weighted_sum, 3),
            "weighted_risk_max": round(weighted_max, 3),
            "epss_above_threshold": len(high_risk),
            "kev_hits": kev_hits,
        },
        "high_risk": sorted(high_risk, key=lambda x: x["weighted_risk"], reverse=True),
        "all_findings": all_findings,
    }

    output_path.write_text(json.dumps(result, indent=2))

    if high_risk:
        (output_path.parent / "gate_failed").write_text("failed\n")
        print(f"[GATE] 🚨 FAILED ({len(high_risk)} risks)")
    else:
        print("[GATE] ✅ PASSED")


if __name__ == "__main__":
    main()
