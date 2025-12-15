#!/usr/bin/env python3
"""
EPSS + CISA KEV gate for Vuln Bank (Optimized & Enhanced)

Features:
- EPSS score and percentile from FIRST.org API
- CISA KEV flag
- CVSS v3 extraction (auto-detect multiple vendors)
- Sort results by highest EPSS
- Gate file creation when risk found
- Historical trend tracking (epss-history.jsonl)
- Dashboard-compatible schema
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any, Optional

import requests
from requests.adapters import HTTPAdapter, Retry


EPSS_API_URL = "https://api.first.org/data/v1/epss"
CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
BATCH_SIZE = 50


# ------------------------------------------------------------
# Argument parsing
# ------------------------------------------------------------
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="EPSS/KEV gate for Trivy SCA results")
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--threshold", required=True, type=float)
    return parser.parse_args()


# ------------------------------------------------------------
# HTTP Session with retry logic
# ------------------------------------------------------------
def get_retry_session() -> requests.Session:
    session = requests.Session()
    retries = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[500, 502, 503, 504],
    )
    session.mount("https://", HTTPAdapter(max_retries=retries))
    return session


# ------------------------------------------------------------
# CVSS extraction helper (Python 3.8 safe)
# ------------------------------------------------------------
def extract_cvss(vuln: Dict[str, Any]) -> Optional[float]:
    cvss_data = vuln.get("CVSS")
    if not isinstance(cvss_data, dict):
        return None

    preferred_sources = ["nvd", "redhat", "github", "ghsa", "vendor"]

    for src in preferred_sources:
        source_data = cvss_data.get(src)
        if isinstance(source_data, dict):
            score = source_data.get("V3Score")
            try:
                return float(score) if score is not None else None
            except (TypeError, ValueError):
                continue

    return None


# ------------------------------------------------------------
# Load Trivy vulnerabilities
# ------------------------------------------------------------
def load_trivy_vulns(path: str) -> List[Dict[str, Any]]:
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        print(f"[ERROR] Cannot read Trivy output: {path}")
        sys.exit(1)

    vulns: List[Dict[str, Any]] = []

    for result in data.get("Results", []):
        detected = result.get("Vulnerabilities") or []

        for v in detected:
            sev = (v.get("Severity") or "").upper()
            if sev not in ("HIGH", "CRITICAL"):
                continue

            vulns.append(
                {
                    "cve": v.get("VulnerabilityID"),
                    "pkg_name": v.get("PkgName"),
                    "installed_version": v.get("InstalledVersion"),
                    "fixed_version": v.get("FixedVersion") or "N/A",
                    "severity": sev,
                    "description": (v.get("Description") or "")[:500],
                    "target": result.get("Target", "Unknown"),
                    "cvss": extract_cvss(v),
                }
            )

    return vulns


# ------------------------------------------------------------
# Fetch EPSS scores
# ------------------------------------------------------------
def fetch_epss_scores(cves: List[str]) -> Dict[str, Dict[str, float]]:
    if not cves:
        return {}

    session = get_retry_session()
    scores: Dict[str, Dict[str, float]] = {}

    for i in range(0, len(cves), BATCH_SIZE):
        batch = cves[i : i + BATCH_SIZE]
        params = {"cve": ",".join(batch)}

        try:
            resp = session.get(EPSS_API_URL, params=params, timeout=20)
            resp.raise_for_status()

            for item in resp.json().get("data", []):
                cve = item["cve"]
                scores[cve] = {
                    "epss": float(item.get("epss", 0.0)),
                    "percentile": float(item.get("percentile", 0.0)),
                }
        except Exception as e:
            print(f"[WARN] EPSS fetch error for batch {batch}: {e}")

    return scores


# ------------------------------------------------------------
# Fetch CISA KEV
# ------------------------------------------------------------
def fetch_cisa_kev() -> Dict[str, bool]:
    session = get_retry_session()

    try:
        resp = session.get(CISA_KEV_URL, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        return {entry["cveID"]: True for entry in data.get("vulnerabilities", [])}
    except Exception as e:
        print(f"[WARN] KEV fetch failed: {e}")
        return {}


# ------------------------------------------------------------
# History tracking
# ------------------------------------------------------------
def write_history(out_dir: Path, stats: Dict[str, Any]) -> None:
    hist = out_dir / "epss-history.jsonl"
    stats["timestamp"] = datetime.now(timezone.utc).isoformat()
    stats["run_id"] = os.getenv("GITHUB_RUN_ID", "manual")

    try:
        with open(hist, "a", encoding="utf-8") as f:
            f.write(json.dumps(stats) + "\n")
    except Exception as e:
        print(f"[WARN] History write failed: {e}")


# ------------------------------------------------------------
# Main logic
# ------------------------------------------------------------
def main():
    args = parse_args()
    threshold = float(args.threshold)

    input_path = Path(args.input)
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    print(f"[INFO] Loading Trivy SCA: {input_path}")
    vulns = load_trivy_vulns(str(input_path))

    stats = {
        "total_trivy_high_crit": len(vulns),
        "epss_above_threshold": 0,
        "kev_hits": 0,
        "max_epss": 0.0,
    }

    if not vulns:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(
                {"threshold": threshold, "total_trivy_high_crit": 0, "high_risk": []},
                f,
                indent=2,
            )
        write_history(output_path.parent, stats)
        print("[GATE] ✅ PASSED (No vulnerabilities)")
        return

    unique_cves = sorted({v["cve"] for v in vulns})
    epss_scores = fetch_epss_scores(unique_cves)
    kev_map = fetch_cisa_kev()

    high_risk: List[Dict[str, Any]] = []

    for v in vulns:
        cve = v["cve"]
        epss_pack = epss_scores.get(cve, {"epss": 0.0, "percentile": 0.0})
        epss = epss_pack["epss"]
        percentile = epss_pack["percentile"]
        is_kev = kev_map.get(cve, False)

        reasons: List[str] = []

        if epss >= threshold:
            reasons.append(f"EPSS>={threshold}")
            stats["epss_above_threshold"] += 1

        if is_kev:
            reasons.append("CISA_KEV")
            stats["kev_hits"] += 1

        stats["max_epss"] = max(stats["max_epss"], epss)

        if reasons:
            high_risk.append(
                {
                    **v,
                    "epss": epss,
                    "percentile": percentile,
                    "is_kev": is_kev,
                    "reasons": reasons,
                }
            )

    high_risk.sort(key=lambda x: x["epss"], reverse=True)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(
            {
                "threshold": threshold,
                "total_trivy_high_crit": len(vulns),
                "high_risk": high_risk,
            },
            f,
            indent=2,
        )

    write_history(output_path.parent, stats)

    gate_file = output_path.parent / "gate_failed"

    if high_risk:
        gate_file.write_text("Gate failed\n", encoding="utf-8")
        print(f"[GATE] 🚨 FAILED – {len(high_risk)} risk findings")
    else:
        print("[GATE] ✅ PASSED")


if __name__ == "__main__":
    main()
