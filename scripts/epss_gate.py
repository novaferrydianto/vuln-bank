#!/usr/bin/env python3
"""
EPSS + CISA KEV gate untuk Vuln Bank

- Input  : Trivy SCA JSON (fs scan) -> --input
- Output : epss-findings.json (dipakai job create_issues)
- Gate   : buat file 'gate_failed' di directory yang sama dengan output
           jika ada CVE HIGH/CRITICAL yang:
           - EPSS >= threshold, atau
           - termasuk dalam CISA KEV catalog
- History: append satu baris JSON per run ke epss-history.jsonl
"""

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Dict, List

import requests

EPSS_API_URL = "https://api.first.org/data/v1/epss"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="EPSS + CISA KEV gate for Trivy SCA results")
    parser.add_argument("--input", required=True, help="Trivy SCA JSON file (fs scan)")
    parser.add_argument("--output", required=True, help="Output JSON file (epss-findings.json)")
    parser.add_argument("--threshold", required=True, help="EPSS threshold (0.0–1.0)")
    return parser.parse_args()


def load_trivy_vulns(path: str) -> List[Dict]:
    """Ambil CVE HIGH/CRITICAL dari Trivy FS JSON."""
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    results = data.get("Results", [])
    vulns: List[Dict] = []

    for result in results:
        for v in result.get("Vulnerabilities", []) or []:
            severity = (v.get("Severity") or "").upper()
            if severity not in ("HIGH", "CRITICAL"):
                continue

            vulns.append(
                {
                    "cve": v.get("VulnerabilityID"),
                    "pkg_name": v.get("PkgName"),
                    "installed_version": v.get("InstalledVersion"),
                    "fixed_version": v.get("FixedVersion"),
                    "severity": severity,
                    "description": (v.get("Description") or "")[:500],
                }
            )

    return vulns


def fetch_epss_scores(cves: List[str]) -> Dict[str, float]:
    """Ambil EPSS untuk list CVE dari FIRST.org."""
    if not cves:
        return {}

    params = {"cve": ",".join(cves)}
    resp = requests.get(EPSS_API_URL, params=params, timeout=20)
    resp.raise_for_status()
    data = resp.json().get("data", [])

    scores: Dict[str, float] = {}
    for item in data:
        cve = item.get("cve")
        try:
            epss = float(item.get("epss", 0.0))
        except (TypeError, ValueError):
            epss = 0.0
        if cve:
            scores[cve] = epss

    return scores


def fetch_cisa_kev() -> Dict[str, bool]:
    """Ambil KEV catalog dari CISA -> return set-like dict {CVE: True}."""
    resp = requests.get(CISA_KEV_URL, timeout=30)
    resp.raise_for_status()
    data = resp.json()

    kev_entries = data.get("vulnerabilities", [])
    kev_map: Dict[str, bool] = {}

    for item in kev_entries:
        cve_id = item.get("cveID")
        if cve_id:
            kev_map[cve_id] = True

    return kev_map


def main() -> None:
    args = parse_args()
    threshold = float(args.threshold)

    input_path = Path(args.input)
    output_path = Path(args.output)
    out_dir = output_path.parent
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"[INFO] Loading Trivy SCA results from: {input_path}")
    vulns = load_trivy_vulns(str(input_path))

    if not vulns:
        print("[INFO] No HIGH/CRITICAL vulnerabilities from Trivy SCA.")
        empty = {"threshold": threshold, "total_high_crit_from_trivy": 0, "high_risk": []}
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(empty, f, indent=2)

        # tetap log ke history sebagai 0
        hist_path = out_dir / "epss-history.jsonl"
        with open(hist_path, "a", encoding="utf-8") as hf:
            hf.write(json.dumps({
                "timestamp": os.getenv("GITHUB_RUN_ID", ""),  # atau isi di job lain
                "total_high_crit_from_trivy": 0,
                "epss_high_count": 0,
                "kev_count": 0,
                "max_epss": 0.0,
            }) + "\n")
        return

    unique_cves = sorted({v["cve"] for v in vulns if v.get("cve")})

    print(f"[INFO] Fetching EPSS scores for {len(unique_cves)} CVEs from FIRST.org")
    try:
      epss_scores = fetch_epss_scores(unique_cves)
    except Exception as e:
      print(f"[WARN] Failed to fetch EPSS data: {e}")
      epss_scores = {}

    print("[INFO] Fetching CISA KEV catalog")
    try:
      kev_map = fetch_cisa_kev()
    except Exception as e:
      print(f"[WARN] Failed to fetch CISA KEV catalog: {e}")
      kev_map = {}

    high_risk: List[Dict] = []
    epss_high_count = 0
    kev_count = 0
    max_epss = 0.0

    for v in vulns:
        cve = v["cve"]
        epss = float(epss_scores.get(cve, 0.0))
        is_kev = kev_map.get(cve, False)

        reasons = []
        if is_kev:
            reasons.append("CISA_KEV")
        if epss >= threshold:
            reasons.append(f"EPSS>={threshold}")

        if reasons:
            entry = {
                **v,
                "epss": epss,
                "is_kev": is_kev,
                "reasons": reasons,
            }
            high_risk.append(entry)

        # stats
        if epss >= threshold:
            epss_high_count += 1
        if is_kev:
            kev_count += 1
        if epss > max_epss:
            max_epss = epss

    result = {
        "threshold": threshold,
        "total_high_crit_from_trivy": len(vulns),
        "high_risk": high_risk,
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)

    # history per run
    hist_path = out_dir / "epss-history.jsonl"
    with open(hist_path, "a", encoding="utf-8") as hf:
        hf.write(json.dumps({
            "timestamp": os.getenv("GITHUB_RUN_ID", ""),  # atau bisa kamu ganti dengan ts real di job lain
            "total_high_crit_from_trivy": len(vulns),
            "epss_high_count": epss_high_count,
            "kev_count": kev_count,
            "max_epss": max_epss,
        }) + "\n")

    # gate file untuk step 'Set gate flag'
    gate_file = out_dir / "gate_failed"

    if high_risk:
        print(
            f"[GATE] 🚨 EPSS/KEV gate FAILED – {len(high_risk)} CVEs "
            f"meeting EPSS>={threshold} and/or in CISA KEV"
        )
        gate_file.write_text("EPSS/KEV gate failed\n", encoding="utf-8")
    else:
        print("[GATE] ✅ EPSS/KEV gate PASSED – no CVE crossing threshold or in KEV")


if __name__ == "__main__":
    main()
