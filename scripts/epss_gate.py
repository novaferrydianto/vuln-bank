#!/usr/bin/env python3
"""
EPSS + CISA KEV gate for Vuln Bank (Optimized)

- Input  : Trivy SCA JSON (fs scan) -> --input
- Output : epss-findings.json (used by create_issues job)
- Gate   : Creates 'gate_failed' file if HIGH/CRITICAL CVEs met criteria
- History: Appends JSON line to epss-history.jsonl
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any

import requests
from requests.adapters import HTTPAdapter, Retry

EPSS_API_URL = "https://api.first.org/data/v1/epss"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
BATCH_SIZE = 50  # Batch size to prevent HTTP 414 (URI Too Long)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="EPSS + CISA KEV gate for Trivy SCA results"
    )
    parser.add_argument("--input", required=True, help="Trivy SCA JSON file (fs scan)")
    parser.add_argument(
        "--output", required=True, help="Output JSON file (epss-findings.json)"
    )
    parser.add_argument(
        "--threshold", required=True, type=float, help="EPSS threshold (0.0–1.0)"
    )
    return parser.parse_args()


def get_retry_session() -> requests.Session:
    """Creates a requests session with retry logic."""
    session = requests.Session()
    retries = Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
    session.mount("https://", HTTPAdapter(max_retries=retries))
    return session


def load_trivy_vulns(path: str) -> List[Dict[str, Any]]:
    """Extract HIGH/CRITICAL CVEs from Trivy FS JSON."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"[ERROR] Input file not found: {path}")
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"[ERROR] Invalid JSON in input file: {path}")
        sys.exit(1)

    results = data.get("Results", [])
    vulns: List[Dict[str, Any]] = []

    for result in results:
        detected_vulns = result.get("Vulnerabilities")
        if not detected_vulns:
            continue

        for v in detected_vulns:
            severity = (v.get("Severity") or "").upper()
            if severity not in ("HIGH", "CRITICAL"):
                continue

            vulns.append(
                {
                    "cve": v.get("VulnerabilityID"),
                    "pkg_name": v.get("PkgName"),
                    "installed_version": v.get("InstalledVersion"),
                    "fixed_version": v.get("FixedVersion", "N/A"),
                    "severity": severity,
                    "description": (v.get("Description") or "")[:500],
                    "target": result.get("Target", "Unknown"),
                }
            )

    return vulns


def fetch_epss_scores(cves: List[str]) -> Dict[str, float]:
    """Fetch EPSS for list of CVEs from FIRST.org using batching."""
    if not cves:
        return {}

    scores: Dict[str, float] = {}
    session = get_retry_session()

    for i in range(0, len(cves), BATCH_SIZE):
        batch = cves[i : i + BATCH_SIZE]
        params = {"cve": ",".join(batch)}

        try:
            resp = session.get(EPSS_API_URL, params=params, timeout=20)
            resp.raise_for_status()
            data = resp.json().get("data", [])

            for item in data:
                cve = item.get("cve")
                try:
                    epss = float(item.get("epss", 0.0))
                except (TypeError, ValueError):
                    epss = 0.0
                if cve:
                    scores[cve] = epss

        except requests.RequestException as e:
            print(f"[WARN] Failed to fetch EPSS batch {i}: {e}")

    return scores


def fetch_cisa_kev() -> Dict[str, bool]:
    """Fetch KEV catalog from CISA -> return set-like dict {CVE: True}."""
    session = get_retry_session()
    try:
        resp = session.get(CISA_KEV_URL, timeout=30)
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException as e:
        print(f"[WARN] Failed to fetch CISA KEV catalog: {e}")
        return {}

    kev_entries = data.get("vulnerabilities", [])
    kev_map: Dict[str, bool] = {}

    for item in kev_entries:
        cve_id = item.get("cveID")
        if cve_id:
            kev_map[cve_id] = True

    return kev_map


def write_history(out_dir: Path, stats: Dict[str, Any]) -> None:
    """Appends a stats record to the history file."""
    hist_path = out_dir / "epss-history.jsonl"

    stats["timestamp"] = datetime.now(timezone.utc).isoformat()
    stats["run_id"] = os.getenv("GITHUB_RUN_ID", "manual")

    try:
        with open(hist_path, "a", encoding="utf-8") as hf:
            hf.write(json.dumps(stats) + "\n")
    except IOError as e:
        print(f"[WARN] Could not write history: {e}")


def main() -> None:
    args = parse_args()
    threshold = args.threshold

    input_path = Path(args.input)
    output_path = Path(args.output)
    out_dir = output_path.parent
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"[INFO] Loading Trivy SCA results from: {input_path}")
    vulns = load_trivy_vulns(str(input_path))

    stats = {
        "total_high_crit_from_trivy": len(vulns),
        "epss_high_count": 0,
        "kev_count": 0,
        "max_epss": 0.0,
    }

    if not vulns:
        print("[INFO] No HIGH/CRITICAL vulnerabilities from Trivy SCA.")
        empty_output = {
            "threshold": threshold,
            "total_high_crit_from_trivy": 0,
            "high_risk": [],
        }
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(empty_output, f, indent=2)

        write_history(out_dir, stats)
        print("[GATE] ✅ EPSS/KEV gate PASSED (Clean scan)")
        return

    unique_cves = sorted({v["cve"] for v in vulns if v.get("cve")})

    print(f"[INFO] Fetching EPSS scores for {len(unique_cves)} unique CVEs...")
    epss_scores = fetch_epss_scores(unique_cves)

    print("[INFO] Fetching CISA KEV catalog...")
    kev_map = fetch_cisa_kev()

    high_risk: List[Dict[str, Any]] = []

    max_epss = 0.0
    epss_breach_count = 0
    kev_breach_count = 0

    for v in vulns:
        cve = v["cve"]
        epss_raw = epss_scores.get(cve)
        epss = float(epss_raw) if epss_raw is not None else 0.0
        is_kev = kev_map.get(cve, False)

        reasons = []
        if is_kev:
            reasons.append("CISA_KEV")
        if epss >= threshold:
            reasons.append(f"EPSS>={threshold}")

        if epss > max_epss:
            max_epss = epss
        if is_kev:
            kev_breach_count += 1
        if epss >= threshold:
            epss_breach_count += 1

        if reasons:
            entry = {
                **v,
                "epss": epss,
                "is_kev": is_kev,
                "reasons": reasons,
            }
            high_risk.append(entry)

    result = {
        "threshold": threshold,
        "total_high_crit_from_trivy": len(vulns),
        "high_risk": high_risk,
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)

    stats.update(
        {
            "epss_high_count": epss_breach_count,
            "kev_count": kev_breach_count,
            "max_epss": max_epss,
        }
    )
    write_history(out_dir, stats)

    gate_file = out_dir / "gate_failed"

    try:
        gate_file.unlink()
    except OSError:
        pass

    if high_risk:
        print(
            f"[GATE] 🚨 EPSS/KEV gate FAILED – {len(high_risk)} findings "
            f"met criteria (EPSS>={threshold} or CISA KEV)"
        )
        gate_file.write_text(
            f"Gate failed: {len(high_risk)} risks found\n",
            encoding="utf-8",
        )
    else:
        print("[GATE] ✅ EPSS/KEV gate PASSED – no prioritization criteria met")


if __name__ == "__main__":
    main()
