#!/usr/bin/env python3
"""
EPSS + CISA KEV gate for Vuln Bank (Optimized & Enhanced)

- Input  : Trivy SCA JSON (fs scan) -> --input
- Output : epss-findings.json (used by create_issues job)
- Gate   : Creates 'gate_failed' file if HIGH/CRITICAL CVEs meet criteria
- History: Appends JSON line to epss-history.jsonl
- Extras : Sort results, include EPSS percentile & CVSS (if available)
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
BATCH_SIZE = 50


# ------------------------------------------------------------
#  Argument parsing
# ------------------------------------------------------------
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="EPSS + CISA KEV gate for Trivy SCA results"
    )
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--threshold", required=True, type=float)
    return parser.parse_args()


# ------------------------------------------------------------
#  HTTP Session with Retry
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
#  Load HIGH/CRITICAL vulnerabilities from Trivy
# ------------------------------------------------------------
def load_trivy_vulns(path: str) -> List[Dict[str, Any]]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"[ERROR] Missing file: {path}")
        sys.exit(1)

    results = data.get("Results", [])
    vulns: List[Dict[str, Any]] = []

    for result in results:
        detected = result.get("Vulnerabilities") or []
        for v in detected:
            sev = (v.get("Severity") or "").upper()
            if sev not in ("HIGH", "CRITICAL"):
                continue

            cvss = None
            if v.get("CVSS", {}).get("nvd"):
                cvss = v["CVSS"]["nvd"].get("V3Score")

            vulns.append(
                {
                    "cve": v.get("VulnerabilityID"),
                    "pkg_name": v.get("PkgName"),
                    "installed_version": v.get("InstalledVersion"),
                    "fixed_version": v.get("FixedVersion") or "N/A",
                    "severity": sev,
                    "description": (v.get("Description") or "")[:500],
                    "target": result.get("Target", "Unknown"),
                    "cvss": cvss,
                }
            )

    return vulns


# ------------------------------------------------------------
#  Fetch EPSS Scores (with batching)
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
                scores[item["cve"]] = {
                    "epss": float(item.get("epss", 0.0)),
                    "percentile": float(item.get("percentile", 0.0)),
                }
        except requests.RequestException as e:
            print(f"[WARN] EPSS batch fetch error: {e}")

    return scores


# ------------------------------------------------------------
#  Fetch CISA KEV Catalog
# ------------------------------------------------------------
def fetch_cisa_kev() -> Dict[str, bool]:
    session = get_retry_session()
    try:
        resp = session.get(CISA_KEV_URL, timeout=30)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        print(f"[WARN] Using empty KEV map due to: {e}")
        return {}

    kev_map = {entry["cveID"]: True for entry in data.get("vulnerabilities", [])}
    return kev_map


# ------------------------------------------------------------
#  Append history record
# ------------------------------------------------------------
def write_history(out_dir: Path, stats: Dict[str, Any]) -> None:
    hist_path = out_dir / "epss-history.jsonl"

    stats["timestamp"] = datetime.now(timezone.utc).isoformat()
    stats["run_id"] = os.getenv("GITHUB_RUN_ID", "manual")

    try:
        with open(hist_path, "a", encoding="utf-8") as hf:
            hf.write(json.dumps(stats) + "\n")
    except Exception as e:
        print(f"[WARN] Could not write history: {e}")


# ------------------------------------------------------------
#  Main logic
# ------------------------------------------------------------
def main() -> None:
    args = parse_args()
    threshold = args.threshold

    input_path = Path(args.input)
    output_path = Path(args.output)
    out_dir = output_path.parent
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"[INFO] Loading Trivy results: {input_path}")
    vulns = load_trivy_vulns(str(input_path))

    stats = {
        "total_trivy_high_crit": len(vulns),
        "epss_above_threshold": 0,
        "kev_hits": 0,
        "max_epss": 0.0,
    }

    if not vulns:
        with open(output_path, "w") as f:
            json.dump(
                {"threshold": threshold, "total_trivy_high_crit": 0, "high_risk": []},
                f,
                indent=2,
            )
        write_history(out_dir, stats)
        print("[GATE] ✅ PASSED – No vulnerabilities")
        return

    unique_cves = sorted({v["cve"] for v in vulns})
    epss_scores = fetch_epss_scores(unique_cves)
    kev_map = fetch_cisa_kev()

    high_risk = []

    for v in vulns:
        cve = v["cve"]
        epss_pack = epss_scores.get(cve, {"epss": 0.0, "percentile": 0.0})
        epss = epss_pack["epss"]
        percentile = epss_pack["percentile"]
        is_kev = kev_map.get(cve, False)

        reasons = []
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

    # Sort: highest EPS score first
    high_risk.sort(key=lambda x: x["epss"], reverse=True)

    result = {
        "threshold": threshold,
        "total_trivy_high_crit": len(vulns),
        "high_risk": high_risk,
    }

    with open(output_path, "w") as f:
        json.dump(result, f, indent=2)

    write_history(out_dir, stats)

    gate_file = out_dir / "gate_failed"
    if high_risk:
        gate_file.write_text("EPSS/KEV gate failed\n")
        print(
            f"[GATE] 🚨 FAILED – {len(high_risk)} risks (EPSS ≥ {threshold} or KEV)"
        )
    else:
        print("[GATE] ✅ PASSED – No critical EPSS/KEV matches")


if __name__ == "__main__":
    main()
