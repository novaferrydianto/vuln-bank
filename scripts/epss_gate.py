#!/usr/bin/env python3
"""
EPSS + KEV Gate Evaluator (Refactored, Low-Complexity)

Modes:
  A = Strict (fail if any EPSS >= threshold or KEV)
  B = Weighted (compute risk score only, do not fail)
  C = Hybrid (strict fail AND weighted score)
"""

import json
import os
import sys
import argparse
from typing import List, Dict, Any
import urllib.request
import urllib.error


# =========================================================
# Helpers: File + HTTP
# =========================================================

def load_json(path: str) -> dict:
    if not os.path.exists(path):
        return {}
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return {}


def fetch_json(url: str) -> dict:
    try:
        with urllib.request.urlopen(url, timeout=10) as r:
            return json.loads(r.read().decode("utf-8"))
    except Exception:
        return {}


# =========================================================
# Extract CVEs from input scanners
# =========================================================

def collect_cves_from_inputs(files: List[str]) -> List[Dict[str, Any]]:
    """Flatten inputs → list of {cve, severity, pkg...} items."""
    results = []
    for path in files:
        data = load_json(path)
        if "Results" in data:  # Trivy SCA
            for res in data.get("Results", []):
                for vuln in res.get("Vulnerabilities", []):
                    results.append({
                        "cve": vuln.get("VulnerabilityID"),
                        "severity": vuln.get("Severity", "UNKNOWN"),
                        "pkg_name": vuln.get("PkgName"),
                        "installed_version": vuln.get("InstalledVersion"),
                        "fixed_version": vuln.get("FixedVersion", "N/A"),
                    })
        elif "vulnerabilities" in data:  # Snyk SCA
            for vuln in data.get("vulnerabilities", []):
                results.append({
                    "cve": vuln.get("id"),
                    "severity": vuln.get("severity", "UNKNOWN"),
                    "pkg_name": vuln.get("packageName"),
                    "installed_version": vuln.get("version"),
                    "fixed_version": vuln.get("fixedIn", ["N/A"])[0],
                })
    return [v for v in results if v.get("cve")]


# =========================================================
# EPSS + KEV Data Fetch
# =========================================================

def enrich_epss(cves: List[str]) -> Dict[str, Dict[str, Any]]:
    """Query FIRST EPSS v2 bulk API."""
    if not cves:
        return {}

    url = "https://api.first.org/data/v1/epss?cve=" + ",".join(cves)
    data = fetch_json(url).get("data", {})
    return {k: v for k, v in data.items()}


def load_kev() -> set:
    kev_feed = fetch_json("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
    items = kev_feed.get("vulnerabilities", [])
    return {v.get("cveID") for v in items if v.get("cveID")}


# =========================================================
# Risk Evaluation
# =========================================================

def evaluate_item(v: Dict[str, Any], epss: Dict[str, Any], kev: set) -> Dict[str, Any]:
    cve = v["cve"]
    epss_data = epss.get(cve, {})
    epss_score = round(float(epss_data.get("epss", 0)), 4)
    epss_pct = round(float(epss_data.get("percentile", 0)), 4)
    is_kev = cve in kev

    return {
        **v,
        "epss": epss_score,
        "percentile": epss_pct,
        "is_kev": is_kev,
    }


def compute_risk_score(item: Dict[str, Any]) -> float:
    # Weight formula: severity + EPSS + KEV
    sev = item.get("severity", "").upper()
    sev_w = {
        "CRITICAL": 0.45,
        "HIGH": 0.35,
        "MEDIUM": 0.20,
        "LOW": 0.10,
    }.get(sev, 0.10)

    epss_w = item["epss"] * 0.35
    kev_w = 0.20 if item["is_kev"] else 0.0
    return round(sev_w + epss_w + kev_w, 4)


# =========================================================
# Mode Logic (A / B / C)
# =========================================================

def filter_high_risk(items: List[Dict[str, Any]], thr: float) -> List[Dict[str, Any]]:
    return [i for i in items if i["epss"] >= thr or i["is_kev"]]


def should_fail(mode: str, high_risk: List[Dict[str, Any]]) -> bool:
    if mode == "A":   # Strict
        return len(high_risk) > 0
    if mode == "C":   # Hybrid
        return len(high_risk) > 0
    return False       # Mode B never fails


# =========================================================
# Main EPSS Gate Flow
# =========================================================

def run_gate(mode: str, input_files: List[str], output_path: str, threshold: float) -> int:
    findings = collect_cves_from_inputs(input_files)
    if not findings:
        save_output(output_path, [], 0, mode, threshold)
        return 0

    cves = [f["cve"] for f in findings]
    epss = enrich_epss(cves)
    kev = load_kev()

    enriched = [evaluate_item(v, epss, kev) for v in findings]

    for i in enriched:
        i["risk_score"] = compute_risk_score(i)

    high_risk = filter_high_risk(enriched, threshold)

    save_output(output_path, high_risk, len(high_risk), mode, threshold)

    return 1 if should_fail(mode, high_risk) else 0


# =========================================================
# Output Writer
# =========================================================

def save_output(path: str, high_risk: List[Dict[str, Any]], count: int, mode: str, thr: float) -> None:
    out = {
        "mode": mode,
        "threshold": thr,
        "total_high_risk": count,
        "high_risk": high_risk,
    }
    with open(path, "w") as f:
        json.dump(out, f, indent=2)


# =========================================================
# Entry Point
# =========================================================

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--mode", required=True, choices=["A", "B", "C"])
    p.add_argument("--input", nargs="+", required=True, help="Trivy/Snyk JSON inputs")
    p.add_argument("--output", required=True)
    p.add_argument("--threshold", required=True, type=float)
    return p.parse_args()


def main():
    args = parse_args()
    rc = run_gate(args.mode, args.input, args.output, args.threshold)
    sys.exit(rc)


if __name__ == "__main__":
    main()
