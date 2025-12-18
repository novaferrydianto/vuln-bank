#!/usr/bin/env python3
"""
EPSS + CISA KEV Gating for Vuln Bank DevSecOps
Hybrid Mode (Mode C): Combine strict threshold AND weighted risk score.

Outputs:
- epss-findings.json
- high_risk[] = merged risk from Trivy + Snyk (SCA) enriched with:
    - EPSS score
    - EPSS percentile
    - CVSS
    - is_kev
    - reasons[]
"""

import os
import json
import argparse
import urllib.request
import urllib.parse

EPSS_API = "https://api.first.org/data/v1/epss?cve="
KEV_API = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def safe_load_json(path):
    """Load JSON safely."""
    if not os.path.exists(path):
        return None
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return None


def fetch_json(url: str):
    """HTTP GET with best-effort behavior."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read().decode())
    except Exception:
        return None


def load_kev_cves():
    """Return a set of all KEV CVEs."""
    data = fetch_json(KEV_API)
    if not data or "vulnerabilities" not in data:
        return set()
    return {v.get("cveID", "") for v in data["vulnerabilities"]}


KEV_SET = load_kev_cves()


def extract_cves_from_trivy(trivy_json):
    results = []
    for res in trivy_json or []:
        vulns = res.get("Vulnerabilities", []) or []
        for v in vulns:
            cve = v.get("VulnerabilityID", "")
            if cve:
                results.append(
                    {
                        "cve": cve,
                        "pkg_name": v.get("PkgName", ""),
                        "installed_version": v.get("InstalledVersion", ""),
                        "fixed_version": v.get("FixedVersion", ""),
                        "severity": v.get("Severity", "").upper(),
                        "cvss": v.get("CVSS", {}).get("nvd", {}).get("V3Score"),
                    }
                )
    return results


def extract_cves_from_snyk(snyk_json):
    results = []
    vulns = snyk_json.get("vulnerabilities", []) or []
    for v in vulns:
        cve = ""
        if "identifiers" in v:
            cve_list = v["identifiers"].get("CVE", [])
            if cve_list:
                cve = cve_list[0]
        if not cve:
            continue
        results.append(
            {
                "cve": cve,
                "pkg_name": v.get("packageName", ""),
                "installed_version": v.get("version", ""),
                "fixed_version": v.get("fixedIn", ""),
                "severity": v.get("severity", "").upper(),
                "cvss": (v.get("cvssScore") or 0),
            }
        )
    return results


def enrich_with_epss(v):
    """Attach EPSS score + percentile + KEV flags."""
    cve = v["cve"]
    url = EPSS_API + urllib.parse.quote(cve)
    epss_data = fetch_json(url)

    score = 0
    percentile = 0
    if epss_data and "data" in epss_data and epss_data["data"]:
        row = epss_data["data"][0]
        score = float(row.get("epss", 0))
        percentile = float(row.get("percentile", 0))

    v["epss"] = round(score, 4)
    v["percentile"] = round(percentile, 4)
    v["is_kev"] = cve in KEV_SET
    return v


def risk_filter_strict(v, threshold: float):
    """Strict EPSS/KEV gating."""
    return (v["epss"] >= threshold) or v["is_kev"]


def risk_filter_weighted(v):
    """Weighted risk scoring: CVSS + EPSS percentile."""
    cvss = v.get("cvss") or 0
    perc = v.get("percentile") or 0
    return (0.7 * cvss + 0.3 * perc * 10) >= 6


def process_reports(inputs, mode, threshold):
    merged = []

    for path in inputs:
        data = safe_load_json(path)
        if not data:
            continue

        # Trivy format
        if isinstance(data, list):
            merged.extend(extract_cves_from_trivy(data))

        # Snyk SCA
        if isinstance(data, dict) and "vulnerabilities" in data:
            merged.extend(extract_cves_from_snyk(data))

    enriched = [enrich_with_epss(v) for v in merged]

    high_risk = []
    for v in enriched:
        reasons = []

        if mode == "A":
            if risk_filter_strict(v, threshold):
                reasons.append("STRICT:EPSS>=threshold")
        elif mode == "B":
            if risk_filter_weighted(v):
                reasons.append("WEIGHTED:RISK_SCORE")
        elif mode == "C":
            if risk_filter_strict(v, threshold):
                reasons.append("STRICT:EPSS>=threshold")
            if risk_filter_weighted(v):
                reasons.append("WEIGHTED:RISK_SCORE")

        if v["is_kev"]:
            reasons.append("CISA_KEV")

        if reasons:
            v["reasons"] = reasons
            high_risk.append(v)

    return {
        "mode": mode,
        "threshold": threshold,
        "total_findings": len(enriched),
        "high_risk": high_risk,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", default="C")
    parser.add_argument("--input", nargs="+", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--threshold", type=float, default=0.5)
    args = parser.parse_args()

    result = process_reports(args.input, args.mode, args.threshold)

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(result, f, indent=2)

    # hybrid mode may produce empty results, that's allowed
    if args.mode == "A" and len(result["high_risk"]) > 0:
        exit(1)


if __name__ == "__main__":
    main()
