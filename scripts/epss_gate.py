#!/usr/bin/env python3
"""
EPSS Gate – Enterprise Version
"""

import os
import json
import argparse
import urllib.request
from datetime import datetime


EPSS_API = "https://api.first.org/data/v1/epss?cve={}"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def fetch_json(url, timeout=10):
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8"))
    except Exception:
        return None


def load_cisa_kev():
    data = fetch_json(CISA_KEV_URL)
    kev = set()

    if not data:
        return kev

    for item in data.get("vulnerabilities", []):
        cve = item.get("cveID")
        if cve:
            kev.add(cve.upper())

    return kev


def extract_from_snyk(raw):
    vulns = []
    for v in raw.get("vulnerabilities", []):
        cve = v.get("id") or v.get("cve") or v.get("CVE")
        if not cve:
            continue

        cvss = (
            v.get("cvssScore")
            or v.get("cvssV3", {}).get("baseScore")
            or v.get("cvss", 0)
        )

        vulns.append({
            "cve": cve.upper(),
            "severity": v.get("severity", "").upper(),
            "cvss": cvss or 0
        })
    return vulns


def extract_from_trivy(raw):
    vulns = []
    for res in raw.get("Results", []):
        for v in res.get("Vulnerabilities", []):
            cve = v.get("VulnerabilityID") or v.get("CVE")
            if not cve:
                continue

            cvss = (
                v.get("CVSS", {}).get("nvd", {}).get("V3Score")
                or v.get("CVSS", {}).get("redhat", {}).get("V3Score")
                or v.get("CVSS_SCORE")
                or 0
            )

            vulns.append({
                "cve": cve.upper(),
                "severity": v.get("Severity", "").upper(),
                "cvss": cvss or 0,
            })
    return vulns


def load_vulnerabilities(path):
    if not path or not os.path.exists(path):
        return []

    with open(path, encoding="utf-8") as f:
        try:
            raw = json.load(f)
        except Exception:
            return []

    if "vulnerabilities" in raw:
        return extract_from_snyk(raw)

    if "Results" in raw:
        return extract_from_trivy(raw)

    vulns = []
    for v in raw.get("items", []):
        cve = v.get("cve") or v.get("CVE") or v.get("id")
        if not cve:
            continue
        vulns.append({
            "cve": cve.upper(),
            "severity": v.get("severity", "").upper(),
            "cvss": v.get("cvss", 0),
        })
    return vulns


def load_epss(cve, cache):
    if cve in cache:
        return cache[cve]

    url = EPSS_API.format(cve)
    data = fetch_json(url)

    if not data:
        cache[cve] = {"epss": 0.0, "percentile": 0.0}
        return cache[cve]

    try:
        d = data["data"][0]
        cache[cve] = {
            "epss": float(d.get("epss", 0.0)),
            "percentile": float(d.get("percentile", 0.0)),
        }
    except Exception:
        cache[cve] = {"epss": 0.0, "percentile": 0.0}

    return cache[cve]


def run(inputs, threshold, outfile):
    kev = load_cisa_kev()
    epss_cache = {}
    vulns = {}

    for p in inputs:
        for v in load_vulnerabilities(p):
            cve = v["cve"]
            if cve not in vulns:
                vulns[cve] = {
                    "cve": cve,
                    "severity": v.get("severity", ""),
                    "cvss": v.get("cvss", 0),
                    "sources": set([os.path.basename(p)]),
                }
            else:
                vulns[cve]["sources"].add(os.path.basename(p))

    high_risk = []

    for cve, item in vulns.items():
        epss = load_epss(cve, epss_cache)
        item.update(epss)

        reasons = []
        if epss["epss"] >= threshold:
            reasons.append("EPSS>=threshold")
        if cve in kev:
            reasons.append("CISA_KEV")
        if item["cvss"] >= 9.0:
            reasons.append("CVSS>=9")

        if reasons:
            item["reasons"] = reasons
            item["is_kev"] = cve in kev
            item["sources"] = list(item["sources"])
            high_risk.append(item)

    result = {
        "threshold": threshold,
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "total_unique_cves": len(vulns),
        "high_risk_count": len(high_risk),
        "high_risk": sorted(
            high_risk,
            key=lambda x: (-x["epss"], -x.get("cvss", 0))
        ),
    }

    with open(outfile, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)

    return result


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", action="append", required=True)
    ap.add_argument("--threshold", type=float, default=0.5)
    ap.add_argument("--mode", default="A")
    ap.add_argument("--output", required=True)

    args = ap.parse_args()
    print(json.dumps(run(args.input, args.threshold, args.output), indent=2))


if __name__ == "__main__":
    main()
