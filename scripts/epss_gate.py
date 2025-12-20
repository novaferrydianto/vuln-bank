#!/usr/bin/env python3
import os
import json
import urllib.request
import urllib.parse
import sys
import argparse

EPSS_API = "https://api.first.org/data/v1/epss"
KEV_API = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

def load_json(path):
    if not os.path.isfile(path):
        print(f"[WARN] File not found: {path}")
        return {}
    with open(path) as f:
        return json.load(f)

def fetch_epss_batch(cve_list):
    """Fetch EPSS scores in batches to avoid URL length limits."""
    if not cve_list:
        return {}
    
    out = {}
    # Batch size of 50 is safe for most API limits
    for i in range(0, len(cve_list), 50):
        batch = cve_list[i:i + 50]
        q = ",".join(batch)
        url = f"{EPSS_API}?cve={urllib.parse.quote(q)}"
        try:
            with urllib.request.urlopen(url) as r:
                data = json.loads(r.read().decode())
                for item in data.get("data", []):
                    out[item["cve"]] = {
                        "epss": float(item.get("epss", 0)),
                        "percentile": float(item.get("percentile", 0))
                    }
        except Exception as e:
            print(f"[ERROR] Failed fetching EPSS batch: {e}")
    return out

def load_kev():
    try:
        with urllib.request.urlopen(KEV_API) as r:
            kev = json.loads(r.read().decode())
            return {x["cveID"]: True for x in kev.get("vulnerabilities", [])}
    except Exception as e:
        print(f"[WARN] Failed fetching CISA KEV: {e}")
        return {}

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--input", required=True, help="Trivy JSON report")
    p.add_argument("--output", required=True, help="Filtered results")
    p.add_argument("--threshold", required=True, type=float, help="EPSS threshold (e.g. 0.5)")
    args = p.parse_args()

    sca = load_json(args.input)
    kev_db = load_kev()

    cve_items = []
    unique_cves = set()

    for result in sca.get("Results", []):
        for v in result.get("Vulnerabilities", []):
            cid = v.get("VulnerabilityID")
            if cid:
                unique_cves.add(cid)
                cve_items.append(v)

    epss_data = fetch_epss_batch(list(unique_cves))

    high_risk = []
    for v in cve_items:
        cve = v.get("VulnerabilityID")
        sev = v.get("Severity", "").upper()
        epss_info = epss_data.get(cve, {})
        epss_score = epss_info.get("epss", 0)
        is_kev = cve in kev_db

        reasons = []
        if epss_score >= args.threshold: reasons.append("EPSS_High")
        if sev in ("HIGH", "CRITICAL"): reasons.append("HighSeverity")
        if is_kev: reasons.append("CISA_KEV")

        if reasons:
            high_risk.append({
                "cve": cve,
                "pkg_name": v.get("PkgName", ""),
                "installed_version": v.get("InstalledVersion", ""),
                "severity": sev,
                "epss": epss_score,
                "is_kev": is_kev,
                "reasons": reasons
            })

    with open(args.output, "w") as f:
        json.dump({"threshold": args.threshold, "high_risk": high_risk}, f, indent=2)

    print(f"[EPSS] Scan complete. Found {len(high_risk)} high-risk vulnerabilities.")
    if high_risk:
        sys.exit(1)

if __name__ == "__main__":
    main()