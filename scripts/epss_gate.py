#!/usr/bin/env python3
import os, json, urllib.request, urllib.parse, sys

EPSS_API = "https://api.first.org/data/v1/epss"
KEV_API = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

def load_json(path):
    if not os.path.isfile(path):
        print(f"[WARN] File not found: {path}")
        return {}
    with open(path) as f:
        return json.load(f)

def fetch_epss(cves):
    if not cves:
        return {}
    q = ",".join(cves)
    url = f"{EPSS_API}?cve={urllib.parse.quote(q)}"
    with urllib.request.urlopen(url) as r:
        data = json.loads(r.read().decode())
    out = {}
    for item in data.get("data", []):
        out[item["cve"]] = {
            "epss": float(item.get("epss", 0)),
            "percentile": float(item.get("percentile", 0))
        }
    return out

def load_kev():
    try:
        with urllib.request.urlopen(KEV_API) as r:
            kev = json.loads(r.read().decode())
            return { x["cveID"]: True for x in kev.get("vulnerabilities", []) }
    except:
        return {}

def main():
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--input", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--threshold", required=True)
    args = p.parse_args()

    threshold = float(args.threshold)

    sca = load_json(args.input)
    kev_db = load_kev()

    # Extract CVEs from Trivy SCA
    cves = []
    items = []

    for result in sca.get("Results", []):
        for v in result.get("Vulnerabilities", []):
            cves.append(v.get("VulnerabilityID"))
            items.append(v)

    cves = [c for c in cves if c]
    epss_data = fetch_epss(cves)

    high_risk = []
    for v in items:
        cve = v.get("VulnerabilityID")
        sev = v.get("Severity", "").upper()
        epss_score = epss_data.get(cve, {}).get("epss", 0)
        percentile = epss_data.get(cve, {}).get("percentile", 0)
        is_kev = cve in kev_db

        reasons = []
        if epss_score >= threshold:
            reasons.append("EPSS>=threshold")
        if sev in ("HIGH", "CRITICAL"):
            reasons.append("HighSeverity")
        if is_kev:
            reasons.append("CISA_KEV")

        if reasons:
            high_risk.append({
                "cve": cve,
                "pkg_name": v.get("PkgName", ""),
                "installed_version": v.get("InstalledVersion", ""),
                "fixed_version": v.get("FixedVersion", ""),
                "severity": sev,
                "cvss": v.get("CVSS", [{}])[0].get("V3Score", None) if isinstance(v.get("CVSS"), list) else None,
                "epss": epss_score,
                "percentile": percentile,
                "is_kev": is_kev,
                "reasons": reasons
            })

    result = {
        "threshold": threshold,
        "total_trivy_high_crit": len(items),
        "high_risk": high_risk
    }

    with open(args.output, "w") as f:
        json.dump(result, f, indent=2)

    print(f"[EPSS] Completed. High risk count: {len(high_risk)}")

    # Fail gate if any high-risk
    if len(high_risk) > 0:
        sys.exit(1)

if __name__ == "__main__":
    main()
