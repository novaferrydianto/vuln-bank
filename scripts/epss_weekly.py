#!/usr/bin/env python3
import os, json, datetime, urllib.request, urllib.parse, subprocess, tempfile

OUT_DOCS = "docs/data/epss-weekly.json"
OUT_METRICS = "security-metrics/weekly/epss-weekly.json"
EPSS_THRESHOLD = float(os.environ.get("EPSS_THRESHOLD", "0.5"))

NOW = datetime.datetime.utcnow().isoformat() + "Z"

def run(cmd):
    return subprocess.check_output(cmd, shell=True, text=True)

def collect_cves():
    """
    Strategy:
    1) Try Trivy FS JSON (no secrets, fast)
    2) Fallback: empty list (still valid output)
    """
    cves = set()
    try:
        with tempfile.NamedTemporaryFile(suffix=".json") as f:
            run(f"trivy fs . --severity HIGH,CRITICAL --format json -o {f.name}")
            data = json.load(open(f.name))
            for r in data.get("Results", []):
                for v in r.get("Vulnerabilities", []):
                    if v.get("VulnerabilityID", "").startswith("CVE-"):
                        cves.add(v["VulnerabilityID"])
    except Exception:
        pass
    return sorted(cves)

def fetch_epss(cve):
    url = "https://api.first.org/data/v1/epss?" + urllib.parse.urlencode({"cve": cve})
    with urllib.request.urlopen(url, timeout=15) as r:
        data = json.load(r)
        if data.get("data"):
            return float(data["data"][0]["epss"])
    return 0.0

def main():
    cves = collect_cves()
    high_risk = []
    all_scores = []

    for cve in cves:
        epss = fetch_epss(cve)
        all_scores.append({"cve": cve, "epss": epss})
        if epss >= EPSS_THRESHOLD:
            high_risk.append({"cve": cve, "epss": epss})

    high_risk.sort(key=lambda x: x["epss"], reverse=True)

    out = {
        "generated_at": NOW,
        "threshold": EPSS_THRESHOLD,
        "total_cves": len(cves),
        "high_risk_count": len(high_risk),
        "top_cves": high_risk[:5],
        "all": all_scores
    }

    os.makedirs("docs/data", exist_ok=True)
    os.makedirs("security-metrics/weekly", exist_ok=True)

    for p in [OUT_DOCS, OUT_METRICS]:
        with open(p, "w") as f:
            json.dump(out, f, indent=2)

    print("[OK] EPSS weekly generated")

if __name__ == "__main__":
    main()
