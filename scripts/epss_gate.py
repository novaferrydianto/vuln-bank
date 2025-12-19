#!/usr/bin/env python3
"""
EPSS Gate – Enterprise Refined Version (Lint-Free)
Prioritizes vulnerabilities based on EPSS, CISA KEV, and CVSS.
"""

import os
import json
import argparse
import urllib.request
import ssl
import time
from datetime import datetime

# Konfigurasi Endpoint
EPSS_API = "https://api.first.org/data/v1/epss?cve={}"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Bypass SSL verification untuk lingkungan self-hosted yang ketat
ssl_context = ssl._create_unverified_context()

def fetch_json(url, timeout=15):
    """Mengambil data JSON dengan penanganan error dan timeout."""
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=timeout, context=ssl_context) as r:
            return json.loads(r.read().decode("utf-8"))
    except Exception as e:
        print(f"[WARN] Gagal mengambil data dari {url}: {e}")
        return None

def load_cisa_kev():
    """Mengambil daftar CVE yang aktif dieksploitasi dari CISA KEV."""
    print("[INFO] Mengambil data CISA KEV...")
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
        if not cve: continue
        cvss = v.get("cvssScore") or v.get("cvssV3", {}).get("baseScore") or v.get("cvss", 0)
        vulns.append({
            "cve": cve.upper(),
            "severity": v.get("severity", "").upper(),
            "cvss": float(cvss) if cvss else 0.0
        })
    return vulns

def extract_from_trivy(raw):
    vulns = []
    for res in raw.get("Results", []):
        for v in res.get("Vulnerabilities", []):
            cve = v.get("VulnerabilityID") or v.get("CVE")
            if not cve: continue
            cvss = (v.get("CVSS", {}).get("nvd", {}).get("V3Score") or 
                    v.get("CVSS_SCORE") or 0.0)
            vulns.append({
                "cve": cve.upper(),
                "severity": v.get("Severity", "").upper(),
                "cvss": float(cvss)
            })
    return vulns

def load_vulnerabilities(path):
    """Membaca file laporan Snyk atau Trivy."""
    if not path or not os.path.exists(path):
        return []
    
    # RUFF FIX: Menghapus parameter "r" yang redundan (UP015)
    with open(path, encoding="utf-8") as f:
        try:
            raw = json.load(f)
        except Exception:
            return []
            
    if "vulnerabilities" in raw: return extract_from_snyk(raw)
    if "Results" in raw: return extract_from_trivy(raw)
    return []

def load_epss(cve, cache):
    """Mengambil skor EPSS dari FIRST.org dengan Rate Limiting."""
    if cve in cache:
        return cache[cve]

    # Jeda 0.1 detik untuk mematuhi rate limit API publik
    time.sleep(0.1)
    
    url = EPSS_API.format(cve)
    data = fetch_json(url)
    if not data or not data.get("data"):
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
        print(f"[INFO] Memproses laporan: {p}")
        for v in load_vulnerabilities(p):
            cve = v["cve"]
            if cve not in vulns:
                vulns[cve] = v
                vulns[cve]["sources"] = {os.path.basename(p)}
            else:
                vulns[cve]["sources"].add(os.path.basename(p))

    high_risk = []
    print(f"[INFO] Menganalisis {len(vulns)} CVE unik...")

    for cve, item in vulns.items():
        epss_data = load_epss(cve, epss_cache)
        item.update(epss_data)

        reasons = []
        if epss_data["epss"] >= threshold: reasons.append(f"EPSS({epss_data['epss']:.4f}) >= Threshold")
        if cve in kev: reasons.append("CISA KEV (Active Exploitation)")
        if item["cvss"] >= 9.0: reasons.append(f"Critical CVSS ({item['cvss']})")

        if reasons:
            item["reasons"] = reasons
            item["is_kev"] = cve in kev
            item["sources"] = list(item["sources"])
            high_risk.append(item)

    result = {
        "threshold": threshold,
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "summary": {
            "total_unique_cves": len(vulns),
            "high_risk_count": len(high_risk)
        },
        "findings": sorted(high_risk, key=lambda x: (-x["epss"], -x["cvss"]))
    }

    with open(outfile, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)
    return result

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", action="append", required=True)
    ap.add_argument("--threshold", type=float, default=0.5)
    ap.add_argument("--output", required=True)
    args = ap.parse_args()

    run(args.input, args.threshold, args.output)
    print(f"[SUCCESS] Analisis EPSS selesai. Output: {args.output}")

if __name__ == "__main__":
    main()