#!/usr/bin/env python3
import os
import json
import argparse
import urllib.request
import urllib.parse
from typing import List, Dict, Any, Set


# ======================================================
# SAFE JSON LOADER (Path Traversal Mitigation)
# ======================================================
def safe_load_json(path: str, base_dir: str) -> Any:
    base_real = os.path.realpath(base_dir)
    target_real = os.path.realpath(path)

    if not target_real.startswith(base_real + os.sep):
        raise ValueError(f"Unsafe path detected: {path}")

    if not os.path.exists(target_real):
        return None

    try:
        with open(target_real) as f:
            return json.load(f)
    except Exception:
        return None


# ======================================================
# Extract vulns from Trivy / Snyk output
# ======================================================
def extract_vulns(files: List[str], base_dir: str) -> List[Dict[str, Any]]:
    results = []

    for path in files:
        data = safe_load_json(path, base_dir)
        if not data:
            continue

        # Trivy SBOM / Config
        if "Results" in data:
            for r in data.get("Results", []):
                for v in r.get("Vulnerabilities", []):
                    cve = v.get("VulnerabilityID")
                    if cve:
                        results.append(
                            {
                                "file": path,
                                "source": "trivy",
                                "cve": cve,
                                "severity": v.get("Severity", "UNKNOWN").upper(),
                                "pkg": v.get("PkgName") or v.get("PkgPath"),
                                "version": v.get("InstalledVersion"),
                            }
                        )
            continue

        # Snyk SCA: vulnerabilities
        if "vulnerabilities" in data:
            for v in data["vulnerabilities"]:
                ids = v.get("identifiers", {})
                cve_list = ids.get("CVE") or []
                cve = cve_list[0] if cve_list else None
                if cve:
                    results.append(
                        {
                            "file": path,
                            "source": "snyk",
                            "cve": cve,
                            "severity": v.get("severity", "UNKNOWN").upper(),
                            "pkg": v.get("packageName"),
                            "version": v.get("version"),
                        }
                    )
            continue

        # Snyk Code / Issues
        if "issues" in data:
            for v in data["issues"]:
                cve = v.get("issueData", {}).get("cve") or v.get("cve")
                if cve:
                    results.append(
                        {
                            "file": path,
                            "source": "snyk",
                            "cve": cve,
                            "severity": v.get("severity", "UNKNOWN").upper(),
                            "pkg": v.get("package"),
                            "version": v.get("version"),
                        }
                    )

    return results


# ======================================================
# EPSS Fetch
# ======================================================
def fetch_epss_map(cves: Set[str]) -> Dict[str, Dict[str, float]]:
    if not cves:
        return {}

    url = "https://api.first.org/data/v1/epss"
    epss_map = {}
    cve_list = list(cves)
    batch_size = 50

    for i in range(0, len(cve_list), batch_size):
        batch = cve_list[i : i + batch_size]
        qs = urllib.parse.urlencode({"cve": ",".join(batch)})
        full = f"{url}?{qs}"

        try:
            with urllib.request.urlopen(full, timeout=10) as resp:
                payload = json.loads(resp.read().decode())
        except Exception:
            continue

        for row in payload.get("data", []):
            c = row.get("cve")
            if not c:
                continue

            try:
                epss_map[c] = {
                    "epss": float(row.get("epss", 0.0)),
                    "percentile": float(row.get("percentile", 0.0)),
                }
            except Exception:
                continue

    return epss_map


# ======================================================
# CISA KEV Fetch
# ======================================================
def fetch_kev_set() -> Set[str]:
    url = (
        "https://www.cisa.gov/sites/default/files/feeds/"
        "known_exploited_vulnerabilities.json"
    )

    try:
        with urllib.request.urlopen(url, timeout=15) as resp:
            payload = json.loads(resp.read().decode())
    except Exception:
        return set()

    kev = set()
    for row in payload.get("vulnerabilities", []):
        c = row.get("cveID")
        if c:
            kev.add(c)

    return kev


# ======================================================
# Risk Classification
# ======================================================
def compute_risk(vulns, epss_map, kev_set, threshold: float):
    high_risk = []

    for v in vulns:
        cve = v.get("cve")
        sev = v.get("severity", "LOW").upper()
        epss = epss_map.get(cve, {}).get("epss", 0.0)
        perc = epss_map.get(cve, {}).get("percentile", 0.0)
        is_kev = cve in kev_set

        reasons = []
        if sev in {"HIGH", "CRITICAL"}:
            reasons.append("SEVERITY_HIGH")
        if epss >= threshold:
            reasons.append("EPSS_THRESHOLD")
        if is_kev:
            reasons.append("CISA_KEV")

        if reasons:
            item = dict(v)
            item.update(
                {
                    "epss": epss,
                    "percentile": perc,
                    "is_kev": is_kev,
                    "reasons": reasons,
                }
            )
            high_risk.append(item)

    return {
        "total_vulns": len(vulns),
        "high_risk_count": len(high_risk),
        "high_risk": high_risk,
    }


# ======================================================
# MAIN
# ======================================================
def main():
    parser = argparse.ArgumentParser(description="Secure EPSS Gate")
    parser.add_argument("--mode", default="C")
    parser.add_argument("--threshold", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--input", action="append", required=True)
    args = parser.parse_args()

    threshold = float(args.threshold)

    base_dir = os.path.commonpath(
        [os.path.dirname(os.path.realpath(p)) for p in args.input]
    )

    vulns = extract_vulns(args.input, base_dir)
    cves = {v["cve"] for v in vulns if v["cve"]}

    epss_map = fetch_epss_map(cves)
    kev_set = fetch_kev_set()

    risk = compute_risk(vulns, epss_map, kev_set, threshold)

    result = {
        "mode": args.mode,
        "threshold": threshold,
        "total_vulns": risk["total_vulns"],
        "high_risk_count": risk["high_risk_count"],
        "high_risk": risk["high_risk"],
        "gate_failed": False,
    }

    mode = args.mode.upper()
    if mode == "A":
        result["gate_failed"] = risk["high_risk_count"] > 0
    elif mode == "B":
        result["gate_failed"] = any(
            v.get("severity") == "CRITICAL" for v in risk["high_risk"]
        )
    else:
        result["gate_failed"] = False

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(result, f, indent=2)

    if result["gate_failed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
