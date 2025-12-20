#!/usr/bin/env python3
"""
EPSS + CISA KEV gate for Vuln Bank (ruff/pyupgrade compliant)

Features:
- Extracts CVEs from Trivy JSON robustly (HIGH/CRITICAL by default)
- Fetches EPSS score + percentile from FIRST.org API with retry/backoff
- Fetches CISA KEV catalog and flags KEV CVEs
- Produces detailed output JSON:
  - stats (counts, processed CVEs, API failures, KEV matches)
  - api_failures map
  - high_risk list with reasons (CISA_KEV, EPSS>=threshold)
- Never silently returns empty: API errors are recorded in output

Exit behavior:
- Default exit code 0 (workflow can decide with jq)
- Optional: --fail exits 1 if high_risk exists
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import time
import urllib.parse
import urllib.request
from typing import Any

EPSS_API = "https://api.first.org/data/v1/epss"
CISA_KEV_JSON = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def _read_json(path: str) -> dict[str, Any]:
    # UP015: do not specify "r" explicitly
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _write_json(path: str, data: dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=False)


def _http_get_json(url: str, headers: dict[str, str] | None = None, timeout: int = 20) -> dict[str, Any]:
    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read().decode("utf-8", errors="replace")
        return json.loads(body)


def _http_get_json_retry(
    url: str,
    headers: dict[str, str] | None = None,
    timeout: int = 20,
    retries: int = 4,
    backoff_base: float = 0.8,
) -> tuple[dict[str, Any] | None, str | None]:
    """
    Returns (json, error_string). On success, error_string is None.
    """
    last_err: str | None = None
    for attempt in range(1, retries + 1):
        try:
            return _http_get_json(url, headers=headers, timeout=timeout), None
        except Exception as e:  # noqa: BLE001
            last_err = f"{type(e).__name__}: {e}"
            time.sleep(backoff_base * (2 ** (attempt - 1)))
    return None, last_err


def _extract_cvss_score(vuln: dict[str, Any]) -> float | None:
    """
    Trivy CVSS formats:
      vuln["CVSS"] -> { "nvd": { "V3Score": 9.8 }, ... } possibly multiple vendors
    We pick the maximum available score.
    """
    cvss = vuln.get("CVSS") or {}
    best: float | None = None

    def _consider(val: Any) -> None:
        nonlocal best
        try:
            f = float(val)
        except Exception:
            return
        if best is None or f > best:
            best = f

    if isinstance(cvss, dict):
        for vendor_obj in cvss.values():
            if isinstance(vendor_obj, dict):
                _consider(vendor_obj.get("V3Score"))
                _consider(vendor_obj.get("V31Score"))
                _consider(vendor_obj.get("V30Score"))
                _consider(vendor_obj.get("V2Score"))

    return best


def _extract_trivy_vulns(trivy: dict[str, Any], severities: set[str]) -> list[dict[str, Any]]:
    """
    Returns Trivy vulnerabilities filtered by severities (e.g., HIGH/CRITICAL).
    """
    out: list[dict[str, Any]] = []
    results = trivy.get("Results") or []
    for r in results:
        vulns = r.get("Vulnerabilities") or []
        for v in vulns:
            sev = (v.get("Severity") or "").upper()
            if sev in severities:
                out.append(v)
    return out


def _extract_unique_cves(vulns: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """
    Map CVE -> list of vuln instances from Trivy.
    """
    cves: dict[str, list[dict[str, Any]]] = {}
    for v in vulns:
        cve = v.get("VulnerabilityID") or v.get("VulnID") or ""
        if not isinstance(cve, str) or not cve.startswith("CVE-"):
            continue
        cves.setdefault(cve, []).append(v)
    return cves


def _fetch_kev_set() -> tuple[set[str], str | None]:
    data, err = _http_get_json_retry(CISA_KEV_JSON, timeout=30, retries=4, backoff_base=0.7)
    if err or not data:
        return set(), err or "Unknown error"

    vulns = data.get("vulnerabilities") or []
    kev: set[str] = set()

    for item in vulns:
        cve = item.get("cveID") or item.get("cveId") or item.get("cve") or ""
        if isinstance(cve, str) and cve.startswith("CVE-"):
            kev.add(cve)

    return kev, None


def _fetch_epss(cve: str) -> tuple[float | None, float | None, str | None]:
    """
    Returns (epss, percentile, error).
    """
    q = urllib.parse.urlencode({"cve": cve})
    url = f"{EPSS_API}?{q}"

    data, err = _http_get_json_retry(url, timeout=20, retries=4, backoff_base=0.7)
    if err or not data:
        return None, None, err or "Unknown error"

    rows = data.get("data") or []
    if not rows:
        return None, None, "EPSS: empty data[]"

    row = rows[0] or {}
    epss: float | None
    pct: float | None

    try:
        epss = float(row.get("epss"))
    except Exception:
        epss = None

    try:
        pct = float(row.get("percentile"))
    except Exception:
        pct = None

    if epss is None:
        return None, pct, "EPSS: epss parse failed"

    return epss, pct, None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True, help="Trivy JSON input (e.g., security-reports/trivy-sca.json)")
    ap.add_argument("--output", required=True, help="Output JSON (e.g., security-reports/epss-findings.json)")
    ap.add_argument("--threshold", required=True, type=float, help="EPSS threshold (e.g., 0.5)")
    ap.add_argument(
        "--severities",
        default="HIGH,CRITICAL",
        help="Comma-separated Trivy severities to consider (default: HIGH,CRITICAL)",
    )
    ap.add_argument(
        "--fail",
        action="store_true",
        help="Exit 1 if high_risk findings exist (default: false; decision can be done in workflow)",
    )
    ap.add_argument(
        "--max-cves",
        type=int,
        default=300,
        help="Safety limit to avoid too many EPSS API calls (default: 300 unique CVEs)",
    )
    ap.add_argument(
        "--sleep",
        type=float,
        default=0.12,
        help="Sleep between EPSS API calls to reduce rate-limit risk (default: 0.12s)",
    )
    args = ap.parse_args()

    severities = {s.strip().upper() for s in args.severities.split(",") if s.strip()}
    threshold = float(args.threshold)
    generated_at = dt.datetime.utcnow().isoformat() + "Z"

    # Load Trivy
    try:
        trivy = _read_json(args.input)
    except Exception as e:  # noqa: BLE001
        out = {
            "generated_at": generated_at,
            "threshold": threshold,
            "error": f"Failed to read Trivy input: {type(e).__name__}: {e}",
            "high_risk": [],
            "stats": {"input": args.input, "output": args.output},
        }
        _write_json(args.output, out)
        return 0

    vulns_filtered = _extract_trivy_vulns(trivy, severities)
    cve_map = _extract_unique_cves(vulns_filtered)
    unique_cves = list(cve_map.keys())

    kev_set, kev_err = _fetch_kev_set()

    epss_failures: dict[str, str] = {}
    epss_cache: dict[str, dict[str, Any]] = {}

    # Safety cap
    if len(unique_cves) > args.max_cves:
        unique_cves = unique_cves[: args.max_cves]

    high_risk: list[dict[str, Any]] = []
    processed = 0

    for cve in unique_cves:
        processed += 1
        epss, pct, err = _fetch_epss(cve)
        if err:
            epss_failures[cve] = err
        epss_cache[cve] = {"epss": epss, "percentile": pct, "error": err}

        is_kev = cve in kev_set
        reasons: list[str] = []

        if is_kev:
            reasons.append("CISA_KEV")
        if epss is not None and epss >= threshold:
            reasons.append(f"EPSS>={threshold}")

        if reasons:
            instances = cve_map.get(cve, [])
            v0 = instances[0] if instances else {}

            cvss = _extract_cvss_score(v0)
            high_risk.append(
                {
                    "cve": cve,
                    "pkg_name": v0.get("PkgName"),
                    "installed_version": v0.get("InstalledVersion"),
                    "fixed_version": v0.get("FixedVersion"),
                    "severity": v0.get("Severity"),
                    "cvss": cvss,
                    "epss": epss,
                    "percentile": pct,
                    "is_kev": is_kev,
                    "instances": len(instances),
                    "reasons": reasons,
                }
            )

        if args.sleep > 0:
            time.sleep(args.sleep)

    # Sort high_risk by (is_kev first), then epss desc, then cvss desc
    def _sort_key(x: dict[str, Any]) -> tuple[int, float, float]:
        kev_rank = 0 if x.get("is_kev") else 1

        epss_val = x.get("epss")
        cvss_val = x.get("cvss")

        try:
            epss_f = float(epss_val) if epss_val is not None else -1.0
        except Exception:
            epss_f = -1.0

        try:
            cvss_f = float(cvss_val) if cvss_val is not None else -1.0
        except Exception:
            cvss_f = -1.0

        return (kev_rank, -epss_f, -cvss_f)

    high_risk.sort(key=_sort_key)

    out = {
        "generated_at": generated_at,
        "threshold": threshold,
        "severities_considered": sorted(severities),
        "stats": {
            "trivy_input": args.input,
            # UP034: no extraneous parentheses
            "total_trivy_vulns_all": sum(
                len(r.get("Vulnerabilities") or []) for r in (trivy.get("Results") or [])
            ),
            "total_trivy_vulns_filtered": len(vulns_filtered),
            "unique_cves_filtered": len(cve_map),
            "unique_cves_processed": processed,
            "kev_catalog_loaded": kev_err is None,
            "kev_catalog_error": kev_err,
            "kev_matches": sum(1 for c in cve_map.keys() if c in kev_set),
            "epss_api_failures": len(epss_failures),
        },
        "api_failures": epss_failures,
        "high_risk": high_risk,
        # optional debug cache (comment out if you want smaller artifact)
        # "epss_cache": epss_cache,
    }

    _write_json(args.output, out)

    if args.fail and high_risk:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
