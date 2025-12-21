#!/usr/bin/env python3
"""
EPSS Gate for Trivy SCA JSON
- Extract CVEs from Trivy JSON report
- Fetch EPSS score + percentile from FIRST EPSS API
- Produce epss-findings.json used for gating & alerting

EPSS API (batch): https://api.first.org/data/v1/epss?cve=CVE-....,CVE-....
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request
from typing import Any

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
EPSS_BASE = "https://api.first.org/data/v1/epss"


def _load_json(path: str) -> Any:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _as_results(trivy_json: Any) -> list[dict[str, Any]]:
    if isinstance(trivy_json, dict) and isinstance(trivy_json.get("Results"), list):
        return trivy_json["Results"]
    if isinstance(trivy_json, list):
        return [x for x in trivy_json if isinstance(x, dict)]
    return []


def _extract_vulns(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    vulns: list[dict[str, Any]] = []
    for r in results:
        vs = r.get("Vulnerabilities") or []
        if isinstance(vs, list):
            for v in vs:
                if isinstance(v, dict):
                    vulns.append(v)
    return vulns


def _extract_cve_ids(vulns: list[dict[str, Any]]) -> list[str]:
    cves: list[str] = []
    for v in vulns:
        vid = str(v.get("VulnerabilityID", "")).strip()
        if CVE_RE.match(vid):
            cves.append(vid)

    seen: set[str] = set()
    out: list[str] = []
    for c in cves:
        if c not in seen:
            seen.add(c)
            out.append(c)
    return out


def _chunk_by_url_length(cves: list[str], max_chars: int = 1900) -> list[list[str]]:
    """
    Keep URL length below typical ~2000 chars (including query and commas).
    """
    chunks: list[list[str]] = []
    cur: list[str] = []
    cur_len = 0

    for c in cves:
        add_len = len(c) + (1 if cur else 0)
        if cur and (cur_len + add_len) > max_chars:
            chunks.append(cur)
            cur = [c]
            cur_len = len(c)
        else:
            cur.append(c)
            cur_len += add_len

    if cur:
        chunks.append(cur)
    return chunks


def _http_get_json(url: str, timeout: int = 20) -> dict[str, Any]:
    req = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "vuln-bank-epss-gate/1.0",
        },
        method="GET",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = resp.read()
    return json.loads(data.decode("utf-8"))


def _fetch_epss_batch(
    cves: list[str],
    *,
    timeout: int = 20,
    sleep_s: float = 0.2,
) -> dict[str, tuple[float, float]]:
    """
    Returns mapping: cve -> (epss_score, percentile)
    """
    out: dict[str, tuple[float, float]] = {}

    for chunk in _chunk_by_url_length(cves):
        qs = urllib.parse.urlencode({"cve": ",".join(chunk)})
        url = f"{EPSS_BASE}?{qs}"
        payload = _http_get_json(url, timeout=timeout)

        for row in payload.get("data", []) or []:
            if not isinstance(row, dict):
                continue
            cve = str(row.get("cve", "")).strip()
            if not CVE_RE.match(cve):
                continue

            try:
                epss = float(row.get("epss", 0.0))
            except Exception:
                epss = 0.0

            try:
                pct = float(row.get("percentile", 0.0))
            except Exception:
                pct = 0.0

            out[cve] = (epss, pct)

        time.sleep(sleep_s)

    return out


def _severity_is_high_or_critical(sev: str) -> bool:
    return sev.strip().upper() in {"HIGH", "CRITICAL"}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True, help="Path to Trivy SCA JSON")
    ap.add_argument("--output", required=True, help="Path to epss-findings.json")
    ap.add_argument("--threshold", required=True, type=float, help="EPSS threshold (e.g., 0.5)")
    ap.add_argument("--timeout", type=int, default=20, help="HTTP timeout seconds")
    ap.add_argument("--max-top", type=int, default=50, help="Max records to keep (sorted by EPSS desc)")
    args = ap.parse_args()

    threshold = float(args.threshold)
    now = dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

    trivy = _load_json(args.input)
    results = _as_results(trivy)
    vulns = _extract_vulns(results)

    cves = _extract_cve_ids(vulns)

    high_crit = [
        v
        for v in vulns
        if _severity_is_high_or_critical(str(v.get("Severity", "")))
        and CVE_RE.match(str(v.get("VulnerabilityID", "")).strip())
    ]
    total_high_crit = len(high_crit)

    warnings: list[str] = []
    epss_map: dict[str, tuple[float, float]] = {}

    if cves:
        try:
            epss_map = _fetch_epss_batch(cves, timeout=args.timeout)
        except Exception as e:
            warnings.append(f"EPSS fetch failed: {type(e).__name__}: {e}")
            epss_map = {}

    high_risk: list[dict[str, Any]] = []
    for v in high_crit:
        cve = str(v.get("VulnerabilityID", "")).strip()
        epss, pct = epss_map.get(cve, (0.0, 0.0))

        if epss < threshold:
            continue

        high_risk.append(
            {
                "cve": cve,
                "pkg_name": v.get("PkgName") or "",
                "installed_version": v.get("InstalledVersion") or "",
                "fixed_version": v.get("FixedVersion") or "",
                "severity": v.get("Severity") or "",
                "title": v.get("Title") or "",
                "epss": round(float(epss), 6),
                "percentile": round(float(pct), 6),
                "reasons": [f"EPSS>={threshold}"],
            }
        )

    high_risk.sort(key=lambda x: x.get("epss", 0.0), reverse=True)
    if len(high_risk) > args.max_top:
        high_risk = high_risk[: args.max_top]

    out: dict[str, Any] = {
        "threshold": threshold,
        "generated_at": now,
        "total_cves": len(cves),
        "total_trivy_high_crit": total_high_crit,
        "high_risk": high_risk,
        "warnings": warnings,
    }

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
