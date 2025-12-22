#!/usr/bin/env python3
"""
Gate decision:
- FAIL if Trivy has any HIGH/CRITICAL CVE vulnerabilities
- FAIL if EPSS findings contain any high_risk entries (epss >= threshold)

Exit code:
  0 = pass
  1 = fail
"""

from __future__ import annotations

import argparse
import json
import re
from typing import Any

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")


def _load_json(path: str) -> Any:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _as_results(trivy_json: Any) -> list[dict[str, Any]]:
    if isinstance(trivy_json, dict) and isinstance(trivy_json.get("Results"), list):
        return trivy_json["Results"]
    if isinstance(trivy_json, list):
        return [x for x in trivy_json if isinstance(x, dict)]
    return []


def _count_high_crit_cves(trivy_json: Any) -> int:
    results = _as_results(trivy_json)
    count = 0

    for r in results:
        vulns = r.get("Vulnerabilities") or []
        if not isinstance(vulns, list):
            continue
        for v in vulns:
            if not isinstance(v, dict):
                continue
            vid = str(v.get("VulnerabilityID", "")).strip()
            sev = str(v.get("Severity", "")).strip().upper()
            if CVE_RE.match(vid) and sev in {"HIGH", "CRITICAL"}:
                count += 1

    return count


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--trivy", required=True, help="Path to trivy-sca.json")
    ap.add_argument("--epss", required=True, help="Path to epss-findings.json")
    args = ap.parse_args()

    trivy = _load_json(args.trivy)
    epss = _load_json(args.epss)

    high_crit = _count_high_crit_cves(trivy)
    high_risk_epss = len((epss or {}).get("high_risk", []) or [])

    if high_crit > 0 or high_risk_epss > 0:
        print(f"GATE_FAIL: trivy_high_crit={high_crit}, epss_high_risk={high_risk_epss}")
        return 1

    print("GATE_PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
