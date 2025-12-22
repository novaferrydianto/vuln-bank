#!/usr/bin/env python3
import argparse
import json
import os
import sys
from typing import Any


def _read_json(path: str) -> dict[str, Any]:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _write_json(path: str, data: dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)


def _count_trivy_severity(trivy: dict[str, Any]) -> tuple[int, int]:
    high = 0
    critical = 0
    for r in trivy.get("Results") or []:
        for v in r.get("Vulnerabilities") or []:
            sev = (v.get("Severity") or "").upper()
            if sev == "HIGH":
                high += 1
            elif sev == "CRITICAL":
                critical += 1
    return high, critical


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--trivy", required=True)
    ap.add_argument("--epss", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--max-critical", type=int, default=0)
    ap.add_argument("--block-on-epss-high", action="store_true")
    args = ap.parse_args()

    trivy = _read_json(args.trivy)
    epss = _read_json(args.epss)

    high, critical = _count_trivy_severity(trivy)
    epss_high = len(epss.get("high_risk") or [])

    reasons = []
    if critical > args.max_critical:
        reasons.append(f"Trivy CRITICAL {critical} > {args.max_critical}")
    if args.block_on_epss_high and epss_high > 0:
        reasons.append(f"EPSS-high findings {epss_high} > 0")

    gate_pass = len(reasons) == 0

    out = {
        "gate_pass": gate_pass,
        "critical_count": critical,
        "high_count": high,
        "epss_high_count": epss_high,
        "reasons": reasons,
    }
    _write_json(args.out, out)

    # Export to GITHUB_OUTPUT
    gh_out = os.environ.get("GITHUB_OUTPUT")
    if gh_out:
        with open(gh_out, "a", encoding="utf-8") as f:
            f.write(f"gate_pass={'true' if gate_pass else 'false'}\n")
            f.write(f"critical_count={critical}\n")
            f.write(f"high_count={high}\n")
            f.write(f"epss_high_count={epss_high}\n")

    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
