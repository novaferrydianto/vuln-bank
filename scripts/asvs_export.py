#!/usr/bin/env python3
"""
ASVS Coverage Exporter (Schema-Compliant, CI/Board Ready)

Inputs:
- Semgrep JSON
- Bandit (DefectDojo-normalized) JSON
- ASVS baseline (optional)

Outputs:
- ASVS coverage JSON (schema-compliant)
- Markdown summary (PR-friendly)
- JSONL history for trending

Schema:
- schemas/asvs-coverage.schema.json
"""

from __future__ import annotations
import argparse
import json
import time
from pathlib import Path
from collections import defaultdict
from typing import Dict, Any, Iterable, List
from datetime import datetime, timezone


# -------------------------------------------------
# Helpers
# -------------------------------------------------
def load_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def extract_asvs_tags(metadata: Dict[str, Any]) -> Iterable[str]:
    """
    Normalize ASVS tag extraction across tools.
    Accepts:
      - string
      - list[str]
      - dict(id/code/control)
    """
    if not metadata:
        return []

    asvs = metadata.get("asvs")
    if isinstance(asvs, list):
        return [str(x).strip() for x in asvs if x]
    if isinstance(asvs, str):
        return [asvs.strip()]
    if isinstance(asvs, dict):
        for k in ("id", "code", "control"):
            if k in asvs:
                return [str(asvs[k]).strip()]
    return []


def extract_from_semgrep(data: Dict[str, Any]) -> Iterable[str]:
    for r in data.get("results", []):
        md = (r.get("extra") or {}).get("metadata") or {}
        yield from extract_asvs_tags(md)


def extract_from_bandit(bandit_dd: Dict[str, Any]) -> Iterable[str]:
    findings = bandit_dd.get("findings") or bandit_dd.get("results") or []
    for f in findings:
        md = f.get("metadata") or {}
        yield from extract_asvs_tags(md)


def derive_level(control_id: str) -> int:
    """
    Best-effort ASVS level inference.
    Example:
      V1 -> L1
      V2 -> L2
      V3 -> L3
    """
    if control_id.startswith("V1"):
        return 1
    if control_id.startswith("V2"):
        return 2
    if control_id.startswith("V3"):
        return 3
    return 1


# -------------------------------------------------
# Main
# -------------------------------------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--semgrep", required=True)
    ap.add_argument("--bandit", required=True)
    ap.add_argument("--out-json", required=True)
    ap.add_argument("--out-md", required=True)
    ap.add_argument("--baseline", default="security-baselines/asvs-baseline.json")
    ap.add_argument("--history", default="security-reports/governance/asvs-history.jsonl")
    ap.add_argument("--repo", default="")
    ap.add_argument("--asvs-version", default="4.0.3")
    args = ap.parse_args()

    semgrep = load_json(Path(args.semgrep))
    bandit = load_json(Path(args.bandit))
    baseline = load_json(Path(args.baseline))

    # -------------------------------------------------
    # Collect signals
    # -------------------------------------------------
    signals = defaultdict(int)

    for tag in extract_from_semgrep(semgrep):
        signals[tag] += 1

    for tag in extract_from_bandit(bandit):
        signals[tag] += 1

    signals = dict(sorted(signals.items()))

    # -------------------------------------------------
    # Build controls array (schema core)
    # -------------------------------------------------
    controls: List[Dict[str, Any]] = []

    for cid, count in signals.items():
        controls.append({
            "id": cid,
            "level": derive_level(cid),
            "status": "FAIL",          # signal exists → control violated
            "evidence": [
                f"{count} finding(s) mapped from SAST/SCA"
            ]
        })

    # Baseline controls not seen now → PASS
    baseline_controls = baseline.get("controls", [])
    seen_ids = {c["id"] for c in controls}

    for bc in baseline_controls:
        cid = bc.get("id")
        if cid and cid not in seen_ids:
            controls.append({
                "id": cid,
                "level": bc.get("level", derive_level(cid)),
                "status": "PASS",
                "evidence": ["No findings detected in current run"]
            })

    # -------------------------------------------------
    # Summary (CEO-friendly numbers)
    # -------------------------------------------------
    total = len(controls)
    passed = sum(1 for c in controls if c["status"] == "PASS")
    failed = sum(1 for c in controls if c["status"] == "FAIL")

    summary = {
        "total": total,
        "passed": passed,
        "failed": failed,
        "coverage_percent": round((passed / total) * 100, 2) if total else 0.0
    }

    # -------------------------------------------------
    # Meta
    # -------------------------------------------------
    meta = {
        "asvs_version": args.asvs_version,
        "generated_at": iso_now(),
        "repo": args.repo or "unknown"
    }

    output = {
        "meta": meta,
        "summary": summary,
        "controls": sorted(
            controls,
            key=lambda x: (x["status"] != "FAIL", x["id"])
        )
    }

    # -------------------------------------------------
    # Write JSON
    # -------------------------------------------------
    out_json = Path(args.out_json)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(output, indent=2), encoding="utf-8")

    # -------------------------------------------------
    # Write Markdown (PR-friendly)
    # -------------------------------------------------
    md = [
        "## ASVS Coverage Report",
        "",
        f"- **Total controls:** `{total}`",
        f"- **Passed:** `{passed}`",
        f"- **Failed:** `{failed}`",
        f"- **Coverage:** `{summary['coverage_percent']}%`",
        "",
        "| Control | Level | Status |",
        "|--------|-------|--------|",
    ]

    for c in output["controls"]:
        md.append(f"| `{c['id']}` | `{c['level']}` | `{c['status']}` |")

    out_md = Path(args.out_md)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_md.write_text("\n".join(md), encoding="utf-8")

    # -------------------------------------------------
    # History (for trending)
    # -------------------------------------------------
    hist = Path(args.history)
    hist.parent.mkdir(parents=True, exist_ok=True)
    with hist.open("a", encoding="utf-8") as f:
        f.write(json.dumps({
            "ts": int(time.time()),
            "summary": summary
        }) + "\n")

    print("[OK] ASVS export complete")
    print(f"- JSON: {out_json}")
    print(f"- MD  : {out_md}")
    print(f"- History appended: {hist}")


if __name__ == "__main__":
    main()
