#!/usr/bin/env python3
"""
ASVS Coverage Exporter (Enterprise-ready)

Inputs:
- Semgrep JSON
- Bandit DefectDojo-normalized JSON

Outputs:
- JSON coverage (counts + summary)
- Markdown coverage (PR-friendly)
- ASVS history (jsonl) for trending
"""

import argparse
import json
import time
from pathlib import Path
from collections import defaultdict
from typing import Dict, Any, Iterable


# ----------------------------
# Helpers
# ----------------------------
def load_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def extract_asvs_from_semgrep(data: Dict[str, Any]) -> Iterable[str]:
    for r in data.get("results", []):
        md = (r.get("extra", {}) or {}).get("metadata", {}) or {}
        asvs = md.get("asvs")
        if isinstance(asvs, list):
            for x in asvs:
                yield str(x).strip()
        elif isinstance(asvs, str):
            yield asvs.strip()
        elif isinstance(asvs, dict):
            for k in ("id", "code", "control"):
                if k in asvs:
                    yield str(asvs[k]).strip()


def extract_asvs_from_bandit(bandit_dd: Dict[str, Any]) -> Iterable[str]:
    findings = bandit_dd.get("findings") or bandit_dd.get("results") or []
    for f in findings:
        md = f.get("metadata", {}) or {}
        asvs = md.get("asvs")
        if isinstance(asvs, list):
            for x in asvs:
                yield str(x).strip()
        elif isinstance(asvs, str):
            yield asvs.strip()
        elif isinstance(asvs, dict):
            for k in ("id", "code", "control"):
                if k in asvs:
                    yield str(asvs[k]).strip()


# ----------------------------
# Main
# ----------------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--semgrep", required=True)
    ap.add_argument("--bandit", required=True)
    ap.add_argument("--out-json", required=True)
    ap.add_argument("--out-md", required=True)
    ap.add_argument("--baseline", default="security-baselines/asvs-baseline.json")
    ap.add_argument("--history", default="security-reports/governance/asvs-history.jsonl")
    args = ap.parse_args()

    semgrep = load_json(Path(args.semgrep))
    bandit = load_json(Path(args.bandit))
    baseline = load_json(Path(args.baseline))

    counts = defaultdict(int)

    for tag in extract_asvs_from_semgrep(semgrep):
        if tag:
            counts[tag] += 1

    for tag in extract_asvs_from_bandit(bandit):
        if tag:
            counts[tag] += 1

    counts = dict(sorted(counts.items()))
    total_signals = sum(counts.values())

    summary = {
        "total_signals": total_signals,
        "unique_controls": len(counts),
    }

    current = {
        "summary": summary,
        "counts": counts,
    }

    # ----------------------------
    # Delta vs baseline
    # ----------------------------
    delta = {
        "added": [],
        "removed": [],
        "changed": {},
    }

    base_counts = baseline.get("counts", {}) if isinstance(baseline, dict) else {}

    cur_keys = set(counts.keys())
    base_keys = set(base_counts.keys())

    delta["added"] = sorted(cur_keys - base_keys)
    delta["removed"] = sorted(base_keys - cur_keys)

    for k in sorted(cur_keys & base_keys):
        if counts[k] != base_counts.get(k, 0):
            delta["changed"][k] = {
                "baseline": base_counts.get(k, 0),
                "current": counts[k],
                "delta": counts[k] - base_counts.get(k, 0),
            }

    current["delta"] = delta

    # ----------------------------
    # Write JSON
    # ----------------------------
    out_json = Path(args.out_json)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(current, indent=2), encoding="utf-8")

    # ----------------------------
    # Write Markdown
    # ----------------------------
    lines = [
        "## ASVS Coverage Report",
        "",
        f"- **Total signals:** `{summary['total_signals']}`",
        f"- **Unique ASVS controls:** `{summary['unique_controls']}`",
        "",
        "### Coverage",
        "",
        "| ASVS Control | Count |",
        "|--------------|-------|",
    ]

    for k, v in counts.items():
        lines.append(f"| `{k}` | `{v}` |")

    lines += [
        "",
        "### Delta vs Baseline",
        "",
        f"- **Added:** {len(delta['added'])}",
        f"- **Removed:** {len(delta['removed'])}",
        f"- **Changed:** {len(delta['changed'])}",
    ]

    if delta["removed"] or any(v["delta"] < 0 for v in delta["changed"].values()):
        lines.append("")
        lines.append("> ❌ **ASVS regression detected**")

    out_md = Path(args.out_md)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_md.write_text("\n".join(lines), encoding="utf-8")

    # ----------------------------
    # History (jsonl)
    # ----------------------------
    hist = Path(args.history)
    hist.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "ts": int(time.time()),
        "summary": summary,
    }
    with hist.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")

    print("[OK] ASVS export complete")
    print(f"- JSON: {out_json}")
    print(f"- MD  : {out_md}")
    print(f"- History appended: {hist}")


if __name__ == "__main__":
    main()
