#!/usr/bin/env python3
"""
ASVS Coverage Exporter (Enterprise-ready)

Inputs:
- Semgrep JSON
- Bandit DefectDojo-normalized JSON

Outputs:
- JSON coverage (schema-compliant: meta + summary + controls)
- Markdown coverage (PR-friendly)
- ASVS history (jsonl) for trending
"""

import argparse
import json
import os
import time
from pathlib import Path
from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, Any, Iterable, Tuple


# ----------------------------
# Helpers
# ----------------------------
def load_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def normalize_asvs_id(x: str) -> str:
    # Keep stable formatting; avoid accidental whitespace / casing issues
    return str(x).strip()


def extract_asvs_from_semgrep(data: Dict[str, Any]) -> Iterable[str]:
    for r in data.get("results", []):
        md = (r.get("extra", {}) or {}).get("metadata", {}) or {}
        asvs = md.get("asvs")
        if isinstance(asvs, list):
            for x in asvs:
                yield normalize_asvs_id(x)
        elif isinstance(asvs, str):
            yield normalize_asvs_id(asvs)
        elif isinstance(asvs, dict):
            for k in ("id", "code", "control"):
                if k in asvs:
                    yield normalize_asvs_id(asvs[k])


def extract_asvs_from_bandit(bandit_dd: Dict[str, Any]) -> Iterable[str]:
    findings = bandit_dd.get("findings") or bandit_dd.get("results") or []
    for f in findings:
        md = f.get("metadata", {}) or {}
        asvs = md.get("asvs")
        if isinstance(asvs, list):
            for x in asvs:
                yield normalize_asvs_id(x)
        elif isinstance(asvs, str):
            yield normalize_asvs_id(asvs)
        elif isinstance(asvs, dict):
            for k in ("id", "code", "control"):
                if k in asvs:
                    yield normalize_asvs_id(asvs[k])


def guess_level(asvs_id: str, default_level: int = 1) -> int:
    """
    Schema requires level in {1,2,3}. If you later encode level in tags (e.g. "V2.1.1:L2"),
    you can parse it here. For now, we keep deterministic safe default: 1.
    """
    # Example future-proof parsing:
    # if ":L2" in asvs_id.upper(): return 2
    return default_level


def now_iso_z() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


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
    ap.add_argument("--asvs-version", default=os.getenv("ASVS_VERSION", "4.0.3"))
    args = ap.parse_args()

    semgrep = load_json(Path(args.semgrep))
    bandit = load_json(Path(args.bandit))
    baseline = load_json(Path(args.baseline))

    # counts per ASVS control
    counts = defaultdict(int)

    # evidence sources per ASVS control (stable list)
    evidence = defaultdict(set)

    for tag in extract_asvs_from_semgrep(semgrep):
        if tag:
            counts[tag] += 1
            evidence[tag].add("semgrep")

    for tag in extract_asvs_from_bandit(bandit):
        if tag:
            counts[tag] += 1
            evidence[tag].add("bandit")

    counts = dict(sorted(counts.items()))
    total_signals = sum(counts.values())
    unique_controls = len(counts)

    # ----------------------------
    # Build schema-required controls[]
    # IMPORTANT: With only "signals", we can safely mark discovered controls as FAIL
    # (signal == finding evidence). PASS coverage requires a full ASVS catalog,
    # which we don't have yet.
    # ----------------------------
    controls = []
    for control_id, cnt in counts.items():
        controls.append({
            "id": control_id,
            "level": guess_level(control_id, default_level=1),
            "status": "FAIL" if cnt > 0 else "PASS",
            "evidence": sorted(list(evidence.get(control_id, set()))),
            # keep extra fields (allowed by schema.additionalProperties)
            "count": cnt,
        })

    # Schema summary contract
    # Here: total = discovered controls; failed = discovered (signals imply findings); passed = 0
    passed = sum(1 for c in controls if c["status"] == "PASS")
    failed = sum(1 for c in controls if c["status"] == "FAIL")
    total = len(controls)
    coverage_percent = round((passed / total) * 100, 2) if total else 0.0

    meta = {
        "asvs_version": str(args.asvs_version),
        "generated_at": now_iso_z(),
        "repo": os.getenv("GITHUB_REPOSITORY", "unknown"),
    }

    # ----------------------------
    # Delta vs baseline (preserve your existing model)
    # ----------------------------
    delta = {"added": [], "removed": [], "changed": {}}
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

    # ----------------------------
    # Final output (schema-compliant + extra analytics)
    # ----------------------------
    out_obj = {
        "meta": meta,
        "summary": {
            "total": total,
            "passed": passed,
            "failed": failed,
            "coverage_percent": coverage_percent,
            # extra analytics (allowed)
            "total_signals": total_signals,
            "unique_controls": unique_controls,
        },
        "controls": controls,

        # extra fields (allowed by schema.additionalProperties)
        "counts": counts,
        "delta": delta,
    }

    # ----------------------------
    # Write JSON
    # ----------------------------
    out_json = Path(args.out_json)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(out_obj, indent=2), encoding="utf-8")

    # ----------------------------
    # Write Markdown
    # ----------------------------
    lines = [
        "## ASVS Coverage Report",
        "",
        f"- **ASVS version:** `{meta['asvs_version']}`",
        f"- **Generated at:** `{meta['generated_at']}`",
        f"- **Repo:** `{meta.get('repo','unknown')}`",
        "",
        "### Summary",
        "",
        f"- **Total controls (discovered):** `{total}`",
        f"- **Passed:** `{passed}`",
        f"- **Failed:** `{failed}`",
        f"- **Coverage:** `{coverage_percent}%`",
        f"- **Total signals:** `{total_signals}`",
        "",
        "### Controls (discovered)",
        "",
        "| ASVS Control | Level | Status | Evidence | Count |",
        "|--------------|-------|--------|----------|-------|",
    ]

    for c in controls:
        ev = ", ".join(c.get("evidence", []))
        lines.append(f"| `{c['id']}` | `{c['level']}` | `{c['status']}` | `{ev}` | `{c.get('count',0)}` |")

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
        "meta": meta,
        "summary": {
            "total": total,
            "passed": passed,
            "failed": failed,
            "coverage_percent": coverage_percent,
            "total_signals": total_signals,
            "unique_controls": unique_controls,
        },
    }
    with hist.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")

    print("[OK] ASVS export complete")
    print(f"- JSON: {out_json}")
    print(f"- MD  : {out_md}")
    print(f"- History appended: {hist}")


if __name__ == "__main__":
    main()
