#!/usr/bin/env python3
"""
baseline_apply.py
-----------------
Apply risk acceptance baseline into normalized findings.

- Matches by fingerprint (deterministic)
- Enforces expiry
- Marks baseline=true only when valid

Input:
- security-reports/normalized.json
- scripts/baseline.json

Output:
- security-reports/normalized.json (in-place)
"""

import json
from pathlib import Path
from datetime import datetime, timezone

REPORT_DIR = Path("security-reports")
NORMALIZED_PATH = REPORT_DIR / "normalized.json"
BASELINE_PATH = Path("scripts/baseline.json")


def load_json(path: Path):
    try:
        return json.loads(path.read_text())
    except Exception:
        return None


def is_expired(expires_at: str) -> bool:
    try:
        exp = datetime.fromisoformat(expires_at).replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) > exp
    except Exception:
        return True  # invalid date = expired


def main():
    normalized = load_json(NORMALIZED_PATH)
    if not normalized:
        print("⚠️ normalized.json not found, skipping baseline apply")
        return

    baseline = load_json(BASELINE_PATH)
    if not baseline:
        print("ℹ️ baseline.json not found, no baseline applied")
        return

    accepted = baseline.get("accepted", [])
    if not accepted:
        print("ℹ️ baseline.json empty, nothing to apply")
        return

    baseline_map = {
        b["fingerprint"]: b
        for b in accepted
        if "fingerprint" in b
    }

    applied = 0
    expired = 0

    for f in normalized.get("findings", []):
        fp = f.get("fingerprint")
        entry = baseline_map.get(fp)

        if not entry:
            continue

        if is_expired(entry.get("expires_at", "")):
            expired += 1
            continue

        f["baseline"] = True
        f["baseline_reason"] = entry.get("reason")
        f["baseline_ticket"] = entry.get("ticket")
        f["baseline_expires_at"] = entry.get("expires_at")
        applied += 1

    NORMALIZED_PATH.write_text(json.dumps(normalized, indent=2))

    print(f"✅ Baseline applied: {applied}")
    if expired:
        print(f"⚠️ Expired baselines ignored: {expired}")


if __name__ == "__main__":
    main()
