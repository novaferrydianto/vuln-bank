#!/usr/bin/env python3
import json
import sys
import os
from datetime import datetime, timezone
from pathlib import Path

if len(sys.argv) < 3:
    print("Usage: update_asvs_baseline.py <asvs-coverage.json> <baseline-dir>")
    sys.exit(2)

coverage_path = Path(sys.argv[1])
baseline_dir = Path(sys.argv[2])

baseline_dir.mkdir(parents=True, exist_ok=True)

baseline_path = baseline_dir / "asvs-baseline.json"
meta_path = baseline_dir / "asvs-baseline.meta.json"

coverage = json.loads(coverage_path.read_text(encoding="utf-8"))

baseline_path.write_text(
    json.dumps(coverage, indent=2),
    encoding="utf-8"
)

meta = {
    "updated_at": datetime.now(timezone.utc).isoformat(),
    "github_run_id": os.getenv("GITHUB_RUN_ID"),
    "github_sha": os.getenv("GITHUB_SHA"),
    "github_ref": os.getenv("GITHUB_REF"),
    "actor": os.getenv("GITHUB_ACTOR"),
}

meta_path.write_text(
    json.dumps(meta, indent=2),
    encoding="utf-8"
)

print(f"[OK] ASVS baseline updated at {baseline_path}")
