#!/usr/bin/env python3
import json, sys, os
from pathlib import Path
from datetime import datetime, timezone

def read_last_entry(hist_path: Path):
  if not hist_path.exists():
    return None
  lines = hist_path.read_text(encoding="utf-8").splitlines()
  for line in reversed(lines):
    line = line.strip()
    if line:
      try:
        return json.loads(line)
      except Exception:
        continue
  return None

def main():
  if len(sys.argv) < 4:
    print("Usage: asvs_trend.py <asvs-coverage.json> <asvs-history.jsonl> <out-delta.json>", file=sys.stderr)
    sys.exit(2)

  cov_path = Path(sys.argv[1])
  hist_path = Path(sys.argv[2])
  delta_path = Path(sys.argv[3])

  cov = json.loads(cov_path.read_text(encoding="utf-8"))
  now = datetime.now(timezone.utc).isoformat()

  hist_path.parent.mkdir(parents=True, exist_ok=True)
  last = read_last_entry(hist_path)

  cur_unique = cov["totals"]["unique_asvs_tags"]
  cur_total = cov["totals"]["signals_total"]

  prev_unique = last["totals"]["unique_asvs_tags"] if last else 0
  prev_total = last["totals"]["signals_total"] if last else 0

  delta = {
    "timestamp": now,
    "run_id": os.getenv("GITHUB_RUN_ID", "manual"),
    "commit": os.getenv("GITHUB_SHA", ""),
    "unique_asvs_delta": int(cur_unique - prev_unique),
    "signals_total_delta": int(cur_total - prev_total),
    "current": {"unique_asvs_tags": cur_unique, "signals_total": cur_total},
    "previous": {"unique_asvs_tags": prev_unique, "signals_total": prev_total},
  }

  # Append current coverage snapshot to history
  hist_path.open("a", encoding="utf-8").write(json.dumps(cov) + "\n")
  delta_path.write_text(json.dumps(delta, indent=2), encoding="utf-8")
  print(f"[OK] ASVS history appended: {hist_path}")
  print(f"[OK] ASVS delta written: {delta_path}")

if __name__ == "__main__":
  main()
