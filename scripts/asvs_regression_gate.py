#!/usr/bin/env python3
import json, sys
from pathlib import Path

def load(path: str):
  p = Path(path)
  if not p.exists():
    return None
  return json.loads(p.read_text(encoding="utf-8"))

def main():
  if len(sys.argv) < 4:
    print("Usage: asvs_regression_gate.py <current.json> <baseline.json> <gate_failed_path>", file=sys.stderr)
    sys.exit(2)

  cur = load(sys.argv[1])
  base = load(sys.argv[2])
  gate_path = Path(sys.argv[3])

  # If no baseline yet, do not fail (first-run bootstrap)
  if base is None:
    print("[INFO] No ASVS baseline found, skipping regression gate (bootstrap).")
    return

  cur_unique = cur["totals"]["unique_asvs_tags"]
  base_unique = base["totals"]["unique_asvs_tags"]

  # Regression rule: unique tags must not drop
  if cur_unique < base_unique:
    gate_path.write_text("ASVS regression gate failed\n", encoding="utf-8")
    print(f"[GATE] 🚨 FAILED – ASVS unique tags dropped: {base_unique} -> {cur_unique}")
    sys.exit(1)

  print(f"[GATE] ✅ PASSED – ASVS unique tags: {base_unique} -> {cur_unique}")

if __name__ == "__main__":
  main()
