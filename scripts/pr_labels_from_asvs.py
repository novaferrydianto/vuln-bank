#!/usr/bin/env python3
import json, sys, os
from pathlib import Path

def main():
  if len(sys.argv) < 2:
    print("Usage: pr_labels_from_asvs.py <asvs-coverage.json>", file=sys.stderr)
    sys.exit(2)

  data = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
  owasp = data.get("owasp_top10_counts", [])

  # pick top 2 OWASP buckets
  top = sorted(owasp, key=lambda x: x["count"], reverse=True)[:2]
  labels = [f"owasp:{x['owasp'].split(':')[0].lower()}" for x in top if x.get("count", 0) > 0]

  Path("security-reports/pr-labels.json").write_text(json.dumps({"labels": labels}, indent=2), encoding="utf-8")
  print("[OK] Labels computed:", labels)

if __name__ == "__main__":
  main()
