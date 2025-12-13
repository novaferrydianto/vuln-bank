#!/usr/bin/env python3
import json, sys
from pathlib import Path
from collections import Counter

def main():
  if len(sys.argv) < 3:
    print("Usage: zap_summary.py <zap_alerts.json> <out.json>", file=sys.stderr)
    sys.exit(2)

  zap = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
  alerts = zap.get("site", [])
  # ZAP traditional-json structure varies; handle common shapes
  all_alerts = []
  for s in alerts:
    all_alerts.extend(s.get("alerts", []) or [])

  sev = Counter((a.get("riskdesc","Unknown").split(" ")[0] for a in all_alerts))
  out = {
    "total_alerts": len(all_alerts),
    "by_severity": dict(sev),
  }
  Path(sys.argv[2]).write_text(json.dumps(out, indent=2), encoding="utf-8")
  print("[OK] ZAP summary written")

if __name__ == "__main__":
  main()
