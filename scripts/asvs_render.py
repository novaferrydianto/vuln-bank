#!/usr/bin/env python3
import json, sys
from pathlib import Path

def main():
  if len(sys.argv) < 3:
    print("Usage: asvs_render.py <asvs-coverage.json> <out.md>", file=sys.stderr)
    sys.exit(2)

  src, out = sys.argv[1], sys.argv[2]
  data = json.loads(Path(src).read_text(encoding="utf-8"))

  totals = data.get("totals", {})
  rows = data.get("asvs_counts", [])[:30]
  owasp = data.get("owasp_top10_counts", [])[:10]

  md = []
  md.append("## ASVS Coverage Summary")
  md.append("")
  md.append(f"- Signals total: **{totals.get('signals_total', 0)}**")
  md.append(f"- Unique ASVS tags: **{totals.get('unique_asvs_tags', 0)}**")
  md.append(f"- Source: semgrep={totals.get('by_source', {}).get('semgrep', 0)}, bandit={totals.get('by_source', {}).get('bandit', 0)}")
  md.append("")
  md.append("### Top ASVS Tags (Top 30)")
  md.append("")
  md.append("| ASVS | Count |")
  md.append("|---|---:|")
  for r in rows:
    md.append(f"| {r['asvs']} | {r['count']} |")
  md.append("")
  md.append("### OWASP Top 10 Coverage Signals")
  md.append("")
  md.append("| OWASP Top 10 | Count |")
  md.append("|---|---:|")
  for r in owasp:
    md.append(f"| {r['owasp']} | {r['count']} |")

  Path(out).parent.mkdir(parents=True, exist_ok=True)
  Path(out).write_text("\n".join(md) + "\n", encoding="utf-8")
  print(f"[OK] ASVS markdown written: {out}")

if __name__ == "__main__":
  main()
