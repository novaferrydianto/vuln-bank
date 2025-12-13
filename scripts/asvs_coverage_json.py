#!/usr/bin/env python3
import json, sys, re, os
from pathlib import Path
from collections import defaultdict
from datetime import datetime, timezone

ASVS_RE = re.compile(r"V\d+(?:\.\d+)+")

# ASVS -> OWASP Top 10 (2021) mapping (practical coverage map)
ASVS_TO_OWASP = {
  # V1: Architecture, Design, Threat Modeling
  "V1": ["A04:2021-Insecure Design", "A05:2021-Security Misconfiguration"],
  # V2: Authentication
  "V2": ["A07:2021-Identification and Authentication Failures", "A01:2021-Broken Access Control"],
  # V3: Session Management
  "V3": ["A07:2021-Identification and Authentication Failures"],
  # V4: Access Control
  "V4": ["A01:2021-Broken Access Control"],
  # V5: Validation, Sanitization, Encoding
  "V5": ["A03:2021-Injection", "A02:2021-Cryptographic Failures"],
  # V6: Stored Cryptography
  "V6": ["A02:2021-Cryptographic Failures"],
  # V7: Error Handling & Logging
  "V7": ["A09:2021-Security Logging and Monitoring Failures"],
  # V8: Data Protection
  "V8": ["A02:2021-Cryptographic Failures"],
  # V9: Communication
  "V9": ["A02:2021-Cryptographic Failures", "A05:2021-Security Misconfiguration"],
  # V10: Malicious Code
  "V10": ["A08:2021-Software and Data Integrity Failures"],
  # V11: Business Logic
  "V11": ["A04:2021-Insecure Design"],
  # V12: Files & Resources
  "V12": ["A05:2021-Security Misconfiguration", "A10:2021-SSRF"],
  # V13: APIs & Web Services
  "V13": ["A03:2021-Injection", "A01:2021-Broken Access Control", "A05:2021-Security Misconfiguration"],
  # V14: Configuration
  "V14": ["A05:2021-Security Misconfiguration"],
}

def load_json(path: str):
  p = Path(path)
  if not p.exists():
    return {}
  return json.loads(p.read_text(encoding="utf-8"))

def as_string(x) -> str:
  if x is None: return ""
  if isinstance(x, str): return x.strip()
  if isinstance(x, (int, float, bool)): return str(x)
  if isinstance(x, dict):
    for k in ("id","code","control","asvs","name","title"):
      v = x.get(k)
      if isinstance(v, str) and v.strip():
        return v.strip()
    return json.dumps(x, sort_keys=True)
  return str(x).strip()

def normalize_asvs(tag: str) -> str:
  m = ASVS_RE.search(tag)
  return m.group(0) if m else tag

def extract_asvs_from_semgrep(semgrep: dict):
  tags = []
  for r in semgrep.get("results", []) or []:
    md = ((r.get("extra") or {}).get("metadata") or {})
    asvs = md.get("asvs")
    if isinstance(asvs, list):
      for item in asvs:
        s = as_string(item)
        if s: tags.append(normalize_asvs(s))
    elif isinstance(asvs, (dict, str)):
      s = as_string(asvs)
      if s: tags.append(normalize_asvs(s))
  return tags

def extract_asvs_from_bandit_dd(bandit: dict):
  tags = []
  findings = bandit.get("findings", []) or bandit.get("results", []) or []
  for f in findings:
    md = f.get("metadata", {}) or {}
    asvs = md.get("asvs")
    if isinstance(asvs, list):
      for item in asvs:
        s = as_string(item)
        if s: tags.append(normalize_asvs(s))
    elif isinstance(asvs, (dict, str)):
      s = as_string(asvs)
      if s: tags.append(normalize_asvs(s))
  return tags

def map_to_owasp(asvs_tag: str):
  # Tag like V5.3.2 -> take V5
  major = asvs_tag.split(".")[0]
  return ASVS_TO_OWASP.get(major, [])

def main():
  if len(sys.argv) < 4:
    print("Usage: asvs_coverage_json.py <semgrep.json> <bandit_dd.json> <out.json>", file=sys.stderr)
    sys.exit(2)

  semgrep_path, bandit_path, out_path = sys.argv[1], sys.argv[2], sys.argv[3]
  semgrep = load_json(semgrep_path)
  bandit = load_json(bandit_path)

  counts = defaultdict(int)
  sources = {"semgrep": 0, "bandit": 0}
  owasp_counts = defaultdict(int)

  for t in extract_asvs_from_semgrep(semgrep):
    counts[t] += 1
    sources["semgrep"] += 1
    for o in map_to_owasp(t):
      owasp_counts[o] += 1

  for t in extract_asvs_from_bandit_dd(bandit):
    counts[t] += 1
    sources["bandit"] += 1
    for o in map_to_owasp(t):
      owasp_counts[o] += 1

  tags_sorted = sorted(counts.items(), key=lambda x: (-x[1], x[0]))
  now = datetime.now(timezone.utc).isoformat()

  payload = {
    "timestamp": now,
    "run_id": os.getenv("GITHUB_RUN_ID", "manual"),
    "commit": os.getenv("GITHUB_SHA", ""),
    "ref": os.getenv("GITHUB_REF", ""),
    "totals": {
      "signals_total": int(sum(counts.values())),
      "unique_asvs_tags": int(len(counts)),
      "by_source": sources,
    },
    "asvs_counts": [{"asvs": k, "count": v} for k, v in tags_sorted],
    "owasp_top10_counts": [{"owasp": k, "count": int(v)} for k, v in sorted(owasp_counts.items())],
  }

  Path(out_path).parent.mkdir(parents=True, exist_ok=True)
  Path(out_path).write_text(json.dumps(payload, indent=2), encoding="utf-8")
  print(f"[OK] ASVS coverage JSON written: {out_path}")

if __name__ == "__main__":
  main()
