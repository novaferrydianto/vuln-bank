#!/usr/bin/env python3
import json
import sys
from collections import defaultdict
from pathlib import Path

def load_json(path: str):
    p = Path(path)
    if not p.exists():
        return {}
    return json.loads(p.read_text(encoding="utf-8"))

def as_string(x) -> str:
    if x is None:
        return ""
    if isinstance(x, str):
        return x.strip()
    if isinstance(x, (int, float, bool)):
        return str(x)
    if isinstance(x, dict):
        # common keys seen in semgrep metadata
        for k in ("id", "code", "control", "asvs", "name", "title"):
            v = x.get(k)
            if isinstance(v, str) and v.strip():
                return v.strip()
        # fallback: stable-ish compact dump
        return json.dumps(x, sort_keys=True)
    # list/tuple handled elsewhere
    return str(x).strip()

def extract_asvs_tags_from_semgrep(semgrep: dict):
    tags = []
    results = semgrep.get("results", []) or []

    for r in results:
        md = (r.get("extra", {}) or {}).get("metadata", {}) or {}

        # many projects store ASVS in one of these shapes:
        # - md["asvs"] = ["V1.2.3", ...]
        # - md["asvs"] = [{"id":"V1.2.3","name":"..."}, ...]
        # - md["asvs"] = {"id":"V1.2.3"}  (single dict)
        # - md["owasp"] / md["references"] etc (optional)
        asvs = md.get("asvs")

        if isinstance(asvs, list):
            for item in asvs:
                s = as_string(item)
                if s:
                    tags.append(s)
        elif isinstance(asvs, dict):
            s = as_string(asvs)
            if s:
                tags.append(s)
        elif isinstance(asvs, str):
            if asvs.strip():
                tags.append(asvs.strip())

    return tags

def extract_asvs_tags_from_bandit_dd(bandit_dd: dict):
    tags = []
    # adjust if your bandit_normalize outputs a different shape
    findings = bandit_dd.get("findings", []) or bandit_dd.get("results", []) or []
    for f in findings:
        md = f.get("metadata", {}) or {}
        asvs = md.get("asvs")
        if isinstance(asvs, list):
            for item in asvs:
                s = as_string(item)
                if s:
                    tags.append(s)
        elif isinstance(asvs, (dict, str)):
            s = as_string(asvs)
            if s:
                tags.append(s)
    return tags

def main():
    if len(sys.argv) < 3:
        print("Usage: asvs_coverage.py <semgrep.json> <bandit_dd.json>", file=sys.stderr)
        sys.exit(2)

    semgrep_path = sys.argv[1]
    bandit_path = sys.argv[2]

    semgrep = load_json(semgrep_path)
    bandit = load_json(bandit_path)

    coverage = defaultdict(int)

    for t in extract_asvs_tags_from_semgrep(semgrep):
        coverage[t] += 1
    for t in extract_asvs_tags_from_bandit_dd(bandit):
        coverage[t] += 1

    # Print simple report
    total = sum(coverage.values())
    unique = len(coverage)
    print(f"ASVS coverage signals: total={total}, unique_tags={unique}")

    # Show top tags
    for k in sorted(coverage.keys())[:50]:
        print(f"- {k}: {coverage[k]}")

if __name__ == "__main__":
    main()
