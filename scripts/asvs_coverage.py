#!/usr/bin/env python3
import json, sys, collections

coverage = collections.Counter()

for path in sys.argv[1:]:
    try:
        data = json.load(open(path))
    except:
        continue

    for r in data.get("results", []):
        meta = r.get("extra", {}).get("metadata", {})
        asvs = meta.get("asvs")
        if asvs:
            coverage[asvs] += 1

print("ASVS Coverage:")
for k, v in sorted(coverage.items()):
    print(f"{k}: {v}")
