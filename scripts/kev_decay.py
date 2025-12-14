#!/usr/bin/env python3
"""
KEV Decay Engine
Risk only decays when remediation evidence exists
"""

from pathlib import Path
import json
from datetime import datetime, timezone

EPSF = Path("docs/data/epss-findings.json")
MANUAL = Path("security-baselines/kev-remediation.json")

DECAY_STEP = 0.5  # 50% reduction per resolved KEV


def load(path):
    return json.loads(path.read_text()) if path.exists() else {}


def main():
    epss = load(EPSF)
    manual = load(MANUAL)

    high_risk = epss.get("high_risk", [])
    kev_all = [v for v in high_risk if v.get("is_kev")]

    kev_open = []
    kev_resolved = []

    for v in kev_all:
        cve = v.get("cve")

        # Evidence via fixed_version
        if v.get("fixed_version"):
            kev_resolved.append(cve)
            continue

        # Manual override
        if cve in manual:
            kev_resolved.append(cve)
            continue

        kev_open.append(cve)

    total = len(kev_all)
    resolved = len(kev_resolved)

    decay_score = 1.0
    if total > 0:
        decay_score = max(
            0.0,
            1.0 - (resolved / total) * DECAY_STEP
        )

    out = {
        "kev_total": total,
        "kev_open": kev_open,
        "kev_resolved": kev_resolved,
        "kev_decay_score": round(decay_score, 2),
        "generated_at": datetime.now(timezone.utc).isoformat()
    }

    Path("security-metrics/weekly/kev-decay.json").write_text(
        json.dumps(out, indent=2)
    )

    print("✅ KEV decay calculated")
    print(out)


if __name__ == "__main__":
    main()
