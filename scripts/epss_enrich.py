#!/usr/bin/env python3
"""
epss_enrich.py
--------------
Enrich normalized.json with EPSS scores and compute summary.exploitable.

Policy:
- Only HIGH / CRITICAL findings with CVE are evaluated
- Skip findings already having epss
- baseline=true findings NEVER trigger exploitable
- exploitable = any(
      severity HIGH|CRITICAL
      AND epss >= EPSS_THRESHOLD
      AND baseline == false
  )
"""

import json
import os
import urllib.request
from pathlib import Path
from typing import Dict, Any, List

REPORT_DIR = Path("security-reports")
NORMALIZED_PATH = REPORT_DIR / "normalized.json"
EPSS_API = "https://api.first.org/data/v1/epss"
EPSS_THRESHOLD = float(os.getenv("EPSS_THRESHOLD", "0.5"))


# -------------------------------------------------
# Helpers
# -------------------------------------------------

def load_json(path: Path) -> Dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except Exception:
        return None


def save_json(path: Path, data: Dict[str, Any]) -> None:
    path.write_text(json.dumps(data, indent=2))


def fetch_epss(cves: List[str]) -> Dict[str, float]:
    """
    Fetch EPSS score per CVE (sequential, simple, deterministic).
    """
    results: Dict[str, float] = {}

    for cve in sorted(set(cves)):
        try:
            url = f"{EPSS_API}?cve={cve}"
            with urllib.request.urlopen(url, timeout=10) as resp:
                payload = json.loads(resp.read().decode())

            score = float(payload.get("data", [{}])[0].get("epss", 0.0))
            results[cve] = score
        except Exception as exc:
            print(f"⚠️ EPSS fetch failed for {cve}: {exc}")
            results[cve] = 0.0

    return results


# -------------------------------------------------
# Main logic
# -------------------------------------------------

def main() -> None:
    data = load_json(NORMALIZED_PATH)
    if not data:
        print("⚠️ normalized.json not found, skipping EPSS enrichment")
        return

    findings: List[Dict[str, Any]] = data.get("findings", [])
    summary = data.setdefault("summary", {})

    # 1️⃣ Collect CVEs needing EPSS
    cves: List[str] = []
    for f in findings:
        if (
            f.get("severity") in ("HIGH", "CRITICAL")
            and f.get("cve")
            and f.get("epss") is None
        ):
            cves.append(f["cve"])

    if not cves:
        summary.setdefault("exploitable", False)
        save_json(NORMALIZED_PATH, data)
        print("✅ EPSS enrichment skipped (no CVEs)")
        return

    # 2️⃣ Fetch EPSS
    epss_map = fetch_epss(cves)

    # 3️⃣ Assign EPSS back to findings
    for f in findings:
        cve = f.get("cve")
        if cve in epss_map:
            f["epss"] = epss_map[cve]

    # 4️⃣ Compute exploitable flag
    exploitable = False
    for f in findings:
        if (
            f.get("severity") in ("HIGH", "CRITICAL")
            and isinstance(f.get("epss"), (int, float))
            and f["epss"] >= EPSS_THRESHOLD
            and not f.get("baseline", False)
        ):
            exploitable = True
            break

    # 5️⃣ Write summary metadata
    summary["exploitable"] = exploitable
    summary["epss"] = {
        "threshold": EPSS_THRESHOLD,
        "source": "FIRST.org",
    }

    save_json(NORMALIZED_PATH, data)

    print(
        f"✅ EPSS enrichment done | "
        f"threshold={EPSS_THRESHOLD} | exploitable={exploitable}"
    )


# -------------------------------------------------
# Entrypoint
# -------------------------------------------------
if __name__ == "__main__":
    main()
