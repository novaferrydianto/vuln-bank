#!/usr/bin/env python3
import json
import os
from pathlib import Path

REPORT_DIR = Path("security-reports")
EPSS_FILE = REPORT_DIR / "epss-findings.json"
LLM_FILE = REPORT_DIR / "llm-findings.json"
CODEQL_FILE = REPORT_DIR / "codeql-results.sarif"

COMPOSITE_OUT = REPORT_DIR / "composite-findings.json"
THRESHOLD = float(os.getenv("COMPOSITE_THRESHOLD", "0.65"))


def safe_json(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        text = path.read_text().strip()
        return json.loads(text) if text else {}
    except Exception:
        return {}


def load_sarif(path: Path) -> int:
    data = safe_json(path)
    runs = data.get("runs", [])
    if not runs:
        return 0
    return len(runs[0].get("results", []))


def compute_risk() -> dict:
    epss = safe_json(EPSS_FILE)
    llm = safe_json(LLM_FILE)
    codeql_count = load_sarif(CODEQL_FILE)

    high_epss = len(epss.get("high_risk", []))
    llm_issues = len(llm.get("issues", [])) if isinstance(llm, dict) else 0

    score = (
        (1 if high_epss > 0 else 0) * 0.5
        + (1 if codeql_count > 0 else 0) * 0.3
        + (1 if llm_issues > 0 else 0) * 0.2
    )

    status = "FAIL" if score >= THRESHOLD else "PASS"

    return {
        "score": round(score, 4),
        "status": status,
        "epss_high": high_epss,
        "codeql_findings": codeql_count,
        "llm_issues": llm_issues,
        "threshold": THRESHOLD,
    }


def main():
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    result = compute_risk()
    COMPOSITE_OUT.write_text(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
