# llm/pipeline.py

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict, Any

from llm.analyzers.bac_agent import BacAgent
from llm.analyzers.ssrf_agent import SSRFAgent
from llm.analyzers.ssti_agent import SSTIAgent
from llm.analyzers.sqli_agent import SQLIAgent
from llm.analyzers.traversal_agent import TraversalAgent
from llm.utils.scanner import scan_codebase


def run_llm_sast(project_root: str | Path) -> Dict[str, Any]:
    """
    Jalankan semua agent LLM terhadap codebase dan kembalikan findings terstruktur.
    Struktur output:

    {
      "meta": {...},
      "findings": {
        "bac": [...],
        "ssrf": [...],
        "ssti": [...],
        "sqli": [...],
        "traversal": [...]
      }
    }
    """
    root = Path(project_root).resolve()
    code_context = scan_codebase(root)

    agents = {
      "bac": BacAgent(),
      "ssrf": SSRFAgent(),
      "ssti": SSTIAgent(),
      "sqli": SQLIAgent(),
      "traversal": TraversalAgent(),
    }

    findings: Dict[str, Any] = {}
    for key, agent in agents.items():
        print(f"[LLM] Running {key} analyzer...")
        try:
            findings[key] = agent.analyze(code_context) or []
        except Exception as exc:  # defensive: jangan jatuhkan pipeline
            print(f"[LLM] {key} analyzer error: {exc}")
            findings[key] = []

    return {
        "meta": {
            "root": str(root),
            "agents": list(agents.keys()),
            "version": "2025.01",
        },
        "findings": findings,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="LLM SAST Multi-Agent Pipeline (BAC/SSRF/SSTI/SQLi/Traversal)")
    parser.add_argument(
        "--scan-path",
        "-s",
        required=True,
        help="Path ke codebase (root project)."
    )
    parser.add_argument(
        "--output",
        "-o",
        default="security-reports/llm-findings.json",
        help="Path output JSON findings."
    )
    args = parser.parse_args()

    result = run_llm_sast(args.scan_path)

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(result, indent=2), encoding="utf-8")

    print(f"[LLM] Findings written to {out_path}")


if __name__ == "__main__":
    main()
