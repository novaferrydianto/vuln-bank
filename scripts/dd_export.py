#!/usr/bin/env python3
"""
Convert LLM findings JSON → DefectDojo Generic Findings Import JSON.
"""

import argparse
import json
from pathlib import Path


SEVERITY_MAP = {
    "LOW": "Low",
    "MEDIUM": "Medium",
    "HIGH": "High",
    "CRITICAL": "Critical",
}


def parse_cwe(cwe_id: str) -> int:
    cwe_id = cwe_id.upper().strip()
    if cwe_id.startswith("CWE-"):
        cwe_id = cwe_id[4:]
    try:
        return int(cwe_id)
    except ValueError:
        return 0


def build_description(f: dict) -> str:
    parts: list[str] = []

    if summary := f.get("summary"):
        parts.append("Summary:")
        parts.append(summary)
        parts.append("")

    if reasoning := f.get("reasoning"):
        parts.append("Reasoning / Analysis:")
        parts.append(reasoning)
        parts.append("")

    if remediation := f.get("remediation"):
        parts.append("Suggested Remediation:")
        parts.append(remediation)
        parts.append("")

    for vc in (f.get("vulnerable_code") or [])[:5]:
        path = vc.get("path", "")
        snippet = vc.get("snippet", "")
        parts.append(f"- File: `{path}`")
        parts.append("```")
        parts.append(snippet[:4000])
        parts.append("```")
        parts.append("")

    return "\n".join(parts).strip()


def convert_findings(in_data: dict) -> dict:
    out: list[dict] = []

    for f in in_data.get("findings", []):
        sev = SEVERITY_MAP.get(str(f.get("severity", "MEDIUM")).upper(), "Medium")
        cwe = parse_cwe(str(f.get("cwe_id", "") or ""))

        vc = f.get("vulnerable_code") or []
        file_path = vc[0]["path"] if vc else ""

        out.append(
            {
                "title": f"LLM {str(f.get('type')).upper()}: {f.get('name')}",
                "description": build_description(f),
                "severity": sev,
                "cwe": cwe,
                "file_path": file_path,
                "line": 0,
                "references": "",
            },
        )

    return {"findings": out}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", "-i", required=True)
    parser.add_argument("--output", "-o", required=True)
    args = parser.parse_args()

    data = json.loads(Path(args.input).read_text("utf-8"))
    out_data = convert_findings(data)

    Path(args.output).write_text(json.dumps(out_data, indent=2), "utf-8")
    print(f"[OK] DefectDojo LLM export → {args.output}")


if __name__ == "__main__":
    main()
