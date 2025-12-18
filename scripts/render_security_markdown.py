#!/usr/bin/env python3
import os
import json
import argparse


def safe_load_json(path: str, base_dir="docs/data"):
    base_real = os.path.realpath(base_dir)
    target_real = os.path.realpath(path)

    if not target_real.startswith(base_real + os.sep):
        raise ValueError(f"Unsafe path: {path}")

    if not os.path.exists(target_real):
        return None

    try:
        with open(target_real) as f:
            return json.load(f)
    except Exception:
        return None


def render_md(data: dict) -> str:
    overview = data.get("overview", {})
    epss = data.get("epss", {})
    llm = data.get("llm", {})
    sla = data.get("sla", {})

    md = []
    md.append("# Security Board Report\n")

    md.append("## Executive Summary")
    md.append(f"- Overall Risk: **{overview.get('overall_risk', 'UNKNOWN')}**")
    md.append(f"- Total Findings: {overview.get('total_findings', 0)}")
    md.append(f"- Critical Issues: {overview.get('critical', 0)}\n")

    md.append("## EPSS Summary")
    md.append(f"- High-risk EPSS: {epss.get('high_risk', 0)}")
    md.append(f"- Threshold: {epss.get('threshold', 'N/A')}\n")

    md.append("## LLM Findings")
    md.append(f"- Total LLM findings: {llm.get('count', 0)}")
    md.append(f"- High-risk: {llm.get('high', 0)}\n")

    md.append("## SLA")
    md.append(f"- Violations: {sla.get('violations', 0)}")
    md.append(f"- Near expiry: {sla.get('near_expiry', 0)}\n")

    return "\n".join(md)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("scorecard_json")
    args = parser.parse_args()

    try:
        data = safe_load_json(args.scorecard_json)
    except Exception as e:
        print(f"[ERROR] {e}")
        data = None

    if not data:
        print("# Security Board Report\nNo data available.")
        return

    print(render_md(data))


if __name__ == "__main__":
    main()
