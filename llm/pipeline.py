#!/usr/bin/env python3
import os
import json
import argparse

from llm.utils.file_loader import read_file
from llm.utils.scanner import walk_targets
from llm.provider import get_client

from llm.analyzers.bac_agent import BacAgent
from llm.analyzers.sqli_agent import SQLiAgent
from llm.analyzers.ssrf_agent import SSRFAgent
from llm.analyzers.ssti_agent import SSTIAgent
from llm.analyzers.traversal_agent import TraversalAgent


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--scan-path", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    client = get_client()

    agents = [
        ("BAC", BacAgent(client)),
        ("SQLI", SQLiAgent(client)),
        ("SSRF", SSRFAgent(client)),
        ("SSTI", SSTIAgent(client)),
        ("TRAVERSAL", TraversalAgent(client)),
    ]

    targets = walk_targets(args.scan_path)
    results = []

    for file_path in targets:
        code = read_file(file_path)
        if not code.strip():
            continue

        for name, agent in agents:
            res = agent.run(code, file_path)
            results.append(res.dict())

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump({
            "total": len(results),
            "results": results
        }, f, indent=2)

    print(f"[OK] LLM multi-agent report generated → {args.output}")


if __name__ == "__main__":
    main()
