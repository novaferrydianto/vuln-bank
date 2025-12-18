
import argparse
import json
import os
from typing import Any, Dict, List

from llm.provider import ModelProvider
from llm.analyzers import (
    BacAgent,
    SQLiAgent,
    SSRFAgent,
    SSTIAgent,
    TraversalAgent,
)
from llm.utils.file_loader import read_file
from llm.utils.scanner import scan_files
from llm.prompts import (
    BAC_PROMPT,
    SQLI_PROMPT,
    SSRF_PROMPT,
    SSTI_PROMPT,
    TRAVERSAL_PROMPT,
)


def build_provider() -> ModelProvider:
    endpoint = os.getenv("AI_API_ENDPOINT", "").strip()
    api_key = os.getenv("AI_API_KEY", "").strip()

    if not endpoint or not api_key:
        raise RuntimeError("AI_API_ENDPOINT and AI_API_KEY must be set")

    model = os.getenv("AI_MODEL", "gpt-4o-mini")
    return ModelProvider(endpoint=endpoint, api_key=api_key, model=model)


def build_agents():
    return [
        BacAgent(BAC_PROMPT),
        SQLiAgent(SQLI_PROMPT),
        SSRFAgent(SSRF_PROMPT),
        SSTIAgent(SSTI_PROMPT),
        TraversalAgent(TRAVERSAL_PROMPT),
    ]


def run(scan_path: str, output: str):
    provider = build_provider()
    agents = build_agents()

    files = scan_files(scan_path)
    findings: List[Dict[str, Any]] = []

    for path in files:
        content = read_file(path)
        for agent in agents:
            result = agent.analyze(provider, content)
            findings.append(
                {
                    "file": path,
                    "agent": agent.name,
                    "result": result,
                },
            )

    os.makedirs(os.path.dirname(output), exist_ok=True)
    with open(output, "w", encoding="utf-8") as fp:
        json.dump({"findings": findings}, fp, indent=2)


def main():
    parser = argparse.ArgumentParser(description="LLM Multi-Agent SAST Pipeline (LLM7)")
    parser.add_argument("--scan-path", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    run(args.scan_path, args.output)


if __name__ == "__main__":
    main()
