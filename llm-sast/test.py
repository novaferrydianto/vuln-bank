#!/usr/bin/env python3
import json
import openai
import re
from typing import List, Dict

# =========================
# Utility: JSON extraction
# =========================
def extract_json_array(raw: str) -> list:
    """
    Safely extract a JSON array from LLM output.
    Handles markdown fences and accidental text.
    """
    raw = raw.strip()

    # Remove markdown fences if present
    if raw.startswith("```"):
        raw = re.sub(r"^```.*?\n|```$", "", raw, flags=re.S)

    start = raw.find("[")
    end = raw.rfind("]")

    if start == -1 or end == -1:
        raise ValueError("No JSON array found in LLM output")

    return json.loads(raw[start:end + 1])


# =========================
# Schema Validation
# =========================
REQUIRED_FIELDS = {
    "scanner",
    "category",
    "severity",
    "confidence",
    "title",
    "description",
    "file",
    "line",
    "cwe",
    "asvs",
    "remediation",
}

SEVERITY_LEVELS = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}


def validate_finding(finding: Dict):
    missing = REQUIRED_FIELDS - finding.keys()
    if missing:
        raise ValueError(f"Missing required fields: {missing}")

    if finding["severity"] not in SEVERITY_LEVELS:
        raise ValueError(f"Invalid severity: {finding['severity']}")

    if not isinstance(finding["asvs"], list):
        raise ValueError("Field 'asvs' must be a list")

    if not isinstance(finding["confidence"], (float, int)):
        raise ValueError("Field 'confidence' must be a number")

    if not 0.0 <= float(finding["confidence"]) <= 1.0:
        raise ValueError("Field 'confidence' must be between 0.0 and 1.0")


# =========================
# LLM-SAST Agent
# =========================
class LLMSASTAgent:
    def __init__(self, model, system_prompt, base_url, api_key):
        self.client = openai.OpenAI(
            base_url=base_url,
            api_key=api_key,
        )
        self.model = model
        self.system_prompt = system_prompt

    def analyze(self, code_context: str) -> List[Dict]:
        response = self.client.chat.completions.create(
            model=self.model,
            temperature=0,
            messages=[
                {"role": "system", "content": self.system_prompt},
                {"role": "user", "content": code_context},
            ],
        )

        raw_output = response.choices[0].message.content

        try:
            findings = extract_json_array(raw_output)

            if not isinstance(findings, list):
                raise ValueError("LLM output is not a JSON array")

            for f in findings:
                # Force source consistency for normalize pipeline
                f.setdefault("source", "llm-sast")
                validate_finding(f)

            return findings

        except Exception as e:
            raise RuntimeError(
                f"""
❌ LLM-SAST OUTPUT ERROR
=======================
Error : {e}

RAW OUTPUT
----------
{raw_output}
"""
            )


# =========================
# System Prompt
# =========================
SYSTEM_PROMPT = """
You are a senior application security engineer.

Task:
Detect BROKEN ACCESS CONTROL vulnerabilities.

STRICT RULES:
- Output ONLY valid JSON
- Output MUST be a JSON array
- No markdown
- No explanations outside JSON

Each finding MUST contain:
- scanner: "llm-sast"
- category: "Access Control"
- severity: CRITICAL | HIGH | MEDIUM | LOW
- confidence: number (0.0–1.0)
- title
- description
- file
- line
- cwe
- asvs (array)
- remediation
"""

# =========================
# Manual Test Runner
# =========================
if __name__ == "__main__":
    agent = LLMSASTAgent(
        model="deepseek-r1",
        system_prompt=SYSTEM_PROMPT,
        base_url="https://api.llm7.io/v1",
        api_key="unused",
    )

    code_snippet = """
@app.route('/admin')
def admin():
    return "admin panel"
"""

    findings = agent.analyze(code_snippet)

    print(json.dumps(findings, indent=2))
