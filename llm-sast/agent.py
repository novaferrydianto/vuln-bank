#!/usr/bin/env python3
from typing import List, Dict, Any
import json
import time
import openai


class LLMSASTAgent:
    """
    Stateless LLM agent for security analysis (LLM-SAST)

    ✅ CI-safe
    ✅ Deterministic
    ✅ JSON-only output
    """

    def __init__(
        self,
        model: str,
        system_prompt: str,
        base_url: str,
        api_key: str,
        timeout: int = 60,
        max_retries: int = 3,
    ):
        self.model = model
        self.system_prompt = system_prompt
        self.timeout = timeout
        self.max_retries = max_retries

        self.client = openai.OpenAI(
            api_key=api_key,
            base_url=base_url,
            timeout=timeout,
        )

    # -----------------------------
    # Core call
    # -----------------------------
    def analyze(self, user_prompt: str) -> Dict[str, Any]:
        """
        Run one deterministic LLM-SAST analysis.
        Always returns parsed JSON or raises exception.
        """

        messages = [
            {"role": "system", "content": self.system_prompt},
            {"role": "user", "content": user_prompt},
        ]

        for attempt in range(1, self.max_retries + 1):
            try:
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=messages,
                    temperature=0,
                    response_format={"type": "json_object"},
                )

                content = response.choices[0].message.content
                return json.loads(content)

            except Exception as e:
                if attempt == self.max_retries:
                    raise RuntimeError(
                        f"LLM-SAST failed after {self.max_retries} attempts: {e}"
                    )
                time.sleep(2 * attempt)

        raise RuntimeError("Unreachable")

