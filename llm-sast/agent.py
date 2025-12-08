#!/usr/bin/env python3
from typing import Dict, Any, Optional
import json
import time
import openai
import re


class LLMSASTAgent:
    """
    CI-safe LLM-SAST agent

    ✅ Plan-aware (JSON mode optional)
    ✅ Graceful degradation
    ✅ Never blocks CI
    ✅ Deterministic
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

    # --------------------------------------------------
    # Public API
    # --------------------------------------------------
    def analyze(self, user_prompt: str) -> Dict[str, Any]:
        """
        Run LLM-SAST analysis.

        ✅ Always returns valid JSON
        ✅ Never throws in CI
        """
        try:
            return self._analyze_json(user_prompt)
        except Exception as exc:
            print(f"⚠️ LLM JSON mode unavailable, degrading: {exc}")
            return self._analyze_text_fallback(user_prompt)

    # --------------------------------------------------
    # JSON mode (preferred)
    # --------------------------------------------------
    def _analyze_json(self, user_prompt: str) -> Dict[str, Any]:
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
                if "JSON response format is not available" in str(e):
                    raise  # trigger fallback immediately

                if attempt == self.max_retries:
                    raise

                time.sleep(2 * attempt)

        raise RuntimeError("Unreachable")

    # --------------------------------------------------
    # Text fallback (CI-safe)
    # --------------------------------------------------
    def _analyze_text_fallback(self, user_prompt: str) -> Dict[str, Any]:
        """
        Fallback when JSON mode is not supported.

        Strategy:
        - Ask LLM anyway
        - Try to extract JSON from text
        - Otherwise return empty findings
        """

        messages = [
            {"role": "system", "content": self.system_prompt},
            {"role": "user", "content": user_prompt},
        ]

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=0,
            )

            text = response.choices[0].message.content or ""

            # Try to recover JSON from text
            extracted = self._extract_json(text)
            if extracted is not None:
                return extracted

        except Exception as exc:
            print(f"⚠️ LLM text fallback failed: {exc}")

        # ✅ CI-safe default
        return {
            "findings": [],
            "meta": {
                "source": "llm-sast",
                "status": "degraded",
                "reason": "json_mode_unavailable",
            },
        }

    # --------------------------------------------------
    # Helpers
    # --------------------------------------------------
    def _extract_json(self, text: str) -> Optional[Dict[str, Any]]:
        """
        Best-effort JSON extraction from text response.
        """
        try:
            # Direct parse
            return json.loads(text)
        except Exception:
            pass

        # Try extracting JSON block
        match = re.search(r"\{[\s\S]*\}", text)
        if match:
            try:
                return json.loads(match.group(0))
            except Exception:
                return None

        return None
