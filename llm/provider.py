
import time
from typing import Optional, Dict, Any

import requests
from requests import Response


class ModelProvider:
    """LLM7-compatible provider with retry & timeout guardrails (Python 3.9 safe)."""

    def __init__(self, endpoint: str, api_key: str, model: Optional[str] = None) -> None:
        self.endpoint = endpoint.rstrip("/")
        self.api_key = api_key
        self.model = model or "gpt-4o-mini"
        self.timeout = 60
        self.max_retries = 5
        self.retry_backoff = 2

    def _post(self, payload: Dict[str, Any]) -> Response:
        headers = {
            "Authorization": "Bearer {0}".format(self.api_key),
            "Content-Type": "application/json",
        }

        last_exc = None

        for attempt in range(1, self.max_retries + 1):
            try:
                resp = requests.post(
                    self.endpoint,
                    headers=headers,
                    json=payload,
                    timeout=self.timeout,
                )
                resp.raise_for_status()
                return resp
            except requests.exceptions.ReadTimeout as exc:
                last_exc = exc
                wait = self.retry_backoff * attempt
                print(
                    "[LLM7 TIMEOUT] retry {0}/{1}, wait {2}s".format(
                        attempt,
                        self.max_retries,
                        wait,
                    ),
                )
                time.sleep(wait)
            except requests.exceptions.RequestException as exc:
                last_exc = exc
                wait = self.retry_backoff * attempt
                print(
                    "[LLM7 ERROR] retry {0}/{1}, wait {2}s".format(
                        attempt,
                        self.max_retries,
                        wait,
                    ),
                )
                time.sleep(wait)

        raise RuntimeError("LLM7 request failed after retries: {0}".format(last_exc))

    def ask(self, prompt: str):
        payload = {
            "model": self.model,
            "messages": [
                {"role": "user", "content": prompt},
            ],
            "stream": False,
        }

        resp = self._post(payload)
        data = resp.json()

        try:
            return data["choices"][0]["message"]["content"]
        except Exception:
            return data
