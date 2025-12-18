
import time
import requests


class ModelProvider:
    """LLM7-compatible provider with retry & timeout guardrails."""

    def __init__(self, endpoint: str, api_key: str, model: str | None = None):
        self.endpoint = endpoint.rstrip("/")
        self.api_key = api_key
        self.model = model or "gpt-4o-mini"
        self.timeout = 60
        self.max_retries = 5
        self.retry_backoff = 2

    def _post(self, payload: dict) -> requests.Response:
        headers = {
            "Authorization": f"Bearer {self.api_key}",
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
                print(f"[LLM7 TIMEOUT] retry {attempt}/{self.max_retries}, waiting {wait}s...")
                time.sleep(wait)
            except requests.exceptions.RequestException as exc:
                last_exc = exc
                wait = self.retry_backoff * attempt
                print(f"[LLM7 ERROR] retry {attempt}/{self.max_retries}, waiting {wait}s...")
                time.sleep(wait)

        raise RuntimeError(f"LLM7 request failed after retries: {last_exc}")

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
