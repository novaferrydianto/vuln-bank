import json
import time
import requests

class ModelProvider:
    def __init__(self, endpoint, api_key, model=None):
        self.endpoint = endpoint.rstrip("/")
        self.api_key = api_key
        self.model = model or "gpt-4o-mini"
        self.timeout = 60               # increase default timeout
        self.max_retries = 5            # retry up to 5 times
        self.retry_backoff = 2          # exponential backoff

    def _post(self, payload):
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }

        last_exc = None

        for attempt in range(1, self.max_retries + 1):
            try:
                resp = requests.post(
                    self.endpoint,
                    headers=headers,
                    json=payload,
                    timeout=self.timeout
                )

                # Raise if non-2xx
                resp.raise_for_status()
                return resp

            except requests.exceptions.ReadTimeout as exc:
                last_exc = exc
                wait = self.retry_backoff * attempt
                print(f"[LLM7 TIMEOUT] retry {attempt}/{self.max_retries}, waiting {wait}s...")
                time.sleep(wait)

            except requests.exceptions.RequestException as exc:
                # for 4xx/5xx
                last_exc = exc
                wait = self.retry_backoff * attempt
                print(f"[LLM7 ERROR] retry {attempt}/{self.max_retries}, waiting {wait}s...")
                time.sleep(wait)

        raise RuntimeError(f"LLM7 request failed after retries: {last_exc}")

    def ask(self, prompt):
        # keep payload minimal for LLM7 stability
        payload = {
            "model": self.model,
            "messages": [
                {"role": "user", "content": prompt}
            ],
            "stream": False
        }

        resp = self._post(payload)
        data = resp.json()

        # OpenAI/LLM7 hybrid extraction
        try:
            return data["choices"][0]["message"]["content"]
        except Exception:
            return data
