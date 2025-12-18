import json
import requests

class ModelProvider:
    def __init__(self, endpoint, api_key, model=None):
        self.endpoint = endpoint.rstrip("/")
        self.api_key = api_key
        # Default model LLM7 (kanan sesuai dokumentasi)
        self.model = model or "gpt-4o-mini"

    def ask(self, prompt):
        # Payload minimal, sesuai LLM7 spec
        payload = {
            "model": self.model,
            "messages": [
                {"role": "user", "content": prompt}
            ],
            "stream": False
        }

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }

        resp = requests.post(
            self.endpoint,
            headers=headers,
            json=payload,
            timeout=30
        )

        # Raise for non-200
        try:
            resp.raise_for_status()
        except Exception as exc:
            raise RuntimeError(
                f"LLM Provider Error ({resp.status_code}): {resp.text}"
            ) from exc

        data = resp.json()

        # LLM7-style extraction
        try:
            return data["choices"][0]["message"]["content"]
        except Exception:
            # fallback handle partly compatible responses
            return data
