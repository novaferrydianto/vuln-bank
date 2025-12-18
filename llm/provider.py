
import json
import requests

class ModelProvider:
    def __init__(self, endpoint, api_key):
        self.endpoint = endpoint
        self.api_key = api_key

    def ask(self, prompt):
        resp = requests.post(
            self.endpoint,
            headers={"Authorization": f"Bearer {self.api_key}"},
            json={"prompt": prompt},
            timeout=30
        )
        resp.raise_for_status()
        return resp.json()
