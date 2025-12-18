import openai
import requests
import os
import json


class LLMProvider:
    def __init__(self):
        self.openai_key = os.getenv("OPENAI_API_KEY")
        self.llm7_key = os.getenv("LLM7_API_KEY")
        self.llm7_base = os.getenv("LLM7_ENDPOINT")

        self.openai_client = openai.OpenAI(api_key=self.openai_key)

    def call(self, model, messages):
        # 1) Try OpenAI
        if self.openai_key:
            try:
              res = self.openai_client.chat.completions.create(
                  model=model,
                  messages=messages
              )
              return res.choices[0].message.content
            except Exception as e:
              print("[LLM] OpenAI failed → fallback to LLM7:", e)

        # 2) Fallback to LLM7
        if self.llm7_base and self.llm7_key:
            url = f"{self.llm7_base}/v1/chat/completions"
            payload = {"model": model, "messages": messages}

            r = requests.post(
                url,
                headers={"Authorization": f"Bearer {self.llm7_key}"},
                json=payload,
                timeout=60
            )

            return r.json()["choices"][0]["message"]["content"]

        raise RuntimeError("No available LLM provider")


