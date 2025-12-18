import json
from openai import OpenAI
from llm.agent import AgentResult
from llm.utils.utils import load_prompt

class BacAgent:
    def __init__(self, client: OpenAI):
        self.client = client
        self.prompt = load_prompt("llm/prompts/bac.txt")

    def run(self, code: str, filepath: str):
        final_prompt = self.prompt.replace("{{CODE}}", code)

        result = self.client.chat.completions.create(
            model="deepseek-chat",
            temperature=0,
            messages=[{"role": "user", "content": final_prompt}]
        )

        try:
            js = json.loads(result.choices[0].message.content)
            return AgentResult(**js)
        except:
            return AgentResult(
                file=filepath,
                type="BAC",
                severity="LOW",
                description="Failed to parse model output",
                recommendation="Improve formatting"
            )
