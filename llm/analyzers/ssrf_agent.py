import json
from openai import OpenAI
from llm.agent import AgentResult
from llm.utils.utils import load_prompt

class SSRFAgent:
    def __init__(self, client: OpenAI):
        self.client = client
        self.prompt = load_prompt("llm/prompts/ssrf.txt")

    def run(self, code: str, filepath: str):
        prompt = self.prompt.replace("{{CODE}}", code)

        out = self.client.chat.completions.create(
            model="deepseek-chat",
            messages=[{"role": "user", "content": prompt}]
        )

        try:
            data = json.loads(out.choices[0].message.content)
            return AgentResult(**data)
        except:
            return AgentResult(
                file=filepath,
                type="SSRF",
                severity="LOW",
                description="Invalid LLM JSON response",
                recommendation="Fix model output"
            )
