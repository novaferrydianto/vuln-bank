import json
from openai import OpenAI
from llm.agent import AgentResult
from llm.utils.utils import load_prompt

class SSTIAgent:
    def __init__(self, client: OpenAI):
        self.client = client
        self.prompt = load_prompt("llm/prompts/ssti.txt")

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
                type="SSTI",
                severity="LOW",
                description="Error parsing SSTI output",
                recommendation="Fix formatting"
            )
