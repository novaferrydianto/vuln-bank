import json
from openai import OpenAI
from llm.agent import AgentResult
from llm.utils.utils import load_prompt

class TraversalAgent:
    def __init__(self, client: OpenAI):
        self.client = client
        self.prompt = load_prompt("llm/prompts/traversal.txt")

    def run(self, code: str, filepath: str):
        prompt = self.prompt.replace("{{CODE}}", code)

        res = self.client.chat.completions.create(
            model="deepseek-chat",
            messages=[{"role": "user", "content": prompt}]
        )

        try:
            data = json.loads(res.choices[0].message.content)
            return AgentResult(**data)
        except:
            return AgentResult(
                file=filepath,
                type="TRAVERSAL",
                severity="LOW",
                description="Traversal scan JSON error",
                recommendation="Fix model output"
            )
