from ..agent import Agent
from ..provider import LLMProvider
from pathlib import Path

class SQLIAgent:
    name = "SQL Injection Agent"

    def __init__(self):
        prompt_path = Path(__file__).resolve().parents[1] / "prompts" / "sqli.txt"
        with open(prompt_path, "r") as f:
            self.prompt = f.read()

        self.agent = Agent(
            model="gpt-4.1",
            system_message=self.prompt,
            provider=LLMProvider()
        )

    def analyze(self, files):
        content = "\n\n".join([f"[FILE] {p}\n{c}" for p, c in files.items()])
        reply = self.agent.chat(content)

        try:
            return json.loads(reply)
        except:
            return []
