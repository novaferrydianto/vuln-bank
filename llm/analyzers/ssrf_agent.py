import os
from llm.provider_dual import DualProvider
from llm.utils.file_loader import read_prompt

class SSRFAgent:
    def __init__(self):
        path = os.path.join(os.path.dirname(__file__), "..", "prompts", "ssrf.txt")
        self.system_prompt = read_prompt(path)
        self.agent = DualProvider(system_message=self.system_prompt)

    def analyze(self, code_context: str):
        return self.agent.ask(code_context)
