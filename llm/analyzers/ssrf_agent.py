
from llm.agent import Agent


class SSRFAgent(Agent):
    def __init__(self, prompt: str):
        super().__init__("SSRF", prompt)
