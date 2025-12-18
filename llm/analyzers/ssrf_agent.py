
from llm.agent import Agent


class SSRFAgent(Agent):
    def __init__(self, prompt: str) -> None:
        super(SSRFAgent, self).__init__("SSRF", prompt)
