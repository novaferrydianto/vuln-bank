
from llm.agent import Agent


class SSTIAgent(Agent):
    def __init__(self, prompt: str):
        super().__init__("SSTI", prompt)
