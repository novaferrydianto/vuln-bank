
from llm.agent import Agent


class SSTIAgent(Agent):
    def __init__(self, prompt: str) -> None:
        super(SSTIAgent, self).__init__("SSTI", prompt)
