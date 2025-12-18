
from llm.agent import Agent


class SQLiAgent(Agent):
    def __init__(self, prompt: str):
        super().__init__("SQLi", prompt)
