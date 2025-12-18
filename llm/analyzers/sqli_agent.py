
from llm.agent import Agent


class SQLiAgent(Agent):
    def __init__(self, prompt: str) -> None:
        super(SQLiAgent, self).__init__("SQLi", prompt)
