
from llm.agent import Agent


class BacAgent(Agent):
    def __init__(self, prompt: str):
        super().__init__("BAC", prompt)
