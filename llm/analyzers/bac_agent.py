
from llm.agent import Agent


class BacAgent(Agent):
    def __init__(self, prompt: str) -> None:
        super(BacAgent, self).__init__("BAC", prompt)
