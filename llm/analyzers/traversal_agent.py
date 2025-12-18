
from llm.agent import Agent


class TraversalAgent(Agent):
    def __init__(self, prompt: str):
        super().__init__("Traversal", prompt)
