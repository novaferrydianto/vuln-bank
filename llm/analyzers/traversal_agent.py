
from llm.agent import Agent


class TraversalAgent(Agent):
    def __init__(self, prompt: str) -> None:
        super(TraversalAgent, self).__init__("Traversal", prompt)
