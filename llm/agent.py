
from typing import Any


class Agent:
    """Base agent used by all vulnerability analyzers."""

    def __init__(self, name: str, prompt: str) -> None:
        self.name = name
        self.prompt = prompt

    def analyze(self, provider: Any, content: str):
        """Format prompt with code and delegate to provider."""
        query = self.prompt.format(code=content)
        return provider.ask(query)
