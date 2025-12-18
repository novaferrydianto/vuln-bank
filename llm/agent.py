
class Agent:
    """Base agent used by all vulnerability analyzers."""

    def __init__(self, name: str, prompt: str):
        self.name = name
        self.prompt = prompt

    def analyze(self, provider, content: str):
        query = self.prompt.format(code=content)
        return provider.ask(query)
