
class Agent:
    def __init__(self, name, prompt):
        self.name = name
        self.prompt = prompt

    def analyze(self, provider, content):
        query = self.prompt.format(code=content)
        return provider.ask(query)
