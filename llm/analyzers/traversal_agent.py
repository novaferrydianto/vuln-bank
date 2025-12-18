from llm.agent import Agent

class TraversalAgent(Agent):
    def __init__(self): super().__init__('Traversal','Analyze for Path Traversal in code: {code}')
