from llm.agent import Agent

class BacAgent(Agent):
    def __init__(self): super().__init__('BAC','Analyze for Broken Access Control in code: {code}')
