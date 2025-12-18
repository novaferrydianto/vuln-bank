from llm.agent import Agent

class SQLiAgent(Agent):
    def __init__(self): super().__init__('SQLi','Analyze for SQL Injection in code: {code}')
