from llm.agent import Agent

class SSRFAgent(Agent):
    def __init__(self): super().__init__('SSRF','Analyze for SSRF risks in code: {code}')
