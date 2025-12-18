from llm.agent import Agent

class SSTIAgent(Agent):
    def __init__(self): super().__init__('SSTI','Analyze for SSTI risks in code: {code}')
