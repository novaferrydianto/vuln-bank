from provider import AIProvider


class Agent:
    def __init__(self, model, system_message):
        self.model = model
        self.messages = [{"role": "system", "content": system_message}]
        self.provider = AIProvider()

    def chat(self, user_message: str):
        self.messages.append({"role": "user", "content": user_message})
        reply = self.provider.chat(self.model, self.messages)
        self.messages.append({"role": "assistant", "content": reply})
        return reply
