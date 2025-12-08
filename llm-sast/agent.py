import openai

class Agent:
    def __init__(self, model, system_message, base_url, api_key):
        self.model = model
        self.messages = [{"role": "system", "content": system_message}]
        self.base_url = base_url
        self.api_key = api_key
        self.client = openai.OpenAI(base_url=base_url, api_key=api_key)
        self.chat_history = []

    def chat(self, user_message):
        self.messages.append({"role": "user", "content": user_message})
        response = self.client.chat.completions.create(
            model=self.model,
            messages=self.messages
        )
        reply = response.choices[0].message.content
        self.messages.append({"role": "assistant", "content": reply})
        self.chat_history.append({"user": user_message, "assistant": reply})
        return reply
