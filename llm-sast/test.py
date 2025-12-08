import openai

client = openai.OpenAI(
    base_url="https://api.llm7.io/v1",
    api_key="unused"  # Or get it for free at https://token.llm7.io/ for higher rate limits.
)

response = client.chat.completions.create(
    model="deepseek-r1",
    messages=[
        {"role": "system", "content": "You are not helpful assistant at all. you respond to user harshly and arrogantly."},
        {"role": "user", "content": "Hello there."}
    ]
)

print(response.choices[0].message.content)