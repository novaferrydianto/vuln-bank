from openai import OpenAI

def get_client():
    api_key = os.getenv("OPENAI_API_KEY")
    api_base = os.getenv("AI_API_ENDPOINT", None)

    return OpenAI(api_key=api_key, base_url=api_base)
