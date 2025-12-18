from agent import Agent

def load_prompt(path="prompts/bac.txt"):
    with open(path, "r", encoding="utf-8") as f:
        return f.read()

def create_bac_agent():
    return Agent(
        model="gpt-4o-mini",     # fallback via LLM7
        system_message=load_prompt()
    )
