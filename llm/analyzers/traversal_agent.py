import json
from llm.provider import get_llm_client
from llm.utils.file_loader import load_prompt
from llm.utils.utils import detect_cwe


class TraversalAgent:
    def __init__(self):
        self.prompt = load_prompt("traversal.txt")
        self.client = get_llm_client()

    def analyze(self, code_text: str):
        msg = self.prompt + "\n\n" + code_text

        try:
            result = self.client.chat(msg)
            parsed = json.loads(result)
        except Exception:
            return []

        # Add CWE classification automatically
        for f in parsed:
            f["cwe"] = detect_cwe(f.get("summary", ""))

        return parsed