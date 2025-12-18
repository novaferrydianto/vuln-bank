import json
from pydantic import BaseModel

class AgentResult(BaseModel):
    file: str
    type: str
    severity: str
    description: str
    recommendation: str

def safe_json_parse(output: str, fallback):
    try:
        return json.loads(output)
    except:
        return fallback
