#!/usr/bin/env python3

import json
import os
from pathlib import Path
from datetime import datetime


def load_json(path: str, default=None):
    p = Path(path)
    if p.exists():
        return json.loads(p.read_text())  # UP015 fixed
    return default


def main():
    owasp = load_json(os.getenv("OWASP_LATEST", ""), {})
    epss = load_json(os.getenv("EPSS_FINDINGS", ""), {})
    sla = load_json(os.getenv("SLA_WEEKLY", ""), {})
    llm = load_json(os.getenv("LLM_FINDINGS", ""), {})

    # Dummy logic (your logic already correct)
    out = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "overall_score": 85.0,
        "dimensions": {
            "owasp": owasp,
            "epss": epss,
            "sla": sla,
            "llm": llm,
        },
    }

    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
