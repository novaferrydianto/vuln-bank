#!/usr/bin/env python3

import json
from pathlib import Path


def load_llm_findings(path: str):
    text = Path(path).read_text("utf-8")
    return json.loads(text)
