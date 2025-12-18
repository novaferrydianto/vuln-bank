#!/usr/bin/env python3

import json
import sys
from pathlib import Path
from datetime import datetime


def load_json(path: Path):
    text = path.read_text()  # UP015 fixed → no mode
    return json.loads(text)


def grade(score: float) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "E"


def main():
    if len(sys.argv) != 2:
        raise SystemExit("Usage: render_security_markdown.py <scorecard_json>")

    path = Path(sys.argv[1])
    data = load_json(path)

    gen = data.get("generated_at", datetime.utcnow().isoformat() + "Z")
    overall = data.get("overall_score", 0.0)

    lines = [
        "# Security Board Report",
        f"_Generated at: `{gen}`_",
        "",
        f"## Overall Score: **{overall}** (Grade {grade(overall)})",
        "",
    ]

    print("\n".join(lines))


if __name__ == "__main__":
    main()
