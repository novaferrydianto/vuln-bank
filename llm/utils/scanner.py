
import os
from typing import List


def scan_files(root: str) -> List[str]:
    exts = (".py", ".js", ".ts", ".go", ".java", ".tf", ".yaml", ".yml")
    results: List[str] = []
    for base, _, files in os.walk(root):
        for name in files:
            if name.lower().endswith(exts):
                results.append(os.path.join(base, name))
    return results
