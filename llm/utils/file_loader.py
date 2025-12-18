
import os


def read_file(path: str) -> str:
    abs_path = os.path.abspath(path)
    with open(abs_path, encoding="utf-8") as f:
        return f.read()
