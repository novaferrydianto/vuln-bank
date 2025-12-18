import os


def collect_files(root, extensions=(".py",)):
    collected = []
    for base, _, files in os.walk(root):
        for f in files:
            if f.endswith(extensions):
                p = os.path.join(base, f)
                try:
                    with open(p, "r", encoding="utf-8") as fh:
                        collected.append((p, fh.read()))
                except Exception:
                    pass
    return collected


def scan_codebase(root) -> str:
    files = collect_files(root)
    msg = "Analyze the following code files:\n\n"
    for path, content in files:
        msg += f"FILE: {path}\n-----\n{content}\n\n"
    return msg
