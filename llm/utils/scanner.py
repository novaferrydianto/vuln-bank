import os

TARGET_EXT = [".py", ".js", ".ts", ".go", ".yaml", ".yml", ".sh"]

def walk_targets(root: str):
    files = []
    for base, _, filenames in os.walk(root):
        for fn in filenames:
            if any(fn.endswith(ext) for ext in TARGET_EXT):
                files.append(os.path.join(base, fn))
    return files
