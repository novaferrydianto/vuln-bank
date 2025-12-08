import os
import re

MAX_FILE_SIZE = 200 * 1024  # 200 KB
ALLOWED_EXTS = {'.py', '.js', '.ts', '.java', '.go', '.php'}

EXCLUDED_DIRS = {
    '.git', 'node_modules', 'dist', 'build',
    'docs', 'doc', 'vendor', '__pycache__'
}

def is_code_file(path):
    ext = os.path.splitext(path)[1].lower()
    return ext in ALLOWED_EXTS

def normalize_path(path, root):
    return os.path.relpath(path, root).replace("\\", "/")

def scan_codebase(root_dir):
    blocks = []

    for dirpath, dirnames, filenames in os.walk(root_dir):
        dirnames[:] = [d for d in dirnames if d not in EXCLUDED_DIRS]

        for filename in filenames:
            full_path = os.path.join(dirpath, filename)

            if not is_code_file(full_path):
                continue

            if os.path.getsize(full_path) > MAX_FILE_SIZE:
                continue

            try:
                with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                    code = f.read()

                rel_path = normalize_path(full_path, root_dir)

                blocks.append(
                    f"\n### FILE: {rel_path}\n{code}\n"
                )

            except Exception:
                continue

    return "\n".join(blocks)
