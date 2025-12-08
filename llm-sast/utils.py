import os
import re
import json

def is_code_file(filename):
    code_exts = ('.js', '.ts', '.py', '.java', '.go', '.c', '.cpp', '.cs', '.rb', '.php')
    exclude_exts = ('.md', '.txt', '.rst')
    return filename.endswith(code_exts) and not filename.endswith(exclude_exts)

def strip_comments(code, ext):
    if ext in ('.js', '.ts'):
        code = re.sub(r'/\*[\s\S]*?\*/', '', code)
        code = re.sub(r'//.*', '', code)
    elif ext == '.py':
        code = re.sub(r'#.*', '', code)
        code = re.sub(r'"""[\s\S]*?"""', '', code)
        code = re.sub(r"'''[\s\S]*?'''", '', code)
    return code

def scan_codebase(root_dir):
    code_contents = []
    for dirpath, dirnames, filenames in os.walk(root_dir):
        # Exclude hidden dirs, docs, readme, and node_modules
        dirnames[:] = [d for d in dirnames if not d.startswith('.') and d.lower() not in ('docs', 'doc', 'readme', 'node_modules')]
        for filename in filenames:
            if is_code_file(filename):
                filepath = os.path.join(dirpath, filename)
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    ext = os.path.splitext(filename)[1]
                    code = f.read()
                    code = strip_comments(code, ext)
                    code_contents.append(f"\n// File: {filepath}\n{code}")
    return "\n".join(code_contents)
