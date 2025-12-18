# llm/utils/scanner.py

from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable, List


SOURCE_EXTENSIONS = {
    ".py",
    ".js",
    ".ts",
    ".tsx",
    ".jsx",
    ".html",
    ".htm",
    ".jinja2",
    ".j2",
    ".go",
    ".java",
    ".cs",
    ".php",
}


def _is_binary(path: Path, chunk_size: int = 2048) -> bool:
    """Heuristic: treat file as binary if it contains NUL bytes."""
    try:
        with path.open("rb") as fh:
            chunk = fh.read(chunk_size)
        return b"\0" in chunk
    except OSError:
        return True


def iter_source_files(root: str | Path) -> Iterable[Path]:
    """
    Iterate semua file source code yang relevan di bawah root.

    Only extensions in SOURCE_EXTENSIONS, skip typical junk dirs.
    """
    root_path = Path(root).resolve()
    skip_dirs = {".git", ".venv", "venv", "node_modules", "__pycache__", ".mypy_cache"}

    for dirpath, dirnames, filenames in os.walk(root_path):
        # prune dirs
        dirnames[:] = [d for d in dirnames if d not in skip_dirs]

        for fname in filenames:
            path = Path(dirpath) / fname
            if path.suffix.lower() not in SOURCE_EXTENSIONS:
                continue
            if _is_binary(path):
                continue
            yield path


def scan_codebase(root: str | Path) -> str:
    """
    Build satu konteks besar untuk LLM:
    - Setiap file diawali header '### FILE: <relative_path>'
    - Diikuti isi file apa adanya

    Return string ini sebagai input utama ke semua agent LLM.
    """
    root_path = Path(root).resolve()
    parts: List[str] = []

    for path in sorted(iter_source_files(root_path)):
        rel = path.relative_to(root_path)
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        parts.append(f"### FILE: {rel}\n{text}\n")

    return "\n".join(parts)