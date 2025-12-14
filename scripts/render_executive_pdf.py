#!/usr/bin/env python3
"""
Render executive markdown into simple board-friendly PDFs.

Inputs (fixed):
  - docs/executive/security-maturity-one-pager.md
  - docs/executive/why-fail-is-not-bad.md

Outputs:
  - docs/executive/security-maturity-one-pager.pdf
  - docs/executive/why-fail-is-not-bad.pdf

Note: This is intentionally simple (no full Markdown engine).
It renders headings and bullet lines cleanly for exec consumption.
"""

from __future__ import annotations
from pathlib import Path
from datetime import datetime, timezone
from typing import List

from reportlab.lib.pagesizes import A4
from reportlab.pdfgen.canvas import Canvas
from reportlab.lib.units import cm


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def read_lines(path: Path) -> List[str]:
    return path.read_text(encoding="utf-8").splitlines() if path.exists() else []


def render_md_simple(md_path: Path, pdf_path: Path, title: str):
    W, H = A4
    c = Canvas(str(pdf_path), pagesize=A4)

    def header(text: str, y: float):
        c.setFont("Helvetica-Bold", 14)
        c.drawString(2.0*cm, y, text)

    def sub(text: str, y: float):
        c.setFont("Helvetica", 9)
        c.drawString(2.0*cm, y, text)

    y = H - 2.2*cm
    header(title, y)
    y -= 0.7*cm
    sub(f"Generated: {iso_now()}", y)
    y -= 1.0*cm

    lines = read_lines(md_path)
    for raw in lines:
        line = raw.rstrip()

        if not line.strip():
            y -= 0.25*cm
            continue

        if line.startswith("# "):
            if y < 3.0*cm:
                c.showPage()
                y = H - 2.2*cm
                header(title, y); y -= 1.4*cm
            c.setFont("Helvetica-Bold", 12)
            c.drawString(2.0*cm, y, line[2:].strip())
            y -= 0.6*cm
            continue

        if line.startswith("## "):
            if y < 3.0*cm:
                c.showPage()
                y = H - 2.2*cm
                header(title, y); y -= 1.4*cm
            c.setFont("Helvetica-Bold", 11)
            c.drawString(2.0*cm, y, line[3:].strip())
            y -= 0.55*cm
            continue

        if line.startswith("- ") or line.startswith("• "):
            txt = line[2:].strip()
            c.setFont("Helvetica", 10)
            c.drawString(2.3*cm, y, f"• {txt}")
            y -= 0.48*cm
            if y < 3.0*cm:
                c.showPage()
                y = H - 2.2*cm
                header(title, y); y -= 1.4*cm
            continue

        # normal paragraph line
        c.setFont("Helvetica", 10)
        c.drawString(2.0*cm, y, line[:120])
        y -= 0.48*cm
        if y < 3.0*cm:
            c.showPage()
            y = H - 2.2*cm
            header(title, y); y -= 1.4*cm

    c.save()
    print("[OK] Rendered:", pdf_path)


def main():
    base = Path("docs/executive")
    base.mkdir(parents=True, exist_ok=True)

    render_md_simple(
        base / "security-maturity-one-pager.md",
        base / "security-maturity-one-pager.pdf",
        "Security Maturity — One Pager"
    )
    render_md_simple(
        base / "why-fail-is-not-bad.md",
        base / "why-fail-is-not-bad.pdf",
        "Why FAIL ≠ Bad — Executive Explainer"
    )


if __name__ == "__main__":
    main()
