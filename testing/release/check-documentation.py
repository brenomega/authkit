#!/usr/bin/env python3
"""Validate local Markdown links and the canonical EN/pt-BR documentation pairs."""

from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import unquote


ROOT = Path(__file__).resolve().parents[2]
CANONICAL_PAIRS = (
    "CONFIGURATION",
    "EMAIL_TEMPLATES",
    "INSTALL",
    "INTEGRATOR",
    "OPERATIONS",
    "RELEASING",
    "SECURITY_MODEL",
    "TRACEABILITY",
)
NESTED_PAIRS = (
    "architecture/SYSTEM_DESIGN",
    "proof/README",
    "reference/SUPPORT_MATRIX",
    "release/RELEASE_GATES",
)
LINK = re.compile(r"(?<!!)\[[^]]*]\(([^)]+)\)")


def fail(message: str, failures: list[str]) -> None:
    failures.append(message)


def main() -> int:
    failures: list[str] = []

    for stem in (*CANONICAL_PAIRS, *NESTED_PAIRS):
        english = ROOT / "docs" / f"{stem}.md"
        portuguese = ROOT / "docs" / f"{stem}-ptBR.md"
        if not english.is_file():
            fail(f"missing normative document: {english.relative_to(ROOT)}", failures)
        if not portuguese.is_file():
            fail(f"missing pt-BR pair: {portuguese.relative_to(ROOT)}", failures)

    markdown_files = sorted(
        path for path in ROOT.rglob("*.md")
        if ".git" not in path.parts and "target" not in path.parts
    )
    for document in markdown_files:
        text = document.read_text(encoding="utf-8")
        for raw_target in LINK.findall(text):
            target = raw_target.strip().split(maxsplit=1)[0].strip("<>")
            if not target or target.startswith(("#", "http://", "https://", "mailto:")):
                continue
            target = unquote(target.split("#", 1)[0].split("?", 1)[0])
            resolved = (document.parent / target).resolve()
            if not resolved.exists():
                fail(
                    f"broken local link in {document.relative_to(ROOT)}: {raw_target}",
                    failures,
                )

    traceability = (ROOT / "docs/TRACEABILITY.md").read_text(encoding="utf-8")
    ids = re.findall(r"^\| (AK-\d{3}) \|", traceability, flags=re.MULTILINE)
    expected = [f"AK-{number:03d}" for number in range(1, 38)]
    if ids != expected:
        fail(f"traceability IDs are incomplete or unordered: {ids}", failures)

    if failures:
        print("Documentation validation failed:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1

    print(
        f"Documentation validation passed: {len(markdown_files)} Markdown files, "
        f"{len(CANONICAL_PAIRS) + len(NESTED_PAIRS)} EN/pt-BR pairs, 37 AK rows."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
