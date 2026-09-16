#!/usr/bin/env python3
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Require example READMEs to link back to every guide that references them."""

import re
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit


# Match repository example paths in links, prose and shell walkthroughs. A
# preceding path component excludes charts/pipelock/examples and remote URLs.
EXAMPLE = re.compile(r"(?<![\w./-])(?:\.\./)*/?examples/([\w.-]+)")
INLINE_LINK = re.compile(r'(?<!!)\[[^\]\n]*\]\(\s*<?([^\s)>]+)>?(?:\s+"[^"]*")?\s*\)')
REFERENCE = re.compile(r'^ {0,3}\[([^\]\n]+)\]:\s*<?([^\s>]+)>?.*$', re.MULTILINE)
REFERENCE_LINK = re.compile(r"(?<!!)\[([^\]\n]+)\]\[([^\]\n]*)\]")
SHORTCUT_LINK = re.compile(r"(?<!!)\[([^\]\n]+)\]")


def visible_markdown(text: str) -> str:
    """Exclude comments and code so a quoted link cannot satisfy a backlink."""
    text = re.sub(r"<!--.*?-->", "", text, flags=re.DOTALL)
    lines = []
    fence = ""
    for line in text.splitlines():
        marker = re.match(r"^ {0,3}(`{3,}|~{3,})", line)
        if marker:
            value = marker.group(1)
            if not fence:
                fence = value
            elif value[0] == fence[0] and len(value) >= len(fence):
                fence = ""
            continue
        if not fence and not line.startswith(("    ", "\t")):
            lines.append(line)
    return re.sub(r"(`+).*?\1", "", "\n".join(lines), flags=re.DOTALL)


def link_targets(text: str) -> list[str]:
    def normalize(value: str) -> str:
        return " ".join(value.split()).casefold()

    text = visible_markdown(text)
    definitions = {normalize(label): target for label, target in REFERENCE.findall(text)}
    text = REFERENCE.sub("", text)
    targets = INLINE_LINK.findall(text)
    text = INLINE_LINK.sub("", text)
    for label, reference in REFERENCE_LINK.findall(text):
        target = definitions.get(normalize(reference or label))
        if target is not None:
            targets.append(target)
    text = REFERENCE_LINK.sub("", text)
    for label in SHORTCUT_LINK.findall(text):
        target = definitions.get(normalize(label))
        if target is not None:
            targets.append(target)
    return targets


def local_target(target: str, source: Path, root: Path) -> Path | None:
    parsed = urlsplit(target)
    if parsed.scheme or parsed.netloc:
        return None
    path = unquote(parsed.path)
    resolved = ((root / path.lstrip("/")) if path.startswith("/") else (source.parent / path)).resolve()
    return resolved if resolved.is_relative_to(root) else None


def check(root: Path) -> tuple[int, list[str]]:
    root = root.resolve()
    guides = sorted((root / "docs/guides").rglob("*.md"))
    if not guides:
        return 0, ["no Markdown guides found under docs/guides"]
    errors = []
    checked = 0
    for guide in guides:
        text = re.sub(r"<!--.*?-->", "", guide.read_text(encoding="utf-8"), flags=re.DOTALL)
        for name in sorted(set(EXAMPLE.findall(text))):
            checked += 1
            example = root / "examples" / name
            readme = example / "README.md" if example.is_dir() else example.parent / "README.md"
            if not example.exists():
                errors.append(f"{guide.relative_to(root)}: referenced example does not exist: examples/{name}")
                continue
            if not readme.is_file():
                errors.append(f"{readme.relative_to(root)}: missing README for {guide.relative_to(root)}")
                continue
            targets = link_targets(readme.read_text(encoding="utf-8"))
            if not any(local_target(target, readme, root) == guide.resolve() for target in targets):
                errors.append(f"{readme.relative_to(root)}: missing Markdown link to {guide.relative_to(root)}")
    return checked, errors


def main() -> int:
    try:
        checked, errors = check(Path(__file__).resolve().parents[1])
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"example-guide-links: FAILED: {exc}", file=sys.stderr)
        return 1
    for error in errors:
        print(error, file=sys.stderr)
    print(f"example-guide-links: {'FAILED' if errors else 'OK'} ({checked} guide/example relationships)")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
