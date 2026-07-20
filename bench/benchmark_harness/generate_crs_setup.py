#!/usr/bin/env python3
"""Materialize the pinned CRS example as LuminaWAF's benchmark PL2 policy."""

from __future__ import annotations

import argparse
from pathlib import Path


def _activate_action(lines: list[str], rule_id: int, variable: str, value: int) -> None:
    marker = f"#    \"id:{rule_id},\\"
    matches = [index for index, line in enumerate(lines) if line == marker]
    if len(matches) != 1:
        raise ValueError(f"expected one commented CRS action {rule_id}, found {len(matches)}")

    marker_index = matches[0]
    start = marker_index - 1
    if start < 0 or lines[start] != "#SecAction \\":
        raise ValueError(f"CRS action {rule_id} has an unexpected opening line")

    setting = f"setvar:tx.{variable}="
    end = None
    for index in range(marker_index, min(marker_index + 16, len(lines))):
        if setting in lines[index]:
            end = index
            break
    if end is None or not lines[end].endswith('"'):
        raise ValueError(f"CRS action {rule_id} has no bounded {variable} assignment")

    for index in range(start, end + 1):
        if not lines[index].startswith("#"):
            raise ValueError(f"CRS action {rule_id} is not fully commented")
        lines[index] = lines[index][1:]
    prefix = lines[end].split(setting, 1)[0]
    lines[end] = f"{prefix}{setting}{value}\""


def render(example: Path) -> str:
    text = example.read_text(encoding="utf-8")
    replacements = {
        'SecDefaultAction "phase:1,log,auditlog,pass"':
            'SecDefaultAction "phase:1,nolog,pass"',
        'SecDefaultAction "phase:2,log,auditlog,pass"':
            'SecDefaultAction "phase:2,nolog,pass"',
    }
    for source, target in replacements.items():
        if text.count(source) != 1:
            raise ValueError(f"unexpected CRS setup occurrence count for: {source}")
        text = text.replace(source, target)

    lines = text.splitlines()
    _activate_action(lines, 900000, "blocking_paranoia_level", 2)
    _activate_action(lines, 900001, "detection_paranoia_level", 2)
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(render(args.input), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
