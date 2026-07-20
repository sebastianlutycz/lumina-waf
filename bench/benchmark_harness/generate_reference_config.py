#!/usr/bin/env python3
"""Render the repository comparator template with a portable CRS root."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from generate_crs_setup import render as render_setup  # noqa: E402


def render(template: Path, crs: Path, setup: Path | None = None) -> str:
    lines: list[str] = []
    for raw in template.read_text(encoding="utf-8").splitlines():
        if not raw.lstrip().startswith("Include "):
            lines.append(raw)
            continue
        value = raw.split(None, 1)[1].strip().strip('"')
        parts = Path(value).parts
        try:
            marker_index = len(parts) - 1 - tuple(reversed(parts)).index("coreruleset")
        except ValueError:
            candidate = (template.parent / value).resolve()
            if candidate.name != "crs-setup.conf":
                raise ValueError(f"comparator include is outside the CRS tree: {value}")
            target = candidate
        else:
            relative = Path(*parts[marker_index + 1:])
            if relative == Path("crs-setup.conf") and setup is not None:
                target = setup.resolve()
            else:
                target = (crs / relative).resolve()
        if not target.is_file():
            raise ValueError(f"comparator include does not exist: {target}")
        lines.append(f"Include {target}")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--template", type=Path, required=True)
    parser.add_argument("--crs", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    setup = args.output.parent / "crs-setup.conf"
    setup.write_text(
        render_setup(args.crs / "crs-setup.conf.example"), encoding="utf-8"
    )
    args.output.write_text(render(args.template, args.crs, setup), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
