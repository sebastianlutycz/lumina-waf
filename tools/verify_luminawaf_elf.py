#!/usr/bin/env python3
"""Verify the public LuminaWAF ELF ABI and local function binding."""

from __future__ import annotations

import argparse
import subprocess
from pathlib import Path


REQUIRED_PUBLIC_FUNCTIONS = frozenset({
    "lumina_commit_generated_rule",
    "luminawaf_audit_bundle_matches",
    "luminawaf_audit_bundle_rule",
    "luminawaf_destroy_worker",
    "luminawaf_init_worker",
    "luminawaf_inspect_buffer",
    "luminawaf_inspect_buffer_ex",
    "luminawaf_inspect_bundle",
    "luminawaf_inspect_request",
    "luminawaf_inspect_tx",
    "luminawaf_rule_state_matched",
    "luminawaf_rule_state_size",
})


def unversioned(symbol: str) -> str:
    return symbol.split("@", 1)[0]


def parse_defined_dynamic_functions(output: str) -> set[str]:
    functions: set[str] = set()
    for line in output.splitlines():
        fields = line.split(None, 7)
        if len(fields) != 8 or not fields[0].endswith(":"):
            continue
        if fields[3] != "FUNC" or fields[6] in {"UND", "ABS"}:
            continue
        functions.add(unversioned(fields[7]))
    return functions


def parse_jump_slot_symbols(output: str) -> set[str]:
    symbols: set[str] = set()
    for line in output.splitlines():
        fields = line.split()
        if len(fields) < 5 or "JUMP_SLOT" not in fields[2]:
            continue
        symbols.add(unversioned(fields[4]))
    return symbols


def verify_outputs(dynamic_symbols: str, relocations: str) -> list[str]:
    defined_functions = parse_defined_dynamic_functions(dynamic_symbols)
    jump_slots = parse_jump_slot_symbols(relocations)
    errors: list[str] = []

    missing = sorted(REQUIRED_PUBLIC_FUNCTIONS - defined_functions)
    if missing:
        errors.append("missing public ABI functions: " + ", ".join(missing))

    preemptible_internal_calls = sorted(defined_functions & jump_slots)
    if preemptible_internal_calls:
        errors.append(
            "locally defined functions still use JUMP_SLOT relocations: "
            + ", ".join(preemptible_internal_calls)
        )
    return errors


def read_elf(readelf: str, option: str, binary: Path) -> str:
    result = subprocess.run(
        [readelf, option, "--wide", str(binary)],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--readelf", default="readelf")
    args = parser.parse_args()

    if not args.binary.is_file():
        parser.error(f"binary does not exist: {args.binary}")

    dynamic_symbols = read_elf(args.readelf, "--dyn-syms", args.binary)
    relocations = read_elf(args.readelf, "--relocs", args.binary)
    errors = verify_outputs(dynamic_symbols, relocations)
    if errors:
        print("LuminaWAF ELF verification failed:")
        for error in errors:
            print(f"- {error}")
        return 1

    defined_count = len(parse_defined_dynamic_functions(dynamic_symbols))
    print(
        "LuminaWAF ELF verification passed: "
        f"{defined_count} defined dynamic functions, no internal JUMP_SLOT relocations"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
