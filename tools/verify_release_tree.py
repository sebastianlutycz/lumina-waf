#!/usr/bin/env python3
"""Fail closed when forbidden generated or third-party artifacts are tracked."""

from __future__ import annotations

import argparse
import re
import subprocess
from pathlib import Path


CRS_GITLINK = "tests/eval_suite/coreruleset"
ALLOWED_MARKDOWN = {
    ".github/PULL_REQUEST_TEMPLATE.md",
    "CONTRIBUTING.md",
    "INTEGRITY.md",
    "README.md",
    "SECURITY.md",
    "bench/benchmark_harness/README.md",
    "methodology/README.md",
    "reports/README.md",
}
ALLOWED_MARKDOWN_PATTERNS = (
    re.compile(
        r"^reports/benchmark_harness_v1/v\d+\.\d+\.\d+(?:-rc\.\d+)?/BENCHMARK_RESULTS\.md$"
    ),
    re.compile(
        r"^reports/canonical/v\d+\.\d+\.\d+(?:-rc\.\d+)?/"
        r"(?:README|BENCHMARK_RESULTS)\.md$"
    ),
    re.compile(
        r"^reports/canonical/v\d+\.\d+\.\d+(?:-rc\.\d+)?/RAW/README\.md$"
    ),
)
FORBIDDEN_EXACT = {
    "CHANGELOG.md",
    "benchmark_results.json",
    "lumina_profile.json",
    "run_all_benchmarks.sh",
    "src/crs_tx_rules.c",
    "src/parser_input.c",
    "test_decode.c",
    "test_scan.c",
    "tests/eval_suite/ftw",
}
FORBIDDEN_PREFIXES = (
    "bench/iron_benchmark/",
    "docs/",
    "infra/soaking_test/",
    "src/generated/",
    "src/precompiled/",
    "test_nginx/",
    "tests/eval_suite/corpus/",
    "third_party/libinjection/",
)
FORBIDDEN_SUFFIXES = (".o", ".so", ".pyc", ".tar.gz", ".tar.zst", ".zip")
RULE_FILE_RE = re.compile(r"(?:^|/)(?:REQUEST|RESPONSE)-[^/]+\.conf$")
PARSER_CHUNK_RE = re.compile(r"^src/parser_rules_[0-9]+\.c$")


def tracked_entries(root: Path) -> list[tuple[str, str]]:
    result = subprocess.run(
        ["git", "ls-files", "--stage", "-z"],
        cwd=root,
        check=True,
        stdout=subprocess.PIPE,
    )
    entries: list[tuple[str, str]] = []
    for record in result.stdout.split(b"\0"):
        if not record:
            continue
        metadata, raw_path = record.split(b"\t", 1)
        mode = metadata.split(b" ", 1)[0].decode("ascii")
        entries.append((mode, raw_path.decode("utf-8", errors="surrogateescape")))
    return entries


def validate_entries(entries: list[tuple[str, str]]) -> list[str]:
    errors: list[str] = []
    gitlink_mode = None
    for mode, path in entries:
        if path == CRS_GITLINK:
            gitlink_mode = mode
            continue
        markdown_allowed = path in ALLOWED_MARKDOWN or any(
            pattern.fullmatch(path) for pattern in ALLOWED_MARKDOWN_PATTERNS
        )
        if path.endswith(".md") and not markdown_allowed:
            errors.append(f"unapproved release documentation is tracked: {path}")
        if path in FORBIDDEN_EXACT:
            errors.append(f"generated or binary artifact is tracked: {path}")
        if path.startswith(FORBIDDEN_PREFIXES):
            errors.append(f"forbidden vendored/generated path is tracked: {path}")
        if path.endswith(FORBIDDEN_SUFFIXES):
            errors.append(f"binary/archive artifact is tracked: {path}")
        if path.startswith("tests/eval_suite/") and path.endswith(".data"):
            errors.append(f"CRS data copy is tracked: {path}")
        if path.endswith("/crs-setup.conf") or path == "crs-setup.conf":
            errors.append(f"generated CRS setup is tracked: {path}")
        if RULE_FILE_RE.search(path):
            errors.append(f"CRS rule file is tracked outside the submodule: {path}")
        if PARSER_CHUNK_RE.match(path):
            errors.append(f"generated parser chunk is tracked: {path}")
        if path.startswith("tests/debug"):
            errors.append(f"one-off debug source is tracked: {path}")
    if gitlink_mode != "160000":
        errors.append(
            f"{CRS_GITLINK} must be a Git submodule, observed mode={gitlink_mode or 'missing'}"
        )
    return sorted(set(errors))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    root = args.root.resolve()
    errors = validate_entries(tracked_entries(root))
    if errors:
        print("Release tree verification failed:")
        for error in errors:
            print(f"- {error}")
        return 1
    print("Release tree verification passed: CRS inputs and generated AOT are untracked")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
