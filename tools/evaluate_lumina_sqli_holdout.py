#!/usr/bin/env python3
"""Evaluate one independent LuminaSQLi candidate against the sealed holdout."""

import argparse
import base64
import ctypes
import json
import os
import pathlib
import subprocess
import sys
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
FORBIDDEN_SOURCE_MARKERS = (
    b"libinjection",
    b"bsearch_keyword_type",
    b"libinjection_sqli_data",
    b"third_party/",
    b"third_party\\",
    b"evidence_b64",
)


def load_rows(path):
    for line_no, line in enumerate(path.read_text(encoding="ascii").splitlines(), 1):
        if not line:
            continue
        row = json.loads(line)
        try:
            match = int(row["match"])
            if match not in (0, 1):
                raise ValueError("match must be 0 or 1")
            yield {
                "id": row["id"],
                "input": base64.b64decode(row["input_b64"], validate=True),
                "match": match,
            }
        except (KeyError, ValueError) as error:
            raise ValueError(f"{path}:{line_no}: invalid holdout row") from error


def scan_candidate(candidate):
    files = sorted(
        path for path in candidate.rglob("*")
        if path.is_file() and path.suffix.lower() in {
            ".c", ".h", ".cc", ".cpp", ".inc", ".md", ".txt", ".py",
        })
    if not files:
        raise ValueError("candidate contains no auditable source files")
    for path in files:
        data = path.read_bytes().lower()
        for marker in FORBIDDEN_SOURCE_MARKERS:
            if marker.lower() in data:
                raise ValueError(f"forbidden reference marker in candidate: {path}")
    return files


def build_classifier(candidate):
    source = candidate / "src" / "lumina_sqli.c"
    header_dir = candidate / "api"
    if not source.is_file() or not (header_dir / "lumina_sqli.h").is_file():
        raise ValueError("candidate is missing src/lumina_sqli.c or api/lumina_sqli.h")
    temporary = tempfile.TemporaryDirectory()
    library = pathlib.Path(temporary.name) / "lumina_sqli_candidate.so"
    subprocess.run(
        [
            "cc", "-std=c11", "-O2", "-fPIC", "-shared",
            "-Wall", "-Wextra", "-Werror", "-pedantic",
            f"-I{header_dir}", str(source), "-o", str(library),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    loaded = ctypes.CDLL(str(library))
    detect = loaded.lumina_sqli_detect
    detect.argtypes = [
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.c_size_t,
    ]
    detect.restype = ctypes.c_int

    def classify(value):
        storage = (ctypes.c_uint8 * max(1, len(value)))()
        if value:
            ctypes.memmove(storage, value, len(value))
        return int(detect(storage, len(value)) != 0)

    return temporary, classify


def evaluate_rows(rows, classify):
    summary = {
        "total": 0,
        "expected_positive": 0,
        "false_negative": 0,
        "false_positive": 0,
    }
    details = []
    for row in rows:
        observed = classify(row["input"])
        summary["total"] += 1
        summary["expected_positive"] += row["match"]
        if row["match"] and not observed:
            summary["false_negative"] += 1
        elif not row["match"] and observed:
            summary["false_positive"] += 1
        if observed != row["match"]:
            details.append({
                "id": row["id"],
                "expected_match": row["match"],
                "observed_match": observed,
            })
    summary["passed"] = (
        summary["false_negative"] == 0
        and summary["false_positive"] == 0
    )
    return summary, details


def write_details(path, details):
    path = path.resolve()
    try:
        path.relative_to(ROOT.resolve())
    except ValueError:
        pass
    else:
        raise ValueError("holdout details must be outside the reference checkout")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(details, indent=2, sort_keys=True) + "\n", encoding="ascii")
    os.chmod(path, 0o600)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("candidate", type=pathlib.Path)
    parser.add_argument("--holdout", type=pathlib.Path, required=True)
    parser.add_argument("--details-output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    try:
        candidate = args.candidate.resolve()
        scan_candidate(candidate)
        temporary, classify = build_classifier(candidate)
        try:
            summary, details = evaluate_rows(load_rows(args.holdout), classify)
        finally:
            temporary.cleanup()
        write_details(args.details_output, details)
    except (OSError, ValueError, json.JSONDecodeError, subprocess.CalledProcessError) as error:
        print(f"holdout evaluation failed: {error}", file=sys.stderr)
        return 2
    print(json.dumps(summary, sort_keys=True))
    return 0 if summary["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
