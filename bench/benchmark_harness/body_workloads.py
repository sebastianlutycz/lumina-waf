#!/usr/bin/env python3
"""Deterministically materialize request-body workloads for Benchmark Harness V1.0."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


BODY_SIZES_KIB = (4, 16, 128)
SAFE_ALPHABET = "bcdfghjklmnpqvwxyz"
SAFE_SEED = 0x9E3779B9
TAIL_ATTACK = "<script>alert(1)</script>"


def make_safe_filler(size_bytes: int) -> str:
    state = SAFE_SEED
    output: list[str] = []
    append = output.append
    for _ in range(size_bytes):
        state ^= (state << 13) & 0xFFFFFFFF
        state ^= state >> 17
        state ^= (state << 5) & 0xFFFFFFFF
        state &= 0xFFFFFFFF
        append(SAFE_ALPHABET[state % len(SAFE_ALPHABET)])
    return "".join(output)


def make_json_body(size_bytes: int, attack: bool) -> str:
    suffix = (
        f'","tail_probe":"{TAIL_ATTACK}"}}'
        if attack
        else '","tail_probe":"clean"}'
    )
    prefix = '{"schema":"body-e2e-v1","payload":"'
    filler_bytes = size_bytes - len(prefix) - len(suffix)
    if filler_bytes < 0:
        raise ValueError(f"body size {size_bytes} is too small")
    body = prefix + make_safe_filler(filler_bytes) + suffix
    encoded = body.encode("utf-8")
    if len(encoded) != size_bytes:
        raise AssertionError(
            f"generated body bytes={len(encoded)}, expected={size_bytes}"
        )
    json.loads(body)
    return body


def workload_payload(size_kib: int, request_class: str) -> dict[str, Any]:
    if size_kib not in BODY_SIZES_KIB:
        raise ValueError(f"unsupported body size: {size_kib} KiB")
    if request_class not in ("allow", "attack"):
        raise ValueError(f"unsupported request class: {request_class}")
    attack = request_class == "attack"
    body = make_json_body(size_kib * 1024, attack)
    expected_status = 403 if attack else 204
    return {
        "schema": 1,
        "name": f"json-{request_class}-{size_kib}kib",
        "body_size_bytes": len(body.encode("utf-8")),
        "request_class": request_class,
        "expected_status": expected_status,
        "requests": [
            {
                "id": f"json-{request_class}-{size_kib}kib",
                "class": request_class,
                "method": "POST",
                "path": "/body-benchmark.json",
                "query": "",
                "headers": [
                    ["Host", "benchmark.local"],
                    ["User-Agent", "LuminaWAF-Body-Evidence/1"],
                    ["Content-Type", "application/json"],
                ],
                "body": body,
                "expected_status": expected_status,
            }
        ],
    }


def materialize(output: Path) -> dict[str, Any]:
    output.mkdir(parents=True, exist_ok=False)
    rows: list[dict[str, Any]] = []
    for size_kib in BODY_SIZES_KIB:
        for request_class in ("allow", "attack"):
            payload = workload_payload(size_kib, request_class)
            path = output / f"json_{request_class}_{size_kib}kib.json"
            serialized = json.dumps(payload, indent=2, sort_keys=True) + "\n"
            path.write_text(serialized, encoding="utf-8")
            rows.append(
                {
                    "id": payload["name"],
                    "request_class": request_class,
                    "size_kib": size_kib,
                    "body_size_bytes": payload["body_size_bytes"],
                    "expected_status": payload["expected_status"],
                    "path": path.name,
                    "sha256": hashlib.sha256(serialized.encode("utf-8")).hexdigest(),
                    "body_sha256": hashlib.sha256(
                        payload["requests"][0]["body"].encode("utf-8")
                    ).hexdigest(),
                }
            )
    manifest = {
        "schema": 1,
        "generator": "Benchmark Harness V1.0 deterministic JSON body generator",
        "safe_alphabet": SAFE_ALPHABET,
        "safe_seed": SAFE_SEED,
        "workloads": rows,
    }
    (output / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    materialize(args.output)
    print(args.output / "manifest.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
