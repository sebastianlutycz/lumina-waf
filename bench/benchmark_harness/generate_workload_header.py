#!/usr/bin/env python3
"""Generate immutable C++ request descriptors from the V1.0 Protocol workload."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def cpp_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)


def render(source: Path) -> str:
    payload = json.loads(source.read_text(encoding="utf-8"))
    requests = [item for item in payload.get("requests", []) if item.get("class") == "allow"]
    if not requests:
        raise RuntimeError("workload has no allow requests")
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    lines = [
        "#pragma once",
        "",
        "#include <cstddef>",
        "",
        "namespace iron_v10_workload {",
        "",
        "struct Header { const char *name; const char *value; };",
        "struct Request {",
        "    const char *id;",
        "    const char *method;",
        "    const char *path;",
        "    const char *query;",
        "    const char *protocol;",
        "    const Header *headers;",
        "    std::size_t header_count;",
        "};",
        "",
    ]
    for index, request in enumerate(requests):
        lines.append(f"inline constexpr Header kHeaders{index}[] = {{")
        for name, value in request.get("headers", []):
            lines.append(f"    {{{cpp_string(str(name))}, {cpp_string(str(value))}}},")
        lines.extend(["};", ""])
    lines.append("inline constexpr Request kAllowRequests[] = {")
    for index, request in enumerate(requests):
        fields = [
            request["id"], request.get("method", "GET"), request["path"],
            request.get("query", ""), request.get("protocol", "HTTP/1.1"),
        ]
        lines.append(
            "    {" + ", ".join(cpp_string(str(value)) for value in fields)
            + f", kHeaders{index}, sizeof(kHeaders{index}) / sizeof(kHeaders{index}[0])" + "},"
        )
    lines.extend([
        "};",
        "inline constexpr std::size_t kAllowRequestCount =",
        "    sizeof(kAllowRequests) / sizeof(kAllowRequests[0]);",
        f"inline constexpr char kWorkloadSha256[] = {cpp_string(digest)};",
        "",
        "}  // namespace iron_v10_workload",
        "",
    ])
    return "\n".join(lines)


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
