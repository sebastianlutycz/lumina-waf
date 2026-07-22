#!/usr/bin/env python3
"""Run the immutable cross-engine allow/attack outcome matrix."""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
from pathlib import Path
from typing import Any

from e2e import NginxLeg, adapters, render_config


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def send(port: int, request: dict[str, Any]) -> int:
    query = request.get("query", "")
    target = request["path"] + (("?" + query) if query else "")
    headers = {str(name): str(value) for name, value in request.get("headers", [])}
    body = str(request.get("body", "")).encode("utf-8")
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5.0)
    try:
        connection.request(
            request.get("method", "GET"), target,
            body=body if body else None, headers=headers,
        )
        response = connection.getresponse()
        response.read()
        return response.status
    finally:
        connection.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--workload", type=Path, required=True)
    parser.add_argument("--nginx", type=Path, required=True)
    parser.add_argument("--library-path", required=True)
    parser.add_argument("--server-cpu", default="1")
    parser.add_argument("--port", type=int, default=19094)
    parser.add_argument("--canonical", action="store_true")
    args = parser.parse_args()

    args.output.mkdir(parents=True, exist_ok=False)
    workload = json.loads(args.workload.read_text(encoding="utf-8"))
    requests = workload.get("requests", [])
    if not requests:
        raise RuntimeError("correctness workload is empty")
    rows: list[dict[str, Any]] = []
    summaries: list[dict[str, Any]] = []
    for adapter in adapters(args.canonical):
        config = args.output / f"nginx_{adapter.name}.conf"
        render_config(adapter, config, args.port, 1, args.workload)
        leg = NginxLeg(args.nginx, config, args.port, args.server_cpu, args.library_path)
        engine_rows: list[dict[str, Any]] = []
        try:
            leg.preflight()
            leg.start()
            for request in requests:
                status = send(args.port, request)
                blocked = not (200 <= status < 400)
                expected_block = request["class"] == "attack"
                if adapter.table == "baseline":
                    passed = not blocked
                elif adapter.table == "crs":
                    passed = blocked == expected_block
                else:
                    passed = True
                row = {
                    "engine": adapter.name,
                    "table": adapter.table,
                    "request_id": request["id"],
                    "class": request["class"],
                    "category": request.get("category"),
                    "status": status,
                    "blocked": blocked,
                    "passed": passed,
                }
                rows.append(row)
                engine_rows.append(row)
        finally:
            leg.stop()
        attacks = [row for row in engine_rows if row["class"] == "attack"]
        allows = [row for row in engine_rows if row["class"] == "allow"]
        summaries.append(
            {
                "engine": adapter.name,
                "table": adapter.table,
                "attack_detection_percent": (
                    100.0 * sum(row["blocked"] for row in attacks) / len(attacks)
                    if attacks else 0.0
                ),
                "false_positive_percent": (
                    100.0 * sum(row["blocked"] for row in allows) / len(allows)
                    if allows else 0.0
                ),
                "passed_contract": all(row["passed"] for row in engine_rows),
            }
        )
    payload = {
        "schema": 1,
        "workload_sha256": sha256(args.workload),
        "results": rows,
        "summary": summaries,
        "valid": all(item["passed_contract"] for item in summaries if item["table"] != "native-waf"),
    }
    (args.output / "results.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    if args.canonical and not payload["valid"]:
        return 2
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"Correctness matrix failed: {exc}")
        raise SystemExit(2)
