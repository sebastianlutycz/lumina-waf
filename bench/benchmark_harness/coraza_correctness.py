#!/usr/bin/env python3
"""Run the pinned CRS FTW suite against the canonical Coraza-NGINX adapter."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
PREFIX = ROOT / "test_nginx"


def render_nginx(source: Path, destination: Path, error_log: Path, pid: Path, port: int) -> None:
    text = source.read_text(encoding="utf-8")
    static_root = destination.parent / "html"
    static_root.mkdir(parents=True, exist_ok=True)
    (static_root / "about").write_bytes(b"")
    text, count = re.subn(r"\blisten\s+\d+\s*;", f"listen {port};", text, count=1)
    if count != 1:
        raise RuntimeError("Coraza NGINX config has no replaceable listen directive")
    text, count = re.subn(
        r"^pid\s+[^;]+;", f"pid {pid};", text, count=1, flags=re.MULTILINE
    )
    if count == 0:
        text = f"pid {pid};\n" + text
    text, count = re.subn(
        r"(^\s*http\s*\{)",
        lambda match: match.group(1) + "\n    max_ranges 0;",
        text,
        count=1,
        flags=re.MULTILINE,
    )
    if count != 1:
        raise RuntimeError("Coraza NGINX config has no HTTP block")
    text, count = re.subn(
        r"(^\s*root\s+)[^;]+;",
        lambda match: match.group(1) + str(static_root) + ";",
        text,
        count=1,
        flags=re.MULTILINE,
    )
    if count != 1:
        raise RuntimeError("Coraza NGINX config has no replaceable static root")
    text = f"error_log {error_log} info;\n" + text
    destination.write_text(text, encoding="utf-8")


def wait_ready(port: int) -> None:
    deadline = time.monotonic() + 15.0
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=0.25):
                return
        except urllib.error.HTTPError:
            return
        except Exception:
            time.sleep(0.1)
    raise RuntimeError("Coraza NGINX did not become ready")


def normalize_ftw(raw: dict[str, Any], manifest_sha: str) -> dict[str, Any]:
    success = list(raw.get("success") or [])
    failed = list(raw.get("failed") or [])
    ignored = list(raw.get("ignored") or [])
    forced_pass = list(raw.get("forced-pass") or [])
    forced_fail = list(raw.get("forced-fail") or [])
    evaluated = len(success) + len(failed)
    parity = (100.0 * len(success) / evaluated) if evaluated else 0.0
    return {
        "schema": 1,
        "engine": "coraza",
        "suite": "go-ftw CRS regression",
        "correctness_mode": "http-verdict",
        "exact_rule_id_observable": False,
        "crs_manifest_sha256": manifest_sha,
        "tests": evaluated,
        "discovered_tests": int(raw.get("run", evaluated)),
        "passed": len(success),
        "failed": len(failed),
        "selection_skipped": len(raw.get("skipped") or []),
        "transport_skipped": 0,
        "ignored": len(ignored),
        "forced_pass": len(forced_pass),
        "forced_fail": len(forced_fail),
        "overall_parity": parity,
        "timeouts": 0,
        "exceptions": 0,
        "outcome_overrides": ignored + forced_pass + forced_fail,
        "failed_tests": failed,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--go-ftw", type=Path, required=True)
    parser.add_argument("--nginx", type=Path, required=True)
    parser.add_argument("--nginx-config", type=Path, required=True)
    parser.add_argument("--tests", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--library-path", required=True)
    parser.add_argument("--port", type=int, default=19093)
    parser.add_argument("--timeout", type=int, default=1800)
    args = parser.parse_args()

    for name in ("go_ftw", "nginx", "nginx_config", "tests", "manifest", "output"):
        setattr(args, name, getattr(args, name).resolve())

    args.output.parent.mkdir(parents=True, exist_ok=True)
    work = args.output.parent / "coraza_ftw"
    work.mkdir(parents=True, exist_ok=False)
    error_log = work / "nginx_error.log"
    error_log.touch()
    pid = work / "nginx.pid"
    nginx_config = work / "nginx.conf"
    ftw_config = work / ".ftw.yaml"
    raw_output = work / "go_ftw.json"
    render_nginx(args.nginx_config, nginx_config, error_log, pid, args.port)
    ftw_config.write_text(
        "\n".join(
            [
                "mode: cloud",
                "testoverride:",
                "  input:",
                "    dest_addr: '127.0.0.1'",
                f"    port: {args.port}",
                "    protocol: 'http'",
                "    virtual_host_mode: true",
                "",
            ]
        ),
        encoding="utf-8",
    )
    env = os.environ.copy()
    env["LD_LIBRARY_PATH"] = args.library_path + ":" + env.get("LD_LIBRARY_PATH", "")
    nginx_base = [str(args.nginx), "-c", str(nginx_config), "-p", str(PREFIX)]
    subprocess.run([*nginx_base, "-t"], env=env, check=True, capture_output=True, text=True)
    started = False
    try:
        subprocess.run(nginx_base, env=env, check=True, capture_output=True, text=True)
        started = True
        wait_ready(args.port)
        manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
        rule_ids = sorted(int(value) for value in manifest["crs"]["inbound_pl2_rule_ids"])
        if not rule_ids:
            raise RuntimeError("CRS manifest contains no PL2 rule inventory")
        include_pattern = "^(?:" + "|".join(str(value) for value in rule_ids) + ")(?:-|$)"
        process = subprocess.run(
            [
                str(args.go_ftw),
                "--config", str(ftw_config),
                "--cloud",
                "run", "--dir", str(args.tests),
                "--include", include_pattern,
                "--output", "json", "--file", str(raw_output),
            ],
            env=env,
            cwd=work,
            timeout=args.timeout,
            capture_output=True,
            text=True,
        )
        (work / "go_ftw.stdout.log").write_text(process.stdout, encoding="utf-8")
        (work / "go_ftw.stderr.log").write_text(process.stderr, encoding="utf-8")
        if not raw_output.is_file() or raw_output.stat().st_size == 0:
            raise RuntimeError(f"go-ftw produced no JSON output (exit={process.returncode})")
        raw = json.loads(raw_output.read_text(encoding="utf-8"))
        summary = normalize_ftw(raw, manifest["manifest_sha256"])
        summary["selected_rule_ids"] = rule_ids
        summary["go_ftw_exit"] = process.returncode
        args.output.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    finally:
        if started:
            subprocess.run(
                [*nginx_base, "-s", "quit"], env=env, check=False,
                capture_output=True, text=True,
            )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f"Coraza correctness failed: {exc}")
        raise SystemExit(2)
