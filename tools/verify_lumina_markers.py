#!/usr/bin/env python3
"""Verify passive LuminaWAF v0.4 origin markers.

This tool performs local source/binary checks and, optionally, a single HTTP
HEAD request against a target URL. It does not send trigger payloads and does
not rely on hidden runtime behavior.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import subprocess
import sys
import urllib.request

BUILD_TAG = "a4e12f09bc8736d5"
BUILD_FINGERPRINT = "lumina-waf/v0.4/agpl/a4e12f09bc8736d5"
REGISTRY_VERSION = "v0.4-clean"


def read_text(path: pathlib.Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return ""


def run(args: list[str]) -> str:
    try:
        return subprocess.check_output(args, stderr=subprocess.STDOUT, text=True)
    except (FileNotFoundError, subprocess.CalledProcessError) as exc:
        return getattr(exc, "output", "") or ""


def check_source(root: pathlib.Path) -> list[tuple[str, bool, str]]:
    checks = []
    files = {
        "marker_header": root / "src" / "lumina_markers.h",
        "marker_source": root / "src" / "lumina_markers.cpp",
        "nginx_module": root / "nginx_module" / "ngx_http_luminawaf_module.c",
        "cmake": root / "CMakeLists.txt",
        "integrity": root / "INTEGRITY.md",
    }
    blob = "\n".join(read_text(p) for p in files.values())
    checks.append(("source.build_tag", BUILD_TAG in blob, BUILD_TAG))
    checks.append(("source.registry_version", REGISTRY_VERSION in blob, REGISTRY_VERSION))
    checks.append(("source.public_api", "luminawaf_build_fingerprint" in blob, "public ABI"))
    checks.append(("source.nginx_header", "X-LuminaWAF-Id" in blob, "AGPL response header"))
    checks.append((
        "source.agpl_license",
        '#define LUMINA_MARKER_LICENSE_MODE "AGPLv3"' in blob,
        "AGPLv3 build mode",
    ))
    return checks


def check_manifest(root: pathlib.Path) -> list[tuple[str, bool, str]]:
    manifest_path = root / "src" / "generated" / "rule_manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return [("manifest.present", False, str(manifest_path))]
    prov = manifest.get("lumina_provenance") or {}
    return [
        ("manifest.provenance", bool(prov), "lumina_provenance"),
        ("manifest.registry_version", prov.get("registry_version") == REGISTRY_VERSION, REGISTRY_VERSION),
        ("manifest.build_tag", prov.get("build_tag") == BUILD_TAG, BUILD_TAG),
        ("manifest.policy", prov.get("marker_policy") == "passive-forensic-no-telemetry", "passive policy"),
    ]


def check_binary(binary: pathlib.Path) -> list[tuple[str, bool, str]]:
    if not binary:
        return []
    strings_out = run(["strings", "-a", str(binary)])
    sections = run(["readelf", "-SW", str(binary)])
    note_hex = run(["readelf", "-x", ".note.lumina", str(binary)])
    fp_hex = run(["readelf", "-x", ".lumina_fingerprint", str(binary)])
    symbols = run(["readelf", "-Ws", str(binary)])
    return [
        ("binary.exists", binary.exists(), str(binary)),
        ("binary.build_fingerprint_string", BUILD_FINGERPRINT in strings_out, BUILD_FINGERPRINT),
        ("binary.note_section", ".note.lumina" in sections, ".note.lumina"),
        ("binary.note_build_tag", re.search(r"a4e12f09|bc8736d5", note_hex, re.I) is not None, BUILD_TAG),
        ("binary.fingerprint_section", ".lumina_fingerprint" in sections, ".lumina_fingerprint"),
        ("binary.fingerprint_bytes", re.search(r"a4e12f09|bce?8736d5", fp_hex.replace(" ", ""), re.I) is not None, "fingerprint bytes"),
        ("binary.no_header_presence_global", "g_hdr_presence_mask_tls" not in symbols,
         "request header state is passed explicitly"),
    ]


def check_url(url: str | None) -> list[tuple[str, bool, str]]:
    if not url:
        return []
    req = urllib.request.Request(url, method="HEAD")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            value = resp.headers.get("X-LuminaWAF-Id", "")
    except Exception as exc:
        return [("http.head", False, str(exc))]
    return [
        ("http.x_luminawaf_id", BUILD_TAG in value and "AGPLv3" in value, value or "missing"),
    ]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--source-root", default=".", help="LuminaWAF source root")
    ap.add_argument("--binary", default=None, help="Path to libluminawaf.so")
    ap.add_argument("--url", default=None, help="Optional URL for a HEAD check")
    args = ap.parse_args()

    root = pathlib.Path(args.source_root).resolve()
    results = []
    results.extend(check_source(root))
    results.extend(check_manifest(root))
    if args.binary:
        results.extend(check_binary(pathlib.Path(args.binary).resolve()))
    results.extend(check_url(args.url))

    ok = True
    for name, passed, detail in results:
        ok &= passed
        print(f"{'PASS' if passed else 'FAIL'} {name}: {detail}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
