#!/usr/bin/env python3
"""Build and validate the immutable LuminaWAF Benchmark Harness v1 CRS manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CRS = ROOT / "tests/eval_suite/coreruleset"
DEFAULT_CONFIG = ROOT / "tests/eval_suite/modsec_crs_pl2.conf"
GENERATED_MANIFEST = ROOT / "src/generated/rule_manifest.json"
WORKLOAD = Path(__file__).resolve().parent / "workloads/requests.json"
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / "tools"))

from audit_crs_mechanisms import audit_rules  # noqa: E402


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git(path: Path, *args: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(path), *args], text=True, stderr=subprocess.DEVNULL
    ).strip()


def normalized_path(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT).as_posix()
    except ValueError:
        return str(path.resolve())


def parse_includes(config: Path) -> list[Path]:
    includes: list[Path] = []
    for raw in config.read_text(encoding="utf-8").splitlines():
        match = re.match(r"^\s*Include\s+(.+?)\s*$", raw)
        if not match:
            continue
        value = match.group(1).strip().strip('"')
        candidate = Path(value)
        if not candidate.is_absolute():
            candidate = config.parent / candidate
        matches = sorted(candidate.parent.glob(candidate.name))
        if not matches:
            raise ValueError(f"Include does not resolve: {value}")
        includes.extend(item.resolve() for item in matches)
    return includes


def policy_value(text: str, name: str) -> int | None:
    patterns = (
        rf"setvar\s*:\s*['\"]?tx\.{re.escape(name)}\s*=\s*(\d+)",
        rf"setvar\s*:\s*['\"]?tx\.{re.escape(name)}\s*=\s*%\{{tx\.{re.escape(name)}\}}",
    )
    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match and match.lastindex:
            return int(match.group(1))
    return None


def active_text(paths: list[Path]) -> str:
    lines: list[str] = []
    for path in paths:
        for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if raw.lstrip().startswith("#"):
                continue
            lines.append(raw)
    return "\n".join(lines)


def file_entry(path: Path) -> dict[str, Any]:
    return {
        "path": normalized_path(path),
        "bytes": path.stat().st_size,
        "sha256": sha256(path),
    }


OVERRIDE_RE = re.compile(
    r"^\s*(SecRuleRemoveById|SecRuleUpdateTargetById|SecRuleUpdateActionById)\b.*$",
    re.IGNORECASE | re.MULTILINE,
)
CRS_CONTROL_RE = re.compile(
    r"\bctl:ruleRemove(?:ById|TargetById)\s*=\s*[^,\s\\]+",
    re.IGNORECASE,
)


def active_directives(path: Path, pattern: re.Pattern[str]) -> list[str]:
    text = active_text([path])
    return [match.group(0).strip() for match in pattern.finditer(text)]


def include_identity(paths: list[Path]) -> list[tuple[str, str]]:
    return [(normalized_path(path), sha256(path)) for path in paths]


def build_manifest(
    crs: Path,
    config: Path,
    strict: bool,
    coraza_config: Path | None = None,
    require_coraza: bool = False,
) -> dict[str, Any]:
    crs = crs.resolve()
    config = config.resolve()
    includes = parse_includes(config)
    if not includes:
        raise ValueError("Comparator configuration has no ordered CRS includes")

    setup_candidates = [path for path in includes if path.name == "crs-setup.conf"]
    setup = setup_candidates[0] if len(setup_candidates) == 1 else None
    policy_text = active_text(includes)
    generated = json.loads(GENERATED_MANIFEST.read_text(encoding="utf-8"))
    audit_rows = audit_rules(crs / "rules", 2)
    inbound_pl2_rule_ids = sorted({row.rule_id for row in audit_rows})
    runtime_covered_ids = sorted({row.rule_id for row in audit_rows if row.runtime_covered})
    tracked_dirty = git(crs, "status", "--porcelain=v1", "--untracked-files=no")
    untracked = git(crs, "status", "--porcelain=v1", "--untracked-files=all")
    untracked_entries = [
        line[3:] for line in untracked.splitlines() if line.startswith("?? ")
    ]
    data_files = sorted((crs / "rules").glob("**/*.data"))

    policy = {
        "blocking_paranoia_level": policy_value(policy_text, "blocking_paranoia_level"),
        "detection_paranoia_level": policy_value(policy_text, "detection_paranoia_level"),
        "inbound_anomaly_score_threshold": policy_value(
            policy_text, "inbound_anomaly_score_threshold"
        ),
    }
    expected = {
        "blocking_paranoia_level": 2,
        "detection_paranoia_level": 2,
        "inbound_anomaly_score_threshold": 5,
    }
    errors: list[str] = []
    if tracked_dirty:
        errors.append("CRS has tracked modifications")
    if untracked_entries:
        errors.append("CRS has untracked entries")
    for key, value in expected.items():
        if policy[key] != value:
            errors.append(f"{key}={policy[key]!r}, expected {value}")
    if setup is None:
        errors.append("ordered include list must contain exactly one crs-setup.conf")
    if not any(path.name == "REQUEST-949-BLOCKING-EVALUATION.conf" for path in includes):
        errors.append("REQUEST-949-BLOCKING-EVALUATION.conf is not enabled")

    comparator_overrides = active_directives(config, OVERRIDE_RE)
    if comparator_overrides:
        errors.append("ModSecurity comparator contains external rule overrides")

    comparators: dict[str, Any] = {
        "modsecurity": {
            "config": file_entry(config),
            "ordered_include_identity": include_identity(includes),
            "external_rule_overrides": comparator_overrides,
        }
    }
    if coraza_config is not None:
        coraza_config = coraza_config.resolve()
        coraza_includes = parse_includes(coraza_config)
        coraza_overrides = active_directives(coraza_config, OVERRIDE_RE)
        if include_identity(coraza_includes) != include_identity(includes):
            errors.append("Coraza and ModSecurity ordered CRS include graphs differ")
        if coraza_overrides:
            errors.append("Coraza comparator contains external rule overrides")
        comparators["coraza"] = {
            "config": file_entry(coraza_config),
            "ordered_include_identity": include_identity(coraza_includes),
            "external_rule_overrides": coraza_overrides,
        }
    elif require_coraza:
        errors.append("Coraza comparator configuration is required in strict mode")

    payload: dict[str, Any] = {
        "schema": 1,
        "canonical": not errors,
        "validation_errors": errors,
        "crs": {
            "origin": git(crs, "remote", "get-url", "origin"),
            "commit": git(crs, "rev-parse", "HEAD"),
            "tracked_worktree_clean": not bool(tracked_dirty),
            "untracked_entries": untracked_entries,
            "config": file_entry(config),
            "ordered_includes": [file_entry(path) for path in includes],
            "data_files": [file_entry(path) for path in data_files],
            "policy": policy,
            "inbound_pl2_rule_count": len(inbound_pl2_rule_ids),
            "inbound_pl2_rule_ids": inbound_pl2_rule_ids,
            "native_rule_controls": [
                directive
                for path in includes
                for directive in active_directives(path, CRS_CONTROL_RE)
            ],
        },
        "comparators": comparators,
        "lumina": {
            "generated_manifest": file_entry(GENERATED_MANIFEST),
            "generated_rule_count": len(generated.get("generated_rule_ids", [])),
            "generated_rule_ids": generated.get("generated_rule_ids", []),
            "runtime_covered_ids": runtime_covered_ids,
        },
        "workload": file_entry(WORKLOAD),
    }
    canonical_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    payload["manifest_sha256"] = hashlib.sha256(canonical_bytes).hexdigest()
    if strict and errors:
        raise ValueError("; ".join(errors))
    return payload


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--crs", type=Path, default=DEFAULT_CRS)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--coraza-config", type=Path)
    parser.add_argument("--require-coraza", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--strict", action="store_true")
    args = parser.parse_args()
    try:
        manifest = build_manifest(
            args.crs,
            args.config,
            args.strict,
            coraza_config=args.coraza_config,
            require_coraza=args.require_coraza,
        )
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"manifest gate failed: {exc}")
        return 2
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"manifest={args.output}")
    print(f"sha256={manifest['manifest_sha256']}")
    print(f"canonical={str(manifest['canonical']).lower()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
