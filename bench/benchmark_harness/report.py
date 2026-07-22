#!/usr/bin/env python3
"""Render LuminaWAF Benchmark Harness v1 Markdown from immutable raw artifacts."""

from __future__ import annotations

import argparse
import csv
import json
import random
import re
import statistics
from pathlib import Path
from typing import Any


def load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def micro_artifact_paths(result_dir: Path, suffix: str) -> list[Path]:
    paths = [result_dir / f"micro.{suffix}"]
    paths.extend(sorted(result_dir.glob(f"micro_process_*.{suffix}")))
    return [path for path in paths if path.exists()]


def overhead_micro_artifact_paths(result_dir: Path, suffix: str) -> list[Path]:
    paths = [result_dir / f"overhead_micro.{suffix}"]
    paths.extend(sorted(result_dir.glob(f"overhead_micro_process_*.{suffix}")))
    return [path for path in paths if path.exists()]


def format_time(ns: float) -> str:
    if ns < 1_000:
        return f"{ns:.1f} ns"
    if ns < 1_000_000:
        return f"{ns / 1_000:.2f} us"
    return f"{ns / 1_000_000:.2f} ms"


def format_signed_time(ns: float) -> str:
    return ("-" if ns < 0 else "") + format_time(abs(ns))


def signed_ci_text(interval: tuple[float, float] | None) -> str:
    if interval is None:
        return "N/A - fewer than two independent runs"
    return f"{format_signed_time(interval[0])} - {format_signed_time(interval[1])}"


def bootstrap_median_ci(
    values: list[float], samples: int = 10_000
) -> tuple[float, float] | None:
    if len(values) < 2:
        return None
    rng = random.Random(0x1A0B10)
    estimates = sorted(
        statistics.median(rng.choice(values) for _ in values) for _ in range(samples)
    )
    return estimates[int(samples * 0.025)], estimates[int(samples * 0.975)]


def micro_rows(paths: list[Path]) -> list[dict[str, Any]]:
    groups: dict[str, list[float]] = {}
    inner_cvs: dict[str, list[float]] = {}
    for path in paths:
        raw = load(path)
        for item in raw.get("benchmarks", []):
            aggregate = item.get("aggregate_name")
            if aggregate not in ("median", "cv"):
                continue
            name = item["run_name"].removesuffix("/repeats:10")
            if aggregate == "median":
                groups.setdefault(name, []).append(float(item["cpu_time"]))
            else:
                inner_cvs.setdefault(name, []).append(float(item["cpu_time"]) * 100.0)
    rows: list[dict[str, Any]] = []
    for name, values in sorted(groups.items()):
        interval = bootstrap_median_ci(values)
        rows.append(
            {"name": name, "cpu": statistics.median(values), "ci": interval,
             "inner_cv": statistics.median(inner_cvs.get(name, []))
             if inner_cvs.get(name) else None,
             "processes": len(values), "qualified": len(values) >= 5}
        )
    return rows


def fixed_rows(raw: dict[str, Any]) -> list[dict[str, Any]]:
    groups: dict[str, list[dict[str, Any]]] = {}
    for item in raw.get("results", []):
        if item.get("valid"):
            groups.setdefault(item["engine"], []).append(item)
    rows: list[dict[str, Any]] = []
    for engine, items in sorted(groups.items()):
        row: dict[str, Any] = {
                "engine": engine,
                "table": items[0].get("table", "unknown"),
                "rate": raw.get("requested_rate"),
                "samples": sum(item["accepted_requests"] for item in items),
                "min_samples": min(item["accepted_requests"] for item in items),
                "runs": len(items),
                "canonical_requested": bool(raw.get("canonical_requested")),
            }
        cvs: list[float] = []
        for percentile in ("p50", "p90", "p99", "p99_9"):
            values = [item["latency_us"][percentile] for item in items]
            interval = bootstrap_median_ci(values)
            row[percentile] = statistics.median(values)
            row[f"{percentile}_ci"] = interval
            if len(values) > 1 and statistics.mean(values) > 0:
                cvs.append(statistics.stdev(values) / statistics.mean(values) * 100.0)
        maxima = [item.get("latency_us", {}).get("max") for item in items]
        row["max"] = (
            statistics.median(float(value) for value in maxima if value is not None)
            if any(value is not None for value in maxima) else None
        )
        rate_values = [float(item["requests_per_second"]) for item in items]
        row["rate_cv"] = (
            statistics.stdev(rate_values) / statistics.mean(rate_values) * 100.0
            if len(rate_values) > 1 and statistics.mean(rate_values) > 0 else None
        )
        row["max_latency_cv"] = max(cvs) if cvs else None
        row["qualified"] = (
            row["canonical_requested"] and row["runs"] >= 5
            and row["min_samples"] >= 100_000
            and row["rate_cv"] is not None and row["rate_cv"] <= 5.0
        )
        rows.append(row)
    return rows


def saturation_rows(raw: dict[str, Any]) -> list[dict[str, Any]]:
    groups: dict[tuple[str, int], list[dict[str, Any]]] = {}
    for item in raw.get("results", []):
        if item.get("valid"):
            groups.setdefault((item["engine"], item["connections"]), []).append(item)
    canonical_requested = bool(raw.get("canonical_requested"))
    sustainable = {
        (item["engine"], item["connections"]): item
        for item in raw.get("stability", [])
        if item.get("sustainable")
    }
    best: dict[str, tuple[float, int, float | None, float | None, int, bool]] = {}
    for (engine, connections), items in groups.items():
        median_rate = statistics.median(item["requests_per_second"] for item in items)
        cpu_values = [item["server_cpu_ns_per_request"] for item in items
                      if item.get("server_cpu_ns_per_request") is not None]
        cpu_ns = statistics.median(cpu_values) if cpu_values else None
        stability = sustainable.get((engine, connections))
        if canonical_requested and stability is None:
            continue
        if stability is None:
            stability = next(
                (item for item in raw.get("stability", [])
                 if item["engine"] == engine and item["connections"] == connections),
                {"cv_percent": None, "valid_runs": len(items)},
            )
        if engine not in best or median_rate > best[engine][0]:
            valid_runs = int(stability["valid_runs"])
            best[engine] = (
                median_rate, connections, cpu_ns,
                float(stability["cv_percent"])
                if valid_runs >= 2 and stability.get("cv_percent") is not None else None,
                valid_runs,
                canonical_requested and valid_runs >= 5
                and stability.get("cv_percent") is not None
                and float(stability["cv_percent"]) <= 5.0,
            )
    return [
        {"engine": engine, "rps": value[0], "connections": value[1], "cpu_ns": value[2],
         "cv": value[3], "runs": value[4], "qualified": value[5],
         "table": next(item.get("table", "unknown") for item in raw.get("results", [])
                       if item.get("engine") == engine)}
        for engine, value in sorted(best.items())
    ]


def overhead_absolute_rows(raw: dict[str, Any]) -> list[dict[str, Any]]:
    groups: dict[tuple[str, int], list[dict[str, Any]]] = {}
    for item in raw.get("results", []):
        if item.get("valid"):
            groups.setdefault((item["engine"], int(item["connections"])), []).append(item)
    stability = {
        (item["engine"], int(item["connections"])): item
        for item in raw.get("stability", [])
    }
    rows = []
    for key, items in sorted(groups.items()):
        rates = [float(item["requests_per_second"]) for item in items]
        cpus = [float(item["server_cpu_ns_per_request"]) for item in items
                if item.get("server_cpu_ns_per_request") is not None]
        stable = stability.get(key, {})
        rows.append({
            "engine": key[0], "connections": key[1], "runs": len(items),
            "rps": statistics.median(rates),
            "cpu_ns": statistics.median(cpus) if cpus else None,
            "cv": stable.get("cv_percent"),
            "qualified": bool(raw.get("canonical_requested"))
            and len(items) >= 5 and bool(stable.get("stable")),
        })
    return rows


def overhead_paired_rows(
    raw: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[str]]:
    groups: dict[tuple[int, int], dict[str, dict[str, Any]]] = {}
    for item in raw.get("results", []):
        key = (int(item.get("repetition", -1)), int(item.get("connections", -1)))
        groups.setdefault(key, {})[str(item.get("engine"))] = item
    required = {"baseline", "luminawaf-loaded-off", "luminawaf"}
    deltas: dict[int, dict[str, list[float]]] = {}
    errors: list[str] = []
    for key, group in sorted(groups.items()):
        if set(group) != required:
            errors.append(f"round {key} missing adapters")
            continue
        values = [group[name] for name in sorted(required)]
        if not all(item.get("valid") for item in values):
            errors.append(f"round {key} contains an invalid source row")
            continue
        if len({item.get("round_id") for item in values}) != 1:
            errors.append(f"round {key} has mismatched round IDs")
            continue
        if len({item.get("workload_sha256") for item in values}) != 1:
            errors.append(f"round {key} has mismatched workloads")
            continue
        if len({item.get("allow_response_contract_sha256") for item in values}) != 1:
            errors.append(f"round {key} has mismatched backend response contracts")
            continue
        if len({(item.get("server_cpu"), item.get("client_cpu"), item.get("workers"))
                for item in values}) != 1:
            errors.append(f"round {key} has mismatched CPU/worker placement")
            continue
        if (group["luminawaf-loaded-off"].get("normalized_config_sha256")
                != group["luminawaf"].get("normalized_config_sha256")):
            errors.append(f"round {key} has mismatched Lumina config identity")
            continue
        cpu = {
            name: group[name].get("server_cpu_ns_per_request") for name in required
        }
        if any(value is None for value in cpu.values()):
            errors.append(f"round {key} has unavailable CPU accounting")
            continue
        point = deltas.setdefault(key[1], {"module_hook": [], "adapter_plus_pl2": []})
        point["module_hook"].append(
            float(cpu["luminawaf-loaded-off"]) - float(cpu["baseline"])
        )
        point["adapter_plus_pl2"].append(
            float(cpu["luminawaf"]) - float(cpu["luminawaf-loaded-off"])
        )
    rows: list[dict[str, Any]] = []
    for connections, metrics in sorted(deltas.items()):
        for metric, values in metrics.items():
            rows.append({
                "connections": connections, "metric": metric,
                "value_ns": statistics.median(values),
                "ci": bootstrap_median_ci(values), "runs": len(values),
                "qualified": bool(raw.get("canonical_requested")) and len(values) >= 5,
                "values": values,
            })
    return rows, errors


def paired_residual_ci(
    integrated: list[float], direct: list[float], samples: int = 10_000,
) -> tuple[float, float] | None:
    if len(integrated) < 2 or len(direct) < 2:
        return None
    rng = random.Random(0x0A11CE)
    estimates = sorted(
        statistics.median(rng.choice(integrated) for _ in integrated)
        - statistics.median(rng.choice(direct) for _ in direct)
        for _ in range(samples)
    )
    return estimates[int(samples * 0.025)], estimates[int(samples * 0.975)]


def benchmark_process_medians(paths: list[Path], name: str) -> list[float]:
    values: list[float] = []
    for path in paths:
        for item in load(path).get("benchmarks", []):
            current = str(item.get("run_name", "")).removesuffix("/repeats:10")
            if current == name and item.get("aggregate_name") == "median":
                values.append(float(item["cpu_time"]))
    return values


def pmu_rows(result_dir: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in sorted(result_dir.glob("pmu_*.csv")):
        counters: dict[str, float] = {}
        running: dict[str, float] = {}
        unavailable: set[str] = set()
        with path.open(encoding="utf-8") as stream:
            for fields in csv.reader(stream):
                if len(fields) < 5:
                    continue
                event = fields[2].strip()
                value = fields[0].strip()
                if not event:
                    continue
                if value.startswith("<"):
                    unavailable.add(event)
                    continue
                try:
                    counters[event] = float(value)
                    running[event] = float(fields[4])
                except ValueError:
                    unavailable.add(event)

        def ratio(numerator: str, denominator: str) -> float | None:
            base = counters.get(denominator, 0.0)
            return counters[numerator] / base * 100.0 if numerator in counters and base else None

        cycles = counters.get("cycles", 0.0)
        engine = path.stem.removeprefix("pmu_")
        core_log = result_dir / f"pmu_{engine}_group_00.log"
        transactions = 0
        if core_log.exists():
            for line in core_log.read_text(encoding="utf-8", errors="replace").splitlines():
                match = re.match(
                    r"^FullTransaction/.+/Allow/repeats:[0-9]+\s+"
                    r"\S+\s+\S+\s+\S+\s+\S+\s+([0-9]+)\s+",
                    line,
                )
                if match:
                    transactions += int(match.group(1))
        rows.append(
            {
                "engine": engine,
                "ipc": counters.get("instructions", 0.0) / cycles if cycles else None,
                "cycles_per_transaction": cycles / transactions if cycles and transactions else None,
                "instructions_per_transaction": (
                    counters["instructions"] / transactions
                    if "instructions" in counters and transactions else None
                ),
                "branch_miss": ratio("branch-misses", "branches"),
                "cache_miss": ratio("cache-misses", "cache-references"),
                "l1d_miss": ratio("L1-dcache-load-misses", "L1-dcache-loads"),
                "llc_miss": ratio("LLC-load-misses", "LLC-loads"),
                "itlb_miss": ratio("iTLB-load-misses", "iTLB-loads"),
                "running": min(running.values()) if running else None,
                "unavailable_events": sorted(unavailable),
                "qualified": (
                    cycles > 0.0
                    and counters.get("instructions", 0.0) > 0.0
                    and counters.get("branches", 0.0) > 0.0
                    and "branch-misses" in counters
                    and bool(running)
                    and min(running.values()) >= 90.0
                ),
            }
        )
    return rows


def overhead_pmu_rows(result_dir: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in sorted(result_dir.glob("overhead_pmu_*.csv")):
        counters: dict[str, float] = {}
        running: dict[str, float] = {}
        unavailable: set[str] = set()
        with path.open(encoding="utf-8") as stream:
            for fields in csv.reader(stream):
                if len(fields) < 5:
                    continue
                event, value = fields[2].strip(), fields[0].strip()
                if not event:
                    continue
                if value.startswith("<"):
                    unavailable.add(event)
                    continue
                try:
                    counters[event] = float(value)
                    running[event] = float(fields[4])
                except ValueError:
                    unavailable.add(event)

        def ratio(numerator: str, denominator: str) -> float | None:
            base = counters.get(denominator, 0.0)
            return counters[numerator] / base * 100.0 if numerator in counters and base else None

        kernel = path.stem.removeprefix("overhead_pmu_")
        core_log = result_dir / f"overhead_pmu_{kernel}_group_00.log"
        transactions = 0
        if core_log.exists():
            for line in core_log.read_text(encoding="utf-8", errors="replace").splitlines():
                match = re.match(
                    r"^Overhead/LuminaWAF/.+/AllowRotation/repeats:[0-9]+\s+"
                    r"\S+\s+\S+\s+\S+\s+\S+\s+([0-9]+)\s+",
                    line,
                )
                if match:
                    transactions += int(match.group(1))
        cycles = counters.get("cycles", 0.0)
        rows.append({
            "kernel": kernel,
            "cycles_per_transaction": cycles / transactions
            if cycles and transactions else None,
            "instructions_per_transaction": counters.get("instructions", 0.0) / transactions
            if counters.get("instructions") and transactions else None,
            "ipc": counters.get("instructions", 0.0) / cycles if cycles else None,
            "branch_miss": ratio("branch-misses", "branches"),
            "cache_miss": ratio("cache-misses", "cache-references"),
            "l1d_miss": ratio("L1-dcache-load-misses", "L1-dcache-loads"),
            "llc_miss": ratio("LLC-load-misses", "LLC-loads"),
            "itlb_miss": ratio("iTLB-load-misses", "iTLB-loads"),
            "running": min(running.values()) if running else None,
            "unavailable_events": sorted(unavailable),
            "qualified": cycles > 0.0 and transactions > 0
            and counters.get("instructions", 0.0) > 0.0
            and counters.get("branches", 0.0) > 0.0 and "branch-misses" in counters
            and bool(running) and min(running.values()) >= 90.0,
        })
    return rows


def ci_text(interval: tuple[float, float] | None, scale: float = 1.0) -> str:
    if interval is None:
        return "N/A - fewer than two independent runs"
    return f"{format_time(interval[0] * scale)} - {format_time(interval[1] * scale)}"


def percent_text(value: float | None) -> str:
    return f"{value:.2f}%" if value is not None else "N/A"


def decimal_text(value: float | None, digits: int = 3) -> str:
    return f"{value:.{digits}f}" if value is not None else "unavailable"


def pmu_percent_text(value: float | None) -> str:
    return f"{value:.2f}%" if value is not None else "unavailable"


def wall_time_text(seconds: int | float) -> str:
    seconds = int(seconds)
    hours, remainder = divmod(seconds, 3600)
    minutes, secs = divmod(remainder, 60)
    return f"{hours}h {minutes}m {secs}s" if hours else f"{minutes}m {secs}s"


def percentile_text(row: dict[str, Any], percentile: str) -> str:
    required = {"p50": 1, "p90": 10, "p99": 10_000, "p99_9": 100_000}[percentile]
    if row["min_samples"] < required:
        return f"N/A - min {required} samples/run"
    value = format_time(row[percentile] * 1000.0)
    interval = row.get(f"{percentile}_ci")
    return f"{value} [{ci_text(interval, 1000.0)}]"


def raw_google_benchmark_appendix(result_dir: Path) -> list[str]:
    lines = [
        "## Raw Google Benchmark Output",
        "",
        "The console output below is embedded verbatim. Corresponding machine-readable JSON is "
        "linked; canonical artifacts are required to retain every inner repetition and aggregate row.",
        "",
    ]
    logs = micro_artifact_paths(result_dir, "log") + overhead_micro_artifact_paths(
        result_dir, "log"
    )
    if not logs:
        return lines + ["No Google Benchmark log artifact was produced.", ""]
    for path in logs:
        json_path = path.with_suffix(".json")
        lines.extend([
            f"### `{path.name}`",
            "",
            f"Raw JSON: [`{json_path.name}`]({json_path.name})",
            "",
            "```text",
            path.read_text(encoding="utf-8", errors="replace").rstrip(),
            "```",
            "",
        ])
    return lines


def full_correctness_rows(result_dir: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    lumina_json = result_dir / "correctness_lumina.json"
    lumina_path = result_dir / "correctness_lumina.log"
    if lumina_json.exists():
        raw = load(lumina_json)
        metrics = raw.get("metrics", {})

        def metric(name: str) -> tuple[str, str, str] | None:
            value = metrics.get(name)
            if not isinstance(value, dict):
                return None
            return (str(value.get("percent", 0.0)), str(value.get("matched", 0)),
                    str(value.get("total", 0)))

        parity_value = float(raw.get("overall_parity", 0.0))
        timeout_count = int(raw.get("timeouts", 0))
        exception_count = int(raw.get("exceptions", 0))
        skips = raw.get("skips", {})
        rows.append(
            {
                "engine": "LuminaWAF vs ModSecurity",
                "oracle": raw.get("oracle", "pinned CRS PL2 expectations"),
                "mode": "exact rule ID + verdict",
                "tests": int(raw.get("tests", 0)),
                "parity": parity_value,
                "transport_skipped": int(skips.get("transport", 0)),
                "selection_skipped": int(skips.get("paranoia_level", 0))
                + int(skips.get("configuration", 0)),
                "failures": int(raw.get("failure_count", 0)),
                "positive_block": metric("positive_block"),
                "positive_exact": metric("positive_exact"),
                "negative": metric("negative_exclusion"),
                "timeouts": timeout_count,
                "exceptions": exception_count,
                "raw": "correctness_lumina.json",
                "passed": parity_value >= 99.70 and timeout_count == 0
                and exception_count == 0,
            }
        )
    elif lumina_path.exists():
        text = lumina_path.read_text(encoding="utf-8", errors="replace")
        parity = re.search(r"OVERALL PARITY\s*:\s*([0-9.]+)%", text)
        tests = re.search(r"elapsed:.*?tests=(\d+)", text)
        transport = re.search(r"transport_skipped=(\d+)", text)
        pl_skipped = re.search(r"pl_skipped=(\d+)", text)
        config_skipped = re.search(r"config_skipped=(\d+)", text)
        timeouts = re.search(r"timeouts=(\d+)", text)
        exceptions = re.search(r"exceptions=(\d+)", text)
        positive_block = re.search(r"positive\(block\)\s*:\s*([0-9.]+)%\s*\((\d+)/(\d+)\)", text)
        positive_exact = re.search(r"positive\(exact\)\s*:\s*([0-9.]+)%\s*\((\d+)/(\d+)\)", text)
        negative = re.search(r"negative\(excl\)\s*:\s*([0-9.]+)%\s*\((\d+)/(\d+)\)", text)
        if parity and tests:
            parity_value = float(parity.group(1))
            timeout_count = int(timeouts.group(1)) if timeouts else 0
            exception_count = int(exceptions.group(1)) if exceptions else 0
            rows.append(
                {
                    "engine": "LuminaWAF vs ModSecurity",
                    "oracle": "ModSecurity 3 + pinned CRS PL2",
                    "mode": "exact rule ID + verdict",
                    "tests": int(tests.group(1)),
                    "parity": parity_value,
                    "transport_skipped": int(transport.group(1)) if transport else 0,
                    "failures": round(int(tests.group(1)) * (100.0 - parity_value) / 100.0),
                    "positive_block": positive_block.groups() if positive_block else None,
                    "positive_exact": positive_exact.groups() if positive_exact else None,
                    "negative": negative.groups() if negative else None,
                    "timeouts": timeout_count,
                    "exceptions": exception_count,
                    "raw": "correctness_lumina.log",
                    "selection_skipped": (
                        (int(pl_skipped.group(1)) if pl_skipped else 0)
                        + (int(config_skipped.group(1)) if config_skipped else 0)
                    ),
                    "passed": parity_value >= 99.70 and timeout_count == 0 and exception_count == 0,
                }
            )
    coraza_path = result_dir / "correctness_coraza.json"
    if coraza_path.exists():
        raw = load(coraza_path)
        rows.append(
            {
                "engine": "Coraza",
                "oracle": "go-ftw expected HTTP verdicts",
                "mode": "HTTP verdict (rule IDs unavailable)",
                "tests": int(raw.get("tests", 0)),
                "parity": float(raw.get("overall_parity", 0.0)),
                "transport_skipped": int(raw.get("transport_skipped", 0)),
                "failures": int(raw.get("failed", 0)),
                "positive_block": None,
                "positive_exact": None,
                "negative": None,
                "timeouts": int(raw.get("timeouts", 0)),
                "exceptions": int(raw.get("exceptions", 0)),
                "raw": "correctness_coraza.json",
                "selection_skipped": int(raw.get("selection_skipped", 0)),
                "passed": (
                    float(raw.get("overall_parity", 0.0)) >= 99.70
                    and int(raw.get("timeouts", 0)) == 0
                    and int(raw.get("exceptions", 0)) == 0
                    and not raw.get("outcome_overrides")
                ),
            }
        )
    return rows


def ratio_text(value: tuple[str, str, str] | None) -> str:
    if value is None:
        return "N/A"
    return f"{float(value[0]):.2f}% ({value[1]}/{value[2]})"


def compact_evidence(value: Any) -> str:
    if value is None or value == "":
        return "unavailable"
    if isinstance(value, (dict, list)):
        value = json.dumps(value, sort_keys=True)
    return str(value).replace("`", "'").replace("\r", " ").replace("\n", "; ")


def render(result_dir: Path) -> str:
    manifest = load(result_dir / "crs_manifest.json")
    run = load(result_dir / "run_manifest.json")
    micro_paths = micro_artifact_paths(result_dir, "json")
    rows = micro_rows(micro_paths)
    overhead_micro_paths = overhead_micro_artifact_paths(result_dir, "json")
    overhead_direct = micro_rows(overhead_micro_paths)
    overhead_saturation_path = result_dir / "overhead_saturation/results.json"
    overhead_saturation_raw = (
        load(overhead_saturation_path) if overhead_saturation_path.exists() else {}
    )
    overhead_absolute = (
        overhead_absolute_rows(overhead_saturation_raw) if overhead_saturation_raw else []
    )
    overhead_paired, overhead_pairing_errors = (
        overhead_paired_rows(overhead_saturation_raw)
        if overhead_saturation_raw else ([], [])
    )
    overhead_fixed_path = result_dir / "overhead_fixed/results.json"
    overhead_fixed_raw = load(overhead_fixed_path) if overhead_fixed_path.exists() else {}
    overhead_fixed = fixed_rows(overhead_fixed_raw) if overhead_fixed_raw else []
    overhead_pmu = overhead_pmu_rows(result_dir)
    full_direct_name = "Overhead/LuminaWAF/FullDirect/AllowRotation"
    full_direct_process_values = benchmark_process_medians(
        overhead_micro_paths, full_direct_name
    )
    overhead_residual = []
    if full_direct_process_values:
        direct_median = statistics.median(full_direct_process_values)
        for row in overhead_paired:
            if row["metric"] == "adapter_plus_pl2":
                overhead_residual.append({
                    "connections": row["connections"],
                    "value_ns": row["value_ns"] - direct_median,
                    "ci": paired_residual_ci(row["values"], full_direct_process_values),
                    "runs": row["runs"],
                    "processes": len(full_direct_process_values),
                    "qualified": row["qualified"] and len(full_direct_process_values) >= 5,
                })
    fixed_path = result_dir / "e2e_fixed/results.json"
    fixed_raw = load(fixed_path) if fixed_path.exists() else {}
    fixed = fixed_rows(fixed_raw) if fixed_raw else []
    saturation_path = result_dir / "e2e_saturation/results.json"
    saturation_raw = load(saturation_path) if saturation_path.exists() else {}
    saturation = saturation_rows(saturation_raw) if saturation_raw else []
    scaling_path = result_dir / "e2e_scaling/results.json"
    scaling_raw = load(scaling_path) if scaling_path.exists() else {}
    scaling = scaling_raw.get("rows", []) if scaling_raw else []
    scaling_plan = scaling_raw.get("plan", {}) if scaling_raw else {}
    scaling_worker_points = [
        item.get("workers") for item in scaling_plan.get("points", [])
    ]
    fixed_primary = [row for row in fixed if row["table"] != "native-waf"]
    fixed_native = [row for row in fixed if row["table"] == "native-waf"]
    saturation_primary = [row for row in saturation if row["table"] != "native-waf"]
    saturation_native = [row for row in saturation if row["table"] == "native-waf"]
    pmu = pmu_rows(result_dir)
    pmu_qualification_path = result_dir / "pmu_qualification.json"
    pmu_qualification = (
        load(pmu_qualification_path) if pmu_qualification_path.exists()
        else run.get("pmu_qualification", {})
    )
    matrix_path = result_dir / "correctness_matrix/results.json"
    correctness = load(matrix_path).get("summary", []) if matrix_path.exists() else []
    full_correctness = full_correctness_rows(result_dir)
    micro_qualification_path = result_dir / "micro_qualification.json"
    micro_qualification = (
        load(micro_qualification_path) if micro_qualification_path.exists()
        else run.get("micro_qualification", {})
    )
    sampling_plan_path = result_dir / "sampling_plan.json"
    sampling_plan = load(sampling_plan_path) if sampling_plan_path.exists() else {}
    environment_path = result_dir / "environment.json"
    environment_end_path = result_dir / "environment_end.json"
    environment = load(environment_path) if environment_path.exists() else {}
    environment_end = load(environment_end_path) if environment_end_path.exists() else {}
    label = "CANONICAL" if run.get("canonical") else "NON-CANONICAL"
    sample_qualified = bool(sampling_plan.get("qualified_sampling"))
    throughput_label = "Sustainable RPS" if sample_qualified else "Diagnostic RPS"
    fixed_qualified = bool(fixed_raw.get("valid")) and bool(fixed) and all(
        row["qualified"] for row in fixed
    )
    saturation_qualified = bool(saturation_raw.get("valid")) and bool(saturation) and all(
        row["qualified"] for row in saturation
    )
    scaling_requested = bool(run.get("scaling_qualification", {}).get("requested"))
    scaling_qualified = (
        scaling_requested and bool(scaling_raw.get("valid")) and bool(scaling)
        and all(row.get("qualified") for row in scaling)
    )
    overhead_qualified = (
        run.get("phases", {}).get("overhead") == "passed"
        and bool(overhead_saturation_raw.get("valid")) and bool(overhead_absolute)
        and all(row["qualified"] for row in overhead_absolute)
        and bool(overhead_paired) and all(row["qualified"] for row in overhead_paired)
        and not overhead_pairing_errors
        and bool(overhead_fixed_raw.get("valid")) and bool(overhead_fixed)
        and all(row["qualified"] for row in overhead_fixed)
        and bool(overhead_direct) and all(row["qualified"] for row in overhead_direct)
        and bool(run.get("overhead_pmu_qualification", {}).get("valid"))
    )
    direct_source_ids = set(manifest["lumina"]["generated_rule_ids"]) | set(
        manifest["lumina"]["runtime_covered_ids"]
    )
    lines = [
        "# LuminaWAF Benchmark Harness v1",
        "",
        f"> **{label}** - {run.get('validity_reason', 'no validity reason recorded')}",
        "",
        "## Evidence",
        "",
        "- Protocol: `V1.0`",
        f"- Run mode: `{run['mode']}`",
        f"- CRS commit: `{manifest['crs']['commit']}`",
        f"- CRS manifest: `{manifest['manifest_sha256']}`",
        f"- Source inbound CRS PL2 rule IDs: `{manifest['crs']['inbound_pl2_rule_count']}`",
        f"- Generated Lumina execution units: `{manifest['lumina']['generated_rule_count']}`",
        f"- Native runtime-covered source IDs: `{len(manifest['lumina']['runtime_covered_ids'])}`",
        f"- Distinct source IDs represented directly by generated/native execution: `{len(direct_source_ids)}`",
        "- Rule-count note: setup, chain and non-score-bearing source rules are not one-to-one "
        "execution units; semantic coverage is established by the oracle gate, not by dividing "
        "execution-unit count by source-rule count.",
        f"- Workload SHA256: `{manifest['workload']['sha256']}`",
        "- Binary/module hashes: [`artifacts.json`](artifacts.json)",
        "- Build provenance and effective flags: "
        "[`build_provenance.json`](build_provenance.json), "
        "[`compile_commands.json`](compile_commands.json)",
        "- ELF dependency and symbol audit: [`symbol_isolation.json`](symbol_isolation.json)",
        "- Artifact integrity: [`artifact_preflight.json`](artifact_preflight.json), "
        "[`artifact_postflight.json`](artifact_postflight.json)",
        "- Methodology: [`methodology/README.md`](../../../methodology/README.md)",
        "",
        "## Host State Annotation",
        "",
        f"- Host profile: `{compact_evidence(environment.get('host_profile'))}`",
        f"- Operator note: {compact_evidence(environment.get('host_note'))}",
        f"- Kernel-isolated CPUs: `{compact_evidence(environment.get('kernel_isolated_cpus'))}`",
        f"- Benchmark CPU sets: `{compact_evidence(environment.get('benchmark_cpu_sets'))}`",
        f"- Governor: `{compact_evidence(environment.get('governor'))}`",
        f"- Start loadavg: `{compact_evidence(environment.get('loadavg'))}`",
        f"- End loadavg: `{compact_evidence(environment_end.get('loadavg'))}`",
        f"- Start CPU PSI: `{compact_evidence(environment.get('pressure', {}).get('cpu'))}`",
        f"- End CPU PSI: `{compact_evidence(environment_end.get('pressure', {}).get('cpu'))}`",
        f"- Start/end process count: `{compact_evidence(environment.get('process_count'))}` / "
        f"`{compact_evidence(environment_end.get('process_count'))}`",
        "- Raw snapshots: [`environment.json`](environment.json), "
        "[`environment_end.json`](environment_end.json)",
        "- A host annotation documents contention but never waives canonical isolation or "
        "clean-provenance requirements.",
        "",
        "## Publication Qualification",
        "",
        "| Evidence class | Observed | Canonical requirement | Status |",
        "|---|---:|---:|---|",
        f"| Independent Google Benchmark processes | {len(micro_paths)} | >=5 | "
        f"{'PASS' if len(micro_paths) >= 5 and micro_qualification.get('valid') else 'NOT QUALIFIED'} |",
        f"| Inner repetitions retained | {micro_qualification.get('required_repetitions', 'unknown')} | 10 raw/process | "
        f"{'PASS' if micro_qualification.get('valid') and len(micro_paths) >= 5 else 'NOT QUALIFIED'} |",
        f"| Engine PMU diagnostics | {len(pmu_qualification.get('rows', []))} engines | complete counters and >=90% running | "
        f"{'PASS' if pmu_qualification.get('valid') else 'NOT QUALIFIED'} |",
        f"| Artifact integrity | {run.get('phases', {}).get('artifacts', 'not-run')} | pre/post hashes identical | "
        f"{'PASS' if run.get('phases', {}).get('artifacts') == 'passed' else 'NOT QUALIFIED'} |",
        f"| Lumina CRS oracle gate | {run.get('phases', {}).get('lumina_crs', 'not-run')} | passed | "
        f"{'PASS' if run.get('phases', {}).get('lumina_crs') == 'passed' else 'NOT QUALIFIED'} |",
        f"| Coraza CRS oracle gate | {run.get('phases', {}).get('coraza_crs', 'not-run')} | passed | "
        f"{'PASS' if run.get('phases', {}).get('coraza_crs') == 'passed' else 'NOT QUALIFIED'} |",
        f"| Fixed-rate E2E | {run.get('phases', {}).get('e2e', 'not-run')} | >=5 runs and >=100000 accepted/run | "
        f"{'PASS' if fixed_qualified else 'NOT QUALIFIED'} |",
        f"| Saturation stability | {run.get('phases', {}).get('e2e', 'not-run')} | >=5 runs and RPS CV <=5% | "
        f"{'PASS' if saturation_qualified else 'NOT QUALIFIED'} |",
        f"| Lumina overhead decomposition | {run.get('phases', {}).get('overhead', 'not-run')} | paired E0/E1/E2 + direct kernels | "
        f"{'PASS' if overhead_qualified else 'NOT QUALIFIED'} |",
        f"| Multi-worker scaling | {run.get('phases', {}).get('scaling', 'not-requested')} | "
        f"1/2/4/8 workers, >=5 runs, CV <=5%, client CPU <=85% | "
        f"{'PASS' if scaling_qualified else 'NOT REQUESTED' if not scaling_requested else 'NOT QUALIFIED'} |",
        "",
        "## Sampling Plan",
        "",
        "The fixed-rate plan is persisted before latency collection. Qualified modes calibrate "
        "against the slowest engine's stable saturation point; smoke remains a bounded diagnostic.",
        "",
        f"- Sampling class: `{'qualified' if sample_qualified else 'diagnostic'}`",
        f"- Fixed rate: `{sampling_plan.get('fixed_rate', 'unavailable')} RPS`",
        f"- Fixed duration per engine/run: `{sampling_plan.get('fixed_duration_seconds', 'unavailable')} s`",
        f"- Target accepted responses per run: `{sampling_plan.get('target_accepted_per_run', 'unavailable')}`",
        f"- Projected accepted responses at qualification floor: "
        f"`{sampling_plan.get('projected_accepted_at_qualification_floor', 'N/A')}`",
        f"- Limiting engine: `{sampling_plan.get('limiting_engine', 'N/A')}`",
        f"- Estimated E2E wall time: "
        f"`{wall_time_text(sampling_plan.get('estimated_e2e_wall_seconds', 0))}`",
        "- Raw plan: [`sampling_plan.json`](sampling_plan.json)",
        "",
        "## Full CRS PL2 Correctness Gates",
        "",
        "The LuminaWAF gate checks exact matched rule IDs against ModSecurity. The stock Coraza "
        "NGINX connector exposes only the final HTTP verdict, so its row is intentionally narrower.",
        "",
        "| Engine | Oracle | Observable contract | Positive block | Exact rule | Negative exclusion | Overall | Skips | Errors | Gate |",
        "|---|---|---|---:|---:|---:|---:|---:|---:|---|",
    ]
    if full_correctness:
        lines.extend(
            f"| `{row['engine']}` | {row['oracle']} | {row['mode']} | "
            f"{ratio_text(row['positive_block'])} | {ratio_text(row['positive_exact'])} | "
            f"{ratio_text(row['negative'])} | {row['parity']:.2f}% ({row['tests']} tests) | "
            f"{row['transport_skipped']} transport / {row['selection_skipped']} selection | "
            f"{row['timeouts']} timeout / {row['exceptions']} exception / "
            f"{row['failures'] if row['failures'] is not None else 'see raw'} disagreement | "
            f"{'PASS' if row['passed'] else 'FAIL'} |"
            for row in full_correctness
        )
    else:
        lines.append("| unavailable | - | - | - | - | - | - | - | - | NOT RUN |")
    lines.extend([
        "",
        "Raw oracle artifacts: [`correctness_lumina.json`](correctness_lumina.json), "
        "[`correctness_lumina.log`](correctness_lumina.log), "
        "[`correctness_coraza.json`](correctness_coraza.json), and "
        "[`correctness_coraza.log`](correctness_coraza.log). Missing links mean the gate was not run.",
    ])
    lines.extend([
        "",
        "## Cross-Engine Outcome Matrix",
        "",
        "This small immutable matrix reports comparable HTTP outcomes. It is not a replacement "
        "for the full CRS regression gates.",
        "",
        "**The detection and false-positive figures below apply only to this small immutable "
        "outcome matrix. They must not be interpreted as full CRS PL2 parity.**",
        "",
        "| Engine | Class | Attack detection | False positives | Contract |",
        "|---|---|---:|---:|---|",
    ])
    if correctness:
        lines.extend(
            f"| `{row['engine']}` | `{row['table']}` | {row['attack_detection_percent']:.2f}% | "
            f"{row['false_positive_percent']:.2f}% | "
            f"{'PASS' if row['passed_contract'] else 'FAIL'} |"
            for row in correctness
        )
    else:
        lines.append("| unavailable | - | - | - | - |")
    lines.extend([
        "",
        "## Full Transaction Microbenchmark",
        "",
        "This table includes the complete inbound transaction lifecycle exposed by each engine. "
        "It is not NGINX E2E latency. Attack rows measure time to a blocking decision and may "
        "terminate earlier than allow rows; they do not enumerate every subsequent matching rule.",
        "",
        "| Engine / workload | Median CPU time | Inner repetition CV | Process-level 95% bootstrap CI | Processes | Qualification |",
        "|---|---:|---:|---:|---:|---|",
    ])
    if rows:
        lines.extend(
            f"| `{row['name']}` | {format_time(row['cpu'])} | "
            f"{percent_text(row['inner_cv'])} | {ci_text(row['ci'])} | {row['processes']} | "
            f"{'QUALIFIED' if row['qualified'] else 'NOT QUALIFIED'} |"
            for row in rows
        )
    else:
        lines.append("| unavailable | unavailable | unavailable | - | NOT RUN |")
    lines.extend([
        "",
        "## LuminaWAF Overhead Decomposition (Diagnostic)",
        "",
        "This section separates plain NGINX, the loaded disabled module, and production CRS PL2 "
        "inspection. CPU deltas are paired within the same round and connection point. Latency "
        "percentiles are shown only as absolute context and are never subtracted.",
        "",
        "### Absolute E2E Saturation Sources",
        "",
        "| Layer | Connections | RPS | Server CPU/request | Runs | RPS CV | Qualification |",
        "|---|---:|---:|---:|---:|---:|---|",
    ])
    if overhead_absolute:
        lines.extend(
            f"| `{row['engine']}` | {row['connections']} | {row['rps']:.2f} | "
            f"{format_time(row['cpu_ns']) if row['cpu_ns'] is not None else 'unavailable'} | "
            f"{row['runs']} | {percent_text(row['cv'])} | "
            f"{'QUALIFIED' if row['qualified'] else 'NOT QUALIFIED'} |"
            for row in overhead_absolute
        )
    else:
        lines.append("| unavailable | - | - | - | - | - | NOT RUN |")
    lines.extend([
        "",
        "### Paired Server CPU Deltas",
        "",
        "| Delta | Connections | Median paired delta | Paired 95% bootstrap CI | Pairs | Qualification |",
        "|---|---:|---:|---:|---:|---|",
    ])
    if overhead_paired:
        labels = {
            "module_hook": "E1 loaded-off - E0 baseline",
            "adapter_plus_pl2": "E2 PL2 - E1 loaded-off",
        }
        lines.extend(
            f"| `{labels[row['metric']]}` | {row['connections']} | "
            f"{format_signed_time(row['value_ns'])} | {signed_ci_text(row['ci'])} | "
            f"{row['runs']} | {'QUALIFIED' if row['qualified'] else 'NOT QUALIFIED'} |"
            for row in overhead_paired
        )
    else:
        lines.append("| unavailable | - | - | - | - | NOT RUN |")
    if overhead_pairing_errors:
        lines.extend([
            "",
            f"Pairing rejected `{len(overhead_pairing_errors)}` source groups; see "
            "[`overhead_saturation/results.json`](overhead_saturation/results.json).",
        ])
    lines.extend([
        "",
        "### Absolute Fixed-Rate Latency",
        "",
        "| Layer | Rate | p50 | p90 | p99 | p99.9 | Runs | Min samples/run | Qualification |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---|",
    ])
    if overhead_fixed:
        lines.extend(
            f"| `{row['engine']}` | {row['rate']} | {percentile_text(row, 'p50')} | "
            f"{percentile_text(row, 'p90')} | {percentile_text(row, 'p99')} | "
            f"{percentile_text(row, 'p99_9')} | {row['runs']} | {row['min_samples']} | "
            f"{'QUALIFIED' if row['qualified'] else 'NOT QUALIFIED'} |"
            for row in overhead_fixed
        )
    else:
        lines.append("| unavailable | - | - | - | - | - | - | - | NOT RUN |")
    lines.extend([
        "",
        "### Direct Allow-Rotation Kernels",
        "",
        "| Boundary | Median CPU time | Inner CV | Process-level 95% bootstrap CI | Processes | Qualification |",
        "|---|---:|---:|---:|---:|---|",
    ])
    if overhead_direct:
        lines.extend(
            f"| `{row['name']}` | {format_time(row['cpu'])} | "
            f"{percent_text(row['inner_cv'])} | {ci_text(row['ci'])} | "
            f"{row['processes']} | {'QUALIFIED' if row['qualified'] else 'NOT QUALIFIED'} |"
            for row in overhead_direct
        )
    else:
        lines.append("| unavailable | - | - | - | - | NOT RUN |")
    lines.extend([
        "",
        "### Integration Residual",
        "",
        "The residual is `paired (E2-E1) CPU/request - FullDirect CPU`. It is an accounting "
        "observation covering NGINX projection and response integration, not a function timer.",
        "",
        "| Connections | Median residual | Combined bootstrap 95% CI | E2E pairs | Direct processes | Qualification |",
        "|---:|---:|---:|---:|---:|---|",
    ])
    if overhead_residual:
        lines.extend(
            f"| {row['connections']} | {format_signed_time(row['value_ns'])} | "
            f"{signed_ci_text(row['ci'])} | {row['runs']} | {row['processes']} | "
            f"{'QUALIFIED' if row['qualified'] else 'NOT QUALIFIED'} |"
            for row in overhead_residual
        )
    else:
        lines.append("| - | unavailable | - | - | - | NOT RUN |")
    lines.extend([
        "",
        "### Direct-Kernel PMU",
        "",
        "| Kernel | Cycles/transaction | Instructions/transaction | IPC | Branch misses | Cache misses | L1D misses | LLC misses | iTLB misses | Running | Quality |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|",
    ])
    if overhead_pmu:
        lines.extend(
            f"| `{row['kernel']}` | {decimal_text(row['cycles_per_transaction'], 0)} | "
            f"{decimal_text(row['instructions_per_transaction'], 0)} | "
            f"{decimal_text(row['ipc'])} | {pmu_percent_text(row['branch_miss'])} | "
            f"{pmu_percent_text(row['cache_miss'])} | {pmu_percent_text(row['l1d_miss'])} | "
            f"{pmu_percent_text(row['llc_miss'])} | {pmu_percent_text(row['itlb_miss'])} | "
            f"{pmu_percent_text(row['running'])} | "
            f"{'QUALIFIED' if row['qualified'] else 'NOT QUALIFIED'} |"
            for row in overhead_pmu
        )
    else:
        lines.append("| unavailable | - | - | - | - | - | - | - | - | - | NOT RUN |")
    lines.extend([
        "",
        "Raw evidence: [`overhead_saturation/results.json`](overhead_saturation/results.json), "
        "[`overhead_fixed/results.json`](overhead_fixed/results.json), and "
        "[`overhead_micro_qualification.json`](overhead_micro_qualification.json), plus "
        "[`overhead_pmu_qualification.json`](overhead_pmu_qualification.json). Empty-policy "
        "evidence is intentionally absent until a separately hashed generated-policy build exists.",
    ])
    lines.extend(
        [
            "",
            "## E2E Fixed-Rate Latency",
            "",
            "Values are medians across independent runs; brackets contain the 95% bootstrap CI. "
            "The immutable performance rotation contains six HTTP/1.1 GET requests with empty "
            "bodies, so this section measures URI, query and request-header inspection rather than "
            "request-body ingestion.",
            "",
            "| Engine | Rate | p50 [95% CI] | p90 [95% CI] | p99 [95% CI] | p99.9 [95% CI] | Max | Runs | Min samples/run | RPS CV | Qualification |",
            "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|",
        ]
    )
    if fixed_primary:
        lines.extend(
            f"| `{row['engine']}` | {row['rate']} | "
            f"{percentile_text(row, 'p50')} | {percentile_text(row, 'p90')} | "
            f"{percentile_text(row, 'p99')} | {percentile_text(row, 'p99_9')} | "
            f"{format_time(row['max'] * 1000) if row['max'] is not None else 'N/A'} | "
            f"{row['runs']} | {row['min_samples']} | "
            f"{percent_text(row['rate_cv'])} | "
            f"{'QUALIFIED' if row['qualified'] else 'NOT QUALIFIED'} |"
            for row in fixed_primary
        )
    else:
        lines.append("| unavailable | - | - | - | - | - | - | - | - | - | NOT RUN |")
    lines.extend(
        [
            "",
            "## Saturation",
            "",
            f"| Engine | {throughput_label} | Connections | CPU/request | Runs | RPS CV | Qualification |",
            "|---|---:|---:|---:|---:|---:|---|",
        ]
    )
    if saturation_primary:
        lines.extend(
            f"| `{row['engine']}` | {row['rps']:.2f} | {row['connections']} | "
            f"{format_time(row['cpu_ns']) if row['cpu_ns'] is not None else 'unavailable'} | "
            f"{row['runs']} | {percent_text(row['cv'])} | "
            f"{'QUALIFIED' if row['qualified'] else 'NOT QUALIFIED'} |"
            for row in saturation_primary
        )
    else:
        lines.append("| unavailable | - | - | - | - | - | NOT RUN |")
    lines.extend(
        [
            "",
            "A point is sustainable only with the required independent runs, zero response errors "
            "and RPS CV no greater than 5%.",
            "CPU/request is NGINX master-plus-direct-worker `utime+stime` from `/proc/<pid>/stat` "
            "divided by completed requests. It excludes the load generator and is diagnostic at "
            "the kernel clock-tick resolution recorded in `e2e_saturation/results.json`.",
            "",
            "## Multi-Worker Scaling",
            "",
            "This optional publication supplement measures throughput scaling independently from "
            "the primary single-worker latency and efficiency results. Every row uses isolated, "
            "disjoint server/client CPU sets. Client saturation invalidates a row; a client-limited "
            "plain-NGINX baseline remains visible but does not invalidate WAF scaling qualification. "
            "Saturation latency is not reported as service latency. NAXSI remains a native-WAF reference.",
            "",
            f"- Worker points: `{scaling_worker_points if scaling_plan else 'not requested'}`",
            f"- Server CPU pool: `{scaling_plan.get('server_cpu_pool', 'not requested')}`",
            f"- Client CPU pool: `{scaling_plan.get('client_cpu_pool', 'not requested')}`",
            f"- Estimated measurement time: "
            f"`{wall_time_text(scaling_plan.get('estimated_wall_seconds', 0)) if scaling_plan else 'not requested'}`",
            "",
            "| Engine | Class | Workers | RPS | Speedup | Efficiency | RPS/worker | CPU/request | Connections | Client CPU median/max | Runs | RPS CV | Qualification |",
            "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|",
        ]
    )
    if scaling:
        lines.extend(
            f"| `{row['engine']}` | `{row.get('table', 'unknown')}` | {row['workers']} | "
            f"{row['rps']:.2f} | {decimal_text(row.get('speedup'), 2)}x | "
            f"{percent_text(row.get('scaling_efficiency_percent'))} | "
            f"{row['rps_per_worker']:.2f} | "
            f"{format_time(row['server_cpu_ns_per_request']) if row.get('server_cpu_ns_per_request') is not None else 'unavailable'} | "
            f"{row['connections']} | "
            f"{percent_text(row.get('client_cpu_utilization_percent'))} / "
            f"{percent_text(row.get('client_cpu_utilization_max_percent'))} | "
            f"{row['runs']} | {percent_text(row.get('rps_cv_percent'))} | "
            f"{'QUALIFIED' if row.get('qualified') else 'NOT QUALIFIED'} |"
            for row in scaling
        )
    else:
        lines.append("| not requested | - | - | - | - | - | - | - | - | - | - | - | NOT RUN |")
    lines.append("")
    if scaling_raw:
        lines.extend([
            "Raw scaling plan and aggregate evidence: "
            "[`e2e_scaling/plan.json`](e2e_scaling/plan.json), "
            "[`e2e_scaling/results.json`](e2e_scaling/results.json).",
            "",
        ])
    else:
        lines.extend(["Multi-worker scaling was not requested for this run.", ""])
    lines.extend(
        [
            "## PMU Diagnostics",
            "",
            "Grouped counters are diagnostics for the allow transaction, not headline latency. "
            "Qualification details are retained in "
            "[`pmu_qualification.json`](pmu_qualification.json).",
            "",
            "| Engine | Cycles/transaction | Instructions/transaction | IPC | Branch misses | Cache misses | L1D misses | LLC misses | iTLB misses | Minimum running | Quality |",
            "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|",
        ]
    )
    if pmu:
        lines.extend(
            f"| `{row['engine']}` | "
            f"{decimal_text(row['cycles_per_transaction'], 0)} | "
            f"{decimal_text(row['instructions_per_transaction'], 0)} | "
            f"{decimal_text(row['ipc'])} | "
            f"{pmu_percent_text(row['branch_miss'])} | {pmu_percent_text(row['cache_miss'])} | "
            f"{pmu_percent_text(row['l1d_miss'])} | {pmu_percent_text(row['llc_miss'])} | "
            f"{pmu_percent_text(row['itlb_miss'])} | {pmu_percent_text(row['running'])} | "
            f"{'QUALIFIED' if row['qualified'] else 'NOT QUALIFIED'} |"
            for row in pmu
        )
    else:
        lines.append("| unavailable | - | - | - | - | - | - | - | - | - | NOT RUN |")
    lines.extend(
        [
            "",
            "## Native-WAF Reference (Not CRS)",
            "",
            "NAXSI does not execute OWASP CRS. It is reported as a native implementation-class "
            "reference and never enters the CRS-equivalence ranking.",
            "",
            "| Engine | Rate | p50 | p90 | p99 | p99.9 | Max | Runs | Min samples/run | Qualification |",
            "|---|---:|---:|---:|---:|---:|---:|---:|---:|---|",
        ]
    )
    if fixed_native:
        lines.extend(
            f"| `{row['engine']}` | {row['rate']} | {percentile_text(row, 'p50')} | "
            f"{percentile_text(row, 'p90')} | {percentile_text(row, 'p99')} | "
            f"{percentile_text(row, 'p99_9')} | "
            f"{format_time(row['max'] * 1000) if row['max'] is not None else 'N/A'} | "
            f"{row['runs']} | {row['min_samples']} | "
            f"{'QUALIFIED' if row['qualified'] else 'NOT QUALIFIED'} |"
            for row in fixed_native
        )
    else:
        lines.append("| unavailable | - | - | - | - | - | - | - | - | NOT RUN |")
    lines.extend(
        [
            "",
            f"| Engine | {throughput_label} | Connections | CPU/request | Runs | RPS CV | Qualification |",
            "|---|---:|---:|---:|---:|---:|---|",
        ]
    )
    if saturation_native:
        lines.extend(
            f"| `{row['engine']}` | {row['rps']:.2f} | {row['connections']} | "
            f"{format_time(row['cpu_ns']) if row['cpu_ns'] is not None else 'unavailable'} | "
            f"{row['runs']} | {percent_text(row['cv'])} | "
            f"{'QUALIFIED' if row['qualified'] else 'NOT QUALIFIED'} |"
            for row in saturation_native
        )
    else:
        lines.append("| unavailable | - | - | - | - | - | NOT RUN |")
    lines.extend(
        [
            "",
            "## Scope",
            "",
            "LuminaWAF, ModSecurity and Coraza may enter the CRS PL2 table only after the shared "
            "manifest and correctness gates pass. NAXSI is reported separately because it does "
            "not execute OWASP CRS. Synthetic rule scaling never appears in either table.",
            "",
        ]
    )
    lines.extend(raw_google_benchmark_appendix(result_dir))
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("result_dir", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    output = args.output or args.result_dir / "BENCHMARK_RESULTS.md"
    output.write_text(render(args.result_dir), encoding="utf-8")
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
