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


BODY_P50_SIZE_INVERSION_LIMIT = 4.0


def load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def micro_artifact_paths(result_dir: Path, suffix: str) -> list[Path]:
    paths = [result_dir / f"micro.{suffix}"]
    paths.extend(sorted(result_dir.glob(f"micro_process_*.{suffix}")))
    return [path for path in paths if path.exists()]


def overhead_micro_artifact_paths(result_dir: Path, suffix: str) -> list[Path]:
    paths = [result_dir / f"overhead_micro.{suffix}"]
    paths.extend(sorted(result_dir.glob(f"overhead_micro_process_*.{suffix}")))
    for slug in ("bundlebuild", "inspectprebuilt", "fulldirect"):
        paths.append(result_dir / f"overhead_micro_{slug}.{suffix}")
        paths.extend(
            sorted(
                result_dir.glob(
                    f"overhead_micro_{slug}_process_*.{suffix}"
                )
            )
        )
    return [path for path in paths if path.exists()]


def body_micro_artifact_paths(result_dir: Path, suffix: str) -> list[Path]:
    paths = [result_dir / f"body_micro.{suffix}"]
    paths.extend(sorted(result_dir.glob(f"body_micro_process_*.{suffix}")))
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


def body_rule_work_rows(
    paths: list[Path],
    rule_ids: tuple[int, ...] = (934100, 934101, 934120),
) -> list[dict[str, Any]]:
    benchmark_name = "FullTransaction128KiB/LuminaWAF/AllowJSONVaried"
    process_rows: list[dict[str, Any]] = []
    for path in paths:
        median = next(
            (
                item
                for item in load(path).get("benchmarks", [])
                if item.get("run_name", "").removesuffix("/repeats:10")
                == benchmark_name
                and item.get("aggregate_name") == "median"
            ),
            None,
        )
        if median is not None:
            process_rows.append(median)

    rows: list[dict[str, Any]] = []
    for rule_id in rule_ids:
        prefix = f"rule_{rule_id}_"
        counter_names = {
            "dispatches": prefix + "dispatches_per_tx",
            "exact_calls": prefix + "exact_calls_per_tx",
            "exact_bytes": prefix + "exact_bytes_per_tx",
        }
        values = {
            name: [
                float(item[counter])
                for item in process_rows
                if item.get(counter) is not None
            ]
            for name, counter in counter_names.items()
        }
        if not any(values.values()):
            continue
        rows.append(
            {
                "rule_id": rule_id,
                "dispatches": (
                    statistics.median(values["dispatches"])
                    if values["dispatches"] else None
                ),
                "exact_calls": (
                    statistics.median(values["exact_calls"])
                    if values["exact_calls"] else None
                ),
                "exact_bytes": (
                    statistics.median(values["exact_bytes"])
                    if values["exact_bytes"] else None
                ),
                "processes": len(process_rows),
                "qualified": len(process_rows) >= 5
                and all(len(items) == len(process_rows) for items in values.values()),
            }
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
                "min_accepted_samples": min(
                    item["accepted_requests"] for item in items
                ),
                "min_samples": min(
                    item.get("latency_samples", item["accepted_requests"])
                    for item in items
                ),
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
            and row["min_accepted_samples"] >= 100_000
            and row["min_samples"] >= 100_000
            and row["rate_cv"] is not None and row["rate_cv"] <= 5.0
        )
        rows.append(row)
    return rows


def body_e2e_rows(raw: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for measurement in raw.get("measurements", []):
        items = [
            item for item in measurement.get("results", [])
            if item.get("valid")
        ]
        if not items:
            continue
        plan = measurement["plan"]
        row: dict[str, Any] = {
            "workload_id": measurement["workload_id"],
            "size_kib": int(measurement["size_kib"]),
            "request_class": measurement["request_class"],
            "engine": measurement["engine"],
            "measurement_mode": plan["measurement_mode"],
            "rate": plan.get("fixed_rate"),
            "connections": int(plan["connections"]),
            "classification": plan["classification"],
            "sample_cap_reason": plan["sample_cap_reason"],
            "required_percentiles": set(plan["required_percentiles"]),
            "target_samples": int(plan["target_samples"]),
            "runs": len(items),
            "min_accepted_samples": min(
                int(item["accepted_requests"]) for item in items
            ),
            "min_samples": min(
                int(item.get("latency_samples", item["accepted_requests"]))
                for item in items
            ),
            "anomalous": bool(measurement.get("anomalous")),
            "anomaly_reasons": list(measurement.get("anomaly_reasons", [])),
            "anomaly_metrics": dict(measurement.get("anomaly_metrics", {})),
            "qualified": bool(raw.get("qualified_sampling"))
            and bool(measurement.get("valid"))
            and not bool(measurement.get("anomalous"))
            and len(items) >= 5,
        }
        for percentile in ("p50", "p90", "p99", "p99_9"):
            if percentile not in row["required_percentiles"]:
                row[percentile] = None
                row[f"{percentile}_ci"] = None
                continue
            values = [
                float(item["latency_us"][percentile])
                for item in items
                if percentile in item.get("latency_us", {})
            ]
            row[percentile] = statistics.median(values) if values else None
            row[f"{percentile}_ci"] = bootstrap_median_ci(values)
        if row.get("p50") is not None and float(row["p50"]) <= 0.0:
            row["anomalous"] = True
            row["qualified"] = False
            row["anomaly_reasons"].append(
                "non-positive p50 from an empty or invalid latency histogram"
            )
        rows.append(row)

    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for row in rows:
        groups.setdefault(
            (str(row["engine"]), str(row["request_class"])), []
        ).append(row)
    for items in groups.values():
        ordered = sorted(items, key=lambda item: int(item["size_kib"]))
        for smaller, larger in zip(ordered, ordered[1:]):
            smaller_p50 = smaller.get("p50")
            larger_p50 = larger.get("p50")
            if (
                smaller_p50 is None
                or larger_p50 is None
                or float(larger_p50) <= 0.0
            ):
                continue
            ratio = float(smaller_p50) / float(larger_p50)
            if ratio <= BODY_P50_SIZE_INVERSION_LIMIT:
                continue
            reason = (
                f"p50 size-trend inversion: {smaller['size_kib']} KiB is "
                f"{ratio:.2f}x {larger['size_kib']} KiB"
            )
            if reason not in smaller["anomaly_reasons"]:
                smaller["anomaly_reasons"].append(reason)
            smaller["anomalous"] = True
            smaller["qualified"] = False
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
    best: dict[str, dict[str, Any]] = {}
    for (engine, connections), items in groups.items():
        median_rate = statistics.median(item["requests_per_second"] for item in items)
        cpu_values = [item["server_cpu_ns_per_request"] for item in items
                      if item.get("server_cpu_ns_per_request") is not None]
        cpu_ns = statistics.median(cpu_values) if cpu_values else None
        client_values = [
            float(item["client_cpu_utilization_percent"])
            for item in items
            if item.get("client_cpu_utilization_percent") is not None
        ]
        stability = sustainable.get((engine, connections))
        if canonical_requested and stability is None:
            continue
        if stability is None:
            stability = next(
                (item for item in raw.get("stability", [])
                 if item["engine"] == engine and item["connections"] == connections),
                {"cv_percent": None, "valid_runs": len(items)},
            )
        if engine not in best or median_rate > float(best[engine]["rps"]):
            valid_runs = int(stability["valid_runs"])
            client_max = max(client_values) if client_values else None
            client_limit = float(
                stability.get(
                    "max_client_utilization_percent",
                    raw.get("max_client_utilization_percent", 90.0),
                )
            )
            client_headroom = bool(
                stability.get(
                    "client_headroom",
                    len(client_values) == len(items)
                    and client_max is not None
                    and client_max <= client_limit,
                )
            )
            best[engine] = {
                "engine": engine,
                "rps": median_rate,
                "connections": connections,
                "cpu_ns": cpu_ns,
                "cv": (
                    float(stability["cv_percent"])
                    if valid_runs >= 2
                    and stability.get("cv_percent") is not None else None
                ),
                "runs": valid_runs,
                "client_cpu_median": (
                    statistics.median(client_values) if client_values else None
                ),
                "client_cpu_max": client_max,
                "client_cpu_limit": client_limit,
                "client_headroom": client_headroom,
                "qualified": (
                    canonical_requested
                    and valid_runs >= 5
                    and stability.get("cv_percent") is not None
                    and float(stability["cv_percent"]) <= 5.0
                    and client_headroom
                ),
                "table": next(
                    item.get("table", "unknown")
                    for item in raw.get("results", [])
                    if item.get("engine") == engine
                ),
            }
    return [value for _, value in sorted(best.items())]


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
        client_values = [
            float(item["client_cpu_utilization_percent"])
            for item in items
            if item.get("client_cpu_utilization_percent") is not None
        ]
        stable = stability.get(key, {})
        rows.append({
            "engine": key[0], "connections": key[1], "runs": len(items),
            "rps": statistics.median(rates),
            "cpu_ns": statistics.median(cpus) if cpus else None,
            "cv": stable.get("cv_percent"),
            "client_cpu_median": (
                statistics.median(client_values) if client_values else None
            ),
            "client_cpu_max": max(client_values) if client_values else None,
            "client_headroom": bool(stable.get("client_headroom")),
            "qualified": bool(raw.get("canonical_requested"))
            and len(items) >= 5 and bool(stable.get("stable"))
            and bool(stable.get("client_headroom")),
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


def body_pmu_rows(result_dir: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in sorted(result_dir.glob("body_pmu_*.csv")):
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
            return (
                counters[numerator] / base * 100.0
                if numerator in counters and base else None
            )

        engine = path.stem.removeprefix("body_pmu_")
        transactions = 0
        core_log = result_dir / f"body_pmu_{engine}_group_00.log"
        if core_log.exists():
            for line in core_log.read_text(
                encoding="utf-8", errors="replace"
            ).splitlines():
                match = re.match(
                    r"^FullTransaction128KiB/.+/AllowJSONVaried(?:/repeats:[0-9]+)?\s+"
                    r"\S+\s+\S+\s+\S+\s+\S+\s+([0-9]+)\s+",
                    line,
                )
                if match:
                    transactions += int(match.group(1))
        cycles = counters.get("cycles", 0.0)
        rows.append(
            {
                "engine": engine,
                "ipc": counters.get("instructions", 0.0) / cycles
                if cycles else None,
                "cycles_per_transaction": cycles / transactions
                if cycles and transactions else None,
                "instructions_per_transaction": (
                    counters["instructions"] / transactions
                    if "instructions" in counters and transactions else None
                ),
                "branch_miss": ratio("branch-misses", "branches"),
                "cache_miss": ratio("cache-misses", "cache-references"),
                "l1d_miss": ratio(
                    "L1-dcache-load-misses", "L1-dcache-loads"
                ),
                "llc_miss": ratio("LLC-load-misses", "LLC-loads"),
                "itlb_miss": ratio(
                    "iTLB-load-misses", "iTLB-loads"
                ),
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


def body_percentile_text(row: dict[str, Any], percentile: str) -> str:
    if percentile not in row["required_percentiles"]:
        return "N/A - outside sample contract"
    required = {"p50": 1, "p90": 10, "p99": 10_000}[percentile]
    if row["min_samples"] < required or row.get(percentile) is None:
        return f"N/A - min {required} samples/run"
    value = format_time(float(row[percentile]) * 1000.0)
    if row["runs"] == 1 and row["min_samples"] == 1:
        return f"{value} (single observation; not a percentile)"
    return f"{value} [{ci_text(row.get(f'{percentile}_ci'), 1000.0)}]"


def body_evidence_class_text(row: dict[str, Any]) -> str:
    evidence = f"{row['classification']} ({row['sample_cap_reason']})"
    if row.get("anomalous"):
        return f"**ANOMALOUS - investigation required**; {evidence}"
    return evidence


def raw_google_benchmark_appendix(result_dir: Path) -> list[str]:
    lines = [
        "## Raw Google Benchmark Output",
        "",
        "The console output below is embedded verbatim. Corresponding machine-readable JSON is "
        "linked; canonical artifacts are required to retain every inner repetition and aggregate row.",
        "",
    ]
    logs = (
        micro_artifact_paths(result_dir, "log")
        + body_micro_artifact_paths(result_dir, "log")
        + overhead_micro_artifact_paths(result_dir, "log")
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
    body_micro_paths = body_micro_artifact_paths(result_dir, "json")
    body_direct = micro_rows(body_micro_paths)
    body_rule_work = body_rule_work_rows(body_micro_paths)
    body_evidence_path = result_dir / "body_evidence/results.json"
    body_evidence_raw = (
        load(body_evidence_path) if body_evidence_path.exists() else {}
    )
    body_e2e = body_e2e_rows(body_evidence_raw) if body_evidence_raw else []
    body_pmu = body_pmu_rows(result_dir)
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
    scaling_client_limit = float(
        scaling_raw.get(
            "max_client_utilization_percent",
            scaling_plan.get("max_client_utilization_percent", 90.0),
        )
    )
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
    body_micro_qualification = run.get("body_micro_qualification", {})
    body_pmu_qualification = run.get("body_pmu_qualification", {})
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
    baseline_consistency_path = result_dir / "baseline_phase_consistency.json"
    baseline_consistency = (
        load(baseline_consistency_path)
        if baseline_consistency_path.exists()
        else run.get("baseline_phase_consistency", {})
    )
    environment_path = result_dir / "environment.json"
    environment_end_path = result_dir / "environment_end.json"
    environment = load(environment_path) if environment_path.exists() else {}
    environment_end = load(environment_end_path) if environment_end_path.exists() else {}
    label = "CANONICAL" if run.get("canonical") else "NON-CANONICAL"
    sample_qualified = bool(sampling_plan.get("qualified_sampling"))
    body_sample_qualified = bool(body_evidence_raw.get("qualified_sampling"))
    e2e_phase = run.get("phases", {}).get("e2e", "not-run")
    body_phase = run.get("phases", {}).get("body", "not-run")
    e2e_observed = (
        "diagnostic only"
        if e2e_phase == "passed" and not sample_qualified
        else e2e_phase
    )
    body_observed = (
        "diagnostic only"
        if body_phase == "passed" and not body_sample_qualified
        else body_phase
    )
    throughput_label = "Sustainable RPS" if sample_qualified else "Diagnostic RPS"
    throughput_section = (
        "Saturation"
        if sample_qualified
        else "Closed-Loop Throughput Sweep (Diagnostic)"
    )
    fixed_qualified = bool(fixed_raw.get("valid")) and bool(fixed) and all(
        row["qualified"] for row in fixed
    )
    saturation_qualified = bool(saturation_raw.get("valid")) and bool(saturation) and all(
        row["qualified"] for row in saturation
    )
    body_e2e_qualified = (
        body_sample_qualified
        and bool(body_evidence_raw.get("valid"))
        and bool(body_e2e)
        and all(row["qualified"] for row in body_e2e)
    )
    oracle_qualified = (
        run.get("phases", {}).get("lumina_crs") == "passed"
        and run.get("phases", {}).get("coraza_crs") == "passed"
        and bool(full_correctness)
        and all(row["passed"] for row in full_correctness)
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
    source_inventory = manifest["lumina"].get(
        "source_rule_inventory_summary", {}
    )
    source_class_counts = source_inventory.get("classification_counts", {})
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
        "- Complete source-ID classification: "
        "[`source_rule_inventory.json`](source_rule_inventory.json)",
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
        "### Source Rule Inventory",
        "",
        f"- Generated execution owner: `{source_class_counts.get('generated', 0)}` IDs",
        f"- Native runtime owner: `{source_class_counts.get('runtime-native', 0)}` IDs",
        f"- CRS control/setup/meta rules: `{source_class_counts.get('control-or-setup', 0)}` IDs",
        f"- Unsupported score-bearing rules: "
        f"`{len(source_inventory.get('unsupported_score_bearing_ids', []))}` IDs",
        "- `subsumed_by` is emitted only from an explicit compiler ownership edge; the harness "
        "does not infer semantic coverage from rule counts.",
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
        f"| Request-body evidence | {body_observed} | "
        f"direct processes + PMU + predeclared 4/16/128 KiB E2E | "
        f"{'PASS' if run.get('phases', {}).get('body') == 'passed' and body_micro_qualification.get('valid') and body_pmu_qualification.get('valid') and body_e2e_qualified else 'NOT QUALIFIED'} |",
        f"| Artifact integrity | {run.get('phases', {}).get('artifacts', 'not-run')} | pre/post hashes identical | "
        f"{'PASS' if run.get('phases', {}).get('artifacts') == 'passed' else 'NOT QUALIFIED'} |",
        f"| Lumina CRS oracle gate | {run.get('phases', {}).get('lumina_crs', 'not-run')} | passed | "
        f"{'PASS' if run.get('phases', {}).get('lumina_crs') == 'passed' else 'NOT QUALIFIED'} |",
        f"| Coraza CRS oracle gate | {run.get('phases', {}).get('coraza_crs', 'not-run')} | passed | "
        f"{'PASS' if run.get('phases', {}).get('coraza_crs') == 'passed' else 'NOT QUALIFIED'} |",
        f"| Fixed-rate E2E | {e2e_observed} | >=5 runs and >=100000 accepted/run | "
        f"{'PASS' if fixed_qualified else 'NOT QUALIFIED'} |",
        f"| Saturation stability | {e2e_observed} | "
        f">=5 runs, RPS CV <=5%, client CPU <=90% | "
        f"{'PASS' if saturation_qualified else 'NOT QUALIFIED'} |",
        f"| Cross-phase plain-NGINX baseline | "
        f"{run.get('phases', {}).get('baseline_consistency', 'not-run')} | "
        f"shared connection point, RPS delta <="
        f"{baseline_consistency.get('max_rps_delta_percent', 'N/A')}%, CPU/request delta <="
        f"{baseline_consistency.get('max_cpu_delta_percent', 'N/A')}% | "
        f"{'PASS' if baseline_consistency.get('valid') and sample_qualified else 'NOT QUALIFIED'} |",
        f"| Lumina overhead decomposition | {run.get('phases', {}).get('overhead', 'not-run')} | paired E0/E1/E2 + direct kernels | "
        f"{'PASS' if overhead_qualified else 'NOT QUALIFIED'} |",
        f"| Multi-worker scaling | {run.get('phases', {}).get('scaling', 'not-requested')} | "
        f"1/2/4/8 workers, >=5 runs, CV <=5%, "
        f"client CPU <={scaling_client_limit:g}% | "
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
        (
            "The full oracle gates passed for these artifacts, so CRS-equivalent comparison is "
            "eligible within each documented observable contract."
            if oracle_qualified
            else "The full oracle gates did not qualify these artifacts. Performance rows show "
            "execution of the generated policy for the pinned CRS PL2 manifest; they are not an "
            "equivalent-full-CRS speedup claim."
        ),
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
        "## Request-Body Evidence",
        "",
        "This is a separate evidence class. It does not alter the canonical empty-body GET "
        "workload. Direct rows measure a complete 128 KiB JSON allow transaction. E2E rows use "
        "deterministic POST requests and a minimal fixed-response backend in the same NGINX "
        "process; both front and backend CPU are included in server CPU accounting.",
        "",
        "### Direct 128 KiB JSON Transactions",
        "",
        "`AllowJSONVaried` is the primary large-body fixture because it avoids a repeated-token "
        "shortcut. `AllowJSON` is retained as a secondary/control workload.",
        "",
        "| Engine / workload | Median CPU time | Effective throughput | Inner CV | Process 95% CI | Processes | Qualification |",
        "|---|---:|---:|---:|---:|---:|---|",
    ])
    if body_direct:
        lines.extend(
            f"| `{row['name']}` | {format_time(row['cpu'])} | "
            f"{(0.125 * 1_000_000_000.0 / row['cpu']):.2f} MiB/s | "
            f"{percent_text(row['inner_cv'])} | {ci_text(row['ci'])} | "
            f"{row['processes']} | "
            f"{'QUALIFIED' if row['qualified'] else 'NOT QUALIFIED'} |"
            for row in body_direct
        )
    else:
        lines.append("| unavailable | - | - | - | - | - | NOT RUN |")
    lines.extend([
        "",
        "### Lumina 9341xx Logical Work on Varied JSON",
        "",
        "These compiler diagnostics count logical work inside the Lumina transaction. They are "
        "not hardware PMU attribution and do not assign cycles to an individual rule.",
        "",
        "| Rule ID | Dispatches/transaction | Exact verifier calls/transaction | Exact subject bytes/transaction | Processes | Quality |",
        "|---:|---:|---:|---:|---:|---|",
    ])
    if body_rule_work:
        lines.extend(
            f"| `{row['rule_id']}` | {decimal_text(row['dispatches'])} | "
            f"{decimal_text(row['exact_calls'])} | "
            f"{decimal_text(row['exact_bytes'], 0)} | {row['processes']} | "
            f"{'QUALIFIED' if row['qualified'] else 'NOT QUALIFIED'} |"
            for row in body_rule_work
        )
    else:
        lines.append("| unavailable | - | - | - | - | NOT RUN |")
    lines.extend([
        "",
        "### NGINX E2E Body Latency",
        "",
        "Qualified rows run at no more than 60% of the engine's own stable saturation rate for "
        "the same body size and verdict class. The current smoke protocol uses at least three "
        "short calibration runs and no more than 40% of their median rate; legacy artifacts "
        "retain their recorded, potentially smaller diagnostic plan. Qualified rates below "
        "wrk2's 1 RPS minimum and smoke rates below the 10 RPS short-run histogram floor use one "
        "explicitly labeled closed-loop connection. p99.9 is never published "
        "from this matrix. A large fixed-rate/calibration p50 amplification or a greater than "
        "4x inversion between adjacent body sizes is retained but marked anomalous.",
        "",
        "| Body | Verdict class | Engine | Load | p50 | p90 | p99 | Runs | Min latency samples/run | Evidence class | Qualification |",
        "|---:|---|---|---:|---:|---:|---:|---:|---:|---|---|",
    ])
    if body_e2e:
        lines.extend(
            f"| {row['size_kib']} KiB | `{row['request_class']}` | "
            f"`{row['engine']}` | "
            f"{str(row['rate']) + ' RPS' if row['measurement_mode'] == 'fixed-rate' else 'closed-loop c=1'} | "
            f"{body_percentile_text(row, 'p50')} | "
            f"{body_percentile_text(row, 'p90')} | "
            f"{body_percentile_text(row, 'p99')} | "
            f"{row['runs']} | {row['min_samples']} | "
            f"{body_evidence_class_text(row)} | "
            f"{'QUALIFIED' if row['qualified'] else 'NOT QUALIFIED'} |"
            for row in body_e2e
        )
    else:
        lines.append("| unavailable | - | - | - | - | - | - | - | - | - | NOT RUN |")
    body_anomalies = [row for row in body_e2e if row.get("anomalous")]
    if body_anomalies:
        lines.extend([
            "",
            "> **Anomalous body latency evidence - investigation required.** "
            "These rows remain visible as diagnostics but cannot qualify:",
        ])
        lines.extend(
            "> - "
            f"`{row['engine']}` {row['size_kib']} KiB "
            f"`{row['request_class']}`: "
            + "; ".join(row["anomaly_reasons"])
            for row in body_anomalies
        )
    lines.extend([
        "",
        "Raw body plans, generated workload hashes and per-leg artifacts: "
        "[`body_evidence/results.json`](body_evidence/results.json).",
        (
            "Planned timed E2E lower bound: "
            + wall_time_text(
                body_evidence_raw.get("planned_timed_seconds", {}).get(
                    "total_lower_bound", 0
                )
            )
            + ". It excludes build, correctness, process startup, direct microbenchmark and PMU "
            "time."
            if body_evidence_raw.get("planned_timed_seconds")
            else "Planned timed E2E lower bound: unavailable."
        ),
        "",
        "### 128 KiB Varied-JSON PMU",
        "",
        "| Engine | Cycles/transaction | Instructions/transaction | IPC | Branch misses | Cache misses | L1D misses | LLC misses | iTLB misses | Minimum running | Quality |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|",
    ])
    if body_pmu:
        lines.extend(
            f"| `{row['engine']}` | "
            f"{decimal_text(row['cycles_per_transaction'], 0)} | "
            f"{decimal_text(row['instructions_per_transaction'], 0)} | "
            f"{decimal_text(row['ipc'])} | "
            f"{pmu_percent_text(row['branch_miss'])} | "
            f"{pmu_percent_text(row['cache_miss'])} | "
            f"{pmu_percent_text(row['l1d_miss'])} | "
            f"{pmu_percent_text(row['llc_miss'])} | "
            f"{pmu_percent_text(row['itlb_miss'])} | "
            f"{pmu_percent_text(row['running'])} | "
            f"{'QUALIFIED' if row['qualified'] else 'NOT QUALIFIED'} |"
            for row in body_pmu
        )
    else:
        lines.append("| unavailable | - | - | - | - | - | - | - | - | - | NOT RUN |")
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
        "| Layer | Connections | RPS | Server CPU/request | Client CPU median/max | Runs | RPS CV | Qualification |",
        "|---|---:|---:|---:|---:|---:|---:|---|",
    ])
    if overhead_absolute:
        lines.extend(
            f"| `{row['engine']}` | {row['connections']} | {row['rps']:.2f} | "
            f"{format_time(row['cpu_ns']) if row['cpu_ns'] is not None else 'unavailable'} | "
            f"{percent_text(row['client_cpu_median'])} / "
            f"{percent_text(row['client_cpu_max'])} | "
            f"{row['runs']} | {percent_text(row['cv'])} | "
            f"{'QUALIFIED' if row['qualified'] else 'NOT QUALIFIED'} |"
            for row in overhead_absolute
        )
    else:
        lines.append("| unavailable | - | - | - | - | - | - | NOT RUN |")
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
        "| Layer | Rate | p50 | p90 | p99 | p99.9 | Runs | Min latency samples/run | Qualification |",
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
        "Each boundary is collected by a separate benchmark process and the boundary order rotates "
        "between independent process sets. These are compiler-visible kernels, not nested function "
        "timers: `FullDirect` may optimize bundle projection together with inspection, while "
        "`InspectPrebuilt` copies a caller-owned bundle before inspection. Their medians must not "
        "be subtracted from each other.",
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
            "| Engine | Rate | p50 [95% CI] | p90 [95% CI] | p99 [95% CI] | p99.9 [95% CI] | Max | Runs | Min latency samples/run | RPS CV | Qualification |",
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
    if not sample_qualified:
        lines.extend([
            "",
            "**Diagnostic only:** bounded smoke p50/p90 values are pipeline sanity checks. "
            "They are not latency claims; sparse samples and host ordering can invert baseline "
            "and loaded-off rows.",
        ])
    lines.extend(
        [
            "",
            f"## {throughput_section}",
            "",
            f"| Engine | {throughput_label} | Connections | CPU/request | Client CPU median/max | Runs | RPS CV | Qualification |",
            "|---|---:|---:|---:|---:|---:|---:|---|",
        ]
    )
    if saturation_primary:
        lines.extend(
            f"| `{row['engine']}` | {row['rps']:.2f} | {row['connections']} | "
            f"{format_time(row['cpu_ns']) if row['cpu_ns'] is not None else 'unavailable'} | "
            f"{percent_text(row['client_cpu_median'])} / "
            f"{percent_text(row['client_cpu_max'])} | "
            f"{row['runs']} | {percent_text(row['cv'])} | "
            f"{'QUALIFIED' if row['qualified'] else 'NOT QUALIFIED'} |"
            for row in saturation_primary
        )
    else:
        lines.append("| unavailable | - | - | - | - | - | - | NOT RUN |")
    lines.extend(
        [
            "",
            "A point is sustainable only with the required independent runs, zero response errors "
            "and RPS CV no greater than 5%, and load-generator CPU no greater than 90%. "
            "Non-qualified runs report the best observed point only as a throughput sweep.",
            "CPU/request is NGINX master-plus-direct-worker `utime+stime` from `/proc/<pid>/stat` "
            "divided by completed requests. It excludes the load generator and is diagnostic at "
            "the kernel clock-tick resolution recorded in `e2e_saturation/results.json`.",
            "",
            "### Cross-Phase Plain-NGINX Consistency",
            "",
            "The same plain-NGINX configuration is measured in the main and overhead phases. "
            "A publication run fails if their medians materially disagree at a shared connection "
            "point; a noisy smoke keeps both observations and labels the mismatch.",
            "",
            "| Connections | Main RPS | Overhead RPS | RPS delta | Main CPU/request | Overhead CPU/request | CPU delta | Status |",
            "|---:|---:|---:|---:|---:|---:|---:|---|",
        ]
    )
    if baseline_consistency.get("rows"):
        lines.extend(
            f"| {row['connections']} | {row['main_median_rps']:.2f} | "
            f"{row['overhead_median_rps']:.2f} | "
            f"{row['rps_delta_percent']:.2f}% | "
            f"{format_time(row['main_median_cpu_ns_per_request']) if row.get('main_median_cpu_ns_per_request') is not None else 'unavailable'} | "
            f"{format_time(row['overhead_median_cpu_ns_per_request']) if row.get('overhead_median_cpu_ns_per_request') is not None else 'unavailable'} | "
            f"{row['cpu_delta_percent']:.2f}% | "
            f"{'CONSISTENT' if row['consistent'] else 'INCONSISTENT'} |"
            for row in baseline_consistency["rows"]
        )
    else:
        lines.append("| - | - | - | - | - | - | - | NOT RUN |")
    lines.extend(
        [
            "",
            "Raw gate: "
            "[`baseline_phase_consistency.json`](baseline_phase_consistency.json).",
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
            "reference and never enters the CRS-equivalence ranking. A diagnostic NAXSI point "
            "must not be ranked against an inconsistent plain-NGINX smoke baseline.",
            "",
            "| Engine | Rate | p50 | p90 | p99 | p99.9 | Max | Runs | Min latency samples/run | Qualification |",
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
            f"| Engine | {throughput_label} | Connections | CPU/request | Client CPU median/max | Runs | RPS CV | Qualification |",
            "|---|---:|---:|---:|---:|---:|---:|---|",
        ]
    )
    if saturation_native:
        lines.extend(
            f"| `{row['engine']}` | {row['rps']:.2f} | {row['connections']} | "
            f"{format_time(row['cpu_ns']) if row['cpu_ns'] is not None else 'unavailable'} | "
            f"{percent_text(row['client_cpu_median'])} / "
            f"{percent_text(row['client_cpu_max'])} | "
            f"{row['runs']} | {percent_text(row['cv'])} | "
            f"{'QUALIFIED' if row['qualified'] else 'NOT QUALIFIED'} |"
            for row in saturation_native
        )
    else:
        lines.append("| unavailable | - | - | - | - | - | - | NOT RUN |")
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
