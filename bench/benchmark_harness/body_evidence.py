#!/usr/bin/env python3
"""Run the separate request-body evidence protocol for Benchmark Harness V1.0."""

from __future__ import annotations

import argparse
import json
import math
import statistics
import subprocess
import sys
from pathlib import Path
from typing import Any

from body_workloads import materialize


HERE = Path(__file__).resolve().parent
ENGINES = ("luminawaf", "modsecurity", "coraza")
LOAD_FRACTION_LIMIT = 0.60
SMOKE_LOAD_FRACTION = 0.40
SMOKE_MIN_CALIBRATION_RUNS = 3
SMOKE_MIN_CALIBRATION_SECONDS = 5.0
SMOKE_MIN_FIXED_RATE = 10
QUALIFIED_MIN_CALIBRATION_SECONDS = 30.0
LARGE_BODY_MIN_CALIBRATION_SECONDS = 10.0
P50_MEDIAN_AMPLIFICATION_LIMIT = 8.0
P50_SINGLE_RUN_AMPLIFICATION_LIMIT = 50.0
P50_SIZE_INVERSION_LIMIT = 4.0


def duration_seconds(value: str) -> float:
    unit = value[-1]
    scale = {"s": 1.0, "m": 60.0, "h": 3600.0}[unit]
    return float(value[:-1]) * scale


def execute(command: list[str], log: Path) -> None:
    with log.open("w", encoding="utf-8") as stream:
        process = subprocess.run(
            command, cwd=HERE.parents[1], stdout=stream, stderr=subprocess.STDOUT
        )
    if process.returncode != 0:
        raise RuntimeError(f"command failed ({process.returncode}); see {log}")


def sample_contract(
    size_kib: int, engine: str, qualified: bool
) -> dict[str, Any]:
    if qualified:
        if size_kib == 4:
            return {
                "target_samples": 10_000,
                "required_percentiles": ["p50", "p90", "p99"],
                "classification": "body latency",
                "sample_cap_reason": "p99 publication floor",
            }
        if size_kib == 16:
            return {
                "target_samples": 1_000,
                "required_percentiles": ["p50", "p90"],
                "classification": "sample-capped diagnostic",
                "sample_cap_reason": "bounded medium-body publication cost",
            }
        return {
            "target_samples": 100 if engine == "coraza" else 1_000,
            "required_percentiles": (
                ["p50"] if engine == "coraza" else ["p50", "p90"]
            ),
            "classification": "time-capped diagnostic",
            "sample_cap_reason": (
                "comparator runtime cap"
                if engine == "coraza"
                else "bounded large-body publication cost"
            ),
        }
    diagnostic_targets = {4: 40, 16: 10, 128: 2}
    return {
        "target_samples": (
            1 if size_kib == 128 and engine == "coraza"
            else diagnostic_targets[size_kib]
        ),
        "required_percentiles": ["p50"],
        "classification": "bounded smoke diagnostic",
        "sample_cap_reason": "smoke runtime cap",
    }


def calibration_point(
    saturation: dict[str, Any], engine: str, qualified: bool
) -> dict[str, Any]:
    candidates = [
        item for item in saturation.get("stability", [])
        if item.get("engine") == engine
        and (
            bool(item.get("stable"))
            if qualified
            else bool(item.get("diagnostic_available"))
        )
    ]
    if not candidates:
        raise RuntimeError(f"no usable body saturation point for {engine}")
    return max(candidates, key=lambda item: float(item.get("median_rps", 0.0)))


def calibration_settings(
    *,
    size_kib: int,
    qualified: bool,
    requested_seconds: float,
    measurement_repetitions: int,
) -> tuple[float, int]:
    minimum_seconds = (
        QUALIFIED_MIN_CALIBRATION_SECONDS
        if qualified
        else (
            LARGE_BODY_MIN_CALIBRATION_SECONDS
            if size_kib == 128
            else SMOKE_MIN_CALIBRATION_SECONDS
        )
    )
    repetitions = (
        measurement_repetitions
        if qualified
        else max(measurement_repetitions, SMOKE_MIN_CALIBRATION_RUNS)
    )
    return max(requested_seconds, minimum_seconds), repetitions


def calibration_latency_us(
    saturation: dict[str, Any],
    *,
    engine: str,
    connections: int,
    percentile: str,
) -> float | None:
    values = [
        float(item["latency_us"][percentile])
        for item in saturation.get("results", [])
        if item.get("engine") == engine
        and int(item.get("connections", -1)) == connections
        and item.get("valid")
        and item.get("latency_us", {}).get(percentile) is not None
    ]
    return statistics.median(values) if values else None


def calibration_rps_floor(
    saturation: dict[str, Any],
    *,
    engine: str,
    connections: int,
) -> float | None:
    values = [
        float(item["requests_per_second"])
        for item in saturation.get("results", [])
        if item.get("engine") == engine
        and int(item.get("connections", -1)) == connections
        and item.get("valid")
        and float(item.get("requests_per_second", 0.0)) > 0.0
    ]
    return min(values) if values else None


def derive_body_plan(
    saturation: dict[str, Any],
    *,
    size_kib: int,
    request_class: str,
    qualified: bool,
    repetitions: int,
    load_fraction: float = LOAD_FRACTION_LIMIT,
) -> dict[str, Any]:
    if not 0.0 < load_fraction <= LOAD_FRACTION_LIMIT:
        raise RuntimeError(
            f"body fixed load fraction must be in (0, {LOAD_FRACTION_LIMIT}]"
        )
    legs: list[dict[str, Any]] = []
    for engine in ENGINES:
        point = calibration_point(saturation, engine, qualified)
        selected_point = point
        stable_rps = float(point["median_rps"])
        if stable_rps <= 0.0:
            raise RuntimeError(f"body saturation is zero for {engine}")
        contract = sample_contract(size_kib, engine, qualified)
        connections = int(point["connections"])
        calibration_latency = {
            percentile: calibration_latency_us(
                saturation,
                engine=engine,
                connections=connections,
                percentile=percentile,
            )
            for percentile in ("p50", "p90", "p99")
        }
        rate_ceiling = stable_rps * load_fraction
        minimum_fixed_rate = 1 if qualified else SMOKE_MIN_FIXED_RATE
        if rate_ceiling >= minimum_fixed_rate:
            rate = max(1, math.floor(rate_ceiling))
            duration = math.ceil(
                contract["target_samples"] * 1.10 / (rate * 0.90)
            )
            if not qualified:
                duration = max(2, duration)
            measurement_mode = "fixed-rate"
        else:
            single = next(
                (
                    item for item in saturation.get("stability", [])
                    if item.get("engine") == engine
                    and int(item.get("connections", -1)) == 1
                    and (
                        bool(item.get("stable"))
                        if qualified
                        else bool(item.get("diagnostic_available"))
                    )
                ),
                None,
            )
            if single is None:
                raise RuntimeError(
                    f"{engine} requires a stable one-connection body point "
                    "because normalized open-loop rate is below 1 RPS"
                )
            selected_point = single
            stable_rps = float(single["median_rps"])
            connections = 1
            calibration_latency = {
                percentile: calibration_latency_us(
                    saturation,
                    engine=engine,
                    connections=connections,
                    percentile=percentile,
                )
                for percentile in ("p50", "p90", "p99")
            }
            rate = None
            calibration_floor_rps = (
                calibration_rps_floor(
                    saturation,
                    engine=engine,
                    connections=connections,
                )
                or stable_rps
            )
            duration = math.ceil(
                contract["target_samples"] * 1.10 / calibration_floor_rps
            )
            measurement_mode = "single-connection-closed-loop"
        if measurement_mode == "fixed-rate":
            calibration_floor_rps = (
                calibration_rps_floor(
                    saturation,
                    engine=engine,
                    connections=connections,
                )
                or stable_rps
            )
        legs.append(
            {
                "engine": engine,
                "size_kib": size_kib,
                "request_class": request_class,
                "measurement_mode": measurement_mode,
                "saturation_rps": stable_rps,
                "calibration_rps_floor": calibration_floor_rps,
                "calibration_runs": int(selected_point.get("valid_runs", 0)),
                "calibration_rps_cv_percent": selected_point.get("cv_percent"),
                "calibration_stable": bool(selected_point.get("stable")),
                "calibration_latency_us": calibration_latency,
                "load_fraction_ceiling": load_fraction,
                "fixed_rate": rate,
                "duration_seconds": max(1, duration),
                "connections": connections,
                "repetitions": repetitions,
                **contract,
            }
        )
    return {
        "schema": 1,
        "qualified_sampling": qualified,
        "size_kib": size_kib,
        "request_class": request_class,
        "load_fraction_limit": LOAD_FRACTION_LIMIT,
        "legs": legs,
    }


def classify_latency_anomalies(
    measurements: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    anomalies: list[dict[str, Any]] = []
    for measurement in measurements:
        reasons: list[str] = []
        plan = measurement.get("plan", {})
        calibration_p50 = (
            plan.get("calibration_latency_us", {}).get("p50")
            if isinstance(plan.get("calibration_latency_us"), dict)
            else None
        )
        fixed_p50_values = [
            float(item["latency_us"]["p50"])
            for item in measurement.get("results", [])
            if item.get("valid")
            and item.get("latency_us", {}).get("p50") is not None
        ]
        amplification_values: list[float] = []
        if (
            plan.get("measurement_mode") == "fixed-rate"
            and calibration_p50 is not None
            and float(calibration_p50) > 0.0
            and fixed_p50_values
        ):
            amplification_values = [
                value / float(calibration_p50) for value in fixed_p50_values
            ]
            median_amplification = statistics.median(amplification_values)
            max_amplification = max(amplification_values)
            if median_amplification > P50_MEDIAN_AMPLIFICATION_LIMIT:
                reasons.append(
                    "median fixed-rate p50 is "
                    f"{median_amplification:.2f}x calibration p50"
                )
            if max_amplification > P50_SINGLE_RUN_AMPLIFICATION_LIMIT:
                reasons.append(
                    "one fixed-rate p50 is "
                    f"{max_amplification:.2f}x calibration p50"
                )
        measurement["anomaly_metrics"] = {
            "calibration_p50_us": calibration_p50,
            "fixed_p50_median_us": (
                statistics.median(fixed_p50_values)
                if fixed_p50_values else None
            ),
            "p50_amplification_median": (
                statistics.median(amplification_values)
                if amplification_values else None
            ),
            "p50_amplification_max": (
                max(amplification_values) if amplification_values else None
            ),
        }
        measurement["anomaly_reasons"] = reasons
        measurement["anomalous"] = bool(reasons)

    grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for measurement in measurements:
        grouped.setdefault(
            (str(measurement["engine"]), str(measurement["request_class"])),
            [],
        ).append(measurement)
    for items in grouped.values():
        ordered = sorted(items, key=lambda item: int(item["size_kib"]))
        for smaller, larger in zip(ordered, ordered[1:]):
            smaller_p50 = smaller["anomaly_metrics"]["fixed_p50_median_us"]
            larger_p50 = larger["anomaly_metrics"]["fixed_p50_median_us"]
            if (
                smaller_p50 is None
                or larger_p50 is None
                or larger_p50 <= 0.0
            ):
                continue
            ratio = float(smaller_p50) / float(larger_p50)
            if ratio <= P50_SIZE_INVERSION_LIMIT:
                continue
            reason = (
                f"p50 size-trend inversion: {smaller['size_kib']} KiB is "
                f"{ratio:.2f}x {larger['size_kib']} KiB"
            )
            smaller["anomaly_reasons"].append(reason)
            smaller["anomalous"] = True

    for measurement in measurements:
        if not measurement["anomalous"]:
            continue
        anomalies.append(
            {
                "workload_id": measurement["workload_id"],
                "engine": measurement["engine"],
                "request_class": measurement["request_class"],
                "size_kib": measurement["size_kib"],
                "reasons": measurement["anomaly_reasons"],
                "metrics": measurement["anomaly_metrics"],
            }
        )
    return anomalies


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--qualified", action="store_true")
    parser.add_argument("--nginx", type=Path, required=True)
    parser.add_argument("--wrk", type=Path, required=True)
    parser.add_argument("--wrk2", type=Path, required=True)
    parser.add_argument("--library-path", required=True)
    parser.add_argument("--server-cpu", required=True)
    parser.add_argument("--client-cpu", required=True)
    parser.add_argument("--threads", type=int, default=1)
    parser.add_argument("--repetitions", type=int, default=1)
    parser.add_argument("--saturation-duration", default="2s")
    parser.add_argument("--connections-sweep", default="1,10")
    parser.add_argument("--port", type=int, default=19400)
    args = parser.parse_args()

    if args.qualified and args.repetitions < 5:
        raise RuntimeError("qualified body evidence requires five repetitions")
    if duration_seconds(args.saturation_duration) <= 0:
        raise RuntimeError("body saturation duration must be positive")

    args.output.mkdir(parents=True, exist_ok=False)
    workload_root = args.output / "workloads"
    workload_manifest = materialize(workload_root)
    base = [
        sys.executable,
        str(HERE / "e2e.py"),
        "--adapter-set", "body-crs",
        "--fixed-response-backend",
        "--nginx", str(args.nginx),
        "--wrk", str(args.wrk),
        "--wrk2", str(args.wrk2),
        "--library-path", args.library_path,
        "--server-cpu", args.server_cpu,
        "--client-cpu", args.client_cpu,
        "--threads", str(args.threads),
        "--workers", "1",
        "--port", str(args.port),
        "--probe-timeout", "30",
        "--request-timeout", "30s",
    ]
    if args.qualified:
        base.append("--canonical")

    plans: list[dict[str, Any]] = []
    measurements: list[dict[str, Any]] = []
    calibration_timed_seconds = 0
    measurement_timed_seconds = 0
    for workload in workload_manifest["workloads"]:
        slug = str(workload["id"])
        request_class = str(workload["request_class"])
        size_kib = int(workload["size_kib"])
        workload_path = workload_root / str(workload["path"])
        saturation_seconds, calibration_repetitions = calibration_settings(
            size_kib=size_kib,
            qualified=args.qualified,
            requested_seconds=duration_seconds(args.saturation_duration),
            measurement_repetitions=args.repetitions,
        )
        saturation_duration = f"{math.ceil(saturation_seconds)}s"
        calibration_timed_seconds += (
            math.ceil(saturation_seconds)
            * calibration_repetitions
            * len(ENGINES)
        )
        saturation_dir = args.output / "saturation" / slug
        saturation_dir.parent.mkdir(parents=True, exist_ok=True)
        execute(
            [
                *base,
                "--mode", "saturation",
                "--output", str(saturation_dir),
                "--workload", str(workload_path),
                "--request-class", request_class,
                "--duration", saturation_duration,
                "--repetitions", str(calibration_repetitions),
                "--connections-sweep", args.connections_sweep,
            ],
            args.output / f"saturation_{slug}.log",
        )
        saturation = json.loads(
            (saturation_dir / "results.json").read_text(encoding="utf-8")
        )
        plan = derive_body_plan(
            saturation,
            size_kib=size_kib,
            request_class=request_class,
            qualified=args.qualified,
            repetitions=args.repetitions,
            load_fraction=(
                LOAD_FRACTION_LIMIT
                if args.qualified
                else SMOKE_LOAD_FRACTION
            ),
        )
        plan["calibration_repetitions"] = calibration_repetitions
        plan["calibration_duration_seconds"] = math.ceil(saturation_seconds)
        plan["workload_id"] = slug
        plan["workload_sha256"] = workload["sha256"]
        plan_path = args.output / f"sampling_plan_{slug}.json"
        plan_path.write_text(
            json.dumps(plan, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        plans.append(plan)

        for leg in plan["legs"]:
            engine = str(leg["engine"])
            leg_dir = args.output / "measurements" / slug / engine
            leg_dir.parent.mkdir(parents=True, exist_ok=True)
            command = [
                *base,
                "--engine", engine,
                "--output", str(leg_dir),
                "--workload", str(workload_path),
                "--request-class", request_class,
                "--duration", f"{leg['duration_seconds']}s",
                "--repetitions", str(args.repetitions),
                "--min-samples", str(leg["target_samples"]),
                "--required-percentiles",
                ",".join(leg["required_percentiles"]),
            ]
            if leg["measurement_mode"] == "fixed-rate":
                measurement_timed_seconds += (
                    (int(leg["duration_seconds"]) + 1) * args.repetitions
                )
                command.extend(
                    [
                        "--mode", "fixed",
                        "--rate", str(leg["fixed_rate"]),
                        "--connections", str(leg["connections"]),
                    ]
                )
            else:
                measurement_timed_seconds += (
                    int(leg["duration_seconds"]) * args.repetitions
                )
                command.extend(
                    [
                        "--mode", "saturation",
                        "--connections-sweep", "1",
                    ]
                )
            execute(command, args.output / f"measurement_{slug}_{engine}.log")
            payload = json.loads(
                (leg_dir / "results.json").read_text(encoding="utf-8")
            )
            measurements.append(
                {
                    "workload_id": slug,
                    "size_kib": size_kib,
                    "request_class": request_class,
                    "engine": engine,
                    "plan": leg,
                    "artifact": str(
                        (leg_dir / "results.json").relative_to(args.output)
                    ),
                    "valid": bool(payload.get("valid")),
                    "results": payload.get("results", []),
                }
            )

    anomalies = classify_latency_anomalies(measurements)
    if args.qualified:
        for measurement in measurements:
            measurement["valid"] = bool(
                measurement["valid"] and not measurement["anomalous"]
            )
    result = {
        "schema": 1,
        "qualified_sampling": args.qualified,
        "valid": bool(measurements) and all(
            item["valid"] for item in measurements
        ),
        "anomalous": bool(anomalies),
        "anomalies": anomalies,
        "workload_manifest": workload_manifest,
        "plans": plans,
        "measurements": measurements,
        "planned_timed_seconds": {
            "calibration": calibration_timed_seconds,
            "measurement_and_fixed_warmup": measurement_timed_seconds,
            "total_lower_bound": (
                calibration_timed_seconds + measurement_timed_seconds
            ),
            "excludes": [
                "NGINX startup and preflight",
                "response probes",
                "inter-leg cooldown",
                "build, correctness, direct microbenchmark and PMU phases",
            ],
        },
    }
    (args.output / "results.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(args.output / "results.json")
    if args.qualified and not result["valid"]:
        return 2
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as exc:
        print(f"Body evidence failed: {exc}", file=sys.stderr)
        raise SystemExit(2)
