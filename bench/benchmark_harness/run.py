#!/usr/bin/env python3
"""Fail-closed orchestration for LuminaWAF Benchmark Harness v1."""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import json
import math
import os
import platform
import re
import shlex
import shutil
import statistics
import subprocess
import sys
from pathlib import Path


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
PINS = json.loads((HERE / "pins.json").read_text(encoding="utf-8"))
CACHE = Path(os.environ.get("LUMINA_BENCH_V1_CACHE", ROOT / ".cache/benchmark_harness_v1"))
DEFAULT_MODULE_DIR = CACHE / "sources" / f"nginx-{PINS['nginx']['version']}" / "objs"
DEFAULT_NGINX = DEFAULT_MODULE_DIR / "nginx"
MAX_PUBLICATION_LOAD_FRACTION = 0.60
MAX_SATURATION_CLIENT_UTILIZATION_PERCENT = 90.0
MAX_BASELINE_RPS_PHASE_DELTA_PERCENT = 10.0
MAX_BASELINE_CPU_PHASE_DELTA_PERCENT = 15.0
OVERHEAD_MICRO_BOUNDARIES = (
    ("bundlebuild", "Overhead/LuminaWAF/BundleBuild/AllowRotation"),
    ("inspectprebuilt", "Overhead/LuminaWAF/InspectPrebuilt/AllowRotation"),
    ("fulldirect", "Overhead/LuminaWAF/FullDirect/AllowRotation"),
)


def execute(command: list[str], *, cwd: Path, log: Path, env: dict[str, str] | None = None) -> None:
    with log.open("w", encoding="utf-8") as stream:
        process = subprocess.run(command, cwd=cwd, env=env, stdout=stream, stderr=subprocess.STDOUT)
    if process.returncode != 0:
        raise RuntimeError(f"command failed ({process.returncode}); see {log}")


def execute_pmu_group(
    command: list[str], *, cwd: Path, log: Path, csv_path: Path,
    events: tuple[str, ...], env: dict[str, str] | None = None,
) -> None:
    with log.open("w", encoding="utf-8") as stream:
        process = subprocess.run(command, cwd=cwd, env=env, stdout=stream, stderr=subprocess.STDOUT)
    if process.returncode == 0:
        return

    diagnostic = log.read_text(encoding="utf-8", errors="replace")
    unsupported = re.fullmatch(
        r"\s*Error:\s*The [A-Za-z0-9_.:/-]+ event is not supported\.\s*",
        diagnostic,
        flags=re.IGNORECASE,
    )
    if unsupported is None:
        raise RuntimeError(f"command failed ({process.returncode}); see {log}")

    with csv_path.open("a", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream, lineterminator="\n")
        for event in events:
            writer.writerow(["<not supported>", "", event, "0", "0.00", "", ""])

    status = {
        "schema": 1,
        "classification": "unsupported_pmu_event_group",
        "returncode": process.returncode,
        "events": list(events),
        "raw_log": log.name,
    }
    log.with_suffix(".status.json").write_text(
        json.dumps(status, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def capture(command: list[str]) -> str:
    try:
        return subprocess.check_output(command, text=True, stderr=subprocess.STDOUT).strip()
    except (OSError, subprocess.CalledProcessError):
        return "unavailable"


def symbol_isolation_evidence(
    symbols: str, relocations: str, dynamic: str
) -> dict[str, object]:
    pattern = r"\blibinjection_[A-Za-z0-9_]+"
    symbol_hits = sorted(set(re.findall(pattern, symbols)))
    relocation_hits = sorted(set(re.findall(pattern, relocations)))
    needed = sorted(set(re.findall(r"\(NEEDED\).*?\[([^\]]+)\]", dynamic)))
    forbidden_needed = sorted(
        library for library in needed
        if re.search(r"(?:libinjection|libmodsecurity|libpcre|libcoraza|libnaxsi)", library)
    )
    return {
        "schema": 3,
        "valid": not symbol_hits and not relocation_hits and not forbidden_needed,
        "legacy_libinjection_symbols": symbol_hits,
        "legacy_libinjection_relocations": relocation_hits,
        "dt_needed": needed,
        "forbidden_dt_needed": forbidden_needed,
        "contract": (
            "LuminaWAF must contain no legacy SQL classifier reference or comparator runtime "
            "dependency"
        ),
    }


def inspect_symbol_isolation(library: Path) -> dict[str, object]:
    try:
        symbols = subprocess.check_output(
            ["readelf", "--symbols", "--wide", str(library)],
            text=True,
            stderr=subprocess.STDOUT,
        )
        relocations = subprocess.check_output(
            ["readelf", "--relocs", "--wide", str(library)],
            text=True,
            stderr=subprocess.STDOUT,
        )
        dynamic = subprocess.check_output(
            ["readelf", "--dynamic", "--wide", str(library)],
            text=True,
            stderr=subprocess.STDOUT,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise RuntimeError(f"cannot inspect LuminaWAF ELF symbol isolation: {exc}") from exc
    evidence = symbol_isolation_evidence(symbols, relocations, dynamic)
    evidence["library"] = str(library.resolve())
    evidence["sha256"] = sha256(library)
    return evidence


def environment_manifest() -> dict[str, object]:
    nginx = os.environ.get("LUMINA_BENCH_V1_NGINX", "nginx")
    return {
        "host_profile": os.environ.get("LUMINA_BENCH_V1_HOST_PROFILE", "unspecified"),
        "host_note": os.environ.get("LUMINA_BENCH_V1_HOST_NOTE", ""),
        "hostname": platform.node(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "python": platform.python_version(),
        "cpu": capture(["bash", "-lc", "lscpu -J"]),
        "microcode": capture(["bash", "-lc", "awk -F: '/^microcode/{gsub(/ /,\"\",$2); print $2; exit}' /proc/cpuinfo"]),
        "smt_active": capture(["bash", "-lc", "cat /sys/devices/system/cpu/smt/active 2>/dev/null"]),
        "numa": capture(["bash", "-lc", "numactl --hardware 2>&1"]),
        "turbo": capture(["bash", "-lc", "cat /sys/devices/system/cpu/intel_pstate/no_turbo /sys/devices/system/cpu/cpufreq/boost 2>/dev/null"]),
        "temperatures": capture(["bash", "-lc", "sensors -j 2>/dev/null"]),
        "loadavg": capture(["bash", "-lc", "cat /proc/loadavg"]),
        "uptime": capture(["bash", "-lc", "uptime"]),
        "pressure": {
            resource: capture(["bash", "-lc", f"cat /proc/pressure/{resource} 2>/dev/null"])
            for resource in ("cpu", "memory", "io")
        },
        "memory": capture(["bash", "-lc", "free -b"]),
        "process_count": capture(["bash", "-lc", "ps -e --no-headers | wc -l"]),
        "kernel_cmdline": capture(["bash", "-lc", "cat /proc/cmdline"]),
        "kernel_isolated_cpus": capture(
            ["bash", "-lc", "cat /sys/devices/system/cpu/isolated 2>/dev/null"]
        ),
        "cpu_affinity": sorted(os.sched_getaffinity(0)),
        "benchmark_cpu_sets": {
            "server": os.environ.get("LUMINA_BENCH_V1_SERVER_CPU", "1"),
            "client": os.environ.get("LUMINA_BENCH_V1_CLIENT_CPU", "2"),
            "micro": os.environ.get(
                "LUMINA_BENCH_V1_MICRO_CPU", os.environ.get("LUMINA_BENCH_V1_SERVER_CPU", "1")
            ),
            "scaling_server": os.environ.get("LUMINA_BENCH_V1_SCALING_SERVER_CPU", ""),
            "scaling_client": os.environ.get("LUMINA_BENCH_V1_SCALING_CLIENT_CPU", ""),
        },
        "go": capture(["go", "version"]),
        "nginx": capture([nginx, "-V"]),
        "wrk": capture([os.environ.get("LUMINA_BENCH_V1_WRK", "wrk"), "--version"]),
        "wrk2": capture([os.environ.get("LUMINA_BENCH_V1_WRK2", "wrk2"), "--version"]),
        "governor": capture(["bash", "-lc", "cat /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor 2>/dev/null | sort -u"]),
        "git_commit": capture(["git", "-C", str(ROOT), "rev-parse", "HEAD"]),
        "git_status": capture(["git", "-C", str(ROOT), "status", "--porcelain=v1"]),
    }


def parse_cpu_set(value: str) -> set[int]:
    cpus: set[int] = set()
    for part in value.split(","):
        bounds = part.strip().split("-", 1)
        if not bounds[0]:
            continue
        start = int(bounds[0])
        end = int(bounds[1]) if len(bounds) == 2 else start
        if start < 0 or end < start:
            raise RuntimeError(f"invalid CPU set: {value}")
        cpus.update(range(start, end + 1))
    return cpus


def cpu_set_text(cpus: set[int]) -> str:
    return ",".join(str(cpu) for cpu in sorted(cpus))


def thread_siblings(cpu: int) -> set[int]:
    path = Path(f"/sys/devices/system/cpu/cpu{cpu}/topology/thread_siblings_list")
    try:
        return parse_cpu_set(path.read_text(encoding="ascii").strip())
    except OSError:
        return {cpu}


def affinity_available(cpus: set[int]) -> bool:
    if not cpus:
        return False
    process = subprocess.run(
        ["taskset", "-c", cpu_set_text(cpus), "true"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return process.returncode == 0


def canonical_environment_gate() -> None:
    server = parse_cpu_set(os.environ.get("LUMINA_BENCH_V1_SERVER_CPU", "1"))
    client = parse_cpu_set(os.environ.get("LUMINA_BENCH_V1_CLIENT_CPU", "2"))
    micro = parse_cpu_set(os.environ.get("LUMINA_BENCH_V1_MICRO_CPU", cpu_set_text(server)))
    if not server or not client or not micro or server & client or micro & client:
        raise RuntimeError(
            "canonical server/micro and load-generator CPU sets must be non-empty and disjoint"
        )
    online_text = capture(["bash", "-lc", "cat /sys/devices/system/cpu/online"])
    online = parse_cpu_set(online_text) if online_text != "unavailable" else set()
    benchmark_cpus = server | client | micro
    if not benchmark_cpus <= online or not affinity_available(benchmark_cpus):
        raise RuntimeError("canonical CPU sets are offline or unavailable to taskset")
    server_threads = set().union(*(thread_siblings(cpu) for cpu in server | micro))
    if server_threads & client:
        raise RuntimeError("canonical load-generator CPUs share an SMT core with server/micro CPUs")
    isolated_text = capture(
        ["bash", "-lc", "cat /sys/devices/system/cpu/isolated 2>/dev/null"]
    )
    isolated = parse_cpu_set(isolated_text) if isolated_text != "unavailable" else set()
    if not (server | client | micro) <= isolated:
        raise RuntimeError(
            "canonical CPU sets must be kernel-isolated; configure isolcpus/nohz_full/rcu_nocbs"
        )
    if os.environ.get("LUMINA_BENCH_V1_ENABLE_SCALING") == "1":
        scaling_server = parse_cpu_set(
            os.environ.get("LUMINA_BENCH_V1_SCALING_SERVER_CPU", "")
        )
        scaling_client = parse_cpu_set(
            os.environ.get("LUMINA_BENCH_V1_SCALING_CLIENT_CPU", "")
        )
        if not scaling_server or not scaling_client or scaling_server & scaling_client:
            raise RuntimeError(
                "canonical scaling server and load-generator CPU sets must be non-empty "
                "and disjoint"
            )
        scaling_cpus = scaling_server | scaling_client
        if not scaling_cpus <= online or not affinity_available(scaling_cpus):
            raise RuntimeError("canonical scaling CPUs are offline or unavailable to taskset")
        if not scaling_cpus <= isolated:
            raise RuntimeError("canonical scaling CPU sets must be kernel-isolated")
        scaling_server_threads = set().union(
            *(thread_siblings(cpu) for cpu in scaling_server)
        )
        if scaling_server_threads & scaling_client:
            raise RuntimeError(
                "canonical scaling load-generator CPUs share an SMT core with server CPUs"
            )
    governors = capture(
        ["bash", "-lc", "cat /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor 2>/dev/null | sort -u"]
    ).splitlines()
    if governors and governors != ["performance"]:
        raise RuntimeError("canonical mode requires the performance CPU governor")


def validate_benchmark_artifacts(
    paths: list[Path], expected: set[str], required_processes: int,
    required_repetitions: int,
) -> dict[str, object]:
    errors: list[str] = []
    process_rows: list[dict[str, object]] = []
    if len(paths) != required_processes:
        errors.append(f"micro processes={len(paths)}, required={required_processes}")
    for path in paths:
        counts = {name: 0 for name in expected}
        aggregates = {name: set() for name in expected}
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            errors.append(f"{path.name}: invalid JSON artifact: {exc}")
            process_rows.append(
                {"path": path.name, "raw_repetitions": counts}
            )
            continue
        for item in raw.get("benchmarks", []):
            run_name = str(item.get("run_name", "")).removesuffix(
                f"/repeats:{required_repetitions}"
            )
            if run_name not in expected:
                continue
            if item.get("error_occurred") or item.get("skipped"):
                errors.append(f"{path.name}: {run_name} returned skip/error")
            aggregate = item.get("aggregate_name")
            if aggregate:
                aggregates[run_name].add(str(aggregate))
            else:
                counts[run_name] += 1
        for name in sorted(expected):
            if counts[name] != required_repetitions:
                errors.append(
                    f"{path.name}: {name} raw repetitions={counts[name]}, "
                    f"required={required_repetitions}"
                )
            missing = {"mean", "median", "stddev", "cv"} - aggregates[name]
            if missing:
                errors.append(f"{path.name}: {name} missing aggregates={sorted(missing)}")
        process_rows.append({"path": path.name, "raw_repetitions": counts})
    return {
        "valid": not errors,
        "required_processes": required_processes,
        "required_repetitions": required_repetitions,
        "processes": process_rows,
        "errors": errors,
    }


def validate_micro_artifacts(
    paths: list[Path], engines: list[str], required_processes: int, required_repetitions: int
) -> dict[str, object]:
    expected = {
        f"FullTransaction/{engine}/{workload}"
        for engine in engines
        for workload in ("Allow", "Attack")
    }
    return validate_benchmark_artifacts(
        paths, expected, required_processes, required_repetitions
    )


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def artifact(path: Path) -> dict[str, object]:
    return {"path": str(path.resolve()), "bytes": path.stat().st_size, "sha256": sha256(path)}


def validate_artifact_manifest(manifest: dict[str, dict[str, object]]) -> dict[str, object]:
    errors: list[str] = []
    checked = 0
    for name, expected in sorted(manifest.items()):
        if expected.get("unavailable"):
            continue
        path = Path(str(expected["path"]))
        if not path.is_file():
            errors.append(f"{name}: artifact disappeared")
            continue
        checked += 1
        if path.stat().st_size != int(expected["bytes"]):
            errors.append(f"{name}: size drift")
        if sha256(path) != expected["sha256"]:
            errors.append(f"{name}: SHA256 drift")
    return {"schema": 1, "valid": not errors, "checked": checked, "errors": errors}


def validate_internal_pl2_coverage(
    coverage: dict[str, object], manifest: dict[str, object]
) -> None:
    contract = coverage.get("reference_contract", {})
    provenance = coverage.get("provenance", {})
    universe = coverage.get("universe", {})
    crs = manifest.get("crs", {})
    if (
        coverage.get("internal_only") is not True
        or not isinstance(contract, dict)
        or contract.get("modsecurity_runtime_verified") is not False
        or contract.get("publication_eligible") is not False
        or not isinstance(provenance, dict)
        or provenance.get("complete_test_corpus") is not True
        or provenance.get("scope") != "inbound"
        or provenance.get("target_pl") != 2
        or not isinstance(crs, dict)
        or provenance.get("crs_commit") != crs.get("commit")
        or not isinstance(universe, dict)
        or universe.get("source_inbound_rule_count")
        != crs.get("inbound_pl2_rule_count")
    ):
        raise RuntimeError("internal PL2 coverage artifact violates its evidence contract")


def cmake_cache_value(path: Path, key: str) -> str:
    prefix = f"{key}:"
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith(prefix) and "=" in line:
            return line.split("=", 1)[1]
    return "unavailable"


def capture_build_provenance(
    build_dir: Path, result: Path, configure: list[str], build_command: list[str]
) -> Path:
    sources = {
        "cmake_cache": build_dir / "CMakeCache.txt",
        "compile_commands": build_dir / "compile_commands.json",
    }
    missing = [name for name, path in sources.items() if not path.is_file()]
    if missing:
        raise RuntimeError("missing build provenance: " + ", ".join(missing))

    retained: dict[str, dict[str, object]] = {}
    for name, source in sources.items():
        destination = result / source.name
        shutil.copyfile(source, destination)
        retained[name] = artifact(destination)

    cache = result / "CMakeCache.txt"
    c_compiler = cmake_cache_value(cache, "CMAKE_C_COMPILER")
    cxx_compiler = cmake_cache_value(cache, "CMAKE_CXX_COMPILER")
    compile_commands = json.loads(
        (result / "compile_commands.json").read_text(encoding="utf-8")
    )
    payload = {
        "schema": 1,
        "configure_command": configure,
        "build_command": build_command,
        "cmake_version": capture(["cmake", "--version"]),
        "build_type": cmake_cache_value(cache, "CMAKE_BUILD_TYPE"),
        "c_compiler": {
            "path": c_compiler,
            "version": capture([c_compiler, "--version"]),
        },
        "cxx_compiler": {
            "path": cxx_compiler,
            "version": capture([cxx_compiler, "--version"]),
        },
        "environment_flags": {
            name: os.environ.get(name, "")
            for name in ("CPPFLAGS", "CFLAGS", "CXXFLAGS", "LDFLAGS")
        },
        "effective_compile_commands": len(compile_commands),
        "retained": retained,
    }
    path = result / "build_provenance.json"
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def create_artifact_manifest(
    result: Path,
    build_dir: Path,
    symbol_isolation_path: Path,
    build_provenance_path: Path,
    publication_data: bool,
) -> dict[str, dict[str, object]]:
    module_dir = Path(os.environ.get("LUMINA_BENCH_V1_MODULE_DIR", DEFAULT_MODULE_DIR))
    artifact_paths = {
        "crs_manifest": result / "crs_manifest.json",
        "source_rule_inventory": result / "source_rule_inventory.json",
        "environment_start": result / "environment.json",
        "configure_log": result / "configure.log",
        "build_log": result / "build.log",
        "build_provenance": build_provenance_path,
        "cmake_cache": result / "CMakeCache.txt",
        "compile_commands": result / "compile_commands.json",
        "lumina_benchmark_harness": build_dir / "lumina_benchmark_harness",
        "luminawaf": build_dir / "libluminawaf.so",
        "lumina_symbol_isolation": symbol_isolation_path,
        "nginx": Path(os.environ.get("LUMINA_BENCH_V1_NGINX", DEFAULT_NGINX)),
        "lumina_nginx_module": module_dir / "ngx_http_luminawaf_module.so",
        "modsecurity_nginx_module": module_dir / "ngx_http_modsecurity_module.so",
    }
    crs_manifest = json.loads(
        (result / "crs_manifest.json").read_text(encoding="utf-8")
    )

    def evidence_path(entry: dict[str, object]) -> Path:
        path = Path(str(entry["path"]))
        return path if path.is_absolute() else ROOT / path

    artifact_paths["crs_policy_config"] = evidence_path(crs_manifest["crs"]["config"])
    artifact_paths["lumina_generated_manifest"] = evidence_path(
        crs_manifest["lumina"]["generated_manifest"]
    )
    artifact_paths["workload"] = evidence_path(crs_manifest["workload"])
    for index, entry in enumerate(crs_manifest["crs"]["ordered_includes"]):
        artifact_paths[f"crs_include_{index:03d}"] = evidence_path(entry)
    for index, entry in enumerate(crs_manifest["crs"]["data_files"]):
        artifact_paths[f"crs_data_{index:03d}"] = evidence_path(entry)
    for name, filename in (
        ("coraza_nginx_module", "ngx_http_coraza_module.so"),
        ("naxsi_nginx_module", "ngx_http_naxsi_module.so"),
    ):
        path = module_dir / filename
        if path.is_file() or publication_data:
            artifact_paths[name] = path
    if os.environ.get("LUMINA_BENCH_V1_CORAZA_SO"):
        artifact_paths["coraza"] = Path(os.environ["LUMINA_BENCH_V1_CORAZA_SO"])
    if os.environ.get("LUMINA_BENCH_V1_GO_FTW"):
        artifact_paths["go_ftw"] = Path(os.environ["LUMINA_BENCH_V1_GO_FTW"])
    if os.environ.get("LUMINA_BENCH_V1_MODSEC_ROOT"):
        modsecurity_root = Path(os.environ["LUMINA_BENCH_V1_MODSEC_ROOT"])
        candidates = (
            modsecurity_root / "lib/libmodsecurity.so.3",
            modsecurity_root / "lib/libmodsecurity.so",
        )
        artifact_paths["modsecurity"] = next(
            (path for path in candidates if path.is_file()), candidates[0]
        )
    if os.environ.get("LUMINA_BENCH_V1_DEPENDENCY_PROVENANCE"):
        provenance = result / "dependency_provenance.json"
        shutil.copyfile(os.environ["LUMINA_BENCH_V1_DEPENDENCY_PROVENANCE"], provenance)
        artifact_paths["dependency_provenance"] = provenance
    for name, variable in (
        ("baseline_nginx_config", "LUMINA_BENCH_V1_BASELINE_NGINX_CONFIG"),
        ("lumina_nginx_config", "LUMINA_BENCH_V1_LUMINA_NGINX_CONFIG"),
        ("lumina_off_nginx_config", "LUMINA_BENCH_V1_LUMINA_OFF_NGINX_CONFIG"),
        ("modsecurity_nginx_config", "LUMINA_BENCH_V1_MODSEC_NGINX_CONFIG"),
        ("coraza_nginx_config", "LUMINA_BENCH_V1_CORAZA_NGINX_CONFIG"),
        ("naxsi_nginx_config", "LUMINA_BENCH_V1_NAXSI_NGINX_CONFIG"),
        ("modsecurity_config", "LUMINA_BENCH_V1_MODSEC_CONFIG"),
        ("coraza_config", "LUMINA_BENCH_V1_CORAZA_CONFIG"),
        ("naxsi_core_rules", "LUMINA_BENCH_V1_NAXSI_CORE_RULES"),
    ):
        if os.environ.get(variable):
            artifact_paths[name] = Path(os.environ[variable])
    return {
        name: artifact(path) if path.is_file() else {"path": str(path), "unavailable": True}
        for name, path in artifact_paths.items()
    }


def validate_pmu_csv(path: Path) -> dict[str, object]:
    events: set[str] = set()
    running: list[float] = []
    unavailable: set[str] = set()
    with path.open(encoding="utf-8") as stream:
        for fields in csv.reader(stream):
            if len(fields) < 5 or not fields[2].strip():
                continue
            event = fields[2].strip()
            if fields[0].strip().startswith("<"):
                unavailable.add(event)
                continue
            try:
                float(fields[0])
                running.append(float(fields[4]))
                events.add(event)
            except ValueError:
                unavailable.add(event)
    required = {"cycles", "instructions", "branches", "branch-misses"}
    missing = sorted(required - events)
    minimum_running = min(running) if running else None
    return {
        "path": path.name,
        "valid": not missing and minimum_running is not None and minimum_running >= 90.0,
        "minimum_running_percent": minimum_running,
        "missing_required_events": missing,
        "unavailable_events": sorted(unavailable),
    }


def duration_seconds(value: str) -> int:
    match = re.fullmatch(r"([1-9][0-9]*)([smh])", value.strip())
    if not match:
        raise RuntimeError(f"invalid duration {value!r}; use an integer followed by s, m or h")
    scale = {"s": 1, "m": 60, "h": 3600}[match.group(2)]
    return int(match.group(1)) * scale


def derive_sampling_plan(
    saturation: dict[str, object], *, target_samples: int, load_fraction: float,
    requested_rate: int | None = None, requested_duration: str | None = None,
) -> dict[str, object]:
    if target_samples < 100_000:
        raise RuntimeError("publication sampling requires at least 100000 accepted responses")
    if not 0.10 <= load_fraction <= MAX_PUBLICATION_LOAD_FRACTION:
        raise RuntimeError(
            "fixed-rate saturation fraction must be between 0.10 and 0.60"
        )

    engines = sorted({str(item["engine"]) for item in saturation.get("results", [])})
    stable_by_engine: dict[str, float] = {}
    for item in saturation.get("stability", []):
        if not item.get("sustainable"):
            continue
        engine = str(item["engine"])
        rate = float(item.get("median_rps", 0.0))
        stable_by_engine[engine] = max(stable_by_engine.get(engine, 0.0), rate)
    missing = [engine for engine in engines if stable_by_engine.get(engine, 0.0) <= 0.0]
    if not engines or missing:
        raise RuntimeError(
            "cannot derive fixed-rate budget; no stable saturation point for: "
            + ", ".join(missing or ["all engines"])
        )

    limiting_engine = min(stable_by_engine, key=stable_by_engine.get)
    limiting_rps = stable_by_engine[limiting_engine]
    calibrated_ceiling = max(1, math.floor(limiting_rps * load_fraction))
    rate = requested_rate if requested_rate is not None else calibrated_ceiling
    if rate < 1 or rate > calibrated_ceiling:
        raise RuntimeError(
            f"fixed rate {rate} exceeds calibrated ceiling {calibrated_ceiling} RPS "
            f"from {limiting_engine} at {limiting_rps:.2f} RPS"
        )

    # Qualification permits only 90% achieved rate, so budget against that floor plus 10% margin.
    required_seconds = math.ceil(target_samples * 1.10 / (rate * 0.90))
    seconds = duration_seconds(requested_duration) if requested_duration else required_seconds
    if seconds < required_seconds:
        raise RuntimeError(
            f"fixed duration {seconds}s cannot qualify {target_samples} samples at {rate} RPS; "
            f"minimum is {required_seconds}s"
        )
    return {
        "schema": 1,
        "qualified_sampling": True,
        "target_accepted_per_run": target_samples,
        "minimum_achieved_rate_fraction": 0.90,
        "duration_safety_factor": 1.10,
        "saturation_load_fraction": load_fraction,
        "stable_saturation_rps": stable_by_engine,
        "limiting_engine": limiting_engine,
        "limiting_engine_rps": limiting_rps,
        "calibrated_rate_ceiling": calibrated_ceiling,
        "fixed_rate": rate,
        "fixed_duration_seconds": seconds,
        "projected_accepted_at_qualification_floor": math.floor(rate * 0.90 * seconds),
        "rate_overridden": requested_rate is not None,
        "duration_overridden": requested_duration is not None,
    }


def derive_scaling_plan(
    server_cpu_text: str, client_cpu_text: str,
    worker_points: tuple[int, ...] = (1, 2, 4, 8),
) -> dict[str, object]:
    server_cpus = sorted(parse_cpu_set(server_cpu_text))
    client_cpus = sorted(parse_cpu_set(client_cpu_text))
    points = tuple(sorted(set(worker_points)))
    if not server_cpus or not client_cpus:
        raise RuntimeError("scaling CPU sets must be non-empty")
    if set(server_cpus) & set(client_cpus):
        raise RuntimeError("scaling server and client CPU sets must be disjoint")
    if not points or points[0] != 1 or any(point < 1 for point in points):
        raise RuntimeError("scaling worker points must be positive and include one worker")
    if points[-1] > len(server_cpus):
        raise RuntimeError(
            f"scaling point {points[-1]} requires at least {points[-1]} server CPUs"
        )
    return {
        "schema": 1,
        "server_cpu_pool": cpu_set_text(set(server_cpus)),
        "client_cpu_pool": cpu_set_text(set(client_cpus)),
        "points": [
            {
                "workers": workers,
                "server_cpu": cpu_set_text(set(server_cpus[:workers])),
                "client_cpu": cpu_set_text(set(client_cpus)),
                "client_threads": len(client_cpus),
            }
            for workers in points
        ],
    }


def summarize_scaling(
    point_payloads: list[dict[str, object]], *,
    max_client_utilization_percent: float = 90.0,
) -> dict[str, object]:
    if not 0.0 < max_client_utilization_percent < 100.0:
        raise RuntimeError("scaling client utilization limit must be between 0 and 100")
    errors: list[str] = []
    warnings: list[str] = []
    rows: list[dict[str, object]] = []
    expected_engines: set[str] | None = None
    seen_workers: set[int] = set()
    for payload in sorted(point_payloads, key=lambda item: int(item.get("workers", 0))):
        workers = int(payload.get("workers", 0))
        if workers < 1 or workers in seen_workers:
            errors.append(f"invalid or duplicate scaling worker point: {workers}")
            continue
        seen_workers.add(workers)
        engines = {str(item["engine"]) for item in payload.get("results", [])}
        if expected_engines is None:
            expected_engines = engines
        elif engines != expected_engines:
            errors.append(f"workers={workers} engine set differs: {sorted(engines)}")
        sustainable = [
            item for item in payload.get("stability", []) if item.get("sustainable")
        ]
        best_by_engine: dict[str, dict[str, object]] = {}
        for item in sustainable:
            engine = str(item["engine"])
            if (
                engine not in best_by_engine
                or float(item.get("median_rps", 0.0))
                > float(best_by_engine[engine].get("median_rps", 0.0))
            ):
                best_by_engine[engine] = item
        for engine in sorted(engines):
            stability = best_by_engine.get(engine)
            if stability is None:
                errors.append(f"workers={workers} engine={engine} has no sustainable point")
                continue
            connections = int(stability["connections"])
            samples = [
                item for item in payload.get("results", [])
                if item.get("valid") and str(item.get("engine")) == engine
                and int(item.get("connections", -1)) == connections
            ]
            client_values = [
                float(item["client_cpu_utilization_percent"])
                for item in samples
                if item.get("client_cpu_utilization_percent") is not None
            ]
            cpu_values = [
                float(item["server_cpu_ns_per_request"])
                for item in samples if item.get("server_cpu_ns_per_request") is not None
            ]
            cv = stability.get("cv_percent")
            table = samples[0].get("table", "unknown") if samples else "unknown"
            blocking = table != "baseline"
            qualified = (
                len(samples) >= 5 and cv is not None and float(cv) <= 5.0
                and len(client_values) == len(samples)
                and max(client_values, default=100.0) <= max_client_utilization_percent
            )
            if not qualified:
                message = (
                    f"workers={workers} engine={engine} fails runs/CV/client-headroom gate"
                )
                (errors if blocking else warnings).append(message)
            rows.append({
                "engine": engine,
                "table": table,
                "qualification_scope": "blocking" if blocking else "diagnostic",
                "workers": workers,
                "server_cpu": payload.get("server_cpu"),
                "client_cpu": payload.get("client_cpu"),
                "client_threads": payload.get("client_threads"),
                "connections": connections,
                "rps": float(stability.get("median_rps", 0.0)),
                "rps_cv_percent": float(cv) if cv is not None else None,
                "runs": len(samples),
                "server_cpu_ns_per_request": (
                    statistics.median(cpu_values) if cpu_values else None
                ),
                "client_cpu_utilization_percent": (
                    statistics.median(client_values) if client_values else None
                ),
                "client_cpu_utilization_max_percent": (
                    max(client_values) if client_values else None
                ),
                "qualified": qualified,
            })
    if 1 not in seen_workers:
        errors.append("scaling evidence has no one-worker baseline")
    baselines = {row["engine"]: row for row in rows if row["workers"] == 1}
    for row in rows:
        baseline = baselines.get(row["engine"])
        baseline_rps = float(baseline["rps"]) if baseline else 0.0
        speedup = float(row["rps"]) / baseline_rps if baseline_rps > 0.0 else None
        row["speedup"] = speedup
        row["scaling_efficiency_percent"] = (
            speedup / int(row["workers"]) * 100.0 if speedup is not None else None
        )
        row["rps_per_worker"] = float(row["rps"]) / int(row["workers"])
    blocking_rows = [
        row for row in rows if row["qualification_scope"] == "blocking"
    ]
    return {
        "schema": 1,
        "valid": bool(blocking_rows) and not errors
        and all(bool(row["qualified"]) for row in blocking_rows),
        "max_client_utilization_percent": max_client_utilization_percent,
        "worker_points": sorted(seen_workers),
        "errors": errors,
        "warnings": warnings,
        "rows": rows,
    }


def rotated_overhead_micro_boundaries(
    process_index: int,
) -> list[tuple[str, str]]:
    boundaries = list(OVERHEAD_MICRO_BOUNDARIES)
    offset = process_index % len(boundaries)
    order = boundaries[offset:] + boundaries[:offset]
    if (process_index // len(boundaries)) % 2:
        order.reverse()
    return order


def repeated_benchmark_filter(name: str, repetitions: int) -> str:
    if repetitions < 1:
        raise RuntimeError("benchmark repetitions must be positive")
    return rf"^{re.escape(name)}/repeats:{repetitions}$"


def relative_delta_percent(left: float, right: float) -> float:
    denominator = min(left, right)
    if denominator <= 0.0:
        return math.inf
    return abs(left - right) / denominator * 100.0


def baseline_phase_consistency(
    main_saturation: dict[str, object],
    overhead_saturation: dict[str, object],
    *,
    required_connections: set[int],
    required_runs: int,
    require_stable: bool,
    max_rps_delta_percent: float = MAX_BASELINE_RPS_PHASE_DELTA_PERCENT,
    max_cpu_delta_percent: float = MAX_BASELINE_CPU_PHASE_DELTA_PERCENT,
) -> dict[str, object]:
    if required_runs < 1:
        raise RuntimeError("baseline consistency requires at least one run")
    if max_rps_delta_percent <= 0.0 or max_cpu_delta_percent <= 0.0:
        raise RuntimeError("baseline consistency thresholds must be positive")

    def grouped(payload: dict[str, object]) -> dict[int, list[dict[str, object]]]:
        groups: dict[int, list[dict[str, object]]] = {}
        for item in payload.get("results", []):
            if item.get("engine") != "baseline" or not item.get("valid"):
                continue
            groups.setdefault(int(item["connections"]), []).append(item)
        return groups

    def stability_by_connection(
        payload: dict[str, object],
    ) -> dict[int, dict[str, object]]:
        return {
            int(item["connections"]): item
            for item in payload.get("stability", [])
            if item.get("engine") == "baseline"
        }

    main_groups = grouped(main_saturation)
    overhead_groups = grouped(overhead_saturation)
    shared_connections = sorted(set(main_groups) & set(overhead_groups))
    main_stability = stability_by_connection(main_saturation)
    overhead_stability = stability_by_connection(overhead_saturation)
    errors: list[str] = []
    rows: list[dict[str, object]] = []
    missing_required = sorted(required_connections - set(shared_connections))
    if missing_required:
        errors.append(
            "missing shared baseline connection points: "
            + ", ".join(str(value) for value in missing_required)
        )

    identity_fields = (
        "config_sha256",
        "normalized_config_sha256",
        "workload_sha256",
        "allow_response_contract_sha256",
        "server_cpu",
        "client_cpu",
        "workers",
    )
    for connections in shared_connections:
        main_items = main_groups[connections]
        overhead_items = overhead_groups[connections]
        row_errors: list[str] = []
        combined = main_items + overhead_items
        for field in identity_fields:
            values = {
                json.dumps(item.get(field), sort_keys=True)
                for item in combined
            }
            if len(values) != 1:
                row_errors.append(f"identity mismatch: {field}")
        if len(main_items) < required_runs:
            row_errors.append(
                f"main runs={len(main_items)}, required={required_runs}"
            )
        if len(overhead_items) < required_runs:
            row_errors.append(
                f"overhead runs={len(overhead_items)}, required={required_runs}"
            )
        main_rate = statistics.median(
            float(item["requests_per_second"]) for item in main_items
        )
        overhead_rate = statistics.median(
            float(item["requests_per_second"]) for item in overhead_items
        )
        main_cpu_values = [
            float(item["server_cpu_ns_per_request"])
            for item in main_items
            if item.get("server_cpu_ns_per_request") is not None
        ]
        overhead_cpu_values = [
            float(item["server_cpu_ns_per_request"])
            for item in overhead_items
            if item.get("server_cpu_ns_per_request") is not None
        ]
        if len(main_cpu_values) != len(main_items):
            row_errors.append("main CPU/request accounting unavailable")
        if len(overhead_cpu_values) != len(overhead_items):
            row_errors.append("overhead CPU/request accounting unavailable")
        main_cpu = statistics.median(main_cpu_values) if main_cpu_values else None
        overhead_cpu = (
            statistics.median(overhead_cpu_values)
            if overhead_cpu_values else None
        )
        rps_delta = relative_delta_percent(main_rate, overhead_rate)
        cpu_delta = (
            relative_delta_percent(main_cpu, overhead_cpu)
            if main_cpu is not None and overhead_cpu is not None
            else math.inf
        )
        if rps_delta > max_rps_delta_percent:
            row_errors.append(
                f"RPS phase delta={rps_delta:.2f}% exceeds "
                f"{max_rps_delta_percent:.2f}%"
            )
        if cpu_delta > max_cpu_delta_percent:
            row_errors.append(
                f"CPU/request phase delta={cpu_delta:.2f}% exceeds "
                f"{max_cpu_delta_percent:.2f}%"
            )
        main_stable = bool(main_stability.get(connections, {}).get("stable"))
        overhead_stable = bool(
            overhead_stability.get(connections, {}).get("stable")
        )
        if require_stable and not main_stable:
            row_errors.append("main baseline point is not stable")
        if require_stable and not overhead_stable:
            row_errors.append("overhead baseline point is not stable")
        rows.append(
            {
                "connections": connections,
                "required": connections in required_connections,
                "main_runs": len(main_items),
                "overhead_runs": len(overhead_items),
                "main_median_rps": main_rate,
                "overhead_median_rps": overhead_rate,
                "rps_delta_percent": rps_delta,
                "main_median_cpu_ns_per_request": main_cpu,
                "overhead_median_cpu_ns_per_request": overhead_cpu,
                "cpu_delta_percent": cpu_delta,
                "main_stable": main_stable,
                "overhead_stable": overhead_stable,
                "consistent": not row_errors,
                "errors": row_errors,
            }
        )
        errors.extend(f"c={connections}: {error}" for error in row_errors)
    return {
        "schema": 1,
        "valid": bool(rows) and not errors,
        "publication_gate": require_stable,
        "required_connections": sorted(required_connections),
        "required_runs_per_phase": required_runs,
        "max_rps_delta_percent": max_rps_delta_percent,
        "max_cpu_delta_percent": max_cpu_delta_percent,
        "rows": rows,
        "errors": errors,
    }


def run_publication_correctness(
    result: Path,
    build_dir: Path,
    manifest: dict[str, object],
    env: dict[str, str],
) -> None:
    parity_env = env.copy()
    parity_env["BUILD_DIR"] = str(build_dir)
    parity_env["LUMINA_WAF_SO"] = str(build_dir / "libluminawaf.so")
    parity_env["JSON_OUTPUT"] = str(result / "correctness_lumina.json")
    parity_env["PL2_COVERAGE_OUTPUT"] = str(
        result / "pl2_coverage_internal.json"
    )
    execute(
        [str(ROOT / "tools/run_crs_parity_gate.sh")],
        cwd=ROOT,
        log=result / "correctness_lumina.log",
        env=parity_env,
    )
    if not (result / "correctness_lumina.json").is_file():
        raise RuntimeError(
            "Lumina correctness gate did not write structured JSON evidence"
        )
    coverage_path = result / "pl2_coverage_internal.json"
    if not coverage_path.is_file():
        raise RuntimeError("Lumina correctness gate did not write PL2 coverage evidence")
    coverage = json.loads(coverage_path.read_text(encoding="utf-8"))
    validate_internal_pl2_coverage(coverage, manifest)

    coraza_output = result / "correctness_coraza.json"
    execute(
        [
            sys.executable,
            str(HERE / "coraza_correctness.py"),
            "--go-ftw", os.environ["LUMINA_BENCH_V1_GO_FTW"],
            "--nginx", os.environ["LUMINA_BENCH_V1_NGINX"],
            "--nginx-config", os.environ["LUMINA_BENCH_V1_CORAZA_NGINX_CONFIG"],
            "--tests", str(ROOT / "tests/eval_suite/coreruleset/tests/regression/tests"),
            "--manifest", str(result / "crs_manifest.json"),
            "--output", str(coraza_output),
            "--library-path", env["LD_LIBRARY_PATH"],
        ],
        cwd=ROOT,
        log=result / "correctness_coraza.log",
        env=env,
    )
    if not coraza_output.exists():
        raise RuntimeError(
            "Coraza correctness adapter did not write its required JSON output"
        )
    coraza_correctness = json.loads(
        coraza_output.read_text(encoding="utf-8")
    )
    required_coraza = {
        "crs_manifest_sha256": manifest["manifest_sha256"],
        "correctness_mode": "http-verdict",
        "exact_rule_id_observable": False,
        "timeouts": 0,
        "exceptions": 0,
    }
    for key, expected in required_coraza.items():
        if coraza_correctness.get(key) != expected:
            raise RuntimeError(
                f"Coraza correctness {key} does not match canonical contract"
            )
    if float(coraza_correctness.get("overall_parity", 0.0)) < 99.70:
        raise RuntimeError("Coraza correctness is below the 99.70% gate")
    if coraza_correctness.get("outcome_overrides"):
        raise RuntimeError("Coraza correctness used ignored/forced FTW outcomes")
    if (
        coraza_correctness.get("selected_rule_ids")
        != manifest["crs"]["inbound_pl2_rule_ids"]
    ):
        raise RuntimeError(
            "Coraza correctness did not execute the manifest PL2 inventory"
        )
    if int(coraza_correctness.get("tests", 0)) == 0:
        raise RuntimeError("Coraza correctness evaluated zero in-scope tests")


def run_outcome_matrix(
    result: Path,
    build_dir: Path,
    env: dict[str, str],
    publication_data: bool,
) -> bool:
    command = [
        sys.executable,
        str(HERE / "correctness.py"),
        "--output", str(result / "correctness_matrix"),
        "--workload", str(HERE / "workloads/requests.json"),
        "--nginx", os.environ.get(
            "LUMINA_BENCH_V1_NGINX", str(DEFAULT_NGINX)
        ),
        "--library-path", env["LD_LIBRARY_PATH"],
        "--server-cpu", os.environ.get("LUMINA_BENCH_V1_SERVER_CPU", "1"),
    ]
    if publication_data:
        command.append("--canonical")
    execute(
        command,
        cwd=ROOT,
        log=result / "correctness_matrix.log",
        env=env,
    )
    matrix = json.loads(
        (result / "correctness_matrix/results.json").read_text(encoding="utf-8")
    )
    return bool(matrix["valid"])


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("smoke", "exploratory", "qualification", "canonical"))
    parser.add_argument("--build-dir", type=Path, default=ROOT / "build")
    parser.add_argument("--result-dir", type=Path)
    args = parser.parse_args()
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    result = (args.result_dir or ROOT / "perf_results" / "benchmark_harness_v1" / stamp).resolve()
    result.mkdir(parents=True, exist_ok=False)

    strict = args.mode == "canonical"
    publication_data = args.mode in ("qualification", "canonical")
    scaling_requested = os.environ.get("LUMINA_BENCH_V1_ENABLE_SCALING") == "1"
    if scaling_requested and not publication_data:
        raise RuntimeError(
            "multi-worker scaling is a publication supplement; use qualification or canonical"
        )
    manifest_command = [
        sys.executable,
        str(HERE / "manifest.py"),
        "--output",
        str(result / "crs_manifest.json"),
    ]
    if os.environ.get("LUMINA_BENCH_V1_MODSEC_CONFIG"):
        manifest_command.extend(["--config", os.environ["LUMINA_BENCH_V1_MODSEC_CONFIG"]])
    coraza_config = os.environ.get("LUMINA_BENCH_V1_CORAZA_CONFIG")
    if coraza_config:
        manifest_command.extend(["--coraza-config", coraza_config])
    pmu_qualification: dict[str, object] = {
        "valid": False, "reason": "PMU is collected only in qualified modes"
    }
    overhead_pmu_qualification: dict[str, object] = {
        "valid": False, "reason": "PMU is collected only in qualified modes"
    }
    body_pmu_qualification: dict[str, object] = {
        "valid": False, "reason": "body PMU is collected only in qualified modes"
    }
    if publication_data:
        manifest_command.extend(["--strict", "--require-coraza"])
    execute(manifest_command, cwd=ROOT, log=result / "manifest.log")
    manifest = json.loads((result / "crs_manifest.json").read_text(encoding="utf-8"))
    source_rule_inventory = {
        "schema": 1,
        **manifest["lumina"]["source_rule_inventory_summary"],
        "rules": manifest["lumina"]["source_rule_inventory"],
        "crs_manifest_sha256": manifest["manifest_sha256"],
    }
    (result / "source_rule_inventory.json").write_text(
        json.dumps(source_rule_inventory, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    required = ["cmake", "perf", "readelf", "taskset"]
    if publication_data:
        required.append("go")
    missing = [tool for tool in required if shutil.which(tool) is None]
    if missing:
        raise RuntimeError("missing canonical dependencies: " + ", ".join(missing))
    if publication_data and (not os.environ.get("LUMINA_BENCH_V1_CORAZA_SO") or not os.environ.get("LUMINA_BENCH_V1_CORAZA_CONFIG")):
        raise RuntimeError("qualified modes require LUMINA_BENCH_V1_CORAZA_SO and LUMINA_BENCH_V1_CORAZA_CONFIG")
    if publication_data and not os.environ.get("LUMINA_BENCH_V1_GO_FTW"):
        raise RuntimeError("qualified modes require the pinned LUMINA_BENCH_V1_GO_FTW binary")
    if publication_data:
        required_env = (
            "LUMINA_BENCH_V1_NGINX", "LUMINA_BENCH_V1_MODULE_DIR",
            "LUMINA_BENCH_V1_BENCHMARK_ROOT", "LUMINA_BENCH_V1_MODSEC_ROOT",
            "LUMINA_BENCH_V1_DEPENDENCY_PROVENANCE", "LUMINA_BENCH_V1_MODSEC_CONFIG",
            "LUMINA_BENCH_V1_BASELINE_NGINX_CONFIG", "LUMINA_BENCH_V1_LUMINA_NGINX_CONFIG",
            "LUMINA_BENCH_V1_LUMINA_OFF_NGINX_CONFIG",
            "LUMINA_BENCH_V1_MODSEC_NGINX_CONFIG", "LUMINA_BENCH_V1_CORAZA_NGINX_CONFIG",
            "LUMINA_BENCH_V1_NAXSI_NGINX_CONFIG", "LUMINA_BENCH_V1_NAXSI_CORE_RULES",
        )
        absent = [name for name in required_env if not os.environ.get(name)]
        if absent:
            raise RuntimeError("qualified modes require: " + ", ".join(absent))
    if strict:
        tracked = capture(["git", "-C", str(ROOT), "status", "--porcelain=v1", "--untracked-files=no"])
        untracked_sources = capture(
            [
                "bash", "-lc",
                f"git -C {shlex.quote(str(ROOT))} ls-files --others --exclude-standard | "
                "grep -E '(^|/)(CMakeLists\\.txt|[^/]+\\.(c|cc|cpp|h|hpp|py|sh))$' || true",
            ]
        )
        if tracked:
            raise RuntimeError("canonical mode requires a clean tracked project worktree")
        if untracked_sources:
            raise RuntimeError("canonical mode rejects untracked build/script sources")
        canonical_environment_gate()

    (result / "environment.json").write_text(
        json.dumps(environment_manifest(), indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    configure = [
        "cmake", "-S", ".", "-B", str(args.build_dir),
        "-DCMAKE_BUILD_TYPE=Release", "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
    ]
    if os.environ.get("LUMINA_BENCH_V1_BENCHMARK_ROOT"):
        configure.append(f"-DLUMINA_BENCH_V1_BENCHMARK_ROOT={os.environ['LUMINA_BENCH_V1_BENCHMARK_ROOT']}")
    if os.environ.get("LUMINA_BENCH_V1_MODSEC_ROOT"):
        configure.append(f"-DLUMINA_BENCH_V1_MODSEC_ROOT={os.environ['LUMINA_BENCH_V1_MODSEC_ROOT']}")
    execute(configure, cwd=ROOT, log=result / "configure.log")
    build_command = [
        "cmake", "--build", str(args.build_dir), "-j", str(os.cpu_count() or 1),
        "--target", "lumina_benchmark_harness", "--clean-first", "--verbose",
    ]
    execute(build_command, cwd=ROOT, log=result / "build.log")
    build_provenance_path = capture_build_provenance(
        args.build_dir, result, configure, build_command
    )
    symbol_isolation = inspect_symbol_isolation(args.build_dir / "libluminawaf.so")
    symbol_isolation_path = result / "symbol_isolation.json"
    symbol_isolation_path.write_text(
        json.dumps(symbol_isolation, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    if not symbol_isolation["valid"]:
        raise RuntimeError(
            "LuminaWAF contains a legacy SQL classifier reference or forbidden runtime "
            "dependency; "
            f"see {symbol_isolation_path}"
        )
    artifact_manifest = create_artifact_manifest(
        result, args.build_dir, symbol_isolation_path, build_provenance_path,
        publication_data,
    )
    (result / "artifacts.json").write_text(
        json.dumps(artifact_manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    artifact_preflight = validate_artifact_manifest(artifact_manifest)
    (result / "artifact_preflight.json").write_text(
        json.dumps(artifact_preflight, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    if not artifact_preflight["valid"]:
        raise RuntimeError("artifact preflight failed before measurement")
    if publication_data and any(
        value.get("unavailable") for value in artifact_manifest.values()
    ):
        raise RuntimeError("qualified modes have unavailable binary artifacts")

    micro_engines = ["LuminaWAF", "ModSecurity"]
    if os.environ.get("LUMINA_BENCH_V1_CORAZA_SO") and os.environ.get("LUMINA_BENCH_V1_CORAZA_CONFIG"):
        micro_engines.append("Coraza")
    benchmark_filter = "FullTransaction/(" + "|".join(micro_engines) + ").*"
    env = os.environ.copy()
    env["LD_LIBRARY_PATH"] = f"{args.build_dir}:{env.get('LD_LIBRARY_PATH', '')}"
    phases = {
        "manifest": "passed",
        "artifacts": "passed",
        "micro": "not-run",
        "lumina_crs": "not-run",
        "coraza_crs": "not-run",
        "outcome_matrix": "not-run",
        "e2e": "not-run",
        "execution_preflight": "not-run",
        "overhead": "not-run",
        "body": "not-run",
        "baseline_consistency": "not-run",
        "scaling": "not-requested",
    }
    if publication_data:
        run_publication_correctness(result, args.build_dir, manifest, env)
        phases["lumina_crs"] = "passed"
        phases["coraza_crs"] = "passed"
    matrix_valid = run_outcome_matrix(
        result, args.build_dir, env, publication_data
    )
    phases["outcome_matrix"] = "passed" if matrix_valid else "invalid"
    if publication_data and not matrix_valid:
        raise RuntimeError(
            "cross-engine outcome matrix failed before performance measurement"
        )
    process_repetitions = 5 if publication_data else (1 if args.mode == "smoke" else 3)
    micro_cpu = os.environ.get(
        "LUMINA_BENCH_V1_MICRO_CPU", os.environ.get("LUMINA_BENCH_V1_SERVER_CPU", "1")
    )
    for process_index in range(process_repetitions):
        suffix = "" if process_index == 0 else f"_process_{process_index:02d}"
        execute(
            [
                "taskset", "-c", micro_cpu,
                str(args.build_dir / "lumina_benchmark_harness"),
                f"--benchmark_filter={benchmark_filter}",
                "--benchmark_min_time=0.10s" if args.mode == "smoke" else "--benchmark_min_time=1s",
                "--benchmark_report_aggregates_only=false",
                "--benchmark_out_format=json",
                f"--benchmark_out={result / ('micro' + suffix + '.json')}",
            ],
            cwd=ROOT,
            log=result / ("micro" + suffix + ".log"),
            env=env,
        )
    micro_qualification = validate_micro_artifacts(
        sorted(result.glob("micro*.json")), micro_engines, process_repetitions, 10
    )
    micro_qualification["cpu_set"] = micro_cpu
    (result / "micro_qualification.json").write_text(
        json.dumps(micro_qualification, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    if not micro_qualification["valid"]:
        raise RuntimeError("Google Benchmark evidence is incomplete")
    body_micro_names = {
        f"FullTransaction128KiB/{engine}/{workload}"
        for engine in micro_engines
        for workload in ("AllowJSON", "AllowJSONVaried")
    }
    for process_index in range(process_repetitions):
        suffix = "" if process_index == 0 else f"_process_{process_index:02d}"
        execute(
            [
                "taskset", "-c", micro_cpu,
                str(args.build_dir / "lumina_benchmark_harness"),
                "--benchmark_filter=FullTransaction128KiB/.*",
                "--benchmark_min_time=0.10s" if args.mode == "smoke"
                else "--benchmark_min_time=1s",
                "--benchmark_report_aggregates_only=false",
                "--benchmark_out_format=json",
                f"--benchmark_out={result / ('body_micro' + suffix + '.json')}",
            ],
            cwd=ROOT,
            log=result / ("body_micro" + suffix + ".log"),
            env=env,
        )
    body_micro_qualification = validate_benchmark_artifacts(
        sorted(result.glob("body_micro*.json")),
        body_micro_names,
        process_repetitions,
        10,
    )
    body_micro_qualification["cpu_set"] = micro_cpu
    (result / "body_micro_qualification.json").write_text(
        json.dumps(body_micro_qualification, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    if not body_micro_qualification["valid"]:
        raise RuntimeError("request-body Google Benchmark evidence is incomplete")
    overhead_artifacts: dict[str, list[Path]] = {
        name: [] for _, name in OVERHEAD_MICRO_BOUNDARIES
    }
    overhead_execution_order: list[dict[str, object]] = []
    for process_index in range(process_repetitions):
        suffix = "" if process_index == 0 else f"_process_{process_index:02d}"
        order = rotated_overhead_micro_boundaries(process_index)
        overhead_execution_order.append(
            {
                "process_index": process_index,
                "boundaries": [name for _, name in order],
            }
        )
        for slug, name in order:
            stem = f"overhead_micro_{slug}{suffix}"
            output_path = result / f"{stem}.json"
            execute(
                [
                    "taskset", "-c", micro_cpu,
                    str(args.build_dir / "lumina_benchmark_harness"),
                    f"--benchmark_filter={repeated_benchmark_filter(name, 10)}",
                    "--benchmark_min_time=0.10s"
                    if args.mode == "smoke" else "--benchmark_min_time=1s",
                    "--benchmark_report_aggregates_only=false",
                    "--benchmark_out_format=json",
                    f"--benchmark_out={output_path}",
                ],
                cwd=ROOT,
                log=result / f"{stem}.log",
                env=env,
            )
            overhead_artifacts[name].append(output_path)
    overhead_boundary_qualification: dict[str, dict[str, object]] = {}
    overhead_errors: list[str] = []
    for _, name in OVERHEAD_MICRO_BOUNDARIES:
        evidence = validate_benchmark_artifacts(
            overhead_artifacts[name], {name}, process_repetitions, 10
        )
        overhead_boundary_qualification[name] = evidence
        overhead_errors.extend(
            f"{name}: {error}" for error in evidence["errors"]
        )
    overhead_micro_qualification = {
        "schema": 2,
        "valid": not overhead_errors,
        "execution_model": "one boundary per process",
        "required_processes_per_boundary": process_repetitions,
        "required_repetitions": 10,
        "execution_order": overhead_execution_order,
        "boundaries": overhead_boundary_qualification,
        "errors": overhead_errors,
    }
    overhead_micro_qualification["cpu_set"] = micro_cpu
    (result / "overhead_micro_qualification.json").write_text(
        json.dumps(overhead_micro_qualification, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    if not overhead_micro_qualification["valid"]:
        raise RuntimeError("overhead Google Benchmark evidence is incomplete")
    phases["micro"] = "passed"
    if publication_data and "Library was built as DEBUG" in (result / "micro.log").read_text(encoding="utf-8"):
        raise RuntimeError("qualified modes reject a DEBUG Google Benchmark library")
    if publication_data:
        pmu_groups = (
            "{cycles,instructions,branches,branch-misses}",
            "{cache-references,cache-misses}",
            "{L1-dcache-loads,L1-dcache-load-misses}",
            "{LLC-loads,LLC-load-misses}",
            "{iTLB-loads,iTLB-load-misses}",
        )
        for engine in ("LuminaWAF", "ModSecurity", "Coraza"):
            pmu_path = result / f"pmu_{engine.lower()}.csv"
            for group_index, group in enumerate(pmu_groups):
                append = ["--append"] if group_index else []
                execute_pmu_group(
                    [
                        "perf", "stat", "-x,", "-o", str(pmu_path), *append,
                        "-e", group,
                        "taskset", "-c", micro_cpu,
                        str(args.build_dir / "lumina_benchmark_harness"),
                        f"--benchmark_filter=FullTransaction/{engine}/Allow",
                        "--benchmark_min_time=1s", "--benchmark_repetitions=1",
                    ],
                    cwd=ROOT,
                    log=result / f"pmu_{engine.lower()}_group_{group_index:02d}.log",
                    csv_path=pmu_path,
                    events=tuple(group.strip("{}").split(",")),
                    env=env,
                )
        pmu_rows = [
            validate_pmu_csv(result / f"pmu_{engine.lower()}.csv")
            for engine in ("LuminaWAF", "ModSecurity", "Coraza")
        ]
        pmu_qualification = {
            "schema": 1,
            "valid": all(row["valid"] for row in pmu_rows),
            "required_minimum_running_percent": 90.0,
            "rows": pmu_rows,
        }
        if not pmu_qualification["valid"]:
            raise RuntimeError("qualified engine PMU evidence is incomplete or multiplexed")
        for kernel in ("InspectPrebuilt", "FullDirect"):
            pmu_path = result / f"overhead_pmu_{kernel.lower()}.csv"
            for group_index, group in enumerate(pmu_groups):
                append = ["--append"] if group_index else []
                execute_pmu_group(
                    [
                        "perf", "stat", "-x,", "-o", str(pmu_path), *append,
                        "-e", group,
                        "taskset", "-c", micro_cpu,
                        str(args.build_dir / "lumina_benchmark_harness"),
                        f"--benchmark_filter=Overhead/LuminaWAF/{kernel}/AllowRotation",
                        "--benchmark_min_time=1s", "--benchmark_repetitions=1",
                    ],
                    cwd=ROOT,
                    log=result / f"overhead_pmu_{kernel.lower()}_group_{group_index:02d}.log",
                    csv_path=pmu_path,
                    events=tuple(group.strip("{}").split(",")),
                    env=env,
                )
        overhead_pmu_rows = [
            validate_pmu_csv(result / f"overhead_pmu_{kernel.lower()}.csv")
            for kernel in ("InspectPrebuilt", "FullDirect")
        ]
        overhead_pmu_qualification = {
            "schema": 1,
            "valid": all(row["valid"] for row in overhead_pmu_rows),
            "required_minimum_running_percent": 90.0,
            "rows": overhead_pmu_rows,
        }
        if not overhead_pmu_qualification["valid"]:
            raise RuntimeError("qualified overhead PMU evidence is incomplete or multiplexed")
        body_pmu_rows = []
        for engine in ("LuminaWAF", "ModSecurity", "Coraza"):
            pmu_path = result / f"body_pmu_{engine.lower()}.csv"
            for group_index, group in enumerate(pmu_groups):
                append = ["--append"] if group_index else []
                execute_pmu_group(
                    [
                        "perf", "stat", "-x,", "-o", str(pmu_path), *append,
                        "-e", group,
                        "taskset", "-c", micro_cpu,
                        str(args.build_dir / "lumina_benchmark_harness"),
                        f"--benchmark_filter=FullTransaction128KiB/{engine}/AllowJSONVaried",
                        "--benchmark_min_time=1s", "--benchmark_repetitions=1",
                    ],
                    cwd=ROOT,
                    log=result / f"body_pmu_{engine.lower()}_group_{group_index:02d}.log",
                    csv_path=pmu_path,
                    events=tuple(group.strip("{}").split(",")),
                    env=env,
                )
            row = validate_pmu_csv(pmu_path)
            row["engine"] = engine.lower()
            row["workload"] = "128 KiB varied JSON allow transaction"
            body_pmu_rows.append(row)
        body_pmu_qualification = {
            "schema": 1,
            "valid": all(row["valid"] for row in body_pmu_rows),
            "required_minimum_running_percent": 90.0,
            "rows": body_pmu_rows,
        }
        if not body_pmu_qualification["valid"]:
            raise RuntimeError("qualified body PMU evidence is incomplete or multiplexed")
    (result / "pmu_qualification.json").write_text(
        json.dumps(pmu_qualification, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (result / "overhead_pmu_qualification.json").write_text(
        json.dumps(overhead_pmu_qualification, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (result / "body_pmu_qualification.json").write_text(
        json.dumps(body_pmu_qualification, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    e2e_base = [
        sys.executable,
        str(HERE / "e2e.py"),
        "--library-path",
        str(args.build_dir),
        "--nginx",
        os.environ.get("LUMINA_BENCH_V1_NGINX", str(DEFAULT_NGINX)),
        "--wrk",
        os.environ.get("LUMINA_BENCH_V1_WRK", shutil.which("wrk") or "wrk"),
        "--wrk2",
        os.environ.get("LUMINA_BENCH_V1_WRK2", shutil.which("wrk2") or "wrk2"),
    ]
    e2e_common = [
        *e2e_base,
        "--server-cpu",
        os.environ.get("LUMINA_BENCH_V1_SERVER_CPU", "1"),
        "--client-cpu",
        os.environ.get("LUMINA_BENCH_V1_CLIENT_CPU", "2"),
        "--max-client-utilization",
        os.environ.get(
            "LUMINA_BENCH_V1_MAX_CLIENT_UTILIZATION",
            str(MAX_SATURATION_CLIENT_UTILIZATION_PERCENT),
        ),
    ]
    e2e_preflight_common = list(e2e_common)
    if publication_data:
        e2e_common.append("--canonical")
    configured_threads = os.environ.get("LUMINA_BENCH_V1_THREADS", "1")
    execute(
        [
            *e2e_preflight_common,
            "--adapter-set", "overhead",
            "--mode", "saturation",
            "--output", str(result / "e2e_execution_preflight"),
            "--duration", "1s",
            "--repetitions", "1",
            "--threads", configured_threads,
            "--connections-sweep", "1",
        ],
        cwd=ROOT, log=result / "e2e_execution_preflight.log", env=env,
    )
    execution_preflight = json.loads(
        (result / "e2e_execution_preflight/results.json").read_text(encoding="utf-8")
    )
    expected_preflight_threads = min(int(configured_threads), 1)
    if (
        not execution_preflight.get("valid")
        or len(execution_preflight.get("results", [])) != 3
        or any(
            int(item.get("client_threads", -1)) != expected_preflight_threads
            for item in execution_preflight.get("results", [])
        )
    ):
        raise RuntimeError("E0/E1/E2 single-connection execution preflight failed")
    phases["execution_preflight"] = "passed"
    repetitions = os.environ.get(
        "LUMINA_BENCH_V1_REPETITIONS", "5" if publication_data else ("1" if args.mode == "smoke" else "3")
    )
    saturation_duration = os.environ.get(
        "LUMINA_BENCH_V1_SATURATION_DURATION", "30s" if publication_data else "2s"
    )
    saturation_sweep = os.environ.get(
        "LUMINA_BENCH_V1_CONNECTION_SWEEP", "1,10,50,100" if publication_data else "1,10"
    )
    execute(
        [
            *e2e_common,
            "--mode", "saturation",
            "--output", str(result / "e2e_saturation"),
            "--duration", saturation_duration,
            "--repetitions", repetitions,
            "--threads", os.environ.get("LUMINA_BENCH_V1_THREADS", "1"),
            "--connections-sweep", saturation_sweep,
        ],
        cwd=ROOT, log=result / "e2e_saturation.log", env=env,
    )
    saturation_results = json.loads(
        (result / "e2e_saturation/results.json").read_text(encoding="utf-8")
    )
    overhead_common = [*e2e_common, "--adapter-set", "overhead"]
    overhead_saturation_duration = os.environ.get(
        "LUMINA_BENCH_V1_OVERHEAD_SATURATION_DURATION",
        "60s" if publication_data else "2s",
    )
    overhead_sweep = os.environ.get(
        "LUMINA_BENCH_V1_OVERHEAD_CONNECTION_SWEEP",
        "1,10,100" if publication_data else "1,10",
    )
    execute(
        [
            *overhead_common,
            "--mode", "saturation",
            "--output", str(result / "overhead_saturation"),
            "--duration", overhead_saturation_duration,
            "--repetitions", repetitions,
            "--threads", os.environ.get("LUMINA_BENCH_V1_THREADS", "1"),
            "--connections-sweep", overhead_sweep,
        ],
        cwd=ROOT,
        log=result / "overhead_saturation.log",
        env=env,
    )
    overhead_saturation = json.loads(
        (result / "overhead_saturation/results.json").read_text(encoding="utf-8")
    )
    overhead_fixed_connections = int(
        os.environ.get("LUMINA_BENCH_V1_OVERHEAD_CONNECTIONS", "10")
    )
    baseline_consistency = baseline_phase_consistency(
        saturation_results,
        overhead_saturation,
        required_connections={overhead_fixed_connections},
        required_runs=5 if publication_data else 1,
        require_stable=publication_data,
    )
    (result / "baseline_phase_consistency.json").write_text(
        json.dumps(baseline_consistency, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    phases["baseline_consistency"] = (
        "passed" if baseline_consistency["valid"]
        else "invalid" if publication_data
        else "diagnostic-inconsistent"
    )
    if publication_data and not baseline_consistency["valid"]:
        raise RuntimeError(
            "plain-NGINX baseline is inconsistent across saturation phases; "
            "see baseline_phase_consistency.json"
        )
    if publication_data:
        sampling_plan = derive_sampling_plan(
            saturation_results,
            target_samples=int(os.environ.get("LUMINA_BENCH_V1_TARGET_SAMPLES", "100000")),
            load_fraction=float(os.environ.get("LUMINA_BENCH_V1_FIXED_LOAD_FRACTION", "0.60")),
            requested_rate=(
                int(os.environ["LUMINA_BENCH_V1_FIXED_RATE"])
                if os.environ.get("LUMINA_BENCH_V1_FIXED_RATE") else None
            ),
            requested_duration=os.environ.get("LUMINA_BENCH_V1_FIXED_DURATION"),
        )
    else:
        fixed_rate_value = int(
            os.environ.get("LUMINA_BENCH_V1_FIXED_RATE", "20" if args.mode == "smoke" else "100")
        )
        fixed_duration_value = os.environ.get(
            "LUMINA_BENCH_V1_FIXED_DURATION", "2s" if args.mode == "smoke" else "30s"
        )
        sampling_plan = {
            "schema": 1,
            "qualified_sampling": False,
            "fixed_rate": fixed_rate_value,
            "fixed_duration_seconds": duration_seconds(fixed_duration_value),
            "target_accepted_per_run": 100_000,
            "projected_accepted_at_requested_rate": (
                fixed_rate_value * duration_seconds(fixed_duration_value)
            ),
            "reason": "diagnostic mode uses a bounded integration sample",
        }
    engine_count = len({item["engine"] for item in saturation_results.get("results", [])})
    point_count = len(saturation_results.get("connection_points", []))
    sampling_plan["repetitions"] = int(repetitions)
    sampling_plan["estimated_e2e_wall_seconds"] = (
        duration_seconds(saturation_duration) * int(repetitions) * engine_count * point_count
        + int(sampling_plan["fixed_duration_seconds"]) * int(repetitions) * engine_count
    )
    (result / "sampling_plan.json").write_text(
        json.dumps(sampling_plan, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    execute(
        [
            *e2e_common,
            "--mode", "fixed",
            "--output", str(result / "e2e_fixed"),
            "--duration", f"{sampling_plan['fixed_duration_seconds']}s",
            "--rate", str(sampling_plan["fixed_rate"]),
            "--repetitions", repetitions,
            "--threads", os.environ.get("LUMINA_BENCH_V1_THREADS", "1"),
            "--connections", os.environ.get("LUMINA_BENCH_V1_CONNECTIONS", "10"),
        ],
        cwd=ROOT, log=result / "e2e_fixed.log", env=env,
    )
    fixed_results = json.loads((result / "e2e_fixed/results.json").read_text(encoding="utf-8"))
    phases["e2e"] = (
        "passed" if fixed_results["valid"] and saturation_results["valid"] else "invalid"
    )

    body_evidence_command = [
        sys.executable,
        str(HERE / "body_evidence.py"),
        "--output", str(result / "body_evidence"),
        "--nginx", os.environ.get("LUMINA_BENCH_V1_NGINX", str(DEFAULT_NGINX)),
        "--wrk", os.environ.get(
            "LUMINA_BENCH_V1_WRK", shutil.which("wrk") or "wrk"
        ),
        "--wrk2", os.environ.get(
            "LUMINA_BENCH_V1_WRK2", shutil.which("wrk2") or "wrk2"
        ),
        "--library-path", str(args.build_dir),
        "--server-cpu", os.environ.get("LUMINA_BENCH_V1_SERVER_CPU", "1"),
        "--client-cpu", os.environ.get("LUMINA_BENCH_V1_CLIENT_CPU", "2"),
        "--threads", configured_threads,
        "--repetitions", repetitions,
        "--saturation-duration", os.environ.get(
            "LUMINA_BENCH_V1_BODY_SATURATION_DURATION",
            "30s" if publication_data else "2s",
        ),
        "--connections-sweep", os.environ.get(
            "LUMINA_BENCH_V1_BODY_CONNECTION_SWEEP",
            "1,10" if publication_data else "1",
        ),
    ]
    if publication_data:
        body_evidence_command.append("--qualified")
    execute(
        body_evidence_command,
        cwd=ROOT,
        log=result / "body_evidence.log",
        env=env,
    )
    body_evidence = json.loads(
        (result / "body_evidence/results.json").read_text(encoding="utf-8")
    )
    phases["body"] = "passed" if body_evidence["valid"] else "invalid"

    scaling_qualification: dict[str, object] = {
        "schema": 1,
        "requested": scaling_requested,
        "valid": False,
        "reason": "multi-worker scaling was not requested",
    }
    if scaling_requested:
        worker_points = tuple(
            int(value) for value in os.environ.get(
                "LUMINA_BENCH_V1_SCALING_WORKERS", "1,2,4,8"
            ).split(",") if value
        )
        scaling_plan = derive_scaling_plan(
            os.environ.get("LUMINA_BENCH_V1_SCALING_SERVER_CPU", ""),
            os.environ.get("LUMINA_BENCH_V1_SCALING_CLIENT_CPU", ""),
            worker_points,
        )
        scaling_plan["duration"] = os.environ.get(
            "LUMINA_BENCH_V1_SCALING_DURATION", "30s"
        )
        scaling_plan["repetitions"] = int(repetitions)
        scaling_plan["connection_sweep"] = os.environ.get(
            "LUMINA_BENCH_V1_SCALING_CONNECTION_SWEEP", "10,50,100,200"
        )
        scaling_plan["max_client_utilization_percent"] = float(
            os.environ.get("LUMINA_BENCH_V1_SCALING_MAX_CLIENT_UTILIZATION", "90")
        )
        scaling_plan["estimated_wall_seconds"] = (
            duration_seconds(str(scaling_plan["duration"]))
            * int(scaling_plan["repetitions"])
            * len(scaling_plan["points"])
            * len(str(scaling_plan["connection_sweep"]).split(","))
            * 5
        )
        scaling_root = result / "e2e_scaling"
        scaling_root.mkdir()
        (scaling_root / "plan.json").write_text(
            json.dumps(scaling_plan, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        point_payloads: list[dict[str, object]] = []
        for point in scaling_plan["points"]:
            workers = int(point["workers"])
            point_dir = scaling_root / f"workers_{workers:02d}"
            execute(
                [
                    *e2e_base,
                    "--canonical",
                    "--mode", "saturation",
                    "--output", str(point_dir),
                    "--duration", str(scaling_plan["duration"]),
                    "--repetitions", repetitions,
                    "--threads", str(point["client_threads"]),
                    "--workers", str(workers),
                    "--server-cpu", str(point["server_cpu"]),
                    "--client-cpu", str(point["client_cpu"]),
                    "--max-client-utilization",
                    str(scaling_plan["max_client_utilization_percent"]),
                    "--connections-sweep", str(scaling_plan["connection_sweep"]),
                ],
                cwd=ROOT,
                log=scaling_root / f"workers_{workers:02d}.log",
                env=env,
            )
            point_payloads.append(
                json.loads((point_dir / "results.json").read_text(encoding="utf-8"))
            )
        scaling_qualification = summarize_scaling(
            point_payloads,
            max_client_utilization_percent=float(
                scaling_plan["max_client_utilization_percent"]
            ),
        )
        scaling_qualification["requested"] = True
        scaling_qualification["plan"] = scaling_plan
        (scaling_root / "results.json").write_text(
            json.dumps(scaling_qualification, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        phases["scaling"] = (
            "passed" if scaling_qualification["valid"] else "invalid"
        )

    if publication_data:
        overhead_calibration = {
            "results": [
                item for item in overhead_saturation.get("results", [])
                if int(item.get("connections", -1)) == overhead_fixed_connections
            ],
            "stability": [
                item for item in overhead_saturation.get("stability", [])
                if int(item.get("connections", -1)) == overhead_fixed_connections
            ],
        }
        overhead_plan = derive_sampling_plan(
            overhead_calibration,
            target_samples=int(os.environ.get("LUMINA_BENCH_V1_OVERHEAD_TARGET_SAMPLES", "100000")),
            load_fraction=float(os.environ.get("LUMINA_BENCH_V1_OVERHEAD_LOAD_FRACTION", "0.60")),
            requested_rate=(
                int(os.environ["LUMINA_BENCH_V1_OVERHEAD_FIXED_RATE"])
                if os.environ.get("LUMINA_BENCH_V1_OVERHEAD_FIXED_RATE") else None
            ),
            requested_duration=os.environ.get("LUMINA_BENCH_V1_OVERHEAD_FIXED_DURATION"),
        )
    else:
        overhead_rate = int(os.environ.get(
            "LUMINA_BENCH_V1_OVERHEAD_FIXED_RATE", "20" if args.mode == "smoke" else "100"
        ))
        overhead_duration = os.environ.get("LUMINA_BENCH_V1_OVERHEAD_FIXED_DURATION", "2s")
        overhead_plan = {
            "schema": 1,
            "qualified_sampling": False,
            "fixed_rate": overhead_rate,
            "fixed_duration_seconds": duration_seconds(overhead_duration),
            "target_accepted_per_run": 100_000,
            "reason": "diagnostic overhead mode uses a bounded integration sample",
        }
    overhead_plan["fixed_connections"] = overhead_fixed_connections
    (result / "overhead_sampling_plan.json").write_text(
        json.dumps(overhead_plan, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    execute(
        [
            *overhead_common,
            "--mode", "fixed",
            "--output", str(result / "overhead_fixed"),
            "--duration", f"{overhead_plan['fixed_duration_seconds']}s",
            "--rate", str(overhead_plan["fixed_rate"]),
            "--repetitions", repetitions,
            "--threads", os.environ.get("LUMINA_BENCH_V1_THREADS", "1"),
            "--connections", str(overhead_fixed_connections),
        ],
        cwd=ROOT, log=result / "overhead_fixed.log", env=env,
    )
    overhead_fixed = json.loads(
        (result / "overhead_fixed/results.json").read_text(encoding="utf-8")
    )
    phases["overhead"] = (
        "passed" if overhead_fixed["valid"] and overhead_saturation["valid"] else "invalid"
    )
    artifact_postflight = validate_artifact_manifest(artifact_manifest)
    (result / "artifact_postflight.json").write_text(
        json.dumps(artifact_postflight, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    phases["artifacts"] = "passed" if artifact_postflight["valid"] else "invalid"
    required_phase_names = (
        "manifest", "artifacts", "micro", "lumina_crs", "coraza_crs",
        "outcome_matrix", "execution_preflight", "e2e", "overhead", "body",
        "baseline_consistency",
    )
    if scaling_requested:
        required_phase_names += ("scaling",)
    engineering_phase_names = (
        required_phase_names if publication_data
        else (
            "manifest", "artifacts", "micro", "outcome_matrix", "e2e",
            "overhead", "body",
        )
    )
    failed_phases = [name for name in engineering_phase_names if phases[name] != "passed"]
    canonical = (
        strict and manifest["canonical"] and bool(micro_qualification["valid"])
        and bool(overhead_micro_qualification["valid"])
        and bool(body_micro_qualification["valid"])
        and bool(pmu_qualification["valid"])
        and bool(overhead_pmu_qualification["valid"])
        and bool(body_pmu_qualification["valid"])
        and bool(artifact_postflight["valid"])
        and fixed_results["valid"] and saturation_results["valid"]
        and overhead_fixed["valid"] and overhead_saturation["valid"]
        and (not scaling_requested or bool(scaling_qualification["valid"]))
        and all(phases[name] == "passed" for name in required_phase_names)
    )
    reason = (
        "all canonical phases passed" if canonical
        else "failed phases: " + ", ".join(failed_phases) if failed_phases
        else "publication-sized evidence without canonical host qualification"
        if args.mode == "qualification" else f"{args.mode} engineering run"
    )
    run_manifest = {
        "schema": 1,
        "protocol": "V1.0",
        "mode": args.mode,
        "canonical": canonical,
        "validity_reason": reason,
        "crs_manifest_sha256": manifest["manifest_sha256"],
        "artifact_manifest_sha256": sha256(result / "artifacts.json"),
        "build_provenance_sha256": sha256(build_provenance_path),
        "artifact_preflight": artifact_preflight,
        "artifact_postflight": artifact_postflight,
        "micro_qualification": micro_qualification,
        "body_micro_qualification": body_micro_qualification,
        "overhead_micro_qualification": overhead_micro_qualification,
        "pmu_qualification": pmu_qualification,
        "body_pmu_qualification": body_pmu_qualification,
        "overhead_pmu_qualification": overhead_pmu_qualification,
        "sampling_plan": sampling_plan,
        "overhead_sampling_plan": overhead_plan,
        "baseline_phase_consistency": baseline_consistency,
        "scaling_qualification": scaling_qualification,
        "phases": phases,
    }
    (result / "run_manifest.json").write_text(
        json.dumps(run_manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (result / "environment_end.json").write_text(
        json.dumps(environment_manifest(), indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    execute(
        [sys.executable, str(HERE / "report.py"), str(result)],
        cwd=ROOT,
        log=result / "report.log",
    )
    if failed_phases:
        raise RuntimeError(
            f"benchmark phases failed ({', '.join(failed_phases)}); "
            f"see {result / 'BENCHMARK_RESULTS.md'}"
        )
    if strict and not canonical:
        raise RuntimeError(f"canonical qualification failed; see {result / 'BENCHMARK_RESULTS.md'}")
    print(result)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as exc:
        print(f"LuminaWAF Benchmark Harness v1 failed: {exc}", file=sys.stderr)
        raise SystemExit(2)
