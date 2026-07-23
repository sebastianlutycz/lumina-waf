#!/usr/bin/env python3
"""Sequential, affinity-pinned NGINX E2E runner for LuminaWAF Benchmark Harness v1."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import resource
import shutil
import statistics
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
PREFIX = ROOT / "test_nginx"
DEFAULT_WORKLOAD = HERE / "workloads/requests.json"


@dataclass(frozen=True)
class Adapter:
    name: str
    table: str
    source_config: Path
    original_port: int | None = None


@dataclass(frozen=True)
class LoadRun:
    returncode: int
    stdout: str
    stderr: str
    thread_affinity: list[dict[str, Any]]


def parse_cpu_set(value: str) -> list[int]:
    cpus: set[int] = set()
    for part in value.split(","):
        bounds = part.strip().split("-", 1)
        if not bounds or not bounds[0]:
            continue
        start = int(bounds[0])
        end = int(bounds[1]) if len(bounds) == 2 else start
        if start < 0 or end < start:
            raise RuntimeError(f"invalid CPU set: {value}")
        cpus.update(range(start, end + 1))
    if not cpus:
        raise RuntimeError(f"empty CPU set: {value}")
    return sorted(cpus)


def child_cpu_seconds() -> float:
    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    return usage.ru_utime + usage.ru_stime


def bind_tasks_to_cpus(task_ids: list[int], cpus: list[int], role: str) -> list[dict[str, Any]]:
    if not task_ids:
        raise RuntimeError(f"cannot bind an empty {role} task set")
    if len(task_ids) != len(cpus):
        raise RuntimeError(
            f"{role} tasks ({len(task_ids)}) do not match allocated CPUs ({len(cpus)})"
        )
    mapping: list[dict[str, Any]] = []
    for task_id, cpu in zip(sorted(task_ids), cpus, strict=True):
        os.sched_setaffinity(task_id, {cpu})
        observed = sorted(os.sched_getaffinity(task_id))
        if observed != [cpu]:
            raise RuntimeError(
                f"{role} task {task_id} affinity {observed} does not match CPU {cpu}"
            )
        mapping.append({"task_id": task_id, "cpu": cpu, "role": role})
    return mapping


def process_threads(pid: int) -> list[int]:
    try:
        return sorted(
            int(path.name) for path in Path(f"/proc/{pid}/task").iterdir()
            if path.name.isdigit() and int(path.name) != pid
        )
    except OSError:
        return []


def pin_load_generator_threads(
    process: subprocess.Popen[str], cpus: list[int], expected_threads: int,
) -> list[dict[str, Any]]:
    deadline = time.monotonic() + 5.0
    worker_threads: list[int] = []
    while time.monotonic() < deadline:
        worker_threads = process_threads(process.pid)
        if len(worker_threads) == expected_threads:
            break
        if len(worker_threads) > expected_threads:
            raise RuntimeError(
                f"load generator created {len(worker_threads)} worker threads; "
                f"expected {expected_threads}"
            )
        if process.poll() is not None:
            raise RuntimeError("load generator exited before affinity was assigned")
        time.sleep(0.001)
    if len(worker_threads) != expected_threads:
        raise RuntimeError(
            f"load generator exposed {len(worker_threads)} worker threads; "
            f"expected {expected_threads}"
        )
    os.sched_setaffinity(process.pid, {cpus[0]})
    main_affinity = sorted(os.sched_getaffinity(process.pid))
    if main_affinity != [cpus[0]]:
        raise RuntimeError(
            f"load-generator main task affinity {main_affinity} does not match CPU {cpus[0]}"
        )
    return [
        {"task_id": process.pid, "cpu": cpus[0], "role": "client-main"},
        *bind_tasks_to_cpus(worker_threads, cpus, "client-worker"),
    ]


def prepare_prefix(prefix: Path = PREFIX, workload: Path = DEFAULT_WORKLOAD) -> None:
    """Materialize the ignored NGINX runtime tree and immutable static targets."""
    for relative in (
        "logs",
        "tmp/client_body",
        "tmp/proxy",
        "tmp/fastcgi",
        "tmp/uwsgi",
        "tmp/scgi",
    ):
        (prefix / relative).mkdir(parents=True, exist_ok=True)
    shutil.rmtree(prefix / "html", ignore_errors=True)
    (prefix / "html").mkdir(parents=True)
    html = (prefix / "html").resolve()
    paths = {"/about"}
    payload = json.loads(workload.read_text(encoding="utf-8"))
    paths.update(str(item["path"]) for item in payload.get("requests", []))
    for request_path in paths:
        if not request_path.startswith("/") or request_path.endswith("/"):
            raise RuntimeError(f"workload path is not a static file target: {request_path!r}")
        target = (html / request_path.lstrip("/")).resolve()
        try:
            target.relative_to(html)
        except ValueError as exc:
            raise RuntimeError(f"workload path escapes static root: {request_path!r}") from exc
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b"OK")


def required_config(variable: str) -> Path:
    value = os.environ.get(variable)
    if not value:
        raise RuntimeError(
            f"{variable} is required; launch the benchmark through "
            "bench/benchmark_harness/run.sh"
        )
    return Path(value).resolve()


def adapters(include_optional: bool, adapter_set: str = "all") -> list[Adapter]:
    if adapter_set == "overhead":
        return [
            Adapter("baseline", "diagnostic", required_config(
                "LUMINA_BENCH_V1_BASELINE_NGINX_CONFIG"), 8090),
            Adapter("luminawaf-loaded-off", "diagnostic", required_config(
                "LUMINA_BENCH_V1_LUMINA_OFF_NGINX_CONFIG"), 8081),
            Adapter("luminawaf", "diagnostic", required_config(
                "LUMINA_BENCH_V1_LUMINA_NGINX_CONFIG"), 8081),
        ]
    values = [
        Adapter("baseline", "baseline", required_config(
            "LUMINA_BENCH_V1_BASELINE_NGINX_CONFIG"), 8090),
        Adapter("luminawaf", "crs", required_config(
            "LUMINA_BENCH_V1_LUMINA_NGINX_CONFIG"), 8081),
        Adapter("modsecurity", "crs", required_config(
            "LUMINA_BENCH_V1_MODSEC_NGINX_CONFIG"), 8082),
    ]
    optional = (
        ("coraza", "crs", "LUMINA_BENCH_V1_CORAZA_NGINX_CONFIG"),
        ("naxsi", "native-waf", "LUMINA_BENCH_V1_NAXSI_NGINX_CONFIG"),
    )
    for name, table, variable in optional:
        configured = os.environ.get(variable)
        if configured:
            values.append(Adapter(name, table, Path(configured).resolve()))
        elif include_optional:
            raise RuntimeError(f"canonical mode requires {variable}")
    return values


def render_config(adapter: Adapter, destination: Path, port: int, workers: int,
                  workload: Path = DEFAULT_WORKLOAD) -> None:
    prepare_prefix(PREFIX, workload)
    text = adapter.source_config.read_text(encoding="utf-8")
    text, listen_count = re.subn(r"\blisten\s+\d+\s*;", f"listen {port};", text, count=1)
    if listen_count != 1:
        raise RuntimeError(f"{adapter.name}: cannot replace listen directive")
    text, worker_count = re.subn(
        r"^worker_processes\s+[^;]+;", f"worker_processes {workers};", text,
        count=1, flags=re.MULTILINE,
    )
    if worker_count != 1:
        raise RuntimeError(f"{adapter.name}: cannot replace worker_processes")
    text, fallback_count = re.subn(
        r"try_files\s+[^;]+;", "try_files $uri =404;", text, count=1
    )
    if fallback_count != 1:
        raise RuntimeError(f"{adapter.name}: cannot normalize static response fallback")
    pid = PREFIX / "logs" / f"benchmark_harness_v1_{adapter.name}_{port}.pid"
    text, pid_count = re.subn(r"^pid\s+[^;]+;", f"pid {pid};", text, count=1, flags=re.MULTILINE)
    if pid_count == 0:
        text = f"pid {pid};\n" + text
    destination.write_text(text, encoding="utf-8")


def normalized_config_sha256(path: Path) -> str:
    text = path.read_text(encoding="utf-8")
    text = re.sub(r"^pid\s+[^;]+;", "pid <INSTANCE>;", text, flags=re.MULTILINE)
    text = re.sub(r"\blisten\s+\d+\s*;", "listen <PORT>;", text, count=1)
    text = re.sub(r"\blumina_waf\s+(?:on|off)\s*;", "lumina_waf <ENABLE>;", text)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def parse_duration_seconds(value: str) -> float:
    match = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)([smh])", value)
    if not match:
        raise ValueError(f"invalid duration: {value}")
    scale = {"s": 1.0, "m": 60.0, "h": 3600.0}[match.group(2)]
    return float(match.group(1)) * scale


def latency_us(value: str) -> float:
    match = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)(us|ms|s)", value)
    if not match:
        raise ValueError(f"invalid latency: {value}")
    scale = {"us": 1.0, "ms": 1000.0, "s": 1_000_000.0}[match.group(2)]
    return float(match.group(1)) * scale


def parse_wrk(text: str, requested_rate: int | None, min_samples: int) -> dict[str, Any]:
    percentiles: dict[str, float] = {}
    wanted = {
        "50.000": "p50", "90.000": "p90", "99.000": "p99",
        "99.900": "p99_9", "100.000": "max",
    }
    for percentile, latency in re.findall(r"^\s*([0-9]+\.[0-9]+)%\s+([0-9.]+(?:us|ms|s))\s*$", text, re.MULTILINE):
        if percentile in wanted and wanted[percentile] not in percentiles:
            percentiles[wanted[percentile]] = latency_us(latency)
    requests_match = re.search(r"\b([0-9]+) requests in\b", text)
    rate_match = re.search(r"^Requests/sec:\s*([0-9.]+)", text, re.MULTILINE)
    errors_match = re.search(r"Non-2xx or 3xx responses:\s*([0-9]+)", text)
    socket_line = re.search(r"^\s*Socket errors:\s*(.+)$", text, re.MULTILINE)
    socket_error_breakdown = {
        name: int(value)
        for name, value in re.findall(
            r"\b(connect|read|write|timeout)\s+([0-9]+)\b",
            socket_line.group(1) if socket_line else "",
        )
    }
    socket_errors = sum(socket_error_breakdown.values())
    total = int(requests_match.group(1)) if requests_match else 0
    errors = int(errors_match.group(1)) if errors_match else 0
    accepted = max(0, total - errors)
    achieved = float(rate_match.group(1)) if rate_match else 0.0
    reasons: list[str] = []
    if errors:
        reasons.append(f"non-success responses={errors}")
    if socket_line and len(socket_error_breakdown) != 4:
        reasons.append("unparsed socket error counters")
    if socket_errors:
        reasons.append(f"socket errors={socket_errors}")
    if requested_rate is not None and achieved < requested_rate * 0.90:
        reasons.append(f"achieved rate {achieved:.2f} < 90% of {requested_rate}")
    if requested_rate is not None and accepted < min_samples:
        reasons.append(f"accepted samples {accepted} < {min_samples}")
    required_percentiles = {"p50", "p90", "p99", "p99_9"}
    if requested_rate is not None and not required_percentiles <= set(percentiles):
        reasons.append("missing required raw percentiles")
    return {
        "requests": total,
        "accepted_requests": accepted,
        "non_success": errors,
        "socket_errors": socket_errors,
        "socket_error_breakdown": socket_error_breakdown,
        "requests_per_second": achieved,
        "latency_us": percentiles,
        "valid": not reasons,
        "invalid_reasons": reasons,
    }


SATURATION_OVERLOAD_REASON_PREFIXES = (
    "non-success responses=",
    "socket errors=",
)


def evaluate_measurement_validity(
    *,
    mode: str,
    canonical: bool,
    adapter_set: str,
    results: list[dict[str, Any]],
    stability: list[dict[str, Any]],
    identity_errors: list[str],
    engine_names: list[str],
    expected_results: int,
) -> dict[str, Any]:
    overload_invalid: list[dict[str, Any]] = []
    infrastructure_invalid: list[dict[str, Any]] = []
    for item in results:
        if item.get("valid"):
            continue
        reasons = item.get("invalid_reasons", [])
        overload_only = (
            mode == "saturation"
            and bool(reasons)
            and all(
                reason.startswith(SATURATION_OVERLOAD_REASON_PREFIXES)
                for reason in reasons
            )
        )
        (overload_invalid if overload_only else infrastructure_invalid).append(item)

    coverage_valid = bool(results) and len(results) == expected_results
    base_valid = coverage_valid and all(item.get("valid") for item in results)
    stable_engines = {item["engine"] for item in stability if item.get("stable")}
    stability_valid = (
        bool(stability) and all(item.get("stable") for item in stability)
        if adapter_set == "overhead"
        else all(engine in stable_engines for engine in engine_names)
    )
    if canonical and mode == "saturation" and adapter_set != "overhead":
        valid = (
            coverage_valid
            and not infrastructure_invalid
            and not identity_errors
            and stability_valid
        )
    else:
        valid = (
            base_valid
            and not identity_errors
            and (stability_valid if canonical else True)
        )

    def summarize(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [
            {
                "engine": item.get("engine"),
                "connections": item.get("connections"),
                "repetition": item.get("repetition"),
                "raw": item.get("raw"),
                "invalid_reasons": item.get("invalid_reasons", []),
            }
            for item in items
        ]

    return {
        "valid": valid,
        "coverage_valid": coverage_valid,
        "expected_results": expected_results,
        "observed_results": len(results),
        "stability_valid": stability_valid,
        "overload_invalid_legs": summarize(overload_invalid),
        "infrastructure_invalid_legs": summarize(infrastructure_invalid),
    }


class NginxLeg:
    def __init__(self, nginx: Path, config: Path, port: int, server_cpu: str, library_path: str):
        self.nginx = nginx
        self.config = config
        self.port = port
        self.server_cpu = server_cpu
        self.server_cpus = parse_cpu_set(server_cpu)
        config_text = config.read_text(encoding="utf-8")
        worker_match = re.search(r"^worker_processes\s+([0-9]+);", config_text, re.MULTILINE)
        if not worker_match:
            raise RuntimeError("rendered NGINX config has no numeric worker_processes value")
        self.workers = int(worker_match.group(1))
        if self.workers > len(self.server_cpus):
            raise RuntimeError("NGINX workers exceed the server CPU allocation")
        self.worker_affinity: list[dict[str, Any]] = []
        pid_match = re.search(r"^pid\s+([^;]+);", config_text, re.MULTILINE)
        if not pid_match:
            raise RuntimeError("rendered NGINX config has no pid path")
        self.pid_file = Path(pid_match.group(1))
        self.env = os.environ.copy()
        self.env["LD_LIBRARY_PATH"] = library_path + ":" + self.env.get("LD_LIBRARY_PATH", "")

    def command(self, *args: str) -> list[str]:
        return [str(self.nginx), *args, "-c", str(self.config), "-p", str(PREFIX)]

    def preflight(self) -> None:
        process = subprocess.run(
            self.command("-t"), env=self.env, capture_output=True, text=True
        )
        if process.returncode != 0:
            detail = (process.stderr or process.stdout).strip()
            raise RuntimeError(
                f"NGINX preflight failed for {self.config}: {detail or 'no diagnostic output'}"
            )

    def start(self) -> None:
        subprocess.run(
            ["taskset", "-c", self.server_cpu, *self.command()], env=self.env,
            check=True, capture_output=True, text=True,
        )
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            try:
                master = int(self.pid_file.read_text(encoding="ascii").strip())
                children = Path(f"/proc/{master}/task/{master}/children")
                workers = [
                    int(value) for value in children.read_text(encoding="ascii").split()
                ]
            except (OSError, ValueError):
                workers = []
            if len(workers) == self.workers:
                self.worker_affinity = bind_tasks_to_cpus(
                    workers, self.server_cpus[:self.workers], "nginx-worker"
                )
                break
            if len(workers) > self.workers:
                raise RuntimeError(
                    f"NGINX exposed {len(workers)} direct children; expected {self.workers}"
                )
            time.sleep(0.01)
        if len(self.worker_affinity) != self.workers:
            raise RuntimeError(
                f"NGINX exposed {len(self.worker_affinity)} workers; expected {self.workers}"
            )
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            try:
                request = urllib.request.Request(
                    f"http://127.0.0.1:{self.port}/about?id=1",
                    headers={"Host": "benchmark.local", "User-Agent": "LuminaIronBenchmark/10"},
                )
                with urllib.request.urlopen(request, timeout=0.5) as response:
                    if 200 <= response.status < 400:
                        return
            except (OSError, urllib.error.URLError):
                time.sleep(0.1)
        raise RuntimeError("NGINX readiness probe failed")

    def stop(self) -> None:
        subprocess.run(self.command("-s", "stop"), env=self.env, capture_output=True, text=True)
        time.sleep(0.5)

    def cpu_seconds(self) -> float:
        if not self.pid_file.exists():
            return 0.0
        try:
            master = int(self.pid_file.read_text(encoding="ascii").strip())
        except (OSError, ValueError):
            return 0.0
        pids = [master]
        children = Path(f"/proc/{master}/task/{master}/children")
        try:
            pids.extend(int(value) for value in children.read_text(encoding="ascii").split())
        except (OSError, ValueError):
            pass
        ticks = 0
        for pid in pids:
            try:
                fields = Path(f"/proc/{pid}/stat").read_text(encoding="ascii").split()
                ticks += int(fields[13]) + int(fields[14])
            except (OSError, ValueError, IndexError):
                continue
        return ticks / os.sysconf("SC_CLK_TCK")


def run_wrk(binary: Path, client_cpu: str, port: int, duration: str, threads: int,
            connections: int, rate: int | None, script: Path) -> LoadRun:
    client_cpus = parse_cpu_set(client_cpu)
    if threads < 1:
        raise RuntimeError("load-generator threads must be positive")
    if threads > len(client_cpus):
        raise RuntimeError("load-generator threads exceed the client CPU allocation")
    if connections < threads:
        raise RuntimeError(
            f"load-generator connections ({connections}) must be >= threads ({threads})"
        )
    assigned_cpus = client_cpus[:threads]
    command = [
        "taskset", "-c", client_cpu, str(binary), f"-t{threads}", f"-c{connections}",
        f"-d{duration}", "-L", "-s", str(script),
    ]
    if rate is not None:
        command.append(f"-R{rate}")
    command.append(f"http://127.0.0.1:{port}")
    process = subprocess.Popen(
        command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    try:
        affinity = pin_load_generator_threads(process, assigned_cpus, threads)
        stdout, stderr = process.communicate()
    except BaseException as error:
        if process.poll() is None:
            process.terminate()
        stdout, stderr = process.communicate()
        if isinstance(error, RuntimeError):
            detail = (stderr or stdout).strip().replace("\n", " ")
            suffix = f"; output={detail}" if detail else ""
            raise RuntimeError(
                f"{error}; exit={process.returncode}{suffix}"
            ) from error
        raise
    return LoadRun(process.returncode, stdout, stderr, affinity)


def effective_load_threads(configured_threads: int, connections: int) -> int:
    if configured_threads < 1:
        raise RuntimeError("load-generator threads must be positive")
    if connections < 1:
        raise RuntimeError("load-generator connections must be positive")
    return min(configured_threads, connections)


def write_wrk_script(workload: Path, destination: Path) -> int:
    raw = json.loads(workload.read_text(encoding="utf-8"))
    requests = [item for item in raw.get("requests", []) if item.get("class") == "allow"]
    if not requests:
        raise RuntimeError("workload has no predeclared allow requests")
    rows: list[str] = []
    for item in requests:
        query = item.get("query", "")
        target = item["path"] + (("?" + query) if query else "")
        header_names = [str(name).lower() for name, _ in item.get("headers", [])]
        if header_names.count("host") != 1:
            raise RuntimeError(
                f"allow request {item.get('id', '<unknown>')} must declare exactly one Host header"
            )
        headers = ", ".join(
            f"[{json.dumps(str(name))}]={json.dumps(str(value))}"
            for name, value in item.get("headers", [])
        )
        body = str(item.get("body", ""))
        lua_body = "nil" if body == "" else json.dumps(body)
        rows.append(
            "  {method=" + json.dumps(item.get("method", "GET"))
            + ", target=" + json.dumps(target)
            + ", body=" + lua_body
            + ", headers={" + headers + "}}"
        )
    destination.write_text(
        "local requests = {\n" + ",\n".join(rows) + "\n}\n"
        "local index = 0\n"
        "request = function()\n"
        "  index = (index % #requests) + 1\n"
        "  local r = requests[index]\n"
        "  return wrk.format(r.method, r.target, r.headers, r.body)\n"
        "end\n",
        encoding="utf-8",
    )
    return len(requests)


def probe_allow_responses(workload: Path, port: int) -> dict[str, dict[str, Any]]:
    payload = json.loads(workload.read_text(encoding="utf-8"))
    contract: dict[str, dict[str, Any]] = {}
    for item in payload.get("requests", []):
        if item.get("class") != "allow":
            continue
        query = str(item.get("query", ""))
        target = str(item["path"]) + (("?" + query) if query else "")
        body = str(item.get("body", "")).encode("utf-8")
        request = urllib.request.Request(
            f"http://127.0.0.1:{port}{target}",
            data=body if body else None,
            headers={str(name): str(value) for name, value in item.get("headers", [])},
            method=str(item.get("method", "GET")),
        )
        try:
            with urllib.request.urlopen(request, timeout=2.0) as response:
                response_body = response.read()
                status = response.status
        except urllib.error.HTTPError as error:
            response_body = error.read()
            status = error.code
        contract[str(item["id"])] = {
            "status": status,
            "body_sha256": hashlib.sha256(response_body).hexdigest(),
        }
    return contract


def rotated_order(items: list[Adapter], repetition: int) -> list[Adapter]:
    offset = repetition % len(items)
    order = items[offset:] + items[:offset]
    if (repetition // len(items)) % 2:
        order = list(reversed(order))
    return order


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("fixed", "saturation"), required=True)
    parser.add_argument("--adapter-set", choices=("all", "overhead"), default="all")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--canonical", action="store_true")
    parser.add_argument("--nginx", type=Path, default=Path(os.environ.get("LUMINA_BENCH_V1_NGINX", "nginx")))
    parser.add_argument("--wrk2", type=Path, default=Path(
        os.environ.get("LUMINA_BENCH_V1_WRK2", shutil.which("wrk2") or "wrk2")
    ))
    parser.add_argument("--wrk", type=Path, default=Path(
        os.environ.get("LUMINA_BENCH_V1_WRK", shutil.which("wrk") or "wrk")
    ))
    parser.add_argument("--duration", default="2s")
    parser.add_argument("--warmup-duration", default="1s")
    parser.add_argument("--rate", type=int, default=50)
    parser.add_argument("--repetitions", type=int, default=1)
    parser.add_argument("--threads", type=int, default=1)
    parser.add_argument("--connections", type=int, default=10)
    parser.add_argument("--connections-sweep", default="1,10,50,100")
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--server-cpu", default="1")
    parser.add_argument("--client-cpu", default="2")
    parser.add_argument("--port", type=int, default=19090)
    parser.add_argument("--library-path", default=str(ROOT / "build"))
    parser.add_argument("--workload", type=Path, default=DEFAULT_WORKLOAD)
    args = parser.parse_args()

    engines = adapters(args.canonical, args.adapter_set)
    binary = args.wrk2 if args.mode == "fixed" else args.wrk
    if not args.nginx.is_file() or not os.access(args.nginx, os.X_OK):
        raise RuntimeError(f"missing NGINX binary: {args.nginx}")
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise RuntimeError(f"missing load generator: {binary}")
    server_cpus = parse_cpu_set(args.server_cpu)
    client_cpus = parse_cpu_set(args.client_cpu)
    if set(server_cpus) & set(client_cpus):
        raise RuntimeError("server and load-generator CPU sets must be disjoint")
    if args.workers > len(server_cpus):
        raise RuntimeError("NGINX workers exceed the server CPU allocation")
    if args.threads < 1:
        raise RuntimeError("load-generator threads must be positive")
    if args.threads > len(client_cpus):
        raise RuntimeError("load-generator threads exceed the client CPU allocation")
    if args.canonical and args.repetitions < 5:
        raise RuntimeError("canonical mode requires at least five independent repetitions")
    if parse_duration_seconds(args.warmup_duration) <= 0.0:
        raise RuntimeError("warmup duration must be positive")

    args.output.mkdir(parents=True, exist_ok=False)
    wrk_script = args.output / "allow_workload.lua"
    workload_requests = write_wrk_script(args.workload, wrk_script)
    workload_sha256 = hashlib.sha256(args.workload.read_bytes()).hexdigest()
    min_samples = 100_000 if args.canonical else 0
    connection_points = (
        [args.connections]
        if args.mode == "fixed"
        else [int(value) for value in args.connections_sweep.split(",") if value]
    )
    if not connection_points or any(value < 1 for value in connection_points):
        raise RuntimeError("connection sweep must contain positive integers")
    results: list[dict[str, Any]] = []
    expected_response_contract: dict[str, dict[str, Any]] | None = None
    for repetition in range(args.repetitions):
        for connections in connection_points:
            client_threads = effective_load_threads(args.threads, connections)
            for adapter in rotated_order(engines, repetition):
                config = args.output / f"nginx_{adapter.name}_{repetition}_{connections}.conf"
                render_config(adapter, config, args.port, args.workers, args.workload)
                leg = NginxLeg(args.nginx, config, args.port, args.server_cpu, args.library_path)
                raw_path = args.output / f"{args.mode}_{repetition:02d}_{connections}_{adapter.name}.txt"
                try:
                    leg.preflight()
                    leg.start()
                    response_contract = probe_allow_responses(args.workload, args.port)
                    contract_errors = [
                        f"allow response {request_id} status={value['status']}"
                        for request_id, value in response_contract.items()
                        if not 200 <= int(value["status"]) < 400
                    ]
                    if expected_response_contract is None:
                        expected_response_contract = response_contract
                    elif response_contract != expected_response_contract:
                        contract_errors.append("allow response status/body hash differs across adapters")
                    warmup_raw = None
                    warmup_client_thread_affinity = None
                    if args.mode == "fixed":
                        warmup_path = args.output / (
                            f"warmup_{repetition:02d}_{connections}_{adapter.name}.txt"
                        )
                        warmup = run_wrk(
                            binary, args.client_cpu, args.port, args.warmup_duration,
                            client_threads, connections, args.rate, wrk_script,
                        )
                        warmup_path.write_text(
                            warmup.stdout + warmup.stderr, encoding="utf-8"
                        )
                        warmup_raw = warmup_path.name
                        warmup_client_thread_affinity = warmup.thread_affinity
                        if warmup.returncode != 0:
                            contract_errors.append(
                                f"fixed-rate warmup exit={warmup.returncode}"
                            )
                    cpu_before = leg.cpu_seconds()
                    client_cpu_before = child_cpu_seconds()
                    process = run_wrk(
                        binary, args.client_cpu, args.port, args.duration, client_threads,
                        connections, args.rate if args.mode == "fixed" else None, wrk_script,
                    )
                    client_cpu_seconds = max(0.0, child_cpu_seconds() - client_cpu_before)
                    raw = process.stdout + process.stderr
                    cpu_after = leg.cpu_seconds()
                    raw_path.write_text(raw, encoding="utf-8")
                    parsed = parse_wrk(raw, args.rate if args.mode == "fixed" else None, min_samples)
                    if process.returncode != 0:
                        parsed["valid"] = False
                        parsed["invalid_reasons"].append(f"load generator exit={process.returncode}")
                    if contract_errors:
                        parsed["valid"] = False
                        parsed["invalid_reasons"].extend(contract_errors)
                    parsed.update(
                        {
                            "engine": adapter.name,
                            "table": adapter.table,
                            "repetition": repetition,
                            "round_id": f"{args.adapter_set}-r{repetition:02d}-c{connections}",
                            "connections": connections,
                            "server_cpu": args.server_cpu,
                            "client_cpu": args.client_cpu,
                            "workers": args.workers,
                            "client_threads": client_threads,
                            "configured_client_threads": args.threads,
                            "server_cpu_count": len(server_cpus),
                            "client_cpu_count": len(client_cpus),
                            "client_cpu_seconds": client_cpu_seconds,
                            "nginx_worker_affinity": leg.worker_affinity,
                            "client_thread_affinity": process.thread_affinity,
                            "warmup_client_thread_affinity": warmup_client_thread_affinity,
                            "client_cpu_utilization_percent": (
                                client_cpu_seconds
                                / (parse_duration_seconds(args.duration) * len(client_cpus))
                                * 100.0
                            ),
                            "server_cpu_seconds": max(0.0, cpu_after - cpu_before),
                            "server_cpu_accounting": {
                                "source": "/proc/<nginx-master-or-worker>/stat",
                                "fields": "utime+stime",
                                "process_scope": "nginx master plus direct workers",
                                "load_generator_included": False,
                                "clock_ticks_per_second": os.sysconf("SC_CLK_TCK"),
                            },
                            "server_cpu_ns_per_request": (
                                max(0.0, cpu_after - cpu_before) * 1_000_000_000
                                / parsed["requests"] if parsed["requests"] else None
                            ),
                            "order": [item.name for item in rotated_order(engines, repetition)],
                            "raw": raw_path.name,
                            "warmup_raw": warmup_raw,
                            "config_sha256": subprocess.check_output(
                                ["sha256sum", str(config)], text=True
                            ).split()[0],
                            "normalized_config_sha256": normalized_config_sha256(config),
                            "workload_sha256": workload_sha256,
                            "allow_response_contract": response_contract,
                            "allow_response_contract_sha256": hashlib.sha256(
                                json.dumps(response_contract, sort_keys=True).encode("utf-8")
                            ).hexdigest(),
                        }
                    )
                    results.append(parsed)
                finally:
                    leg.stop()
                time.sleep(1.0)

    stability: list[dict[str, Any]] = []
    for adapter in engines:
        for connections in connection_points:
            samples = [
                item["requests_per_second"]
                for item in results
                if item["engine"] == adapter.name
                and item["connections"] == connections
                and item["valid"]
            ]
            mean = statistics.mean(samples) if samples else 0.0
            cv = (
                statistics.stdev(samples) / mean * 100.0
                if len(samples) > 1 and mean > 0.0
                else None
            )
            required_runs = 5
            stable = len(samples) >= required_runs and cv is not None and cv <= 5.0
            stability.append(
                {
                    "engine": adapter.name,
                    "connections": connections,
                    "valid_runs": len(samples),
                    "median_rps": statistics.median(samples) if samples else 0.0,
                    "cv_percent": cv,
                    "diagnostic_available": len(samples) >= 1,
                    "stable": stable,
                    "sustainable": args.mode == "saturation" and stable,
                }
            )
    identity_errors: list[str] = []
    if args.adapter_set == "overhead":
        grouped: dict[tuple[int, int], dict[str, dict[str, Any]]] = {}
        for item in results:
            grouped.setdefault((item["repetition"], item["connections"]), {})[
                item["engine"]
            ] = item
        required = {"baseline", "luminawaf-loaded-off", "luminawaf"}
        for key, group in grouped.items():
            if set(group) != required:
                identity_errors.append(f"round {key} has adapters {sorted(group)}")
                continue
            if (group["luminawaf-loaded-off"]["normalized_config_sha256"]
                    != group["luminawaf"]["normalized_config_sha256"]):
                identity_errors.append(f"round {key} Lumina enabled/off config identity differs")
    validity = evaluate_measurement_validity(
        mode=args.mode,
        canonical=args.canonical,
        adapter_set=args.adapter_set,
        results=results,
        stability=stability,
        identity_errors=identity_errors,
        engine_names=[adapter.name for adapter in engines],
        expected_results=len(engines) * len(connection_points) * args.repetitions,
    )
    payload = {
        "schema": 1,
        "mode": args.mode,
        "adapter_set": args.adapter_set,
        "canonical_requested": args.canonical,
        "duration": args.duration,
        "warmup_duration": args.warmup_duration if args.mode == "fixed" else None,
        "requested_rate": args.rate if args.mode == "fixed" else None,
        "server_cpu": args.server_cpu,
        "client_cpu": args.client_cpu,
        "workers": args.workers,
        "client_threads": args.threads,
        "client_thread_policy": "min(configured_threads, connections)",
        "server_cpu_count": len(server_cpus),
        "client_cpu_count": len(client_cpus),
        "connection_points": connection_points,
        "workload": str(args.workload.resolve()),
        "workload_sha256": workload_sha256,
        "workload_allow_requests": workload_requests,
        "results": results,
        "stability": stability,
        "identity_errors": identity_errors,
        **validity,
    }
    (args.output / "results.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(args.output / "results.json")
    if args.canonical and not payload["valid"]:
        return 2
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as exc:
        print(f"E2E failed: {exc}")
        raise SystemExit(2)
