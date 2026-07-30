# LuminaWAF Benchmark Harness v1

LuminaWAF Benchmark Harness v1 implements the normative V1.0 Protocol for LuminaWAF v0.4. It compares
equivalent outcomes and equivalent request inputs, while preserving the natural
deployment cost of each engine.

## Architecture

- **Manifest gate:** freezes the real OWASP CRS tree, ordered includes, PL2
  policy, generated Lumina inventory and workload before measurement, then
  proves ModSecurity and Coraza resolve the identical include/hash sequence.
- **Transaction harness:** Google Benchmark executes a complete inbound request
  transaction for LuminaWAF, ModSecurity and Coraza.
- **E2E harness:** fixed-rate latency and closed-loop saturation are separate
  experiments against isolated NGINX instances.
- **Multi-worker scaling:** an optional 1/2/4/8-worker publication supplement measures
  throughput scaling with disjoint server/client CPU pools and a client-headroom gate.
- **Overhead decomposition:** paired baseline, loaded-off and PL2 NGINX legs plus direct
  allow-rotation kernels isolate module, adapter and inspection cost without a runtime bypass.
- **Owned SQLi boundary:** LuminaWAF uses its allocation-free scalar LuminaSQLi operator. V1.0 Protocol
  rejects any release library containing a legacy SQL-classifier symbol or relocation.
- **Evidence store:** raw JSON, histograms, logs, hashes and validity decisions
  are retained. Build provenance includes `CMakeCache.txt`, `compile_commands.json`, a verbose clean
  build log and compiler versions. Binary/configuration hashes are captured before measurement and
  revalidated after it.
  The Markdown report is generated only from these artifacts.
- **Report boundary:** NAXSI is reported as a native-WAF comparator, never as a
  CRS-compatible engine.

## One-liner

The supported bootstrap host is Linux on `x86_64` or `aarch64`. It requires a C/C++ build
toolchain, CMake, Autotools, Python 3, Git, Curl, `jq`, `pkg-config`, Perl, Flex, Bison, Patch,
Unzip and Linux `taskset`; the launcher checks these commands before downloading sources.
Distribution development packages required by NGINX and ModSecurity must also be installed.
The benchmark does not modify system packages or install with elevated privileges.

```bash
./bench/benchmark_harness/run.sh smoke
```

This is the repository-owned entry point. On a fresh clone it automatically runs the pinned
bootstrap, initializes the pinned CRS submodule, materializes the BYOR AOT runtime and builds
the pinned NGINX, WAF comparators, `wrk`, `wrk2` and Google Benchmark toolchain. With an existing
cache it refreshes the strict CRS manifest, generated NGINX configs and `env.sh` before every run.
No host-specific path or manual `source` is required. Set
`LUMINA_BENCH_V1_AUTO_BOOTSTRAP=0` only when CI should fail immediately instead of downloading/building
missing pinned dependencies.

The parent repository contains only the CRS Git submodule pointer, never CRS rule/data files or
generated parser C. `tools/verify_release_tree.py` enforces this boundary before every harness run;
the user-triggered bootstrap fetches the pinned test input and keeps all derived AOT files ignored.

The V1.0 canonical performance rotation remains six empty-body HTTP/1.1 GET requests. LuminaWAF
v0.4.2 supports bounded request bodies in the production NGINX adapter, but the existing canonical
rows must not be described as body-ingestion measurements. Body-path publication requires a
separate byte-identical cross-engine workload, repeated E2E evidence and bystander-latency
qualification. The adapter's current protocol evidence covers HTTP/1.1 and HTTP/2; HTTP/3 remains
unclaimed pending a pinned QUIC-capable test build.

Publication runs use:

```bash
./bench/benchmark_harness/run.sh canonical
```

To collect publication-sized evidence on a host that is not yet kernel-isolated, use:

```bash
LUMINA_BENCH_V1_HOST_PROFILE=shared-loaded-homelab \
LUMINA_BENCH_V1_HOST_NOTE='Background services remained active; this is not a canonical host.' \
./bench/benchmark_harness/run.sh qualification
```

This runs the same five-process, five-repetition, full-correctness and sample-volume contract but
always labels the report `NON-CANONICAL`. It is intended to validate the evidence pipeline before
the final isolated run. The environment artifacts and generated report retain the operator note,
start/end load average, CPU pressure, process count, CPU sets, governor and kernel isolation state.
An annotation never upgrades a qualification run to canonical status.

The bootstrap uses exact commits and archive hashes from `pins.json`, installs
into `.cache/benchmark_harness_v1`, and does not replace system libraries.

`canonical` is fail-closed. It requires every pinned comparator, real CRS PL2,
five complete independent Google Benchmark processes, ten retained raw inner
repetitions, kernel-isolated non-SMT-overlapping CPU sets, at least 100,000
accepted responses per fixed-rate repetition, raw percentile data and all
validity gates. `exploratory` may
record unavailable components, but every generated report is marked
`NON-CANONICAL`.

Qualified modes run saturation first. The harness selects a common fixed rate no greater than 60%
of the slowest engine's highest stable point, then computes the fixed-rate duration from the
100,000-response budget, the 90% achieved-rate floor and a 10% safety margin. The immutable choice
is written to `sampling_plan.json`. `LUMINA_BENCH_V1_FIXED_RATE` and `LUMINA_BENCH_V1_FIXED_DURATION` may only
override this plan when they remain below the calibrated rate ceiling and above the required sample
duration. A selected saturation point also requires load-generator utilization no greater than
90%. Before the long fixed-rate phase, the runner compares the plain-NGINX baseline from the main
and overhead sweeps at the same connection point. Publication fails when median RPS differs by more
than 10% or server CPU/request differs by more than 15%.

Smoke reports show Google Benchmark's real inner CV across ten repetitions. Process-level CI stays
`N/A` until at least two independent processes exist, and p99/p99.9 remain withheld until their
sample thresholds are met. Its closed-loop table is a throughput sweep, not a sustainable
saturation claim. A body row with one accepted transaction is labeled as a single observation,
not a percentile. Use `qualification` or `canonical` to collect publishable tails.

Set `LUMINA_BENCH_V1_SERVER_CPU`, `LUMINA_BENCH_V1_CLIENT_CPU` and optionally
`LUMINA_BENCH_V1_MICRO_CPU` to the isolated CPU sets prepared for the run. Canonical
mode rejects affinity-only placement when `/sys/devices/system/cpu/isolated`
does not cover every declared benchmark CPU. The client set must be disjoint from both server and
microbenchmark sets, including SMT siblings. Server and microbenchmark sets may overlap because
their phases execute sequentially. Isolated CPUs need not be present in the launch shell's inherited
affinity mask; the preflight requires them to be online and verifies that `taskset` can enter the
declared sets before measurement.

To include the fail-closed multi-worker supplement in a qualification or canonical run, reserve
an isolated server pool large enough for the largest worker point and a separate client pool:

```bash
LUMINA_BENCH_V1_ENABLE_SCALING=1 \
LUMINA_BENCH_V1_SCALING_SERVER_CPU=4-11 \
LUMINA_BENCH_V1_SCALING_CLIENT_CPU=12-15 \
./bench/benchmark_harness/run.sh canonical
```

The default points are `1,2,4,8`, with five 30-second repetitions at each connection point. Every
point uses the complete client pool and the same client-thread count, records load-generator CPU consumption,
and rejects any selected row whose maximum client utilization exceeds 90%. Every NGINX worker PID
and load-generator worker TID is bound to one recorded CPU and verified after startup. This explicit
per-task binding is required because `isolcpus=domain` disables scheduler load balancing inside a
multi-CPU affinity mask. This section remains separate from the primary single-worker latency and
CPU-efficiency tables. A client-limited plain-NGINX baseline remains visible as `NOT QUALIFIED`,
but it does not invalidate WAF scaling rows; every CRS and native-WAF row remains blocking.

The harness records Lumina's complete `DT_NEEDED` set and rejects legacy `libinjection_*` symbols,
relocations, and comparator/runtime dependencies such as PCRE or ModSecurity before the first
measurement. `artifact_preflight.json` and
`artifact_postflight.json` prove that measured binaries, modules, configurations and build
provenance, including every manifest-owned CRS/data input, did not drift during the run.

For structured request-body diagnostics, generated ModSecurity and Coraza policies use identical
phase-1 XML/JSON processor selectors before the shared CRS includes. The direct 128 KiB JSON rows
run an untimed escaped-value probe that fails unless decoded JSON reaches the inspected
collections. Both the repeated-token and deterministic varied fixtures are byte-identical across
LuminaWAF, ModSecurity and Coraza, and each fixture is built before the measured loop.
ModSecurity's private pinned PCRE2 is built with JIT enabled and records that fact in dependency
provenance; long-body comparator rows are invalid without these gates.

### Request-Body Evidence Status

Request-body behavior currently has four distinct verification boundaries:

1. `tests/integration/test_nginx_request_body.py` validates production NGINX ingestion and
   fail-closed behavior over HTTP/1.1 and HTTP/2, including limits, byte preservation, JSON, XML,
   multipart and unsupported representations. These are functional integration tests, not
   performance measurements.
2. `request_body_complexity_gate` measures LuminaWAF thread CPU for deterministic JSON fixtures
   from 4 KiB through 128 KiB. It checks verdict stability and rejects super-linear growth above
   its adjacent and two-doubling limits. It is a Lumina-only complexity regression gate, not a
   cross-engine comparison.
3. The repository one-liner retains repeated-token and deterministic-varied 128 KiB JSON direct
   transactions for LuminaWAF, ModSecurity and Coraza. Qualified modes require five independent
   processes with ten raw repetitions and grouped PMU evidence for the varied allow fixture.
4. `body_evidence.py` generates exact-size 4, 16 and 128 KiB JSON allow and tail-attack requests.
   Qualified runs calibrate each engine with at least five `30s` repetitions, require RPS CV
   `<=5%`, freeze a plan at no more than 60% of that rate, and then run byte-identical POST
   requests through NGINX. Smoke uses three `5s` calibration repetitions (`10s` for 128 KiB) and
   no more than 40% of their median rate. The fixed response backend runs in the same NGINX
   process, so its CPU remains in server accounting.

The qualified sample contract is:

| Body | Samples per engine per run | Reported percentiles | Evidence class |
|---:|---:|---|---|
| 4 KiB | 10,000 | p50, p90, p99 | body latency |
| 16 KiB | 1,000 | p50, p90 | sample-capped diagnostic |
| 128 KiB | 1,000 LuminaWAF/ModSecurity; 100 Coraza | p50/p90 fast engines; p50 Coraza | time-capped diagnostic |

Every row requires five valid runs, exact expected HTTP outcomes and zero socket errors. p99.9 is
always withheld because this matrix does not collect its 100,000-sample floor. Qualified rates
below `1 RPS` and smoke rates below the `10 RPS` short-run histogram floor switch explicitly to
one closed-loop connection. Body runs use a recorded `30s` request timeout so a slow but completed
comparator transaction is not mislabeled as zero throughput.
Fixed-rate percentile gates use HdrHistogram's recorded `Total count`, not the number of completed
HTTP responses. Missing or empty histograms invalidate the leg.

These E2E percentiles are absolute per-engine observations at normalized load, not same-rate
latency comparisons. Direct CPU/PMU rows remain the appropriate boundary for comparing engine
work on the identical 128 KiB value.
The report marks a row `ANOMALOUS - investigation required` when fixed-rate p50 diverges sharply
from calibration or when an adjacent body-size trend inverts by more than `4x`. Such evidence is
retained for diagnosis and cannot qualify.
For Lumina, the report also exposes per-transaction dispatches, exact-verifier calls and exact
subject bytes for `934100`, `934101` and `934120`. These are logical-work diagnostics, not
per-rule hardware PMU attribution.

Correctness payloads come from the pinned public OWASP CRS/go-ftw suite. The harness records the
CRS commit, selected test IDs and selection hashes but does not vendor CRS rules or test files.
Third-party payload collections may supplement fuzzing; they do not define parity or performance
claims.

## Result Classes

1. **Correctness:** FTW/CRS verdicts, exact rule matches where available,
   false positives and category coverage. Coraza uses pinned go-ftw cloud mode
   without forced outcomes and is reported as HTTP verdict parity because the
   stock NGINX connector does not export matched rule IDs. NAXSI receives a
   separate native-WAF outcome matrix.
2. **Full transaction micro:** complete in-process inbound lifecycle through
   the Google Benchmark harness. This is not an E2E latency claim.
3. **Fixed-rate E2E latency:** allow-only workload using `wrk2`, with raw
   p50/p90/p99/p99.9 distributions and coordinated-omission resistance.
4. **Saturation:** closed-loop maximum sustainable throughput. Queueing latency
   from this mode is never substituted for service latency. Canonical points
   require five runs, RPS CV no greater than 5%, client CPU no greater than 90% and a consistent
   plain-NGINX baseline across the main and overhead phases.
5. **Controlled scaling:** synthetic 1/10/100/1000 rule experiments, isolated
   from all CRS PL2 tables and labeled synthetic.
6. **LuminaWAF overhead decomposition:** E0 plain NGINX, E1 the identical Lumina module with
   `lumina_waf off`, and E2 production CRS PL2 at matching connection points. The report derives
   paired server CPU/request deltas, direct bundle/inspection kernels and an integration residual;
   latency percentiles are absolute context and are never subtracted.
7. **Multi-worker scaling:** optional closed-loop 1/2/4/8-worker throughput, speedup, efficiency,
   RPS/worker, CPU/request and load-generator headroom. It is a deployment-scaling result, not a
   replacement for single-worker latency or direct transaction CPU time.
8. **Request-body evidence:** direct 128 KiB JSON transaction CPU and PMU plus bounded 4/16/128 KiB
   NGINX E2E diagnostics. This section does not relabel the bodyless canonical GET workload.

Qualified runs also emit PMU diagnostics for the allow transaction: cycles and instructions per
transaction, IPC, branch-miss rate, generic cache-miss rate, L1D, LLC and iTLB miss rates, and the
minimum counter running percentage. Numerator/denominator pairs execute in separate small atomic
groups; unsupported cache events remain `unavailable` without suppressing IPC or branch metrics.
The `InspectPrebuilt` and `FullDirect` overhead kernels receive the same grouped PMU treatment.
`BundleBuild`, `InspectPrebuilt` and `FullDirect` run as separate benchmark processes with rotated
boundary order. They are compiler-visible boundaries, not nested function timers, so their
medians are not subtracted from each other.

The manifest also emits `source_rule_inventory.json`, which classifies every inbound PL2 source ID
as generated, runtime-native, control/setup/meta, non-score-bearing or unsupported score-bearing.
No `subsumed` relationship is inferred from rule counts.

The normative protocol is documented in [methodology/README.md](../../methodology/README.md).
