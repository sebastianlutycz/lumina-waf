# LuminaWAF Benchmark Harness v1

LuminaWAF Benchmark Harness v1 implements the normative V1.0 Protocol for LuminaWAF v0.4. It compares
equivalent outcomes and equivalent request inputs, while preserving the natural
deployment cost of each engine.

## ABB

- **Manifest gate:** freezes the real OWASP CRS tree, ordered includes, PL2
  policy, generated Lumina inventory and workload before measurement, then
  proves ModSecurity and Coraza resolve the identical include/hash sequence.
- **Transaction harness:** Google Benchmark executes a complete inbound request
  transaction for LuminaWAF, ModSecurity and Coraza.
- **E2E harness:** fixed-rate latency and closed-loop saturation are separate
  experiments against isolated NGINX instances.
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
duration.

Smoke reports show Google Benchmark's real inner CV across ten repetitions. Process-level CI stays
`N/A` until at least two independent processes exist, and p99/p99.9 remain withheld until their
sample thresholds are met. Use `qualification` or `canonical` to collect publishable tails.

Set `LUMINA_BENCH_V1_SERVER_CPU`, `LUMINA_BENCH_V1_CLIENT_CPU` and optionally
`LUMINA_BENCH_V1_MICRO_CPU` to the isolated CPU sets prepared for the run. Canonical
mode rejects affinity-only placement when `/sys/devices/system/cpu/isolated`
does not cover every declared benchmark CPU. The client set must be disjoint from both server and
microbenchmark sets, including SMT siblings. Server and microbenchmark sets may overlap because
their phases execute sequentially.

The harness records Lumina's complete `DT_NEEDED` set and rejects legacy `libinjection_*` symbols,
relocations, and comparator/runtime dependencies such as PCRE or ModSecurity before the first
measurement. `artifact_preflight.json` and
`artifact_postflight.json` prove that measured binaries, modules, configurations and build
provenance, including every manifest-owned CRS/data input, did not drift during the run.

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
   require five runs and RPS CV no greater than 5%.
5. **Controlled scaling:** synthetic 1/10/100/1000 rule experiments, isolated
   from all CRS PL2 tables and labeled synthetic.
6. **LuminaWAF overhead decomposition:** E0 plain NGINX, E1 the identical Lumina module with
   `lumina_waf off`, and E2 production CRS PL2 at matching connection points. The report derives
   paired server CPU/request deltas, direct bundle/inspection kernels and an integration residual;
   latency percentiles are absolute context and are never subtracted.

Qualified runs also emit PMU diagnostics for the allow transaction: cycles and instructions per
transaction, IPC, branch-miss rate, generic cache-miss rate, L1D, LLC and iTLB miss rates, and the
minimum counter running percentage. Numerator/denominator pairs execute in separate small atomic
groups; unsupported cache events remain `unavailable` without suppressing IPC or branch metrics.
The `InspectPrebuilt` and `FullDirect` overhead kernels receive the same grouped PMU treatment.

The normative protocol is documented in [methodology/README.md](../../methodology/README.md).
