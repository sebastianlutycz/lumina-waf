# LuminaWAF Benchmark Methodology

This document defines the normative **V1.0 Protocol** implemented by LuminaWAF Benchmark Harness
v1 for the LuminaWAF `v0.4.x` release line. Historical synthetic parser experiments are not part
of this contract.

## Claim Boundary

V1.0 Protocol answers four separate questions:

1. Does each CRS-capable engine produce the required inbound PL2 security outcome?
2. What is the CPU cost of a complete inbound transaction through each engine ABI?
3. What latency and throughput does the complete NGINX deployment deliver?
4. When requested, how does closed-loop throughput scale across 1/2/4/8 NGINX workers?

These measurements are not interchangeable. Direct transaction CPU time is not NGINX latency,
and saturation throughput is not fixed-rate service latency.

LuminaWAF, ModSecurity and Coraza enter the CRS table only when they consume the same pinned CRS
tree, ordered inbound includes, PL2 policy and anomaly threshold `5`. NAXSI is reported separately
as a native-WAF reference because it does not execute OWASP CRS. Synthetic rule scaling never
supports a CRS compatibility or production performance claim.

## CRS PL2 Compatibility Contract

LuminaWAF may be described as compatible with the pinned inbound CRS PL2 profile only after the
manifest and correctness gates pass. The claim means that the translator and runtime implement the
`SecRule`/`SecAction`, collection, chain, transform and operator semantics exercised by that pinned
profile to at least the declared release threshold.

It does not mean that LuminaWAF is a general ModSecurity configuration interpreter. Unsupported
directives or semantics outside the pinned profile are not covered by the compatibility claim.
Release reports must state the CRS commit, manifest hash, evaluated test count, exact-rule parity,
negative exclusions, skips, disagreements, timeouts and exceptions. The release threshold is
`>=99.70%` overall parity with zero timeout and exception failures.

Coraza uses final HTTP verdict parity because the stock coraza-nginx/libcoraza connector does not
expose non-disruptive matched-rule IDs. LuminaWAF and ModSecurity retain exact matched-rule evidence.

## Immutable Evidence

Before the build, `manifest.py` records and hashes:

- CRS origin, exact commit and tracked-worktree state;
- ordered `Include` graph and every included `.conf` file;
- all CRS `.data` resources in the pinned rule tree;
- blocking and detection paranoia levels and inbound anomaly threshold;
- independently parsed inbound phase 1/2 PL2 source-rule inventory;
- Lumina generated manifest and native runtime-covered inventory;
- immutable request workload;
- ModSecurity and Coraza policy configurations.

After the release build and before the first timed process, `run.py` writes:

- `build_provenance.json` with the exact configure/build commands, CMake version, selected C and
  C++ compilers, compiler versions, build type and build-related environment flags;
- retained `CMakeCache.txt`, `compile_commands.json` and verbose clean-build log, which together
  contain the effective regular-target and custom AOT compile commands;
- `artifacts.json` with paths, sizes and SHA256 values for the benchmark executable, Lumina library,
  NGINX binary, WAF modules, comparator configurations and retained provenance files;
- `symbol_isolation.json` with legacy SQL-classifier symbol/relocation results and the complete
  Lumina `DT_NEEDED` set.

`artifact_preflight.json` validates these hashes, every included CRS/data input and the generated
Lumina manifest before measurement. `artifact_postflight.json` revalidates the same files after all
measurement phases. Any disappearance, size change or SHA256 drift invalidates the run.

The ModSecurity and Coraza configurations are generated from one ordered include graph. Canonical
mode requires identical resolved path and SHA256 sequences. External rule-removal or rule-update
directives invalidate the comparator configuration; controls shipped inside the hashed CRS tree are
retained as native CRS semantics.

Canonical mode fails closed on a missing comparator, hash drift, dirty input tree, policy drift,
incorrect response, stale artifact, insufficient samples or missing raw evidence.

## Result Classes

### Full Transaction CPU Time

Google Benchmark executes one complete inbound lifecycle per iteration:

- LuminaWAF receives typed request collections and fresh request-local state;
- ModSecurity receives a fresh transaction and follows the connector order: connection, URI,
  request headers and request body, with an intervention check after every phase;
- Coraza receives the equivalent phase order and intervention cadence through the pinned
  libcoraza ABI.

Immutable request storage and engine configuration stay outside the timed loop. Transaction-local
work remains inside because it is part of the engine cost. Attack rows measure time to a blocking
decision and may terminate before the full allow-path traversal.

Every qualified workload requires five independent processes and ten retained raw repetitions per
process. The report uses median CPU time and process-level bootstrap 95% confidence intervals.
Inner-repetition CV remains a diagnostic and is never substituted for process-level variation.

### Fixed-Rate NGINX Latency

Fixed-rate latency uses `wrk2` with one immutable, predeclared allow-request rotation. The load
generator and NGINX worker use disjoint recorded CPU sets. Worker count, connections, keepalive,
headers and backend response are identical across engines.

The V1.0 performance rotation contains six HTTP/1.1 `GET` requests with empty bodies. Its E2E
results therefore cover URI, query and request-header inspection, not request-body ingestion. The
generated Lua sends an absent body as `nil`, preserving the manifest header set instead of allowing
`wrk.format()` to synthesize `Content-Length: 0`.

Every workload path is materialized as an identical two-byte static file. NGINX uses
`try_files $uri =404`; it does not internally redirect misses to a shared fallback URI. This keeps
one external request equal to one WAF transaction and preserves the original URI through all WAF
phases.

Each fixed-rate leg runs an unmeasured one-second `wrk2` warm-up after NGINX preflight and response
probing. Its raw output and exit status are retained. Server CPU accounting starts only after this
warm-up, which removes first-process rate-controller initialization from the measured interval.

The common offered rate is selected at no more than 60% of the slowest engine's highest stable
saturation point. The selection is frozen in `sampling_plan.json` before latency collection. The
minimum duration is calculated from the 100,000-response target, the 90% achieved-rate floor and a
10% sample safety margin.

Each publishable repetition requires:

- zero non-success responses;
- achieved rate at least 90% of the offered rate;
- at least 100,000 accepted responses;
- raw HdrHistogram output;
- p50, p90, p99 and p99.9;
- no affinity, thermal, restart or preflight failure.

At least five valid, balanced-order repetitions are required. The report shows medians of per-run
percentiles and bootstrap confidence intervals; it never pools request samples across runs.
Achieved RPS CV must be no greater than 5%.

### Saturation Throughput

Saturation is a separate closed-loop connection sweep without `wrk2 -R`. A sustainable point is the
highest connection point with at least five valid runs, zero non-success responses and RPS CV no
greater than 5%. Queueing latency at saturation is never presented as service latency.

The server CPU/request diagnostic sums NGINX master and direct-worker `utime+stime` from
`/proc/<pid>/stat`, divides by completed requests and records `SC_CLK_TCK`. It excludes the load
generator.

### Multi-Worker Scaling

Multi-worker scaling is an optional publication supplement and never replaces the primary
single-worker fixed-rate, saturation or direct CPU results. It repeats the identical closed-loop
allow workload at `1`, `2`, `4` and `8` NGINX workers. The worker process and its WAF retain the
production binaries and configurations used by the single-worker experiment.

For an `N`-worker point, NGINX receives `N` dedicated CPUs from the start of the declared server
pool. The load generator receives `min(N, client_pool_size)` dedicated CPUs and the same number of
threads. Server and client pools must be disjoint, kernel-isolated physical CPUs. Housekeeping,
interrupt handling and unrelated services remain outside both pools.

Each point uses at least five independent balanced-order repetitions and a connection sweep. For
each engine, the report selects its highest sustainable point with zero response errors and RPS CV
no greater than 5%. It derives speedup relative to that engine's one-worker result, scaling
efficiency, RPS/worker and server CPU/request.

The runner also measures load-generator `RUSAGE_CHILDREN` CPU time. A selected row is invalid when
maximum client utilization exceeds 85% of its assigned CPU capacity, preventing a client-limited
plateau from being reported as a WAF scaling limit. Saturation latency is not reported as service
latency. NAXSI retains its separate `native-waf` classification in the scaling table.

### LuminaWAF Overhead Decomposition

The diagnostic decomposition uses one workload and three production NGINX configurations:

- `E0`: plain NGINX without the Lumina module;
- `E1`: the same module and library loaded with `lumina_waf off`;
- `E2`: the production Lumina CRS PL2 path enabled.

Balanced `E0/E1/E2` rounds use identical connection counts, worker count, workload hash and CPU
placement. CPU deltas are paired within each round:

```text
module_hook_cpu       = CPU(E1) - CPU(E0)
adapter_plus_pl2_cpu  = CPU(E2) - CPU(E1)
integration_residual  = adapter_plus_pl2_cpu - CPU(FullDirect/AllowRotation)
```

The report retains negative paired differences when noise produces them. It never subtracts p50,
p90, p99 or p99.9 because the difference between two percentiles is not an overhead distribution.

Direct `BundleBuild`, `InspectPrebuilt` and `FullDirect` Google Benchmark kernels use descriptors
generated from the same allow workload. An empty-policy result may be added only through a separate,
hashed generated-policy build; it is never approximated with an empty bundle or runtime bypass.

## Correctness Before Performance

Qualified runs execute the pinned CRS suites before accepting performance evidence. Lumina reports
positive block, exact matched-rule, negative exclusion, transport skip, timeout, exception and
bounded disagreement records. Coraza independently executes its selected manifest inventory through
pinned go-ftw cloud mode without forced outcomes.

All NGINX adapters also run a small immutable outcome matrix covering benign requests and SQLi,
XSS, LFI, RCE and RFI. This matrix is a connector smoke, not a substitute for the full CRS gate.

## Hardware And Isolation

Every run records CPU model, microcode, architecture, topology, SMT, NUMA, kernel, governor, boost
state, temperature, compiler, effective flags, binary hashes, affinity and background load.
Environment snapshots are captured before and after measurement.

Canonical mode requires:

- no tracked source-tree changes or untracked build/script sources;
- no tracked or untracked changes in the pinned CRS tree;
- kernel-isolated benchmark CPU sets;
- load-generator CPUs disjoint from both server and microbenchmark CPUs;
- when scaling is enabled, all declared scaling server/client CPUs are isolated and mutually
  disjoint;
- no SMT siblings shared between the load generator and server/microbenchmark sets;
- the `performance` governor;
- every correctness, sample-volume and stability gate.

Server and microbenchmark CPU sets may overlap because those phases execute sequentially, never
concurrently. Their overlap is recorded and all declared CPUs must still be kernel-isolated.

Affinity without kernel isolation is insufficient. `qualification` runs use the full process,
correctness and sample contract but remain `NON-CANONICAL` on a shared host. Operator annotations,
load averages, pressure-stall data and process counts document contention but never waive canonical
requirements.

Linux commonly starts SSH and service processes on housekeeping CPUs after `isolcpus`. Therefore
canonical preflight does not require the launch shell's inherited affinity mask to already contain
the isolated CPUs. It requires every declared CPU to be online and kernel-isolated, and probes that
`taskset` can enter the complete declared benchmark set before any measurement starts.

## PMU Diagnostics

PMU numerator and denominator pairs run in small sequential groups: cycles with instructions,
branches with branch misses, and each cache/TLB access count with its miss count. This avoids
silently multiplexing more events than the physical PMU can schedule.

Qualified rows require minimum `time_running >=90%` and report:

- cycles and instructions per transaction;
- IPC;
- branch-miss rate;
- generic cache-miss rate;
- L1D, LLC and iTLB miss rates.

Unsupported events are rendered as `unavailable`, never zero, without hiding supported counters.
PMU values explain execution behavior; they do not replace latency or throughput measurements.
Canonical mode fails closed if cycles, instructions, branches or branch misses are absent, or if
their grouped running percentage falls below 90%, for any CRS engine.

LuminaWAF's SQL injection operator is the Lumina-owned `src/lumina_sqli.c`. Before benchmark or PMU
collection, V1.0 Protocol rejects `libluminawaf.so` if `readelf` finds a legacy `libinjection_*`
symbol or relocation. The same audit records the complete `DT_NEEDED` set and rejects Libinjection,
PCRE, ModSecurity, Coraza or NAXSI runtime dependencies. Comparator-only private libraries never
enter the Lumina runtime target.

## Statistical Qualification

- Fewer than two independent runs: confidence interval and run-level CV are `N/A`.
- Fixed-rate p99 requires at least 10,000 accepted responses in every contributing run.
- Fixed-rate p99.9 requires at least 100,000 accepted responses in every contributing run.
- Qualified microbenchmarks require five independent processes and ten raw inner repetitions.
- Qualified fixed-rate and saturation rows require five valid runs and RPS CV `<=5%`.
- Negative or wide confidence bounds are retained rather than clamped.

`smoke` is an engineering integration run. `qualification` collects publication-sized evidence on
a non-isolated host. `canonical` adds the strict hardware, provenance and clean-tree gates.

## Report Generation

`BENCHMARK_RESULTS.md` is generated from retained JSON, console logs, histograms, manifests and
hashes. It contains no manually entered performance number. Every row carries its qualification
status, and every relative comparison includes both absolute values and direction.

Headline claims must name the measurement boundary, workload, run mode and host qualification.
A `NON-CANONICAL` result may be reported as qualification evidence but must not be presented as a
canonical or hardware-independent performance guarantee.
