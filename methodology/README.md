# LuminaWAF Benchmark Methodology

This document defines the normative **V1.0 Protocol** implemented by LuminaWAF Benchmark Harness
v1 for the LuminaWAF `v0.4.x` release line. Historical synthetic parser experiments are not part
of this contract.

## Claim Boundary

V1.0 Protocol answers five separate questions:

1. Does each CRS-capable engine produce the required inbound PL2 security outcome?
2. What is the CPU cost of a complete inbound transaction through each engine ABI?
3. What latency and throughput does the complete NGINX deployment deliver?
4. When requested, how does closed-loop throughput scale across 1/2/4/8 NGINX workers?
5. What direct and integrated cost does bounded JSON request-body inspection add across
   representative body sizes?

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

### Internal PL2 Rule-Coverage Oracle

Per-test parity and rule coverage are separate metrics. The internal coverage oracle derives a
testable inbound PL2 universe from active phase 1/2 rules that directly add anomaly score, including
chain heads whose members carry the score action. Setup actions, chain members without independent
rule identity and blocking-evaluation rules do not enter this denominator.

The initial internal artifact uses pinned OWASP CRS FTW `expect_ids` and `no_expect_ids` as reference
activations, then records which expected IDs LuminaWAF matched over the same byte-preserved request.
It reports positive reference coverage, exact-ID implementation coverage, negative-assertion
coverage, dual-sided coverage and observed body-media activations. This artifact is explicitly
marked `internal_only` and `modsecurity_runtime_verified=false`.

It must not support a publication claim until every counted reference activation has been replayed
through the pinned ModSecurity comparator under the immutable manifest. FTW expectations,
ModSecurity observations and Lumina observations must then agree on the same raw request hash.
Transport-rejected requests remain outside the offline rule-coverage denominator.

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

`source_rule_inventory.json` assigns every source inbound PL2 ID to one evidence-backed structural
class: generated execution owner, native runtime owner, CRS control/setup/meta, non-score-bearing
metadata or unsupported score-bearing. A `subsumed_by` edge is never inferred from counts; it may be
emitted only when compiler IR records explicit ownership. Oracle results, not the ratio of generated
units to source IDs, establish semantic coverage.

The ModSecurity and Coraza configurations are generated from one ordered include graph. Canonical
mode requires identical resolved path and SHA256 sequences. External rule-removal or rule-update
directives invalidate the comparator configuration; controls shipped inside the hashed CRS tree are
retained as native CRS semantics.

Both comparator configurations select the XML and JSON request-body processors with the same
phase-1 rules before the CRS include graph. JSON selection covers `application/json` and structured
syntax suffixes ending in `+json`. The direct 128 KiB body benchmark also runs an untimed escaped
JSON probe that can block only after JSON projection; a comparator that merely exposes raw
`REQUEST_BODY` is rejected. The private PCRE2 build used only by ModSecurity must have JIT enabled,
and this capability is retained in dependency provenance.

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

### Request-Body Adapter Contract

LuminaWAF v0.4.2 adds bounded request-body ingestion to the production NGINX adapter. This does not
change the V1.0 publication workload above: its retained canonical HTTP/1.1 GET evidence remains a
bodyless URI, query and header measurement. Body-path performance is a separate evidence class and
must not be inferred by relabeling the existing canonical rows.

The adapter:

- acquires bodies asynchronously through `ngx_http_read_client_request_body()` and the common
  request-body filter chain;
- never parses HTTP/1.1 chunks, HTTP/2 DATA frames, HTTP/3 frames or QUIC state;
- permits at most `128 KiB` of inspected body data and checks both declared and received lengths;
- uses direct in-memory data when contiguous, one exact capture for known spill-prone input, or
  bounded request-pool slabs plus at most one final coalesce for unknown-length input;
- performs no synchronous request-body file read on the NGINX event-loop thread;
- builds one complete typed `LuminaBundle` and invokes the engine exactly once per request;
- accepts absent or explicit `identity` request `Content-Encoding`, rejects every other content
  coding with `415`, and fails closed on limit, capture, projection, capacity or engine errors;
- preserves allowed request-body bytes for downstream handlers.

The engine returns one request-body status in addition to the inspection result. The production
adapter maps malformed structured syntax to `400`, security-forbidden structured constructs to
`403`, unsupported representations to `415`, the inspection-size or parser-depth boundary to
`413`, and internal capture or engine failures to `500`. Status handling precedes the ordinary
allow/block response so an attack token inside a malformed document cannot turn a parser failure
into a successful backend request.

The v0.4.2 structured projection contract is:

- **JSON:** strict object, array, number, literal and string grammar; UTF-8 validation; decoded keys
  and string values; correct UTF-16 surrogate-pair composition; maximum nesting depth `64`.
- **XML:** UTF-8, UTF-16LE and UTF-16BE; optional BOM plus byte-signature detection for UTF-16;
  encoding-declaration consistency; validated code units, surrogate pairs and XML codepoints;
  balanced element stack; bounded attributes, comments, CDATA and processing instructions;
  predefined and numeric Unicode entities. A zero-allocation codepoint cursor tokenizes the source
  representation directly and converts only projected text and attribute values to UTF-8.
  A bounded internal DTD profile accepts a document-root declaration with an optional subset of at
  most `32` internal general text entities. The declared root must match the document element.
  DTD root and entity names are ASCII and limited to `64` bytes, total replacement declarations to
  `8192` codepoints, recursive expansion to four levels, and total expanded output to the smaller
  of `128 KiB` or twice the request-body length. Expansion supports forward references, predefined
  entities and numeric Unicode references, and rejects cycles or unknown references. External
  subsets, `SYSTEM`, `PUBLIC`, parameter entities and parameter references are security-forbidden
  and map to `403`; `ATTLIST`, `ELEMENT` and `NOTATION` are outside the supported profile and map
  to `415`. The engine performs no filesystem or network resolution.
- **Multipart:** exact opening and closing boundary framing; quoted boundary parameters; at most
  `256` parts, `64` headers per part and four nested multipart levels; `name`, `filename` and
  RFC 5987 `filename*`; identity, `7bit`, `8bit`, `binary`, strict `base64` and
  `quoted-printable` transfer decoding. Encoded nested multipart is unsupported because it would
  require a second materialization workspace.

Raw `REQUEST_BODY` inspection and structured projection are both retained. JSON values enter
`ARGS`, JSON keys enter `ARGS_NAMES`, XML content and attributes enter XML collections, and
multipart metadata and fields enter their corresponding file/name/body collections. Parser
scratch is bounded transaction-local or thread-local storage; the core parser path performs no
heap allocation.

HTTP/1.1 fixed-length and chunked requests and HTTP/2 bodies with and without `Content-Length` have
protocol-level integration coverage, including concurrent streams on one connection. HTTP/3 is an
architectural compatibility target because it crosses the same common NGINX body API; no HTTP/3
correctness or performance claim is valid until a pinned QUIC-capable build passes equivalent
protocol tests.

A complete body-path deployment study additionally requires media-type coverage, peak worker RSS,
temporary-file and copy accounting, plus a bystander-latency test where maximum-size body scans
share a worker with fixed-rate empty GET traffic. Those measurements are not inferred from the
bounded JSON matrix below. Direct engine time, body acquisition, materialization and complete
NGINX E2E latency remain separate boundaries.

### Dedicated JSON Body Evidence

The body evidence phase is separate from the six-request empty-body canonical rotation. It
generates exact-size 4, 16 and 128 KiB JSON requests with a deterministic clean value and a
deterministic attack token near the end of the value. Every engine receives byte-identical method,
target, headers and body bytes. Allow requests must return `204`; attack requests must return
`403`.

POST requests use a minimal fixed-response backend inside the same NGINX process. Front-server WAF
work and backend response work are both included in NGINX master-plus-worker CPU accounting. A
recorded `30s` load-generator request timeout prevents multi-second comparator transactions from
being reported as zero throughput; any actual timeout still invalidates the leg.

Saturation is calibrated separately for every engine, body size and verdict class. Qualified
calibration requires at least five valid `30s` runs and RPS CV `<=5%`; each fixed-rate leg then
runs at no more than 60% of that engine's stable rate. Smoke calibration uses three short runs (`5s`, or
`10s` for 128 KiB) and no more than 40% of their median rate. Legacy artifacts retain their
original sampling plan. Smoke stability is diagnostic and
never satisfies the publication gate. This controls queueing without forcing all engines down to
the slowest comparator. The consequence is explicit: E2E percentiles are per-engine observations
at normalized load and are not same-rate latency ratios.

The harness retains but rejects suspicious latency evidence. A fixed-rate p50 whose median exceeds
the matching calibration p50 by more than `8x`, any run exceeding it by more than `50x`, or a
greater than `4x` p50 inversion between adjacent 4/16/128 KiB sizes is labeled
`ANOMALOUS - investigation required`. An anomalous qualified leg fails closed. Smoke keeps the
row visible for diagnosis but cannot promote it into a performance claim.

When a qualified rate is below `1 RPS`, the leg uses one closed-loop connection because `wrk2`
cannot represent the required open-loop rate. Smoke also switches rates below `10 RPS` to
closed-loop because a short low-rate `wrk2` process may complete HTTP responses without populating
HdrHistogram. The mode is retained in the sampling plan and report. No percentile from a
closed-loop leg is presented as coordinated-omission-resistant.

Qualified sampling uses:

| Body | Samples per engine per run | Required percentiles | Classification |
|---:|---:|---|---|
| 4 KiB | 10,000 | p50, p90, p99 | body latency |
| 16 KiB | 1,000 | p50, p90 | sample-capped diagnostic |
| 128 KiB | 1,000 LuminaWAF/ModSecurity; 100 Coraza | p50/p90 fast engines; p50 Coraza | time-capped diagnostic |

Every row requires five valid runs, exact expected outcomes, zero unexpected responses and zero
socket errors. p99.9 is always withheld because no body row reaches its 100,000-sample floor. The
report retains medians across runs and process-level bootstrap intervals; it never pools request
samples.

Accepted HTTP responses and latency observations are separate counters. For fixed-rate legs the
harness parses HdrHistogram's raw `Total count` and applies percentile floors to that value. A
completed run with an absent or empty `wrk2` histogram is invalid even when every HTTP response
has the expected status; zero-valued percentiles from such output are never reported as latency.

Direct 128 KiB JSON evidence uses five independent Google Benchmark processes with ten retained
raw repetitions. The varied allow fixture also receives grouped PMU collection under the same
minimum 90% counter-running contract as the ordinary transaction rows. Direct CPU/PMU is the
cross-engine work comparison; NGINX E2E includes acquisition, adapter and response handling.
The Lumina row additionally reports per-transaction dispatch count, exact-verifier calls and exact
subject bytes for rules `934100`, `934101` and `934120`. These are compiler logical-work counters,
not hardware PMU attribution; cycles, instructions and miss rates remain transaction-wide.

Body correctness uses selected tests from the pinned public OWASP CRS/go-ftw corpus. Selection is
recorded by CRS commit, test ID and hash. CRS rules and test files are fetched by the
user-triggered bootstrap and are never copied into the release tree. External payload lists may be
used for supplemental fuzzing, but they are neither the parity oracle nor a latency workload.

### Canonical Fixed-Rate Qualification

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
greater than 5%. Maximum load-generator utilization must also remain at or below 90% of its
assigned CPU capacity. Queueing latency at saturation is never presented as service latency.

The plain-NGINX baseline is measured independently in the main and overhead saturation phases.
`baseline_phase_consistency.json` compares median RPS and server CPU/request at every shared
connection point while requiring identical configuration, workload, response contract, placement
and worker count. Publication requires five stable runs per phase, RPS disagreement no greater than
10% and CPU/request disagreement no greater than 15%. The overhead fixed-rate connection point
must exist in both phases. This gate runs before the long fixed-rate collection.

A smoke run has too few repetitions to establish sustainable throughput. Its section is therefore
named `Closed-Loop Throughput Sweep (Diagnostic)` and reports only the best observed point; it must
not be ranked as saturation capacity.

The server CPU/request diagnostic sums NGINX master and direct-worker `utime+stime` from
`/proc/<pid>/stat`, divides by completed requests and records `SC_CLK_TCK`. It excludes the load
generator.

### Multi-Worker Scaling

Multi-worker scaling is an optional publication supplement and never replaces the primary
single-worker fixed-rate, saturation or direct CPU results. It repeats the identical closed-loop
allow workload at `1`, `2`, `4` and `8` NGINX workers. The worker process and its WAF retain the
production binaries and configurations used by the single-worker experiment.

For an `N`-worker point, NGINX receives `N` dedicated CPUs from the start of the declared server
pool. Every point uses the complete load-generator CPU pool and one worker thread per client CPU;
client resources do not scale with the server point. Server and client pools must be disjoint,
kernel-isolated physical CPUs. Housekeeping,
interrupt handling and unrelated services remain outside both pools.

The runner binds each direct NGINX worker PID and each `wrk`/`wrk2` worker TID to one distinct CPU,
then reads the effective affinity back before accepting traffic. A process-level multi-CPU mask is
not sufficient: kernels booted with `isolcpus=domain` do not balance runnable tasks between those
isolated scheduling domains. The main load-generator task remains on the first client CPU and is
included in the recorded client CPU utilization.

Each point uses at least five independent balanced-order repetitions and a connection sweep. For
each engine, the report selects its highest sustainable point with zero response errors and RPS CV
no greater than 5%. It derives speedup relative to that engine's one-worker result, scaling
efficiency, RPS/worker and server CPU/request.

The runner also measures load-generator `RUSAGE_CHILDREN` CPU time. A selected row is invalid when
maximum client utilization exceeds 90% of its assigned CPU capacity, preventing a client-limited
plateau from being reported as a WAF scaling limit. Saturation latency is not reported as service
latency. A client-limited plain-NGINX baseline is retained and marked `NOT QUALIFIED`, but it is a
non-blocking transport diagnostic. All CRS engines and NAXSI remain blocking scaling rows; NAXSI
retains its separate `native-waf` classification in the scaling table.

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
Each direct boundary runs in a separate process/filter, and boundary order rotates between
independent process sets. These kernels are compiler-visible implementations rather than nested
function timers: `FullDirect` may optimize projection and inspection together, while
`InspectPrebuilt` copies a caller-owned bundle before inspection. Their medians are not
arithmetically subtracted.

## Correctness Before Performance

Qualified runs execute the pinned CRS suites and immutable outcome matrix after artifact preflight
and before launching any timed benchmark process. Lumina reports
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
- Qualified fixed-rate and saturation rows require five valid runs, RPS CV `<=5%` and
  load-generator utilization `<=90%`.
- A one-transaction time-capped body row is a single observation, not a percentile estimate.
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
