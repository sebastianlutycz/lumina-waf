# LuminaWAF

**An experimental AOT-compiled, SIMD-oriented Web Application Firewall engine for NGINX.**

LuminaWAF explores a simple question:

> How much of OWASP Core Rule Set inspection can be moved out of a dynamic, regex-heavy runtime and compiled into a bounded native dataplane?

LuminaWAF translates the supported semantics of a pinned inbound OWASP Core Rule Set paranoia level 2 policy into native execution units.

The production request path does not parse CRS rule files, load a regular-expression engine or dynamically resolve an external SQL injection classifier.

The current release line is `v0.4.x`.

> [!WARNING]
> LuminaWAF is a systems-engineering research prototype and portfolio project.
>
> It is **not** an audited, production-ready replacement for ModSecurity.

I built it independently over several months, mostly because I enjoy going one layer lower than is probably reasonable.

Sometimes the best reason to build something is simply:

> **Make cool shit and learn what breaks.**

---

## What LuminaWAF Is

LuminaWAF consists of:

* a build-time policy translator and materializer;
* generated native execution units;
* a bounded request-inspection runtime;
* an NGINX dynamic module;
* a correctness and performance evidence pipeline.

Instead of interpreting rule files on every request, LuminaWAF freezes a supported policy at build time and translates it into:

* generated finite-state matchers;
* compact candidate routers;
* native structural operators;
* bounded transformation pipelines;
* architecture-specific SIMD and scalar execution paths.

At runtime, NGINX passes request data to the generated inspection dataplane and receives an allow or block decision together with matched-rule metadata.

---

## Why It Exists

Traditional WAF engines provide highly dynamic execution environments. That flexibility can introduce significant work into the request path:

* rule parsing;
* regular-expression dispatch;
* dynamic transformation pipelines;
* allocation;
* generic operator routing;
* repeated metadata lookup.

LuminaWAF takes the opposite approach:

1. Pin the policy and source provenance.
2. Validate the supported rule semantics.
3. Compile the policy ahead of time.
4. Materialize native execution code.
5. Execute the generated dataplane over caller-owned request bytes.
6. Retain evidence for the exact policy that was built and measured.

The project is an experiment in:

* ahead-of-time security policy compilation;
* SIMD-oriented request inspection;
* bounded execution;
* cache-conscious data layout;
* branch-aware and branchless processing;
* deterministic memory ownership;
* reproducible performance engineering.

---

## Current Status

The current release supports a pinned inbound OWASP CRS PL2 profile through a combination of generated and native execution paths.

Internal non-canonical qualification of a pre-RC commit established:

* approximately **99.75% overall agreement** in the pinned CRS regression gate;
* separate correctness, full-transaction, fixed-rate latency, saturation and PMU experiments;
* a benchmark pipeline for paired NGINX overhead decomposition;
* retained raw JSON, logs, histograms, hashes and validity decisions.

Two consecutive diagnostic smoke runs from the current x86-64 pre-RC line observed:

* **106.20 µs** and **107.42 µs** median CPU time for the direct full allowed transaction;
* **2.44 ms** and **2.47 ms** for the equivalent ModSecurity boundary, meaning ModSecurity used
  approximately **23×** as much CPU time in those runs;
* **170.82 µs** and **207.04 µs** of paired NGINX server CPU/request overhead for production PL2
  inspection over the loaded-but-disabled Lumina module, at 1 and 10 connections respectively in
  the latest run.

The direct full-transaction CPU measurement and integrated NGINX server CPU/request overhead are
different boundaries and must not be substituted for one another. These smoke observations use one
independent benchmark process and one E2E repetition, so they are diagnostic rather than publication
claims and do not provide process-level confidence intervals.

These numbers are not universal performance claims.

They apply only to the exact:

* LuminaWAF commit;
* CRS source commit;
* ordered include manifest;
* workload hash;
* engine configuration;
* hardware profile;
* measurement boundary;
* qualification class.

Neither the pre-RC qualification nor the smoke observations are the publication result for
`v0.4.0-rc.1`. They were collected on a shared Intel Haswell host without full kernel CPU isolation.
The final report must be regenerated from the exact tagged source state and will remain
`NON-CANONICAL` unless every canonical host gate passes.

See:

* [LuminaWAF Benchmark Harness v1](bench/benchmark_harness/README.md)
* [Benchmark methodology](methodology/README.md)
* [Published evidence contract](reports/README.md)

---

## Runtime Design

The production inspection path follows these rules:

* AOT execution of supported inbound CRS PL2 semantics.
* No runtime parsing of CRS `.conf` files.
* No dynamically loaded regular-expression engine.
* No dynamically loaded SQL injection classifier.
* No heap allocation in the request-inspection hot path.
* Caller-owned request bytes.
* Bounded thread-local transformation storage.
* Generated finite-state matchers and routing tables.
* Native structural and transformation operators.
* An integrated, zero-allocation SQL injection tokenizer.

**Zero third-party runtime dependencies.** The current x86-64 `libluminawaf.so` requires only the
platform C runtime and ELF loader in its `DT_NEEDED` table. The loader supplies the TLS resolver
used by bounded thread-local transform storage. The core library does not require a regex engine,
external SQL classifier or another WAF library at runtime.

NGINX, benchmark comparators, generators and build tools are development or integration dependencies. They are not runtime dependencies of the core inspection library.

---

## Execution Model

```text
pinned OWASP CRS policy
          │
          ▼
manifest and semantic inventory
          │
          ▼
AOT translator and materializer
          │
          ▼
generated matchers, routers and native operators
          │
          ▼
libluminawaf.so
          │
          ▼
NGINX request adapter
          │
          ▼
allow / block decision and matched-rule metadata
```

Generated execution-unit counts do not map one-to-one to CRS source-rule counts.

Setup rules, chains, metadata and non-score-bearing rules may be consolidated or represented by shared native execution.

Compatibility is therefore established through the pinned manifest and regression oracle, not by dividing generated execution-unit count by source-rule count.

---

## Compatibility Scope

The precise compatibility claim for the current release is:

> **LuminaWAF AOT-compiles the supported semantics of a pinned inbound OWASP CRS PL2 policy into native execution units.**

Compatibility is validated against the pinned CRS PL2 regression suite using ModSecurity-compatible expectations.

LuminaWAF does not currently claim:

* support for every ModSecurity directive;
* support for arbitrary user-supplied `.conf` files;
* complete CRS PL3 or PL4 support;
* byte-for-byte equivalence with the ModSecurity runtime;
* production security certification;
* universal superiority on every processor or workload;
* drop-in compatibility with every existing ModSecurity deployment.

The exact supported boundary is defined by:

* the pinned CRS commit;
* the ordered include manifest;
* the generated policy inventory;
* the workload hash;
* the structured correctness artifacts;
* the retained benchmark evidence.


---

## Supported Architectures

### x86-64

The `v0.4` release baseline requires:

* AVX2;
* BMI1;
* POPCNT.

CMake does not enable `-march=native` by default.

Host-local builds may opt in with:

```bash
-DLUMINA_NATIVE_TUNING=ON
```

Native-tuned binaries are not portable release artifacts.

### AArch64

AArch64 support is experimental and incomplete in `v0.4`. Partial scalar and NEON paths are
present, but the complete generated runtime and NGINX integration have not passed native release
validation. Official AArch64 support is planned for a later release.

---

## Build the Core Library

### Prerequisites

* Linux on x86-64 with AVX2, BMI1 and POPCNT
* CMake 3.20+
* Clang or GCC
* Python 3
* Git

OWASP CRS rules and data files are not distributed directly in this repository.

The pinned CRS source is fetched as a Git submodule. The materializer writes generated AOT sources into ignored local paths.

```bash
git clone https://github.com/sebastianlutycz/lumina-waf.git
cd lumina-waf

git submodule update --init tests/eval_suite/coreruleset

./bench/benchmark_harness/materialize_runtime.sh

cmake -S . -B build \
  -DCMAKE_BUILD_TYPE=Release

cmake --build build \
  -j"$(nproc)" \
  --target luminawaf
```

The resulting core library is:

```text
build/libluminawaf.so
```

The standard public build compiles the materialized generated sources using the C compiler selected
by CMake. It does not consume a precompiled parser object.

---

## NGINX Integration

Build the module against the exact NGINX version used in the target environment.

The module build expects the core library at:

```text
build/libluminawaf.so
```

Example:

```bash
LUMINA_ROOT="$(pwd)"
NGINX_SRC=/path/to/nginx-source

cmake -S "$LUMINA_ROOT" -B "$LUMINA_ROOT/build" \
  -DCMAKE_BUILD_TYPE=Release

cmake --build "$LUMINA_ROOT/build" \
  -j"$(nproc)" \
  --target luminawaf

cd "$NGINX_SRC"

./configure \
  --with-compat \
  --add-dynamic-module="$LUMINA_ROOT/nginx_module"

make modules
```

Load the resulting module and enable inspection where required:

```nginx
load_module /absolute/path/to/ngx_http_luminawaf_module.so;

events {}

http {
    server {
        listen 8080;

        location / {
            lumina_waf on;
            root /srv/www;
        }
    }
}
```

Package `ngx_http_luminawaf_module.so` together with its matching `libluminawaf.so`.

Preserve the runtime library lookup path selected during the module build and validate the configuration before activation:

```bash
nginx -t
```

The benchmark harness generates and validates its own pinned NGINX configurations.

The repository does not ship host-specific production configurations.

---

## Reproducible Benchmark

LuminaWAF Benchmark Harness v1 implements the repository-owned V1.0 Protocol evidence pipeline for
LuminaWAF `v0.4`.

The complete smoke pipeline can be started from a fresh clone with:

```bash
./bench/benchmark_harness/run.sh smoke
```

The launcher:

* verifies required host commands;
* initializes the pinned CRS submodule;
* downloads exact pinned source revisions and verified archives;
* materializes the AOT runtime;
* builds pinned NGINX and WAF comparators;
* builds `wrk`, `wrk2` and Google Benchmark;
* generates isolated NGINX configurations;
* executes the diagnostic evidence pipeline;
* generates a Markdown report exclusively from retained artifacts.

The bootstrap installs into:

```text
.cache/benchmark_harness_v1
```

It does not replace system libraries or install packages with elevated privileges.

### Smoke

```bash
./bench/benchmark_harness/run.sh smoke
```

`smoke` verifies the complete pipeline.

It is diagnostic and does not contain enough independent processes or request samples for publication-level confidence intervals or tail-latency claims.

### Qualification

```bash
LUMINA_BENCH_V1_HOST_PROFILE=shared-loaded-homelab \
LUMINA_BENCH_V1_HOST_NOTE='Background services remained active; this is not a canonical host.' \
./bench/benchmark_harness/run.sh qualification
```

`qualification` executes the publication-sized evidence contract.

A qualification run on a shared or non-isolated machine remains explicitly labeled `NON-CANONICAL`.

An operator annotation never upgrades a run to canonical status.

### Canonical

```bash
./bench/benchmark_harness/run.sh canonical
```

Canonical mode is fail-closed.

It requires, among other gates:

* all pinned benchmark comparators;
* the real pinned CRS PL2 policy;
* complete correctness gates;
* five independent Google Benchmark processes;
* ten retained raw inner repetitions per process;
* kernel-isolated benchmark CPUs;
* non-overlapping SMT sibling placement;
* at least 100,000 accepted fixed-rate responses per repetition;
* raw percentile evidence;
* stable saturation points;
* retained compiler versions and effective per-file compile commands;
* complete artifact and provenance hashes captured before measurement and revalidated afterward;
* a recorded Lumina `DT_NEEDED` set and clean legacy SQL-classifier symbol/relocation audit.

Affinity through `taskset` alone is not sufficient.

Canonical mode verifies that every declared benchmark CPU is covered by the kernel-isolated CPU mask exposed through sysfs.
Load-generator CPUs must be disjoint from server and microbenchmark CPUs, including SMT siblings.
Server and microbenchmark CPU sets may overlap because their phases execute sequentially.

See:

* [LuminaWAF Benchmark Harness v1](bench/benchmark_harness/README.md)
* [Normative methodology](methodology/README.md)

---

## Measurement Classes

The V1.0 Protocol intentionally separates different measurement boundaries.

### Correctness

The correctness gate retains:

* positive block agreement;
* exact matched-rule agreement where observable;
* negative exclusions;
* false-positive checks;
* category coverage;
* skips;
* timeouts;
* exceptions;
* disagreements.

LuminaWAF is evaluated against ModSecurity-compatible pinned expectations.

The stock Coraza NGINX connector exposes the final HTTP verdict but does not export matched rule IDs. Its observable contract is therefore intentionally narrower.

NAXSI is reported separately as a native-WAF implementation-class reference. It is never presented as a CRS-compatible engine.

### Full Transaction CPU Time

Google Benchmark executes the complete inbound transaction lifecycle exposed by each engine.

This is an in-process CPU measurement.

It is not NGINX end-to-end request latency.

### Fixed-Rate E2E Latency

`wrk2` is used for an allow-only fixed-rate workload with coordinated-omission resistance.

The report retains:

* p50;
* p90;
* p99;
* p99.9;
* maximum latency;
* raw histogram evidence.

### Saturation

Closed-loop saturation measures maximum sustainable throughput.

Queueing latency from saturation is never substituted for service latency.

Canonical saturation points require:

* five independent runs;
* zero response errors;
* RPS coefficient of variation no greater than 5%.

### Controlled Scaling

Synthetic rule-count experiments are isolated from the real CRS PL2 comparison and are always labeled synthetic.

### LuminaWAF Overhead Decomposition

The decomposition separates:

* `E0`: plain NGINX;
* `E1`: the identical Lumina module with `lumina_waf off`;
* `E2`: production CRS PL2 inspection.

The report derives paired server CPU/request differences at matching connection points.

It also contains direct kernels for:

* request-to-bundle projection;
* inspection of a prebuilt bundle;
* complete direct inspection;
* integration residual.

Latency percentiles are shown only as absolute context and are never subtracted.

---

## PMU Diagnostics

Qualified runs collect grouped hardware performance-counter diagnostics for the allow transaction:

* cycles per transaction;
* instructions per transaction;
* IPC;
* branch-miss rate;
* generic cache-miss rate;
* L1 data-cache misses;
* LLC misses;
* instruction-TLB misses;
* minimum counter running percentage.

Counter numerator and denominator pairs execute in separate small atomic groups.

Unsupported cache events remain marked `unavailable` without suppressing supported IPC or branch metrics.

The direct `InspectPrebuilt` and `FullDirect` kernels receive the same grouped PMU treatment.

PMU results are diagnostic and are not treated as headline request-latency measurements.

---

## Correctness and Release Integrity

The release gate evaluates LuminaWAF against ModSecurity-compatible expectations on the pinned inbound CRS PL2 regression suite.

A generated-source drift audit must reproduce the materialized runtime before a release is accepted.

The manifest and structured correctness artifacts define the tested semantic boundary.

Run the release-tree verification gate with:

```bash
python3 tools/verify_release_tree.py
```

Passive source and binary provenance markers are documented in:

* [INTEGRITY.md](INTEGRITY.md)

Performance results may only be quoted together with their:

* measurement boundary;
* qualification class;
* hardware profile;
* workload hash;
* policy manifest;
* engine configuration;
* sample volume.

Direct engine CPU time, fixed-rate NGINX latency and NGINX saturation are separate claims.

A `NON-CANONICAL` result must remain labeled as such.

Smoke results are diagnostic.

---

## Security

This project processes hostile input and should be treated accordingly.

Do not deploy LuminaWAF as a production security boundary without:

* reviewing the source;
* reproducing the generated runtime;
* running the full correctness gate;
* validating the target NGINX build;
* testing the selected policy against the intended workload;
* conducting an independent security review.

Security issues should be reported according to:

* [SECURITY.md](SECURITY.md)

Please avoid publishing directly exploitable vulnerabilities before a coordinated fix is available.

---

## Contributing

Issues, technical criticism, and focused pull requests are welcome. Before contributing, read:

* [CONTRIBUTING.md](CONTRIBUTING.md)

The contribution contract covers the AOT architecture boundary, required validation, benchmark
evidence, dependency policy, and release rules.

---

## Project Philosophy

I am not a security vendor or a research group with a FAANG-sized hardware budget.

I'm just a homelabber who likes C, old hardware, performance counters and asking whether an expensive abstraction really needs to exist in the hot path.

LuminaWAF was built mostly for fun, curiosity and learning.


Technical criticism is welcome.

Please do not roast me too hard, but if the benchmark is wrong, the architecture is questionable or an assumption does not survive contact with reality, open an issue and bring evidence.

That is what the project is for.

---

## Side Quests

These are interesting experiments that are not allowed to block the main release, preferably.

- [ ] Teach LuminaWAF to speak AVX-512
- [ ] Run it on hardware younger than the first release of Docker
- [ ] Validate the NEON backend without accidentally buying another server
- [ ] Measure NUMA scaling on a dual-socket machine
- [ ] Add an API translation layer (SecLang -> C -> Atomic Flip, because even AOT needs to listen sometimes)
- [ ] Find out how much of the remaining integration residual is NGINX being NGINX
- [ ] Make the benchmark harness complain even more aggressively when I accidentally try to cheat

---

## Licensing

LuminaWAF is currently licensed under the GNU Affero General Public License v3.0.

See:

* [LICENSE](LICENSE)

Only the AGPLv3 license is offered for the `v0.4` release line.

---

## Project Independence

LuminaWAF is an independent project.

It is not affiliated with, sponsored by or endorsed by the OWASP Foundation or the OWASP Core Rule Set project.

OWASP Core Rule Set remains governed by its own license and project policies.

---

## Feedback

Feedback is especially welcome in the following areas:

* AOT rule translation;
* correctness methodology;
* NGINX integration;
* adversarial parser behavior;
* PMU interpretation;
* benchmark reproducibility;
* NUMA and multi-core scaling;
* SQL injection tokenization;
* newer x86 server hardware;
* AArch64 portability.

Issues, reproducible counterexamples and raw evidence are considerably more useful than arguments based only on headline numbers.

If this is the kind of engineering problem your team works on, I am also open to systems, performance and R&D engineering opportunities.
