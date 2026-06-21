# LuminaWAF: Architecture & Methodology

This document describes how the LuminaWAF parser is built, why it's built that way, and how the benchmark numbers elsewhere in this repo were produced. It's split into three parts: the parser design itself, the LuminaC toolchain used to tune it, and the benchmarking setup used to measure it.

Throughout this doc, it's worth keeping three things separate:
- **What's actually built** — the SIMD code, the memory layout, the toolchain.
- **What we expect as a result** — the reasoning for why a given change should help.
- **What we measured** — numbers from real runs, with the conditions they were measured under.

Expected results are not the same as measured results, and we try to be explicit about which is which below.

---

## 1. Benchmark Setup & Reproducibility

### Metrics
We report three primary signals:
- Cycles per byte, under fixed-payload saturation.
- IPC (instructions retired per cycle), measured at the function boundary.
- End-to-end processed payload bandwidth.

### Real-World Homelab Environment
Unlike clean-room environments, these benchmarks were run on an active homelab under normal operating pressure. This means:
1. **Background Load**: A baseline load average (~2.0) and swap usage were present during measurements.
2. **Dynamic Scaling**: CPU governors were set to performance mode with Turbo Boost enabled (scaling up to 3.5GHz) rather than static frequency pinning.
3. **Core Isolation**: Benchmark threads were pinned to isolated cores via `isolcpus` to minimize direct context switching, though shared resources (like memory controllers) still experience homelab contention.

This approach trades theoretical peak isolation for realistic deployment jitter.

### Handling noise
CPU timing is inherently noisy — out-of-order execution, TLB shootdowns, and cache contention all introduce variance run-to-run. We use **Google Benchmark** for iterative measurement and:
- discard explicit warm-up iterations,
- report median (not mean) as the primary statistic, since it's less sensitive to the occasional outlier from an interrupt or scheduler hiccup,
- report 95% confidence intervals alongside it.

### Known sources of bias we can't fully remove
A few things bias the numbers in ways we mitigate but can't eliminate entirely:
- L2 streamer prefetch heuristics — we align memory to make prefetching easier to predict, but we don't control the prefetcher directly.
- Speculative execution recovery cost after a misprediction.
- µop cache eviction variability.

---

## 2. Parser Design: Branchless URI Decoding

NGINX's default URI decoder (`ngx_unescape_uri`) is a DFA-style state machine driven by per-byte `if`/`switch` branches. On payloads heavy with `%XX`-encoded sequences — which is exactly what adversarial input tends to look like — this leads to a high branch misprediction rate and correspondingly poor instruction throughput.

LuminaWAF replaces this with a branchless, vectorized approach:

1. A 32-byte block is loaded into a 256-bit YMM register.
2. `_mm256_cmpeq_epi8` builds a bitmask locating `%` characters across the whole block at once.
3. `_mm256_shuffle_epi8` does the hex-to-byte lookup for all matched positions in parallel, using the shuffle as an in-register lookup table.

The effect is that the bottleneck shifts away from branch prediction and toward SIMD execution port throughput and L1 bandwidth. Per-vector cost is roughly constant regardless of how many escape sequences are actually present in that block — a block with zero `%XX` sequences and a block saturated with them cost about the same to process. This only describes the parser's own behavior; see Section 5 for where this assumption breaks down under specific input shapes.

---

## 3. Memory Layout & Alignment

All internal memory arenas use 32-byte alignment (`alignas(32)`), matching the AVX2 vector width. This reduces split-line memory accesses and makes prefetching more predictable under sustained streaming loads.

One open question we haven't resolved yet: the cost of `_mm256_testz_si256` (used in the branchless filter) may vary across microarchitectures — Intel and AMD implementations don't necessarily cost the same number of cycles for the same instruction. **We haven't measured this on non-Intel hardware** (all current numbers are from an i5-4210H, a Haswell-generation part); this is a known gap rather than a verified cross-platform result.

---

## 4. Toolchain: LuminaC and Phase Ordering

Standard compilers (Clang 18, GCC 13) make loop-unrolling decisions before they've finalized structure layout and offset calculations. This ordering — unrolling decisions locked in before layout is known — is a known limitation often called the **phase ordering problem**, and it leaves real performance on the table for hot-path code like this parser.

To work around it, the final version of `parser_avx2.cpp` was tuned using **LuminaC**, a separate experimental compiler toolchain (repo: [LuminaC](https://github.com/sebastianlutycz/LuminaC)). The process:

- The parser source is lowered to LLVM IR.
- LuminaC runs successive mutations of that IR — different unrolling factors, different struct padding — inside a dedicated LLJIT sandbox.
- Each mutation is measured directly on the CPU using PMU counters, selecting for fewer Trace Cache and L1i misses.
- The best-performing mutation found is emitted as a standalone `.o` object file via LLVM's `TargetMachine`, using absolute addressing (No-PIE), tailored to the CPU it was profiled on.

This is also exactly why the precompiled `.o` shipped in this repo is tied to one specific CPU and shouldn't be used as-is in production — see the security notice in the main README.

---

## 5. Comparing Against Baseline

We track three relative measures against the scalar baseline:

- **ΔT** = T_baseline − T_vectorized
- **ΔIPC** = IPC_vectorized / IPC_baseline
- **ΔMPKI** = misses per kilo-instruction (L1i and L1d)

A caveat on IPC specifically: it's a secondary signal, not a direct throughput proxy, for SIMD-heavy code. IPC can go up simply because there are fewer branch-mispredict pipeline flushes, or it can go *down* on a SIMD code path while overall throughput still goes up, because each instruction is doing more work per cycle. We look at IPC alongside throughput, not as a replacement for it.

We don't have (and didn't want to fake) a single closed-form formula combining branch behavior, memory pressure, SIMD utilization, and front-end decode pressure into one number. These are tracked as separate signals, each useful for diagnosing *why* a given run was fast or slow, not combined into a unified "cost model."

---

## 6. Where This Breaks Down

The branchless approach isn't free of failure modes:

- **Saturation collapse**: once a 32-byte block has more than ~85% of its bytes as part of `%XX` sequences, throughput drops back toward baseline. This is a threshold effect, not a gradual degradation — once the SIMD lanes are mostly occupied by overlapping mask operations, the branchless advantage mostly disappears.
- We think of execution as falling into one of three rough regimes:
  - **Regime A** — branchless SIMD path, uniform/typical payload. This is where the gains show up.
  - **Regime B** — mask saturation fallback, dense `%XX` payloads. Gains shrink toward zero.
  - **Regime C** — memory-bound scalar fallback, when payload size exceeds what fits in pre-allocated memory (currently 16 KB per request context). Larger payloads require multiple smaller chunk invocations, and that per-chunk overhead eats into the win.

This means the benchmark numbers in this repo describe Regime A specifically — uniform payloads, 1 KB requests, within the 16 KB context cap. Pathological inputs designed to land in Regime B or C won't see the same improvement.

---

## 7. Benchmarking Toolchain & Workload

**Tools:**
- **Google Benchmark** for C++ microarchitectural tests.
- **perf_events**, integrated via direct `ioctl`/`read` syscalls, for L1 cache misses, branch mispredictions, and cycle counts at the function boundary.
- **wrk2** for end-to-end testing against the full NGINX stack — chosen over plain `wrk` because it avoids coordinated omission, which matters for getting an honest tail-latency distribution (P50/P90/P95/P99).
- **libFuzzer** for semantic equivalence testing against the reference DFA implementation.

**Workload:**
- All microarchitectural tests use payloads normalized to 1 KB, to remove algorithmic scaling as a variable.
- Rule-matching tests use 1,000 real rules from the OWASP ModSecurity Core Rule Set (CRS), to approximate realistic "rule explosion" behavior against PCRE-based engines.
- Adversarial corpora are seeded from SecLists-derived exploitation patterns, swept across `%XX` saturation levels from 0% to 100%.
- Tests are run in both **warm cache** (L1d preloaded) and **cold cache** (flushed between iterations) states.

**Statistics:** median as the primary statistic, mean/stddev/CV reported alongside it, N ≥ 10 runs per workload, warm-up iterations discarded before aggregation.

---

## 8. Assumptions and Boundaries

To be explicit about what this evaluation does and doesn't claim:

- **Front-end behavior** is inferred from µop cache residency and decode bandwidth (roughly a 4–6 µop/cycle limit), using L1i misses as a proxy for front-end starvation — we don't have direct visibility into the front end beyond that.
- **Out-of-order execution** is real but abstracted away: we observe retired instructions (IPC) at the function boundary rather than modeling instruction scheduling directly.
- **Cache hierarchy** is assumed roughly static during a warm-cache benchmark loop; OS context switches and TLB shootdowns still introduce some jitter, which `isolcpus` reduces but doesn't eliminate.
- **Prefetcher behavior** is heuristic and outside our control. Alignment to 32-byte boundaries is meant to probabilistically improve prefetch hit rates, not guarantee them.
