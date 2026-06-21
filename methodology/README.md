# Methodology & Architecture: The Science of LuminaWAF

This document presents a formal description of the microarchitectural transformations applied to the LuminaWAF engine, explicitly separating mechanism descriptions, observational data, and hardware hypotheses.

## 0. Experimental Design & Measurement Theory

To establish a reviewer-proof evaluation, we formally decouple claims into three isolated domains:
* **[MECHANISM CLAIM]**: Theoretical transformations applied to the parser (e.g., SIMD vectorization, cache layout).
* **[PERFORMANCE CLAIM]**: Hypothesized gains resulting from the mechanisms (e.g., amortized throughput, branch decoupling).
* **[BENCHMARK CLAIM]**: Empirical limits verified through telemetry (e.g., Google Benchmark median latency).

### 0.1 Metric Semantics Contract
All telemetry reported inside this document follows strict semantic definitions. We reject absolute algorithmic timing in favor of hardware-bound bounds. Performance is evaluated strictly via:
* Cycles per byte under fixed-payload saturation.
* Retire-rate Instructions Per Cycle (IPC) measured at the function boundary.
* End-to-end processed payload bandwidth.

### 0.2 Reproducibility & System State Lock
All benchmarks are executed within a locked system state. Hardware Governors are overridden to prevent dynamic frequency scaling, and execution threads are pinned via `isolcpus`. This environment guarantees that context switches, interrupt handlers, and noisy neighbor effects do not compromise the integrity of the data plane.

### 0.3 Noise Model & Statistical Filtering
CPU timing is inherently probabilistic due to out-of-order execution, TLB shootdowns, and cache contention. To establish a robust noise model, we rely strictly on **Google Benchmark** to execute iterative microarchitectural tests. Filtering is enforced by:
* Discarding explicit warm-up iterations.
* Utilizing `Median` over `Mean` to filter asynchronous interrupts.
* Defining bounding envelopes via 95% Confidence Intervals (CI).

### 0.4 Threat Model (Microarchitectural Bias Sources)
Our measurements acknowledge the following sources of systemic microarchitectural bias, which we mitigate but cannot entirely eliminate:
* L2 Streamer prefetch heuristics (which we align memory to guide, but cannot dictate).
* Speculative execution path recovery cost.
* $\mu$op cache eviction variability.

## 1. Formal Description of Atomic Bitmap Branchless (ABB)

**[OBSERVATION]** Traditional NGINX parsers (`ngx_unescape_uri`) utilize Deterministic Finite Automaton (DFA) state machines, which heavily rely on dense conditional instructions (`if / switch`). When analyzing URI strings saturated with URL-encoded characters (`%XX`), complex state transitions significantly increase the branch misprediction rate, leading to suboptimal instruction throughput.

**[MECHANISM]** The vectorized ABB implementation reduces data-dependent branching in the hot path. Instead of logical evaluation per byte, we employ a mathematical transformation:
1. A 32-byte block is loaded into a 256-bit YMM register (`YMM0`).
2. The `_mm256_cmpeq_epi8` instruction creates a bitmask locating `%` characters.
3. Byte-shuffling instructions (`_mm256_shuffle_epi8`) simultaneously map all bytes to the corresponding hexadecimal transform tables (Lookup Table in Register).

The primary throughput constraint shifts from branch prediction to SIMD execution port saturation and L1 bandwidth availability.

**[HYPOTHESIS]** Algorithmic complexity achieves a constant per-vector processing cost under fixed-width SIMD execution, amortized as $O(N / \text{SIMD width})$ with branch entropy decoupling in the hot path. This minimizes the data-dependent branch misprediction penalty across the 32-byte vector, regardless of whether the packet contains zero escapes or consists of aggressive encoded payloads.

## 2. Vectorization and Alignment Analysis

Optimal Memory Bandwidth critically depends on memory address alignment. LuminaWAF forces the compiler to impose strict 32-byte alignment (`alignas(32)`) for all internal memory arenas. This alignment reduces the probability of split-line accesses and improves prefetch predictability, particularly under sustained streaming loads.

**[OBSERVATION]** Furthermore, analyzing the hits of the `_mm256_testz_si256` instruction across different microarchitectures (Intel Haswell vs. AMD Zen 4) determines the decision cost of the entire AVX2 filter. 

**[HYPOTHESIS]** The memory layout is strictly structured to align access patterns and improve stride predictability, which increases the likelihood that hardware prefetchers will more effectively mask asymmetric decoder latency.

## 3. Toolchain & Phase Ordering Automation via LuminaC

Static compilation of vectorized code using standard Clang 18/GCC 13 releases encounters the **Phase Ordering Problem**. Standard compiler heuristics prematurely make loop unrolling decisions before ultimately determining structure address offsets (GEP alignment).

To mitigate this overhead, the final transformation of the `parser_avx2.cpp` code was subjected to evolutionary profiling using the proprietary **LuminaC** toolchain (available in the separate `LuminaC` repository).

### Feedback-Directed IR Topology Optimization (FDITO):

*   **IR Isolation:** The parser source code is transformed into LLVM IR (Intermediate Representation).
*   **Evolutionary Profiling Loop:** LuminaC executes successive pipeline mutations within a dedicated LLJIT machine instance, dynamically modifying unrolling parameters and structure padding.
*   **Hardware Telemetry:** Every mutation is measured directly on the CPU core using PMU counters. The algorithm selects variants that minimize Trace Cache and Instruction Cache (L1i) misses.
*   **AOT Emission:** Upon selecting the optimal mutation (The Golden DNA), the LuminaC `TargetMachine` module emits a physical `.o` object using absolute machine addressing (No-PIE).

## 4. Formal Baseline Comparison Model

To objectively quantify the microarchitectural gains, the evaluation model relies on the following relative equations:
* $\Delta T = T_{baseline} - T_{vectorized}$
* $\Delta IPC = \frac{IPC_{vectorized}}{IPC_{baseline}}$
* $\Delta MPKI$ = Misses Per Kilo Instruction (tracking L1i and L1d cache efficiency)

**[OBSERVATION]** IPC is treated as a secondary proxy metric and not a direct throughput estimator under SIMD-dominant workloads. An IPC increase may stem from reduced branch mispredict flushes or better Instruction-Level Parallelism (ILP), but SIMD transitions can also lower IPC while simultaneously increasing overall throughput.

### Formal Execution Cost Function
The microarchitectural cost is modeled as:
$T = f(B, M, S, F)$

Where:
* $B$ = Branch entropy
* $M$ = Memory hierarchy pressure
* $S$ = SIMD utilization efficiency
* $F$ = Front-end decode pressure

## 5. Boundary Conditions & Limitations (Where the Algorithm Fails)

**[OBSERVATION]** Despite aggressive gains, this architecture is sensitive to asymmetric data density (a known microarchitectural degradation mode). The system exhibits performance degradation to baseline levels when payload saturation with `%XX` sequences exceeds 85% per 32-byte block. 

**[MECHANISM]** Under this mask-heavy condition, throughput drops via a threshold-based collapse rather than a linear degradation. This stems from the necessity of repeatedly applying longitudinal masks, which leads to SIMD lane utilization collapse. 

Execution regime transitions follow a distinct phase diagram:
* **Regime A**: Branchless SIMD dominant (Optimal throughput, uniform payload).
* **Regime B**: Mask saturation fallback (SIMD lane collapse under dense `%XX` saturation).
* **Regime C**: Memory-bound scalar fallback (L1 bandwidth saturation, reverting to the sequential decoding pipeline).

Moreover, the benefits of bypassing the heap drastically diminish for payloads exceeding the size of available pre-allocated memory rows (currently capped at 16 KB per request context), nearing the L1 bandwidth saturation threshold. This forces a drop in efficiency due to the overhead of managing multiple smaller chunk invocations within a single NGINX request lifecycle.

## 6. Experimental Methodology & Instrumentation Contract

To ensure absolute rigor and prevent any benchmarking manipulation, our measurement environment (the "Iron Benchmark") strictly adheres to the following methodology and tools:

### 6.1 Benchmarking Toolchain
1. **Google Benchmark**: Used for all C++ microarchitecture tests.
2. **Hardware PMU Profiler (perf_events)**: Directly integrated into our testing harness via `ioctl`/`read` syscalls to capture L1 cache misses, branch mispredictions, and CPU cycles precisely at the function boundary.
3. **wrk2**: Utilized for End-to-End (E2E) integration benchmarking against the full NGINX stack. Unlike traditional `wrk`, `wrk2` avoids coordinated omission, providing a much more accurate latency distribution profile capturing tail latency (`P50`, `P90`, `P95`, `P99`).
4. **libFuzzer**: Employed for semantic equivalence testing against the reference DFA implementation.

### 6.2 Workload Specification Model
* **Dataset Size Normalization**: All microarchitectural workloads are normalized to exactly 1KB payload chunks to eliminate algorithmic scaling bias.
* **The 1000 Rules**: To perform a fair comparison against PCRE-based engines, we load exactly 1000 real-world firewall rules sourced from the **OWASP ModSecurity Core Rule Set (CRS)**. This accurately simulates the "Rule Explosion" phenomenon.
* **Adversarial Saturation**: Synthetic and corpus datasets are seeded with known aggressive HTTP exploitation vectors (derived from **SecLists**). Branch penalty is measured across a spectrum of `%XX` saturation levels (from 0% to 100%).
* **Cache State Definition**: Tests are explicitly divided into `Warm Cache` (L1d preloaded) and `Cold Cache` (cache flushes invoked between iterations) states.

### 6.3 Execution Environment Control
To eliminate scheduler noise and OS interference:
* **Core Isolation**: Benchmark threads are strictly isolated using the `isolcpus` kernel parameter.
* **CPU Governors**: Frequencies are pinned, and Turbo Boost behavior is locked via Performance Governors to prevent thermal throttling jitter.
* **Idle State Enforcement**: The system must remain entirely idle, measuring wall-clock performance free from external multi-tenant noise.

### 6.4 Statistical Model
To guarantee a peer-review safe reproducibility contract:
* **Primary Metric**: `Median` is utilized as the primary central tendency metric to resist outlier skewing.
* **Secondary Metric**: `Mean` is reported alongside `StdDev` and Coefficient of Variation (`CV`).
* **Iteration Count**: All values are reported across $N \geq 10$ runs per workload.
* **Warm-up**: Explicit warm-up iterations are discarded before telemetry aggregation begins.

## 7. Execution Model Assumptions

To ground all claims regarding CPU determinism, we explicitly define the microarchitectural abstraction boundaries within which LuminaWAF is evaluated:
* **Front-End Bottlenecks**: Front-end saturation is measured via µop cache residency and decode bandwidth pressure (4–6 uops/cycle limit). L1i cache misses serve as an explicit proxy for front-end starvation.
* **In-Order vs Out-of-Order (OoO) Execution**: While the parser instructions are executed out-of-order, our performance model abstracts this by observing retired instructions (`IPC`) at the function boundary, accepting OoO pipeline reordering as a non-deterministic but bounded variable.
* **Cache Hierarchy**: The L1d/L1i and L2 caches are assumed to be statically mapped for the duration of a `Warm Cache` benchmark loop, though OS context switching and TLB shootdowns introduce probabilistic jitter (mitigated by `isolcpus`).
* **Prefetcher Non-Determinism**: Hardware prefetcher behavior (e.g., L2 Streamer) is inherently heuristic-based. We cannot guarantee deterministic prefetch hits, but we enforce alignment limits (32-byte chunks) to probabilistically bound the latency penalty.
