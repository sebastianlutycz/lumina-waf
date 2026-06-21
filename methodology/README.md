# LuminaWAF Internals and Design Decisions

This document outlines the low-level optimizations, AVX2 SIMD mechanisms, and memory layout decisions that enable LuminaWAF's performance profile.

## 1. Branchless Parsing with AVX2

Most standard NGINX parsers (such as `ngx_unescape_uri`) rely on traditional state machines. They process data byte-by-byte, using conditional `if/switch` logic to identify URL-encoded characters (`%XX`), letters, or numbers.

When parsing heavily URL-encoded or obfuscated payloads, the CPU's branch predictor frequently mispredicts, causing pipeline flushes and wasting CPU cycles. This leads to latency spikes during attacks.

**The Solution:** 
LuminaWAF mitigates this using an Atomic Bitmap Branchless (ABB) approach built on AVX2 intrinsics. Instead of byte-by-byte conditional checks, the parser:
1. Loads 32 bytes of the payload at once into a 256-bit YMM register.
2. Uses `_mm256_cmpeq_epi8` to generate a bitmask identifying all `%` characters in the 32-byte chunk.
3. Uses byte shuffle instructions (`_mm256_shuffle_epi8`) to perform parallel table lookups directly within the SIMD registers.

By replacing control-flow branching with data-flow bitwise operations, the primary performance constraint shifts from branch prediction to SIMD instruction throughput. This results in a flat, predictable processing time, regardless of payload obfuscation.

## 2. Memory Alignment and SoA (Struct of Arrays)

Memory bandwidth is a critical bottleneck in high-throughput parsers. LuminaWAF enforces strict 32-byte alignment (`alignas(32)`) for its internal data structures to align with AVX2 memory requirements.

This alignment prevents split cache-line accesses and improves the predictability of memory access patterns for the hardware prefetcher (e.g., the L2 Streamer). When streaming large HTTP payloads, the CPU is more likely to have the necessary data loaded into the L1 cache before the SIMD registers request it, significantly reducing memory latency.

## 3. The "Phase Ordering Problem" and LuminaC

Relying purely on standard compilers (Clang/GCC with `-O3 -march=native`) for heavily vectorized code often yields suboptimal results due to the Phase Ordering Problem. Compilers may make premature loop unrolling decisions before finalizing structure memory offsets, missing critical cache optimization opportunities.

To address this, the final AVX2 implementation was optimized using a custom profiling toolchain called **LuminaC** (available in the adjacent repository).

**The LuminaC Workflow:**
1. The C/C++ parser is compiled to LLVM IR.
2. LuminaC executes the IR within a JIT Sandbox, applying evolutionary mutations to loop unrolling parameters and memory alignments.
3. Each mutation is benchmarked on the actual hardware using the Performance Monitor Unit (PMU) to measure real CPU cycles and L1 cache misses.
4. The toolchain selects the optimal mutation for the specific microarchitecture and emits a precompiled `.o` object file.

This process generated the `parser_v3.o` file included in this repository. (See the main README for security considerations regarding this file).

## 4. Edge Cases and Fallback Mechanisms

While the SIMD pipeline is highly efficient for most traffic, it has recognized degradation modes:

* **Mask Saturation:** If a 32-byte chunk consists almost entirely of `%XX` sequences (over 85% saturation), SIMD lane utilization drops. In this extreme scenario, the overhead of applying multiple longitudinal bitmasks exceeds the cost of scalar parsing. LuminaWAF detects this and falls back to a sequential scalar decoder to prevent a performance collapse.
* **Memory Limits:** To guarantee zero dynamic allocations on the hot path, LuminaWAF utilizes a pre-allocated memory pool (currently 16 KB per request context). If a request URI exceeds this size, the engine must process it in chunks, introducing minor management overhead.

## 5. Benchmarking Methodology

To ensure performance claims are accurate and reproducible, the following strict benchmarking methodology was applied:
* **Google Benchmark** for isolated microarchitectural testing.
* **Hardware PMU (perf_events)** for exact counting of L1 cache misses and branch mispredictions.
* **wrk2** for End-to-End NGINX integration tests, chosen specifically to avoid coordinated omission and provide accurate tail-latency distributions.
* **System Isolation:** CPU scaling governors were disabled and `isolcpus` was used to pin threads, eliminating OS scheduler noise during testing.

Validation was performed against a subset of 1000 rules from the **OWASP ModSecurity Core Rule Set (CRS)** to simulate a realistic production rule-matching workload.
