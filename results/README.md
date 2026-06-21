# Experimental Data & Validation Ledger

This document presents empirical results regarding the performance and semantic correctness of the LuminaWAF microarchitecture. All data was collected under controlled conditions to evaluate throughput, latency distribution, and hardware engine metrics.

The primary artifact containing the cryptographically sealed system outputs is available here:
[LuminaWAF_Iron_Report_20260621_113607.md](../final_reports/LuminaWAF_Iron_Report_20260621_113607.md)

## 1. Hardware Environment Specification

Measurements were conducted in an isolated environment to minimize OS scheduler interference.

| Parameter                 | Configuration |
| ------------------------- | ------------- |
| **CPU Architecture**      | x86_64 (Intel i5-4210H) |
| **Linux Kernel**          | 6.x (Ubuntu 22.04) |
| **Core Isolation**        | `isolcpus` enabled for the benchmarking process. |
| **C-States Management**   | C-States disabled at BIOS/GRUB level. |
| **Base Compiler**         | Clang/GCC (-O3 -flto -march=native -DNDEBUG) |

*Note on CPU Specifications: You may notice differences between `lscpu` (which reports aggregate physical topology, e.g., 2.90 GHz Base Clock and 512 KiB shared L2 cache) and Google Benchmark logs (which report active Turbo frequency, e.g., 3.5 GHz, and per-core L2 cache of 256 KiB). Both are physically accurate descriptions of the same i5-4210H processor.*

## 2. Differential Validation (Data Parity)

Semantic correctness of the vectorized implementation was evaluated in two phases against the reference scalar parser (`ngx_unescape_uri` / ModSecurity PCRE engine):

**Phase 1: Differential Red Team Fuzzing**
- Evaluated 10,000 mutated adversarial payloads (case swapping, double encoding, Unicode tricks) on a live NGINX integration.
- Result: 0 divergences, 0 False Positives, 0 False Negatives.

**Phase 2: Continuous libFuzzer Execution**
- Executed continuous in-process memory fuzzing with `-fsanitize=fuzzer,address,undefined`.
- Result: The analysis identified 0 memory defects and 0 deviations in output, with no semantic divergence observed across $2 \cdot 10^9$ fuzz iterations against the reference implementation.

## 3. The Iron Benchmark Harness Procedure

To mitigate coordinated omission and measurement bias, all validation steps are orchestrated by a deterministic harness (`tools/iron_benchmark.sh`). The procedure consists of four stages:

1. **Compilation Enforcement**: Clears `CMakeCache.txt` and enforces `-DNDEBUG` and `-O3` to prevent debug symbols from affecting execution time.
2. **Microarchitectural Evaluation**: Executes Google Benchmark suites using 1000 rules from the ModSecurity Core Rule Set under varying L1 cache conditions (Warm/Cold).
3. **Branch Penalty Saturation**: Evaluates parser degradation under worst-case branching scenarios by injecting 100% URL-encoded payloads (`%XX`).
4. **End-to-End Saturation (`wrk2`)**: Measures the full NGINX proxy stack throughput against a 1000-connection baseline to observe latency distributions.

## 4. Empirical Performance Snapshot

**Methodological Rigor Statement:**
* All workloads are normalized to identical input size distributions unless explicitly stated (e.g., branch saturation tests).
* All microbenchmark values are reported as the median of $N \geq 10$ runs to establish a reliable baseline.
* Throughput is reported as end-to-end processed payload bandwidth, not raw memory bus utilization.

The following table summarizes the throughput and latency metrics of the SIMD AVX2 pipeline compared to the DFA scalar baseline (ModSecurity).

| Metric | Vanilla NGINX | LuminaWAF | ModSecurity (Baseline) |
| :--- | :--- | :--- | :--- |
| **Micro Benchmark (Warm Cache)** | N/A | **2.01 MiB/s** | 0.59 MiB/s |
| **Micro Benchmark (Cold Cache)** | N/A | **1.98 MiB/s** | - |
| **Synthetic (0% Branch Penalty)** | N/A | **2.05 MiB/s** | N/A |
| **Synthetic (100% Branch Penalty)**| N/A | **0.80 MiB/s** | N/A |
| **Corpus Throughput (Mmap)** | N/A | **1.23 MiB/s** | N/A |
| **wrk2 E2E (1000 connections)** | 105,112 Req/s | **94,772 Req/s** | 85,415 Req/s |

### Analysis:
Under isolated warm-cache conditions on 1KB payloads, the LuminaWAF architecture achieves approximately 2.01 MiB/s throughput, representing a 3.4x factor improvement over the scalar baseline under identical warm-cache 1KB payload workloads.

In worst-case adversarial loads (100% branch penalty saturation), the throughput degrades to 0.80 MiB/s. This indicates that while the vectorized pipeline is sensitive to encoded data density, the fallback behavior is functionally deterministic in control flow, though performance characteristics remain input-sensitive. End-to-end integration metrics show an approximate 10% gain in overall server throughput when deployed as an NGINX module under high connection concurrency.
