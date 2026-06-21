# LuminaWAF: The Hardware-Software Co-Design Firewall

LuminaWAF is an ultra-low latency, branchless Web Application Firewall engine designed for NGINX. By abandoning scalar parsing loops in favor of SIMD (AVX2) instructions and Struct-of-Arrays (SoA) memory alignment, it achieves a deterministic, flat-tail latency profile regardless of adversarial load.

> **Snapshot Dashboard (deterministic projection of immutable benchmark runs; no cross-run aggregation):**
> Visit our interactive benchmark matrix at [GitHub Pages](https://sebastianlutycz.github.io/lumina-waf/) to see throughput metrics, tail latency stability, and flat memory footprint.
> 
> *Current Local Validation:*
> - Platform: Intel i5-4210H
> - Metric: median of $N \geq 10$ runs
> - Noise: CV < 5%
> - Selection Policy: all runs included; no outlier removal unless system state violation is detected (thermal throttle / scheduler anomaly)
> - Workload: 1000-rule CRS subset + normalized 1KB URI corpus

## 🔬 Project Nature: The LuminaC Validation Harness

LuminaWAF is a validation-driven execution artifact designed to evaluate compiler-level and microarchitectural optimization strategies under real CPU constraints. This project serves as a **rigorous validation harness** for our experimental evolutionary compiler toolchain: **LuminaC** (available in the [LuminaC Repository](https://github.com/sebastianlutycz/LuminaC)).

### The Goal of the Experiment
The primary objective was to verify whether genetically-driven code transformations at the LLVM IR level (such as aggressive, non-linear loop unrolling targeting the Trace Cache or AoS -> SoA memory layout transformations) could yield real, measurable performance gains against critical, hand-optimized system components, such as the URI/Header parser within the NGINX core.

### Why Does It Matter?
Standard compilers (Clang/GCC) rely on static, generalized heuristics. LuminaC optimizes code "in vivo" (JIT/PGO), measuring actual CPU cycles and cache misses via hardware Performance Monitor Unit (PMU) counters on a specific microarchitecture.

LuminaWAF is the direct, tangible result of this process—a binary proof that eliminating the *Phase Ordering Problem* can reduce overhead in specific hot-path components (URI/header parsing pipeline) by approximately 15–30% under controlled microarchitectural conditions, where traditional `-O3 -march=native` flags hit an insurmountable wall.

## Quick Start & Reproduction

LuminaWAF utilizes a **Dual-Path Build Architecture** to maximize accessibility while preserving the full power of hardware-specific genetic evolution. 

### Prerequisites
- Clang 18 or GCC 13+
- CMake 3.20+
- Linux (for hardware PMU profiling)

### Path A: Pre-Optimized AOT (Default)
By default, the build system links a pre-evolved genetic module (`parser_v3.o`) optimized for `Prefetch(256B) + Devirt`. In our hardware tests (Intel i5-4210H), this provided a ~4x parsing performance improvement and achieved ~94,000 req/s under 1000 concurrent NGINX connections. This path does not require compiling the LuminaC LLVM infrastructure.

```bash
git clone https://github.com/sebastianlutycz/lumina-waf.git
cd lumina-waf
mkdir build && cd build
cmake -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ ..
make -j4
```

### Path B: True Genetic Evolution (Power Users)
If you are deploying on a different microarchitecture (e.g., AVX-512, ARM Graviton) and wish to run the JIT Sandbox to empirically evaluate the optimal mutation for your specific silicon, you can invoke the orchestrator natively:

1. Compile the [LuminaC Orchestrator](https://github.com/sebastianlutycz/LuminaC) in the adjacent directory.
2. Enable the evolutionary compiler during CMake configuration:
```bash
cmake -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DENABLE_GENETIC_COMPILER=ON ..
make -j4
```
*Note: This will spawn the JIT Sandbox, mutate the LLVM IR across multiple memory/branch variants, empirically evaluate the execution cycles via Hot/Cold Cache runs, and generate a `.o` object file tailored to your CPU.*

### Run Zero-Trust Testing
Validate bit-perfect compliance using our LLVM libFuzzer harness compiled with ASan and UBSan:
```bash
./build/lumina_fuzzer -max_total_time=60
```

### Run Microarchitectural Benchmarks
Execute the isolated branch-miss penalty evaluations:
```bash
./build/synthetic_bench
./build/corpus_bench
```

### Integrate with NGINX
LuminaWAF is designed as a standard dynamic NGINX module. To load it into your own NGINX stack:

1. Download the exact same NGINX source code version that you are currently running.
2. Compile NGINX with the LuminaWAF module:
```bash
wget http://nginx.org/download/nginx-1.24.0.tar.gz
tar -zxvf nginx-1.24.0.tar.gz
cd nginx-1.24.0
./configure --with-compat --add-dynamic-module=../lumina-waf/nginx_module
make modules
```
3. Copy the resulting `objs/ngx_http_luminawaf_module.so` to your NGINX modules directory (e.g., `/etc/nginx/modules/`).
4. Load the module in the main `nginx.conf` context:
```nginx
load_module modules/ngx_http_luminawaf_module.so;
```

## C ABI Definition
LuminaWAF strictly guarantees a zero-dynamic-allocation hot path, adhering to embedded software constraints. The C interface exposes no C++ types and completely mitigates heap fragmentation.

```c
typedef struct {
    int error_flag;
    int threat_level;
    const char* decoded_buffer;
    size_t decoded_length;
} LuminaResult;

int luminawaf_init_worker(size_t expected_concurrent_connections);
int luminawaf_inspect_request(const unsigned char* uri_data, size_t uri_len, LuminaResult* out_result);
void luminawaf_destroy_worker();

// Memory Contract:
// All pointers returned by LuminaWAF are valid until the next call on the same worker context.
// No cross-thread ownership is permitted.
//
// Thread Safety:
// Worker instances are not thread-safe. Each thread must maintain its own worker context.
```

## Non-Goals

LuminaWAF does not aim to:
- Provide formal security guarantees against all attack classes.
- Replace full WAF rule engines in compliance-heavy environments.
- Guarantee identical performance across heterogeneous microarchitectures.
- Optimize for scalar workloads where SIMD utilization is low.
- Assume idealized workload representativeness beyond defined benchmark corpus distributions.

## Deep Technical Documentation

For engineers seeking raw micrometrics and rigorous systems evaluation, the documentation is strictly decoupled into a hierarchical truth model:

**Primary Source of Truth:**
* [Experimental Methodology](./methodology/README.md) - Measurement contract, noise models, system isolation, and reproducibility rules.

**Derived Mechanisms:**
* [Architecture & Cost Model](./methodology/README.md) - SIMD AVX2 pipeline logic, Branchless Bitmap mechanisms, and the formal cost model.

**Empirical Validation Layer:**
* [Empirical Data](./results/README.md) - Fuzzing equivalence, synthetic stress bounds, and raw PMU telemetry.

**Immutable Execution Artifacts:**
* `final_reports/*` - Sealed benchmark runs.
