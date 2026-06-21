# LuminaWAF: A High-Performance, Branchless Web Application Firewall

LuminaWAF is a high-performance Web Application Firewall engine designed for NGINX. It explores the application of low-level microarchitectural optimizations—specifically SIMD AVX2 instructions and Struct-of-Arrays (SoA) memory alignment—to the problem of HTTP payload parsing.

Traditional NGINX parsers rely on sequential `if/switch` loops, which are highly susceptible to branch mispredictions when processing obfuscated or heavily URL-encoded payloads. LuminaWAF mitigates this by utilizing branchless AVX2 processing. This approach yields a flat, deterministic latency profile, ensuring consistent performance even under adversarial load.

> **Live Soaking Test Telemetry:**
> An interactive telemetry dashboard is available at [GitHub Pages](https://sebastianlutycz.github.io/lumina-waf/), displaying throughput metrics, tail latency stability, and overhead comparisons against vanilla NGINX and ModSecurity.
> 
> **Scope Boundary / Disclaimer:**
> Performance claims are valid only within the defined benchmark corpus, hardware configurations, and isolation constraints described in `/methodology`.

---

## Performance Context: Hardware Constraints

The primary local validation and benchmarking for this project were conducted on an **Intel i5-4210H**, a mobile processor from 2014. 

This constraint is intentional. Achieving over **105,000 requests per second** on a decade-old dual-core mobile chip via AVX2 and memory alignment serves as a proof-of-concept for the efficiency of these optimizations. The relative performance gains demonstrated here scale significantly when deployed on modern server architectures (e.g., current-generation Xeon or EPYC processors).

## SECURITY NOTICE: Precompiled Binary Object (`parser_v3.o`)

This repository contains a precompiled object file (`src/precompiled/parser_v3.o`). In a security-critical context such as a Web Application Firewall, utilizing unverified binary blobs is a significant security risk and should never be done in production.

**Purpose of the Object File:**
LuminaWAF was developed alongside a custom profiling compiler toolchain called **LuminaC**. LuminaC mutates the parser's LLVM IR, profiles it against hardware PMU counters, and emits a highly-optimized `.o` object file tailored to the specific CPU it profiled on. 

The `parser_v3.o` file included here is a cached output of that process, optimized for the i5-4210H. It is provided strictly to facilitate rapid testing, GitHub Actions CI/CD builds, and the quick-start demo without requiring users to compile the entire LuminaC LLVM infrastructure.

**Production Deployment:**
For any real-world use, **do not use the provided `.o` file**. You must build the parser from the raw `parser_input.c` source code (see **Path B** below).

---

## Quick Start & Reproduction

### Prerequisites
- Clang 18 or GCC 13+
- CMake 3.20+
- Linux (for hardware PMU profiling)

### Path A: Quick Evaluation (Uses Precompiled Blob)
This path links the provided genetic module (`parser_v3.o`). It is intended for rapid evaluation only.

```bash
git clone https://github.com/sebastianlutycz/lumina-waf.git
cd lumina-waf
mkdir build && cd build
cmake -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ ..
make -j4
```

### Path B: Build from Source (Recommended / Production)
This is the required path for secure deployment. It compiles the parser from source. If the genetic compiler is enabled, it utilizes the LuminaC JIT Sandbox to determine the optimal memory/branch variants for your specific CPU.

1. Compile the [LuminaC Orchestrator](https://github.com/sebastianlutycz/LuminaC) in the adjacent directory.
2. Enable the evolutionary compiler during CMake configuration:
```bash
cmake -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DENABLE_GENETIC_COMPILER=ON ..
make -j4
```

### Validation and Benchmarking
To validate bit-perfect compliance using the LLVM libFuzzer harness and execute microarchitectural benchmarks:
```bash
./build/lumina_fuzzer -max_total_time=60
./build/synthetic_bench
./build/corpus_bench
```

### NGINX Integration
LuminaWAF is implemented as a standard dynamic NGINX module. To integrate it:

1. Download the NGINX source code matching your target environment.
2. Compile NGINX with the LuminaWAF module:
```bash
wget http://nginx.org/download/nginx-1.24.0.tar.gz
tar -zxvf nginx-1.24.0.tar.gz
cd nginx-1.24.0
./configure --with-compat --add-dynamic-module=../lumina-waf/nginx_module
make modules
```
3. Copy the compiled module (`objs/ngx_http_luminawaf_module.so`) to your NGINX modules directory (e.g., `/etc/nginx/modules/`).
4. Load the module in your `nginx.conf`:
```nginx
load_module modules/ngx_http_luminawaf_module.so;
```

## Technical Documentation

For detailed information on the parser's internals, SIMD logic, and hardware profiling methodologies:

* [LuminaWAF Internals and Design Decisions](./methodology/README.md) - Deep dive into the AVX2 parser, memory alignment strategies, and identified edge cases.
* [Empirical Data](./results/README.md) - Results from fuzzing equivalence tests, synthetic stress bounds, and raw PMU telemetry.
