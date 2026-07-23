# LuminaWAF Benchmark Harness v1

> **CANONICAL** - all canonical phases passed

## Evidence

- Protocol: `V1.0`
- Run mode: `canonical`
- CRS commit: `fe593879e90b34ac6cf3e63151d48df0a4784790`
- CRS manifest: `4123125ca52d7f0247179073cf1bedbb99fea40aeb9ec1fd1eebc6d1aea40994`
- Source inbound CRS PL2 rule IDs: `423`
- Generated Lumina execution units: `229`
- Native runtime-covered source IDs: `9`
- Distinct source IDs represented directly by generated/native execution: `237`
- Rule-count note: setup, chain and non-score-bearing source rules are not one-to-one execution units; semantic coverage is established by the oracle gate, not by dividing execution-unit count by source-rule count.
- Workload SHA256: `279e86a07fc480cb736122719e94ca4a8d34a56819e480201787deeda9032b01`
- Binary/module hashes: [`artifacts.json`](artifacts.json)
- Build provenance and effective flags: [`build_provenance.json`](build_provenance.json), [`compile_commands.json`](compile_commands.json)
- ELF dependency and symbol audit: [`symbol_isolation.json`](symbol_isolation.json)
- Artifact integrity: [`artifact_preflight.json`](artifact_preflight.json), [`artifact_postflight.json`](artifact_postflight.json)
- Methodology: [`methodology/README.md`](../../../methodology/README.md)

## Host State Annotation

- Host profile: `isolated-baremetal`
- Operator note: Dedicated_AMD_EPYC_9124P_bare_metal_SMT_off_CPUs_1-15_isolated_CPU_0_housekeeping
- Kernel-isolated CPUs: `1-15`
- Benchmark CPU sets: `{"client": "9-10", "micro": "1", "scaling_client": "9-15", "scaling_server": "1-8", "server": "1"}`
- Governor: `performance`
- Start loadavg: `0.24 0.55 0.51 1/446 105097`
- End loadavg: `0.45 0.77 1.41 1/441 177200`
- Start CPU PSI: `some avg10=1.56 avg60=0.59 avg300=2.63 total=1299456952; full avg10=0.00 avg60=0.00 avg300=0.00 total=0`
- End CPU PSI: `some avg10=0.00 avg60=0.05 avg300=0.06 total=2283775572; full avg10=0.00 avg60=0.00 avg300=0.00 total=0`
- Start/end process count: `415` / `410`
- Raw snapshots: [`environment.json`](environment.json), [`environment_end.json`](environment_end.json)
- A host annotation documents contention but never waives canonical isolation or clean-provenance requirements.

## Publication Qualification

| Evidence class | Observed | Canonical requirement | Status |
|---|---:|---:|---|
| Independent Google Benchmark processes | 5 | >=5 | PASS |
| Inner repetitions retained | 10 | 10 raw/process | PASS |
| Engine PMU diagnostics | 3 engines | complete counters and >=90% running | PASS |
| Artifact integrity | passed | pre/post hashes identical | PASS |
| Lumina CRS oracle gate | passed | passed | PASS |
| Coraza CRS oracle gate | passed | passed | PASS |
| Fixed-rate E2E | passed | >=5 runs and >=100000 accepted/run | PASS |
| Saturation stability | passed | >=5 runs and RPS CV <=5% | PASS |
| Lumina overhead decomposition | passed | paired E0/E1/E2 + direct kernels | PASS |
| Multi-worker scaling | passed | 1/2/4/8 workers, >=5 runs, CV <=5%, client CPU <=90% | PASS |

## Sampling Plan

The fixed-rate plan is persisted before latency collection. Qualified modes calibrate against the slowest engine's stable saturation point; smoke remains a bounded diagnostic.

- Sampling class: `qualified`
- Fixed rate: `422 RPS`
- Fixed duration per engine/run: `290 s`
- Target accepted responses per run: `100000`
- Projected accepted responses at qualification floor: `110142`
- Limiting engine: `modsecurity`
- Estimated E2E wall time: `2h 50m 50s`
- Raw plan: [`sampling_plan.json`](sampling_plan.json)

## Full CRS PL2 Correctness Gates

The LuminaWAF gate checks exact matched rule IDs against ModSecurity. The stock Coraza NGINX connector exposes only the final HTTP verdict, so its row is intentionally narrower.

| Engine | Oracle | Observable contract | Positive block | Exact rule | Negative exclusion | Overall | Skips | Errors | Gate |
|---|---|---|---:|---:|---:|---:|---:|---:|---|
| `LuminaWAF vs ModSecurity` | ModSecurity-compatible pinned CRS PL2 expectations | exact rule ID + verdict | 98.33% (3117/3170) | 99.72% (3161/3170) | 99.88% (815/816) | 99.75% (3986 tests) | 22 transport / 641 selection | 0 timeout / 0 exception / 10 disagreement | PASS |
| `Coraza` | go-ftw expected HTTP verdicts | HTTP verdict (rule IDs unavailable) | N/A | N/A | N/A | 99.85% (4009 tests) | 0 transport / 779 selection | 0 timeout / 0 exception / 6 disagreement | PASS |

Raw oracle artifacts: [`correctness_lumina.json`](correctness_lumina.json), [`correctness_lumina.log`](correctness_lumina.log), [`correctness_coraza.json`](correctness_coraza.json), and [`correctness_coraza.log`](correctness_coraza.log). Missing links mean the gate was not run.

## Cross-Engine Outcome Matrix

This small immutable matrix reports comparable HTTP outcomes. It is not a replacement for the full CRS regression gates.

**The detection and false-positive figures below apply only to this small immutable outcome matrix. They must not be interpreted as full CRS PL2 parity.**

| Engine | Class | Attack detection | False positives | Contract |
|---|---|---:|---:|---|
| `baseline` | `baseline` | 0.00% | 0.00% | PASS |
| `luminawaf` | `crs` | 100.00% | 0.00% | PASS |
| `modsecurity` | `crs` | 100.00% | 0.00% | PASS |
| `coraza` | `crs` | 100.00% | 0.00% | PASS |
| `naxsi` | `native-waf` | 100.00% | 0.00% | PASS |

## Full Transaction Microbenchmark

This table includes the complete inbound transaction lifecycle exposed by each engine. It is not NGINX E2E latency. Attack rows measure time to a blocking decision and may terminate earlier than allow rows; they do not enumerate every subsequent matching rule.

| Engine / workload | Median CPU time | Inner repetition CV | Process-level 95% bootstrap CI | Processes | Qualification |
|---|---:|---:|---:|---:|---|
| `FullTransaction/Coraza/Allow` | 1.28 ms | 0.24% | 1.28 ms - 1.29 ms | 5 | QUALIFIED |
| `FullTransaction/Coraza/Attack` | 1.19 ms | 0.38% | 1.19 ms - 1.19 ms | 5 | QUALIFIED |
| `FullTransaction/LuminaWAF/Allow` | 55.47 us | 0.22% | 54.97 us - 55.64 us | 5 | QUALIFIED |
| `FullTransaction/LuminaWAF/Attack` | 32.74 us | 0.21% | 32.32 us - 32.86 us | 5 | QUALIFIED |
| `FullTransaction/ModSecurity/Allow` | 1.58 ms | 0.60% | 1.58 ms - 1.59 ms | 5 | QUALIFIED |
| `FullTransaction/ModSecurity/Attack` | 1.45 ms | 0.32% | 1.44 ms - 1.46 ms | 5 | QUALIFIED |

## LuminaWAF Overhead Decomposition (Diagnostic)

This section separates plain NGINX, the loaded disabled module, and production CRS PL2 inspection. CPU deltas are paired within the same round and connection point. Latency percentiles are shown only as absolute context and are never subtracted.

### Absolute E2E Saturation Sources

| Layer | Connections | RPS | Server CPU/request | Runs | RPS CV | Qualification |
|---|---:|---:|---:|---:|---:|---|
| `baseline` | 1 | 22826.82 | 28.57 us | 5 | 0.37% | QUALIFIED |
| `baseline` | 10 | 42898.88 | 23.31 us | 5 | 0.25% | QUALIFIED |
| `baseline` | 100 | 43177.80 | 23.16 us | 5 | 0.31% | QUALIFIED |
| `luminawaf` | 1 | 7130.40 | 126.94 us | 5 | 0.50% | QUALIFIED |
| `luminawaf` | 10 | 9373.02 | 105.08 us | 5 | 0.73% | QUALIFIED |
| `luminawaf` | 100 | 9574.88 | 103.90 us | 5 | 1.48% | QUALIFIED |
| `luminawaf-loaded-off` | 1 | 22905.43 | 28.47 us | 5 | 0.50% | QUALIFIED |
| `luminawaf-loaded-off` | 10 | 43035.69 | 23.23 us | 5 | 0.51% | QUALIFIED |
| `luminawaf-loaded-off` | 100 | 43175.87 | 23.16 us | 5 | 0.42% | QUALIFIED |

### Paired Server CPU Deltas

| Delta | Connections | Median paired delta | Paired 95% bootstrap CI | Pairs | Qualification |
|---|---:|---:|---:|---:|---|
| `E1 loaded-off - E0 baseline` | 1 | 77.0 ns | -142.0 ns - 206.4 ns | 5 | QUALIFIED |
| `E2 PL2 - E1 loaded-off` | 1 | 98.44 us | 98.09 us - 99.65 us | 5 | QUALIFIED |
| `E1 loaded-off - E0 baseline` | 10 | -112.4 ns | -222.6 ns - 144.6 ns | 5 | QUALIFIED |
| `E2 PL2 - E1 loaded-off` | 10 | 81.69 us | 81.37 us - 84.15 us | 5 | QUALIFIED |
| `E1 loaded-off - E0 baseline` | 100 | -12.1 ns | -111.5 ns - 247.3 ns | 5 | QUALIFIED |
| `E2 PL2 - E1 loaded-off` | 100 | 80.65 us | 79.62 us - 84.17 us | 5 | QUALIFIED |

### Absolute Fixed-Rate Latency

| Layer | Rate | p50 | p90 | p99 | p99.9 | Runs | Min samples/run | Qualification |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| `baseline` | 5623 | 734.00 us [731.00 us - 737.00 us] | 1.20 ms [1.20 ms - 1.21 ms] | 1.36 ms [1.35 ms - 1.38 ms] | 1.50 ms [1.49 ms - 1.51 ms] | 5 | 123645 | QUALIFIED |
| `luminawaf` | 5623 | 1.11 ms [1.10 ms - 1.13 ms] | 1.80 ms [1.74 ms - 1.89 ms] | 2.31 ms [2.21 ms - 2.36 ms] | 2.60 ms [2.51 ms - 2.65 ms] | 5 | 123642 | QUALIFIED |
| `luminawaf-loaded-off` | 5623 | 735.00 us [728.00 us - 737.00 us] | 1.20 ms [1.19 ms - 1.20 ms] | 1.35 ms [1.32 ms - 1.37 ms] | 1.46 ms [1.43 ms - 1.50 ms] | 5 | 123644 | QUALIFIED |

### Direct Allow-Rotation Kernels

| Boundary | Median CPU time | Inner CV | Process-level 95% bootstrap CI | Processes | Qualification |
|---|---:|---:|---:|---:|---|
| `Overhead/LuminaWAF/BundleBuild/AllowRotation` | 64.2 ns | 0.11% | 64.2 ns - 64.6 ns | 5 | QUALIFIED |
| `Overhead/LuminaWAF/FullDirect/AllowRotation` | 47.25 us | 0.14% | 47.12 us - 47.31 us | 5 | QUALIFIED |
| `Overhead/LuminaWAF/InspectPrebuilt/AllowRotation` | 47.22 us | 0.25% | 47.15 us - 47.30 us | 5 | QUALIFIED |

### Integration Residual

The residual is `paired (E2-E1) CPU/request - FullDirect CPU`. It is an accounting observation covering NGINX projection and response integration, not a function timer.

| Connections | Median residual | Combined bootstrap 95% CI | E2E pairs | Direct processes | Qualification |
|---:|---:|---:|---:|---:|---|
| 1 | 51.19 us | 50.82 us - 52.40 us | 5 | 5 | QUALIFIED |
| 10 | 34.44 us | 34.12 us - 36.90 us | 5 | 5 | QUALIFIED |
| 100 | 33.40 us | 32.36 us - 36.92 us | 5 | 5 | QUALIFIED |

### Direct-Kernel PMU

| Kernel | Cycles/transaction | Instructions/transaction | IPC | Branch misses | Cache misses | L1D misses | LLC misses | iTLB misses | Running | Quality |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| `fulldirect` | 146553 | 445455 | 3.040 | 0.47% | 1.00% | 0.66% | unavailable | 0.01% | 100.00% | QUALIFIED |
| `inspectprebuilt` | 146491 | 444944 | 3.037 | 0.46% | 0.90% | 0.69% | unavailable | 0.01% | 100.00% | QUALIFIED |

Raw evidence: [`overhead_saturation/results.json`](overhead_saturation/results.json), [`overhead_fixed/results.json`](overhead_fixed/results.json), and [`overhead_micro_qualification.json`](overhead_micro_qualification.json), plus [`overhead_pmu_qualification.json`](overhead_pmu_qualification.json). Empty-policy evidence is intentionally absent until a separately hashed generated-policy build exists.

## E2E Fixed-Rate Latency

Values are medians across independent runs; brackets contain the 95% bootstrap CI. The immutable performance rotation contains six HTTP/1.1 GET requests with empty bodies, so this section measures URI, query and request-header inspection rather than request-body ingestion.

| Engine | Rate | p50 [95% CI] | p90 [95% CI] | p99 [95% CI] | p99.9 [95% CI] | Max | Runs | Min samples/run | RPS CV | Qualification |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| `baseline` | 422 | 1.03 ms [1.03 ms - 1.04 ms] | 1.15 ms [1.14 ms - 1.16 ms] | 1.22 ms [1.21 ms - 1.24 ms] | 1.37 ms [1.35 ms - 1.39 ms] | 1.62 ms | 5 | 122382 | 0.00% | QUALIFIED |
| `coraza` | 422 | 2.08 ms [2.06 ms - 2.28 ms] | 3.20 ms [3.08 ms - 3.50 ms] | 6.56 ms [6.47 ms - 6.89 ms] | 8.15 ms [7.87 ms - 8.62 ms] | 10.04 ms | 5 | 122380 | 0.00% | QUALIFIED |
| `luminawaf` | 422 | 733.00 us [728.00 us - 735.00 us] | 1.16 ms [1.15 ms - 1.16 ms] | 1.80 ms [1.80 ms - 1.82 ms] | 2.11 ms [2.10 ms - 2.12 ms] | 2.21 ms | 5 | 122382 | 0.00% | QUALIFIED |
| `modsecurity` | 422 | 2.41 ms [2.34 ms - 2.48 ms] | 3.33 ms [3.12 ms - 3.47 ms] | 4.00 ms [3.87 ms - 4.05 ms] | 4.37 ms [4.28 ms - 4.43 ms] | 4.82 ms | 5 | 122381 | 0.00% | QUALIFIED |

## Saturation

| Engine | Sustainable RPS | Connections | CPU/request | Runs | RPS CV | Qualification |
|---|---:|---:|---:|---:|---:|---|
| `baseline` | 43126.94 | 200 | 23.18 us | 5 | 0.48% | QUALIFIED |
| `coraza` | 774.17 | 10 | 1.29 ms | 5 | 0.25% | QUALIFIED |
| `luminawaf` | 9570.88 | 50 | 103.00 us | 5 | 0.42% | QUALIFIED |
| `modsecurity` | 704.01 | 50 | 1.42 ms | 5 | 0.68% | QUALIFIED |

A point is sustainable only with the required independent runs, zero response errors and RPS CV no greater than 5%.
CPU/request is NGINX master-plus-direct-worker `utime+stime` from `/proc/<pid>/stat` divided by completed requests. It excludes the load generator and is diagnostic at the kernel clock-tick resolution recorded in `e2e_saturation/results.json`.

## Multi-Worker Scaling

This optional publication supplement measures throughput scaling independently from the primary single-worker latency and efficiency results. Every row uses isolated, disjoint server/client CPU sets. Client saturation invalidates a row; a client-limited plain-NGINX baseline remains visible but does not invalidate WAF scaling qualification. Saturation latency is not reported as service latency. NAXSI remains a native-WAF reference.

- Worker points: `[1, 2, 4, 8]`
- Server CPU pool: `1,2,3,4,5,6,7,8`
- Client CPU pool: `9,10,11,12,13,14,15`
- Estimated measurement time: `3h 20m 0s`

| Engine | Class | Workers | RPS | Speedup | Efficiency | RPS/worker | CPU/request | Connections | Client CPU median/max | Runs | RPS CV | Qualification |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| `baseline` | `baseline` | 1 | 43250.50 | 1.00x | 100.00% | 43250.50 | 23.11 us | 10 | 13.81% / 13.92% | 5 | 0.32% | QUALIFIED |
| `coraza` | `crs` | 1 | 769.42 | 1.00x | 100.00% | 769.42 | 1.30 ms | 50 | 0.32% / 0.32% | 5 | 0.30% | QUALIFIED |
| `luminawaf` | `crs` | 1 | 9481.07 | 1.00x | 100.00% | 9481.07 | 105.47 us | 50 | 3.09% / 3.14% | 5 | 0.55% | QUALIFIED |
| `modsecurity` | `crs` | 1 | 704.81 | 1.00x | 100.00% | 704.81 | 1.42 ms | 10 | 0.29% / 0.29% | 5 | 0.13% | QUALIFIED |
| `naxsi` | `native-waf` | 1 | 29594.95 | 1.00x | 100.00% | 29594.95 | 33.78 us | 10 | 9.44% / 9.48% | 5 | 0.42% | QUALIFIED |
| `baseline` | `baseline` | 2 | 86279.31 | 1.99x | 99.74% | 43139.65 | 23.17 us | 50 | 26.39% / 26.70% | 5 | 0.88% | QUALIFIED |
| `coraza` | `crs` | 2 | 1537.86 | 2.00x | 99.94% | 768.93 | 1.28 ms | 10 | 0.57% / 0.57% | 5 | 0.34% | QUALIFIED |
| `luminawaf` | `crs` | 2 | 18970.22 | 2.00x | 100.04% | 9485.11 | 104.21 us | 100 | 6.09% / 6.12% | 5 | 0.67% | QUALIFIED |
| `modsecurity` | `crs` | 2 | 1417.08 | 2.01x | 100.53% | 708.54 | 1.41 ms | 10 | 0.52% / 0.53% | 5 | 0.53% | QUALIFIED |
| `naxsi` | `native-waf` | 2 | 59124.73 | 2.00x | 99.89% | 29562.37 | 33.82 us | 100 | 18.35% / 18.59% | 5 | 0.77% | QUALIFIED |
| `baseline` | `baseline` | 4 | 170360.71 | 3.94x | 98.47% | 42590.18 | 23.45 us | 50 | 49.32% / 50.22% | 5 | 0.93% | QUALIFIED |
| `coraza` | `crs` | 4 | 3048.48 | 3.96x | 99.05% | 762.12 | 1.31 ms | 50 | 1.06% / 1.06% | 5 | 0.65% | QUALIFIED |
| `luminawaf` | `crs` | 4 | 38068.05 | 4.02x | 100.38% | 9517.01 | 104.97 us | 200 | 12.00% / 12.15% | 5 | 0.56% | QUALIFIED |
| `modsecurity` | `crs` | 4 | 2839.06 | 4.03x | 100.70% | 709.76 | 1.41 ms | 200 | 1.01% / 1.02% | 5 | 0.38% | QUALIFIED |
| `naxsi` | `native-waf` | 4 | 117233.56 | 3.96x | 99.03% | 29308.39 | 34.07 us | 200 | 34.91% / 35.27% | 5 | 0.45% | QUALIFIED |
| `baseline` | `baseline` | 8 | 341652.43 | 7.90x | 98.74% | 42706.55 | 23.35 us | 200 | 86.11% / 86.73% | 5 | 0.52% | QUALIFIED |
| `coraza` | `crs` | 8 | 6047.31 | 7.86x | 98.24% | 755.91 | 1.32 ms | 200 | 2.02% / 2.04% | 5 | 0.25% | QUALIFIED |
| `luminawaf` | `crs` | 8 | 75966.78 | 8.01x | 100.16% | 9495.85 | 105.20 us | 200 | 23.01% / 23.20% | 5 | 0.95% | QUALIFIED |
| `modsecurity` | `crs` | 8 | 5682.75 | 8.06x | 100.79% | 710.34 | 1.41 ms | 100 | 1.90% / 1.91% | 5 | 0.29% | QUALIFIED |
| `naxsi` | `native-waf` | 8 | 233927.27 | 7.90x | 98.80% | 29240.91 | 34.12 us | 200 | 63.52% / 63.77% | 5 | 0.32% | QUALIFIED |

Raw scaling plan and aggregate evidence: [`e2e_scaling/plan.json`](e2e_scaling/plan.json), [`e2e_scaling/results.json`](e2e_scaling/results.json).

## PMU Diagnostics

Grouped counters are diagnostics for the allow transaction, not headline latency. Qualification details are retained in [`pmu_qualification.json`](pmu_qualification.json).

| Engine | Cycles/transaction | Instructions/transaction | IPC | Branch misses | Cache misses | L1D misses | LLC misses | iTLB misses | Minimum running | Quality |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| `coraza` | 4102249 | 12586580 | 3.068 | 0.68% | 14.75% | 1.43% | unavailable | 0.61% | 100.00% | QUALIFIED |
| `luminawaf` | 175574 | 553171 | 3.151 | 0.21% | 0.67% | 0.70% | unavailable | 0.01% | 100.00% | QUALIFIED |
| `modsecurity` | 4931781 | 14788435 | 2.999 | 0.39% | 13.73% | 1.45% | unavailable | 0.10% | 100.00% | QUALIFIED |

## Native-WAF Reference (Not CRS)

NAXSI does not execute OWASP CRS. It is reported as a native implementation-class reference and never enters the CRS-equivalence ranking.

| Engine | Rate | p50 | p90 | p99 | p99.9 | Max | Runs | Min samples/run | Qualification |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---|
| `naxsi` | 422 | 643.00 us [634.00 us - 674.00 us] | 1.53 ms [1.52 ms - 1.54 ms] | 1.73 ms [1.73 ms - 1.75 ms] | 1.87 ms [1.86 ms - 1.88 ms] | 2.00 ms | 5 | 122382 | QUALIFIED |

| Engine | Sustainable RPS | Connections | CPU/request | Runs | RPS CV | Qualification |
|---|---:|---:|---:|---:|---:|---|
| `naxsi` | 29600.56 | 200 | 33.78 us | 5 | 0.28% | QUALIFIED |

## Scope

LuminaWAF, ModSecurity and Coraza may enter the CRS PL2 table only after the shared manifest and correctness gates pass. NAXSI is reported separately because it does not execute OWASP CRS. Synthetic rule scaling never appears in either table.

## Raw Google Benchmark Output

The console output below is embedded verbatim. Corresponding machine-readable JSON is linked; canonical artifacts are required to retain every inner repetition and aggregate row.

### `micro.log`

Raw JSON: [`micro.json`](micro.json)

```text
2026-07-23T07:18:56+00:00
Running /srv/lumina-canonical/LuminaWAF/build/lumina_benchmark_harness
Run on (16 X 2988.87 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB (x16)
  L1 Instruction 32 KiB (x16)
  L2 Unified 1024 KiB (x16)
  L3 Unified 16384 KiB (x4)
Load Average: 3.83, 1.51, 0.84
---------------------------------------------------------------------------------------------------------------
Benchmark                                                     Time             CPU   Iterations UserCounters...
---------------------------------------------------------------------------------------------------------------
FullTransaction/LuminaWAF/Allow/repeats:10                54989 ns        54989 ns        25628 bytes_per_second=781.413Ki/s
FullTransaction/LuminaWAF/Allow/repeats:10                55109 ns        55109 ns        25628 bytes_per_second=779.702Ki/s
FullTransaction/LuminaWAF/Allow/repeats:10                55187 ns        55187 ns        25628 bytes_per_second=778.604Ki/s
FullTransaction/LuminaWAF/Allow/repeats:10                55191 ns        55191 ns        25628 bytes_per_second=778.546Ki/s
FullTransaction/LuminaWAF/Allow/repeats:10                55060 ns        55060 ns        25628 bytes_per_second=780.404Ki/s
FullTransaction/LuminaWAF/Allow/repeats:10                55052 ns        55052 ns        25628 bytes_per_second=780.519Ki/s
FullTransaction/LuminaWAF/Allow/repeats:10                54918 ns        54918 ns        25628 bytes_per_second=782.416Ki/s
FullTransaction/LuminaWAF/Allow/repeats:10                54869 ns        54869 ns        25628 bytes_per_second=783.113Ki/s
FullTransaction/LuminaWAF/Allow/repeats:10                54874 ns        54874 ns        25628 bytes_per_second=783.045Ki/s
FullTransaction/LuminaWAF/Allow/repeats:10                55043 ns        55043 ns        25628 bytes_per_second=780.633Ki/s
FullTransaction/LuminaWAF/Allow/repeats:10_mean           55029 ns        55029 ns           10 bytes_per_second=780.84Ki/s
FullTransaction/LuminaWAF/Allow/repeats:10_median         55047 ns        55048 ns           10 bytes_per_second=780.576Ki/s
FullTransaction/LuminaWAF/Allow/repeats:10_stddev           117 ns          117 ns           10 bytes_per_second=1.65755Ki/s
FullTransaction/LuminaWAF/Allow/repeats:10_cv              0.21 %          0.21 %            10 bytes_per_second=0.21%
FullTransaction/LuminaWAF/Attack/repeats:10               32446 ns        32446 ns        43085 bytes_per_second=1.32268Mi/s
FullTransaction/LuminaWAF/Attack/repeats:10               32406 ns        32406 ns        43085 bytes_per_second=1.3243Mi/s
FullTransaction/LuminaWAF/Attack/repeats:10               32392 ns        32392 ns        43085 bytes_per_second=1.32486Mi/s
FullTransaction/LuminaWAF/Attack/repeats:10               32385 ns        32385 ns        43085 bytes_per_second=1.32518Mi/s
FullTransaction/LuminaWAF/Attack/repeats:10               32420 ns        32420 ns        43085 bytes_per_second=1.32371Mi/s
FullTransaction/LuminaWAF/Attack/repeats:10               32402 ns        32402 ns        43085 bytes_per_second=1.32448Mi/s
FullTransaction/LuminaWAF/Attack/repeats:10               32378 ns        32378 ns        43085 bytes_per_second=1.32545Mi/s
FullTransaction/LuminaWAF/Attack/repeats:10               32388 ns        32388 ns        43085 bytes_per_second=1.32503Mi/s
FullTransaction/LuminaWAF/Attack/repeats:10               32342 ns        32342 ns        43085 bytes_per_second=1.32694Mi/s
FullTransaction/LuminaWAF/Attack/repeats:10               32425 ns        32425 ns        43085 bytes_per_second=1.32352Mi/s
FullTransaction/LuminaWAF/Attack/repeats:10_mean          32398 ns        32398 ns           10 bytes_per_second=1.32462Mi/s
FullTransaction/LuminaWAF/Attack/repeats:10_median        32397 ns        32397 ns           10 bytes_per_second=1.32467Mi/s
FullTransaction/LuminaWAF/Attack/repeats:10_stddev         28.9 ns         28.9 ns           10 bytes_per_second=1.20946Ki/s
FullTransaction/LuminaWAF/Attack/repeats:10_cv             0.09 %          0.09 %            10 bytes_per_second=0.09%
FullTransaction/ModSecurity/Allow/repeats:10            1597479 ns      1597476 ns          873 bytes_per_second=26.8979Ki/s
FullTransaction/ModSecurity/Allow/repeats:10            1596664 ns      1596661 ns          873 bytes_per_second=26.9116Ki/s
FullTransaction/ModSecurity/Allow/repeats:10            1578256 ns      1578253 ns          873 bytes_per_second=27.2255Ki/s
FullTransaction/ModSecurity/Allow/repeats:10            1569117 ns      1569114 ns          873 bytes_per_second=27.3841Ki/s
FullTransaction/ModSecurity/Allow/repeats:10            1568934 ns      1568930 ns          873 bytes_per_second=27.3873Ki/s
FullTransaction/ModSecurity/Allow/repeats:10            1581633 ns      1581630 ns          873 bytes_per_second=27.1674Ki/s
FullTransaction/ModSecurity/Allow/repeats:10            1579266 ns      1579263 ns          873 bytes_per_second=27.2081Ki/s
FullTransaction/ModSecurity/Allow/repeats:10            1580952 ns      1580948 ns          873 bytes_per_second=27.1791Ki/s
FullTransaction/ModSecurity/Allow/repeats:10            1580808 ns      1580805 ns          873 bytes_per_second=27.1816Ki/s
FullTransaction/ModSecurity/Allow/repeats:10            1572404 ns      1572401 ns          873 bytes_per_second=27.3268Ki/s
FullTransaction/ModSecurity/Allow/repeats:10_mean       1580551 ns      1580548 ns           10 bytes_per_second=27.1869Ki/s
FullTransaction/ModSecurity/Allow/repeats:10_median     1580037 ns      1580034 ns           10 bytes_per_second=27.1948Ki/s
FullTransaction/ModSecurity/Allow/repeats:10_stddev        9925 ns         9925 ns           10 bytes_per_second=174.154/s
FullTransaction/ModSecurity/Allow/repeats:10_cv            0.63 %          0.63 %            10 bytes_per_second=0.63%
FullTransaction/ModSecurity/Attack/repeats:10           1428232 ns      1428229 ns          981 bytes_per_second=30.7691Ki/s
FullTransaction/ModSecurity/Attack/repeats:10           1430327 ns      1430324 ns          981 bytes_per_second=30.724Ki/s
FullTransaction/ModSecurity/Attack/repeats:10           1429301 ns      1429298 ns          981 bytes_per_second=30.7461Ki/s
FullTransaction/ModSecurity/Attack/repeats:10           1432205 ns      1432202 ns          981 bytes_per_second=30.6837Ki/s
FullTransaction/ModSecurity/Attack/repeats:10           1439066 ns      1439062 ns          981 bytes_per_second=30.5375Ki/s
FullTransaction/ModSecurity/Attack/repeats:10           1444400 ns      1444397 ns          981 bytes_per_second=30.4247Ki/s
FullTransaction/ModSecurity/Attack/repeats:10           1446554 ns      1446551 ns          981 bytes_per_second=30.3794Ki/s
FullTransaction/ModSecurity/Attack/repeats:10           1443175 ns      1443172 ns          981 bytes_per_second=30.4505Ki/s
FullTransaction/ModSecurity/Attack/repeats:10           1440677 ns      1440674 ns          981 bytes_per_second=30.5033Ki/s
FullTransaction/ModSecurity/Attack/repeats:10           1440395 ns      1440392 ns          981 bytes_per_second=30.5093Ki/s
FullTransaction/ModSecurity/Attack/repeats:10_mean      1437433 ns      1437430 ns           10 bytes_per_second=30.5728Ki/s
FullTransaction/ModSecurity/Attack/repeats:10_median    1439730 ns      1439727 ns           10 bytes_per_second=30.5234Ki/s
FullTransaction/ModSecurity/Attack/repeats:10_stddev       6793 ns         6793 ns           10 bytes_per_second=148.062/s
FullTransaction/ModSecurity/Attack/repeats:10_cv           0.47 %          0.47 %            10 bytes_per_second=0.47%
FullTransaction/Coraza/Allow/repeats:10                 1342944 ns      1286668 ns         1127 bytes_per_second=33.3954Ki/s
FullTransaction/Coraza/Allow/repeats:10                 1338737 ns      1283955 ns         1127 bytes_per_second=33.4659Ki/s
FullTransaction/Coraza/Allow/repeats:10                 1342181 ns      1288802 ns         1127 bytes_per_second=33.3401Ki/s
FullTransaction/Coraza/Allow/repeats:10                 1340243 ns      1286692 ns         1127 bytes_per_second=33.3947Ki/s
FullTransaction/Coraza/Allow/repeats:10                 1341719 ns      1288418 ns         1127 bytes_per_second=33.35Ki/s
FullTransaction/Coraza/Allow/repeats:10                 1341201 ns      1287784 ns         1127 bytes_per_second=33.3664Ki/s
FullTransaction/Coraza/Allow/repeats:10                 1340933 ns      1287396 ns         1127 bytes_per_second=33.3765Ki/s
FullTransaction/Coraza/Allow/repeats:10                 1341543 ns      1288882 ns         1127 bytes_per_second=33.338Ki/s
FullTransaction/Coraza/Allow/repeats:10                 1338756 ns      1285348 ns         1127 bytes_per_second=33.4297Ki/s
FullTransaction/Coraza/Allow/repeats:10                 1338436 ns      1284612 ns         1127 bytes_per_second=33.4488Ki/s
FullTransaction/Coraza/Allow/repeats:10_mean            1340669 ns      1286856 ns           10 bytes_per_second=33.3906Ki/s
FullTransaction/Coraza/Allow/repeats:10_median          1341067 ns      1287044 ns           10 bytes_per_second=33.3856Ki/s
FullTransaction/Coraza/Allow/repeats:10_stddev             1572 ns         1741 ns           10 bytes_per_second=46.2782/s
FullTransaction/Coraza/Allow/repeats:10_cv                 0.12 %          0.14 %            10 bytes_per_second=0.14%
FullTransaction/Coraza/Attack/repeats:10                1242678 ns      1199487 ns         1150 bytes_per_second=36.6368Ki/s
FullTransaction/Coraza/Attack/repeats:10                1228978 ns      1189702 ns         1150 bytes_per_second=36.9381Ki/s
FullTransaction/Coraza/Attack/repeats:10                1229327 ns      1189701 ns         1150 bytes_per_second=36.9381Ki/s
FullTransaction/Coraza/Attack/repeats:10                1243810 ns      1202130 ns         1150 bytes_per_second=36.5562Ki/s
FullTransaction/Coraza/Attack/repeats:10                1230011 ns      1190428 ns         1150 bytes_per_second=36.9156Ki/s
FullTransaction/Coraza/Attack/repeats:10                1227330 ns      1188576 ns         1150 bytes_per_second=36.9731Ki/s
FullTransaction/Coraza/Attack/repeats:10                1232632 ns      1193616 ns         1150 bytes_per_second=36.817Ki/s
FullTransaction/Coraza/Attack/repeats:10                1229772 ns      1190420 ns         1150 bytes_per_second=36.9158Ki/s
FullTransaction/Coraza/Attack/repeats:10                1229606 ns      1190119 ns         1150 bytes_per_second=36.9252Ki/s
FullTransaction/Coraza/Attack/repeats:10                1228357 ns      1189336 ns         1150 bytes_per_second=36.9494Ki/s
FullTransaction/Coraza/Attack/repeats:10_mean           1232250 ns      1192351 ns           10 bytes_per_second=36.8565Ki/s
FullTransaction/Coraza/Attack/repeats:10_median         1229689 ns      1190269 ns           10 bytes_per_second=36.9205Ki/s
FullTransaction/Coraza/Attack/repeats:10_stddev            5956 ns         4690 ns           10 bytes_per_second=147.715/s
FullTransaction/Coraza/Attack/repeats:10_cv                0.48 %          0.39 %            10 bytes_per_second=0.39%
```

### `micro_process_01.log`

Raw JSON: [`micro_process_01.json`](micro_process_01.json)

```text
2026-07-23T07:20:23+00:00
Running /srv/lumina-canonical/LuminaWAF/build/lumina_benchmark_harness
Run on (16 X 2996.83 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB (x16)
  L1 Instruction 32 KiB (x16)
  L2 Unified 1024 KiB (x16)
  L3 Unified 16384 KiB (x4)
Load Average: 1.81, 1.41, 0.87
---------------------------------------------------------------------------------------------------------------
Benchmark                                                     Time             CPU   Iterations UserCounters...
---------------------------------------------------------------------------------------------------------------
FullTransaction/LuminaWAF/Allow/repeats:10                55458 ns        55458 ns        25269 bytes_per_second=774.798Ki/s
FullTransaction/LuminaWAF/Allow/repeats:10                55550 ns        55550 ns        25269 bytes_per_second=773.518Ki/s
FullTransaction/LuminaWAF/Allow/repeats:10                55540 ns        55540 ns        25269 bytes_per_second=773.652Ki/s
FullTransaction/LuminaWAF/Allow/repeats:10                55655 ns        55655 ns        25269 bytes_per_second=772.05Ki/s
FullTransaction/LuminaWAF/Allow/repeats:10                55618 ns        55617 ns        25269 bytes_per_second=772.577Ki/s
FullTransaction/LuminaWAF/Allow/repeats:10                55490 ns        55490 ns        25269 bytes_per_second=774.348Ki/s
FullTransaction/LuminaWAF/Allow/repeats:10                55486 ns        55486 ns        25269 bytes_per_second=774.414Ki/s
FullTransaction/LuminaWAF/Allow/repeats:10                55492 ns        55492 ns        25269 bytes_per_second=774.32Ki/s
FullTransaction/LuminaWAF/Allow/repeats:10                55353 ns        55353 ns        25269 bytes_per_second=776.266Ki/s
FullTransaction/LuminaWAF/Allow/repeats:10                55198 ns        55198 ns        25269 bytes_per_second=778.445Ki/s
FullTransaction/LuminaWAF/Allow/repeats:10_mean           55484 ns        55484 ns           10 bytes_per_second=774.439Ki/s
FullTransaction/LuminaWAF/Allow/repeats:10_median         55491 ns        55491 ns           10 bytes_per_second=774.334Ki/s
FullTransaction/LuminaWAF/Allow/repeats:10_stddev           131 ns          131 ns           10 bytes_per_second=1.83131Ki/s
FullTransaction/LuminaWAF/Allow/repeats:10_cv              0.24 %          0.24 %            10 bytes_per_second=0.24%
FullTransaction/LuminaWAF/Attack/repeats:10               32818 ns        32818 ns        42560 bytes_per_second=1.30768Mi/s
FullTransaction/LuminaWAF/Attack/repeats:10               32915 ns        32915 ns        42560 bytes_per_second=1.30381Mi/s
FullTransaction/LuminaWAF/Attack/repeats:10               33000 ns        33000 ns        42560 bytes_per_second=1.30048Mi/s
FullTransaction/LuminaWAF/Attack/repeats:10               32949 ns        32949 ns        42560 bytes_per_second=1.30247Mi/s
FullTransaction/LuminaWAF/Attack/repeats:10               32839 ns        32839 ns        42560 bytes_per_second=1.30682Mi/s
FullTransaction/LuminaWAF/Attack/repeats:10               32820 ns        32820 ns        42560 bytes_per_second=1.3076Mi/s
FullTransaction/LuminaWAF/Attack/repeats:10               32864 ns        32864 ns        42560 bytes_per_second=1.30585Mi/s
FullTransaction/LuminaWAF/Attack/repeats:10               32864 ns        32864 ns        42560 bytes_per_second=1.30584Mi/s
FullTransaction/LuminaWAF/Attack/repeats:10               32865 ns        32865 ns        42560 bytes_per_second=1.3058Mi/s
FullTransaction/LuminaWAF/Attack/repeats:10               33078 ns        33078 ns        42560 bytes_per_second=1.29742Mi/s
FullTransaction/LuminaWAF/Attack/repeats:10_mean          32901 ns        32901 ns           10 bytes_per_second=1.30438Mi/s
FullTransaction/LuminaWAF/Attack/repeats:10_median        32865 ns        32865 ns           10 bytes_per_second=1.30582Mi/s
FullTransaction/LuminaWAF/Attack/repeats:10_stddev         84.8 ns         84.8 ns           10 bytes_per_second=3.43489Ki/s
FullTransaction/LuminaWAF/Attack/repeats:10_cv             0.26 %          0.26 %            10 bytes_per_second=0.26%
FullTransaction/ModSecurity/Allow/repeats:10            1578363 ns      1578360 ns          879 bytes_per_second=27.2237Ki/s
FullTransaction/ModSecurity/Allow/repeats:10            1556220 ns      1556216 ns          879 bytes_per_second=27.611Ki/s
FullTransaction/ModSecurity/Allow/repeats:10            1554948 ns      1554945 ns          879 bytes_per_second=27.6336Ki/s
FullTransaction/ModSecurity/Allow/repeats:10            1570197 ns      1570194 ns          879 bytes_per_second=27.3652Ki/s
FullTransaction/ModSecurity/Allow/repeats:10            1571990 ns      1571986 ns          879 bytes_per_second=27.334Ki/s
FullTransaction/ModSecurity/Allow/repeats:10            1579411 ns      1579408 ns          879 bytes_per_second=27.2056Ki/s
FullTransaction/ModSecurity/Allow/repeats:10            1578640 ns      1578637 ns          879 bytes_per_second=27.2189Ki/s
FullTransaction/ModSecurity/Allow/repeats:10            1578063 ns      1578060 ns          879 bytes_per_second=27.2288Ki/s
FullTransaction/ModSecurity/Allow/repeats:10            1575841 ns      1575837 ns          879 bytes_per_second=27.2672Ki/s
FullTransaction/ModSecurity/Allow/repeats:10            1579971 ns      1579967 ns          879 bytes_per_second=27.196Ki/s
FullTransaction/ModSecurity/Allow/repeats:10_mean       1572364 ns      1572361 ns           10 bytes_per_second=27.3284Ki/s
FullTransaction/ModSecurity/Allow/repeats:10_median     1576952 ns      1576949 ns           10 bytes_per_second=27.248Ki/s
FullTransaction/ModSecurity/Allow/repeats:10_stddev        9406 ns         9406 ns           10 bytes_per_second=168.488/s
FullTransaction/ModSecurity/Allow/repeats:10_cv            0.60 %          0.60 %            10 bytes_per_second=0.60%
FullTransaction/ModSecurity/Attack/repeats:10           1447721 ns      1447718 ns          968 bytes_per_second=30.3549Ki/s
FullTransaction/ModSecurity/Attack/repeats:10           1448798 ns      1448795 ns          968 bytes_per_second=30.3323Ki/s
FullTransaction/ModSecurity/Attack/repeats:10           1448873 ns      1448870 ns          968 bytes_per_second=30.3308Ki/s
FullTransaction/ModSecurity/Attack/repeats:10           1449129 ns      1449126 ns          968 bytes_per_second=30.3254Ki/s
FullTransaction/ModSecurity/Attack/repeats:10           1448049 ns      1448046 ns          968 bytes_per_second=30.348Ki/s
FullTransaction/ModSecurity/Attack/repeats:10           1449153 ns      1449150 ns          968 bytes_per_second=30.3249Ki/s
FullTransaction/ModSecurity/Attack/repeats:10           1445025 ns      1445021 ns          968 bytes_per_second=30.4115Ki/s
FullTransaction/ModSecurity/Attack/repeats:10           1453160 ns      1453157 ns          968 bytes_per_second=30.2413Ki/s
FullTransaction/ModSecurity/Attack/repeats:10           1453788 ns      1453785 ns          968 bytes_per_second=30.2282Ki/s
FullTransaction/ModSecurity/Attack/repeats:10           1450416 ns      1450411 ns          968 bytes_per_second=30.2985Ki/s
FullTransaction/ModSecurity/Attack/repeats:10_mean      1449411 ns      1449408 ns           10 bytes_per_second=30.3196Ki/s
FullTransaction/ModSecurity/Attack/repeats:10_median    1449001 ns      1448998 ns           10 bytes_per_second=30.3281Ki/s
FullTransaction/ModSecurity/Attack/repeats:10_stddev       2560 ns         2560 ns           10 bytes_per_second=54.809/s
FullTransaction/ModSecurity/Attack/repeats:10_cv           0.18 %          0.18 %            10 bytes_per_second=0.18%
FullTransaction/Coraza/Allow/repeats:10                 1349821 ns      1293047 ns         1121 bytes_per_second=33.2306Ki/s
FullTransaction/Coraza/Allow/repeats:10                 1344418 ns      1293039 ns         1121 bytes_per_second=33.2308Ki/s
FullTransaction/Coraza/Allow/repeats:10                 1344889 ns      1292733 ns         1121 bytes_per_second=33.2387Ki/s
FullTransaction/Coraza/Allow/repeats:10                 1345458 ns      1294150 ns         1121 bytes_per_second=33.2023Ki/s
FullTransaction/Coraza/Allow/repeats:10                 1346122 ns      1295709 ns         1121 bytes_per_second=33.1624Ki/s
FullTransaction/Coraza/Allow/repeats:10                 1346028 ns      1292983 ns         1121 bytes_per_second=33.2323Ki/s
FullTransaction/Coraza/Allow/repeats:10                 1346315 ns      1294485 ns         1121 bytes_per_second=33.1937Ki/s
FullTransaction/Coraza/Allow/repeats:10                 1344313 ns      1291984 ns         1121 bytes_per_second=33.258Ki/s
FullTransaction/Coraza/Allow/repeats:10                 1347050 ns      1295232 ns         1121 bytes_per_second=33.1746Ki/s
FullTransaction/Coraza/Allow/repeats:10                 1344451 ns      1294168 ns         1121 bytes_per_second=33.2018Ki/s
FullTransaction/Coraza/Allow/repeats:10_mean            1345887 ns      1293753 ns           10 bytes_per_second=33.2125Ki/s
FullTransaction/Coraza/Allow/repeats:10_median          1345743 ns      1293598 ns           10 bytes_per_second=33.2165Ki/s
FullTransaction/Coraza/Allow/repeats:10_stddev             1666 ns         1186 ns           10 bytes_per_second=31.1576/s
FullTransaction/Coraza/Allow/repeats:10_cv                 0.12 %          0.09 %            10 bytes_per_second=0.09%
FullTransaction/Coraza/Attack/repeats:10                1246372 ns      1203530 ns         1168 bytes_per_second=36.5137Ki/s
FullTransaction/Coraza/Attack/repeats:10                1229148 ns      1191378 ns         1168 bytes_per_second=36.8861Ki/s
FullTransaction/Coraza/Attack/repeats:10                1231953 ns      1193028 ns         1168 bytes_per_second=36.8351Ki/s
FullTransaction/Coraza/Attack/repeats:10                1229593 ns      1190755 ns         1168 bytes_per_second=36.9054Ki/s
FullTransaction/Coraza/Attack/repeats:10                1235286 ns      1194241 ns         1168 bytes_per_second=36.7977Ki/s
FullTransaction/Coraza/Attack/repeats:10                1229029 ns      1191169 ns         1168 bytes_per_second=36.8926Ki/s
FullTransaction/Coraza/Attack/repeats:10                1229456 ns      1191446 ns         1168 bytes_per_second=36.884Ki/s
FullTransaction/Coraza/Attack/repeats:10                1235818 ns      1195454 ns         1168 bytes_per_second=36.7604Ki/s
FullTransaction/Coraza/Attack/repeats:10                1228804 ns      1190883 ns         1168 bytes_per_second=36.9015Ki/s
FullTransaction/Coraza/Attack/repeats:10                1229638 ns      1191742 ns         1168 bytes_per_second=36.8749Ki/s
FullTransaction/Coraza/Attack/repeats:10_mean           1232510 ns      1193363 ns           10 bytes_per_second=36.8251Ki/s
FullTransaction/Coraza/Attack/repeats:10_median         1229616 ns      1191594 ns           10 bytes_per_second=36.8794Ki/s
FullTransaction/Coraza/Attack/repeats:10_stddev            5521 ns         3896 ns           10 bytes_per_second=122.373/s
FullTransaction/Coraza/Attack/repeats:10_cv                0.45 %          0.33 %            10 bytes_per_second=0.32%
```

### `micro_process_02.log`

Raw JSON: [`micro_process_02.json`](micro_process_02.json)

```text
2026-07-23T07:21:50+00:00
Running /srv/lumina-canonical/LuminaWAF/build/lumina_benchmark_harness
Run on (16 X 3001.32 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB (x16)
  L1 Instruction 32 KiB (x16)
  L2 Unified 1024 KiB (x16)
  L3 Unified 16384 KiB (x4)
Load Average: 1.44, 1.37, 0.91
---------------------------------------------------------------------------------------------------------------
Benchmark                                                     Time             CPU   Iterations UserCounters...
---------------------------------------------------------------------------------------------------------------
FullTransaction/LuminaWAF/Allow/repeats:10                55504 ns        55504 ns        25387 bytes_per_second=774.152Ki/s
FullTransaction/LuminaWAF/Allow/repeats:10                55528 ns        55528 ns        25387 bytes_per_second=773.823Ki/s
FullTransaction/LuminaWAF/Allow/repeats:10                55697 ns        55697 ns        25387 bytes_per_second=771.468Ki/s
FullTransaction/LuminaWAF/Allow/repeats:10                55728 ns        55728 ns        25387 bytes_per_second=771.039Ki/s
FullTransaction/LuminaWAF/Allow/repeats:10                55621 ns        55621 ns        25387 bytes_per_second=772.522Ki/s
FullTransaction/LuminaWAF/Allow/repeats:10                55667 ns        55667 ns        25387 bytes_per_second=771.887Ki/s
FullTransaction/LuminaWAF/Allow/repeats:10                55643 ns        55643 ns        25387 bytes_per_second=772.228Ki/s
FullTransaction/LuminaWAF/Allow/repeats:10                55630 ns        55630 ns        25387 bytes_per_second=772.397Ki/s
FullTransaction/LuminaWAF/Allow/repeats:10                55584 ns        55584 ns        25387 bytes_per_second=773.041Ki/s
FullTransaction/LuminaWAF/Allow/repeats:10                55951 ns        55951 ns        25387 bytes_per_second=767.97Ki/s
FullTransaction/LuminaWAF/Allow/repeats:10_mean           55655 ns        55655 ns           10 bytes_per_second=772.053Ki/s
FullTransaction/LuminaWAF/Allow/repeats:10_median         55637 ns        55637 ns           10 bytes_per_second=772.312Ki/s
FullTransaction/LuminaWAF/Allow/repeats:10_stddev           125 ns          125 ns           10 bytes_per_second=1.73064Ki/s
FullTransaction/LuminaWAF/Allow/repeats:10_cv              0.22 %          0.22 %            10 bytes_per_second=0.22%
FullTransaction/LuminaWAF/Attack/repeats:10               32740 ns        32740 ns        42978 bytes_per_second=1.31078Mi/s
FullTransaction/LuminaWAF/Attack/repeats:10               32717 ns        32717 ns        42978 bytes_per_second=1.31171Mi/s
FullTransaction/LuminaWAF/Attack/repeats:10               32898 ns        32898 ns        42978 bytes_per_second=1.30449Mi/s
FullTransaction/LuminaWAF/Attack/repeats:10               32883 ns        32883 ns        42978 bytes_per_second=1.3051Mi/s
FullTransaction/LuminaWAF/Attack/repeats:10               32812 ns        32812 ns        42978 bytes_per_second=1.30793Mi/s
FullTransaction/LuminaWAF/Attack/repeats:10               32757 ns        32757 ns        42978 bytes_per_second=1.3101Mi/s
FullTransaction/LuminaWAF/Attack/repeats:10               32707 ns        32707 ns        42978 bytes_per_second=1.3121Mi/s
FullTransaction/LuminaWAF/Attack/repeats:10               32718 ns        32718 ns        42978 bytes_per_second=1.31169Mi/s
FullTransaction/LuminaWAF/Attack/repeats:10               32796 ns        32796 ns        42978 bytes_per_second=1.30856Mi/s
FullTransaction/LuminaWAF/Attack/repeats:10               32733 ns        32733 ns        42978 bytes_per_second=1.31106Mi/s
FullTransaction/LuminaWAF/Attack/repeats:10_mean          32776 ns        32776 ns           10 bytes_per_second=1.30935Mi/s
FullTransaction/LuminaWAF/Attack/repeats:10_median        32749 ns        32749 ns           10 bytes_per_second=1.31044Mi/s
FullTransaction/LuminaWAF/Attack/repeats:10_stddev         69.1 ns         69.1 ns           10 bytes_per_second=2.82366Ki/s
FullTransaction/LuminaWAF/Attack/repeats:10_cv             0.21 %          0.21 %            10 bytes_per_second=0.21%
FullTransaction/ModSecurity/Allow/repeats:10            1608241 ns      1608238 ns          870 bytes_per_second=26.7179Ki/s
FullTransaction/ModSecurity/Allow/repeats:10            1589304 ns      1589300 ns          870 bytes_per_second=27.0363Ki/s
FullTransaction/ModSecurity/Allow/repeats:10            1587426 ns      1587423 ns          870 bytes_per_second=27.0682Ki/s
FullTransaction/ModSecurity/Allow/repeats:10            1582091 ns      1582087 ns          870 bytes_per_second=27.1595Ki/s
FullTransaction/ModSecurity/Allow/repeats:10            1577853 ns      1577849 ns          870 bytes_per_second=27.2325Ki/s
FullTransaction/ModSecurity/Allow/repeats:10            1572683 ns      1572679 ns          870 bytes_per_second=27.322Ki/s
FullTransaction/ModSecurity/Allow/repeats:10            1574194 ns      1574191 ns          870 bytes_per_second=27.2958Ki/s
FullTransaction/ModSecurity/Allow/repeats:10            1572918 ns      1572915 ns          870 bytes_per_second=27.3179Ki/s
FullTransaction/ModSecurity/Allow/repeats:10            1574577 ns      1574573 ns          870 bytes_per_second=27.2891Ki/s
FullTransaction/ModSecurity/Allow/repeats:10            1576624 ns      1576621 ns          870 bytes_per_second=27.2537Ki/s
FullTransaction/ModSecurity/Allow/repeats:10_mean       1581591 ns      1581588 ns           10 bytes_per_second=27.1693Ki/s
FullTransaction/ModSecurity/Allow/repeats:10_median     1577239 ns      1577235 ns           10 bytes_per_second=27.2431Ki/s
FullTransaction/ModSecurity/Allow/repeats:10_stddev       11061 ns        11061 ns           10 bytes_per_second=192.675/s
FullTransaction/ModSecurity/Allow/repeats:10_cv            0.70 %          0.70 %            10 bytes_per_second=0.69%
FullTransaction/ModSecurity/Attack/repeats:10           1444092 ns      1444089 ns          968 bytes_per_second=30.4312Ki/s
FullTransaction/ModSecurity/Attack/repeats:10           1444446 ns      1444444 ns          968 bytes_per_second=30.4237Ki/s
FullTransaction/ModSecurity/Attack/repeats:10           1447031 ns      1447028 ns          968 bytes_per_second=30.3694Ki/s
FullTransaction/ModSecurity/Attack/repeats:10           1456681 ns      1456678 ns          968 bytes_per_second=30.1682Ki/s
FullTransaction/ModSecurity/Attack/repeats:10           1448229 ns      1448226 ns          968 bytes_per_second=30.3442Ki/s
FullTransaction/ModSecurity/Attack/repeats:10           1454827 ns      1454824 ns          968 bytes_per_second=30.2066Ki/s
FullTransaction/ModSecurity/Attack/repeats:10           1455583 ns      1455580 ns          968 bytes_per_second=30.1909Ki/s
FullTransaction/ModSecurity/Attack/repeats:10           1453815 ns      1453811 ns          968 bytes_per_second=30.2277Ki/s
FullTransaction/ModSecurity/Attack/repeats:10           1450999 ns      1450995 ns          968 bytes_per_second=30.2863Ki/s
FullTransaction/ModSecurity/Attack/repeats:10           1453076 ns      1453072 ns          968 bytes_per_second=30.243Ki/s
FullTransaction/ModSecurity/Attack/repeats:10_mean      1450878 ns      1450875 ns           10 bytes_per_second=30.2891Ki/s
FullTransaction/ModSecurity/Attack/repeats:10_median    1452037 ns      1452034 ns           10 bytes_per_second=30.2647Ki/s
FullTransaction/ModSecurity/Attack/repeats:10_stddev       4644 ns         4644 ns           10 bytes_per_second=99.3718/s
FullTransaction/ModSecurity/Attack/repeats:10_cv           0.32 %          0.32 %            10 bytes_per_second=0.32%
FullTransaction/Coraza/Allow/repeats:10                 1342143 ns      1286857 ns         1123 bytes_per_second=33.3905Ki/s
FullTransaction/Coraza/Allow/repeats:10                 1335361 ns      1282785 ns         1123 bytes_per_second=33.4965Ki/s
FullTransaction/Coraza/Allow/repeats:10                 1335394 ns      1281902 ns         1123 bytes_per_second=33.5195Ki/s
FullTransaction/Coraza/Allow/repeats:10                 1332469 ns      1279615 ns         1123 bytes_per_second=33.5794Ki/s
FullTransaction/Coraza/Allow/repeats:10                 1325361 ns      1274343 ns         1123 bytes_per_second=33.7184Ki/s
FullTransaction/Coraza/Allow/repeats:10                 1333660 ns      1282917 ns         1123 bytes_per_second=33.493Ki/s
FullTransaction/Coraza/Allow/repeats:10                 1337433 ns      1283390 ns         1123 bytes_per_second=33.4807Ki/s
FullTransaction/Coraza/Allow/repeats:10                 1334977 ns      1282121 ns         1123 bytes_per_second=33.5138Ki/s
FullTransaction/Coraza/Allow/repeats:10                 1335391 ns      1281319 ns         1123 bytes_per_second=33.5348Ki/s
FullTransaction/Coraza/Allow/repeats:10                 1337478 ns      1283767 ns         1123 bytes_per_second=33.4708Ki/s
FullTransaction/Coraza/Allow/repeats:10_mean            1334967 ns      1281902 ns           10 bytes_per_second=33.5197Ki/s
FullTransaction/Coraza/Allow/repeats:10_median          1335376 ns      1282453 ns           10 bytes_per_second=33.5051Ki/s
FullTransaction/Coraza/Allow/repeats:10_stddev             4277 ns         3246 ns           10 bytes_per_second=87.1299/s
FullTransaction/Coraza/Allow/repeats:10_cv                 0.32 %          0.25 %            10 bytes_per_second=0.25%
FullTransaction/Coraza/Attack/repeats:10                1246114 ns      1202728 ns         1172 bytes_per_second=36.538Ki/s
FullTransaction/Coraza/Attack/repeats:10                1226849 ns      1188500 ns         1172 bytes_per_second=36.9755Ki/s
FullTransaction/Coraza/Attack/repeats:10                1230619 ns      1191534 ns         1172 bytes_per_second=36.8813Ki/s
FullTransaction/Coraza/Attack/repeats:10                1227468 ns      1188727 ns         1172 bytes_per_second=36.9684Ki/s
FullTransaction/Coraza/Attack/repeats:10                1228595 ns      1190127 ns         1172 bytes_per_second=36.9249Ki/s
FullTransaction/Coraza/Attack/repeats:10                1236170 ns      1194733 ns         1172 bytes_per_second=36.7825Ki/s
FullTransaction/Coraza/Attack/repeats:10                1228616 ns      1189392 ns         1172 bytes_per_second=36.9477Ki/s
FullTransaction/Coraza/Attack/repeats:10                1229411 ns      1190272 ns         1172 bytes_per_second=36.9204Ki/s
FullTransaction/Coraza/Attack/repeats:10                1234643 ns      1193125 ns         1172 bytes_per_second=36.8321Ki/s
FullTransaction/Coraza/Attack/repeats:10                1226872 ns      1187851 ns         1172 bytes_per_second=36.9956Ki/s
FullTransaction/Coraza/Attack/repeats:10_mean           1231536 ns      1191699 ns           10 bytes_per_second=36.8766Ki/s
FullTransaction/Coraza/Attack/repeats:10_median         1229013 ns      1190200 ns           10 bytes_per_second=36.9226Ki/s
FullTransaction/Coraza/Attack/repeats:10_stddev            6023 ns         4430 ns           10 bytes_per_second=139.552/s
FullTransaction/Coraza/Attack/repeats:10_cv                0.49 %          0.37 %            10 bytes_per_second=0.37%
```

### `micro_process_03.log`

Raw JSON: [`micro_process_03.json`](micro_process_03.json)

```text
2026-07-23T07:23:18+00:00
Running /srv/lumina-canonical/LuminaWAF/build/lumina_benchmark_harness
Run on (16 X 2996.56 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB (x16)
  L1 Instruction 32 KiB (x16)
  L2 Unified 1024 KiB (x16)
  L3 Unified 16384 KiB (x4)
Load Average: 1.17, 1.29, 0.92
---------------------------------------------------------------------------------------------------------------
Benchmark                                                     Time             CPU   Iterations UserCounters...
---------------------------------------------------------------------------------------------------------------
FullTransaction/LuminaWAF/Allow/repeats:10                55347 ns        55347 ns        25367 bytes_per_second=776.348Ki/s
FullTransaction/LuminaWAF/Allow/repeats:10                55359 ns        55359 ns        25367 bytes_per_second=776.177Ki/s
FullTransaction/LuminaWAF/Allow/repeats:10                55497 ns        55497 ns        25367 bytes_per_second=774.25Ki/s
FullTransaction/LuminaWAF/Allow/repeats:10                55255 ns        55255 ns        25367 bytes_per_second=777.642Ki/s
FullTransaction/LuminaWAF/Allow/repeats:10                55384 ns        55384 ns        25367 bytes_per_second=775.831Ki/s
FullTransaction/LuminaWAF/Allow/repeats:10                55441 ns        55441 ns        25367 bytes_per_second=775.038Ki/s
FullTransaction/LuminaWAF/Allow/repeats:10                55583 ns        55583 ns        25367 bytes_per_second=773.055Ki/s
FullTransaction/LuminaWAF/Allow/repeats:10                55598 ns        55598 ns        25367 bytes_per_second=772.852Ki/s
FullTransaction/LuminaWAF/Allow/repeats:10                55589 ns        55589 ns        25367 bytes_per_second=772.973Ki/s
FullTransaction/LuminaWAF/Allow/repeats:10                55578 ns        55578 ns        25367 bytes_per_second=773.132Ki/s
FullTransaction/LuminaWAF/Allow/repeats:10_mean           55463 ns        55463 ns           10 bytes_per_second=774.73Ki/s
FullTransaction/LuminaWAF/Allow/repeats:10_median         55469 ns        55469 ns           10 bytes_per_second=774.644Ki/s
FullTransaction/LuminaWAF/Allow/repeats:10_stddev           123 ns          123 ns           10 bytes_per_second=1.72234Ki/s
FullTransaction/LuminaWAF/Allow/repeats:10_cv              0.22 %          0.22 %            10 bytes_per_second=0.22%
FullTransaction/LuminaWAF/Attack/repeats:10               32742 ns        32742 ns        42515 bytes_per_second=1.31071Mi/s
FullTransaction/LuminaWAF/Attack/repeats:10               32700 ns        32700 ns        42515 bytes_per_second=1.31239Mi/s
FullTransaction/LuminaWAF/Attack/repeats:10               32727 ns        32727 ns        42515 bytes_per_second=1.3113Mi/s
FullTransaction/LuminaWAF/Attack/repeats:10               32724 ns        32724 ns        42515 bytes_per_second=1.31144Mi/s
FullTransaction/LuminaWAF/Attack/repeats:10               32750 ns        32750 ns        42515 bytes_per_second=1.31041Mi/s
FullTransaction/LuminaWAF/Attack/repeats:10               32769 ns        32769 ns        42515 bytes_per_second=1.30965Mi/s
FullTransaction/LuminaWAF/Attack/repeats:10               32758 ns        32758 ns        42515 bytes_per_second=1.31007Mi/s
FullTransaction/LuminaWAF/Attack/repeats:10               32740 ns        32740 ns        42515 bytes_per_second=1.31078Mi/s
FullTransaction/LuminaWAF/Attack/repeats:10               32751 ns        32751 ns        42515 bytes_per_second=1.31034Mi/s
FullTransaction/LuminaWAF/Attack/repeats:10               32701 ns        32701 ns        42515 bytes_per_second=1.31236Mi/s
FullTransaction/LuminaWAF/Attack/repeats:10_mean          32736 ns        32736 ns           10 bytes_per_second=1.31095Mi/s
FullTransaction/LuminaWAF/Attack/repeats:10_median        32741 ns        32741 ns           10 bytes_per_second=1.31075Mi/s
FullTransaction/LuminaWAF/Attack/repeats:10_stddev         23.0 ns         23.0 ns           10 bytes_per_second=967.563/s
FullTransaction/LuminaWAF/Attack/repeats:10_cv             0.07 %          0.07 %            10 bytes_per_second=0.07%
FullTransaction/ModSecurity/Allow/repeats:10            1594000 ns      1593996 ns          870 bytes_per_second=26.9566Ki/s
FullTransaction/ModSecurity/Allow/repeats:10            1593249 ns      1593246 ns          870 bytes_per_second=26.9693Ki/s
FullTransaction/ModSecurity/Allow/repeats:10            1592196 ns      1592193 ns          870 bytes_per_second=26.9872Ki/s
FullTransaction/ModSecurity/Allow/repeats:10            1592205 ns      1592201 ns          870 bytes_per_second=26.987Ki/s
FullTransaction/ModSecurity/Allow/repeats:10            1591750 ns      1591746 ns          870 bytes_per_second=26.9947Ki/s
FullTransaction/ModSecurity/Allow/repeats:10            1589081 ns      1589078 ns          870 bytes_per_second=27.0401Ki/s
FullTransaction/ModSecurity/Allow/repeats:10            1590462 ns      1590459 ns          870 bytes_per_second=27.0166Ki/s
FullTransaction/ModSecurity/Allow/repeats:10            1590389 ns      1590385 ns          870 bytes_per_second=27.0178Ki/s
FullTransaction/ModSecurity/Allow/repeats:10            1590875 ns      1590871 ns          870 bytes_per_second=27.0096Ki/s
FullTransaction/ModSecurity/Allow/repeats:10            1594854 ns      1594850 ns          870 bytes_per_second=26.9422Ki/s
FullTransaction/ModSecurity/Allow/repeats:10_mean       1591906 ns      1591903 ns           10 bytes_per_second=26.9921Ki/s
FullTransaction/ModSecurity/Allow/repeats:10_median     1591973 ns      1591970 ns           10 bytes_per_second=26.9909Ki/s
FullTransaction/ModSecurity/Allow/repeats:10_stddev        1780 ns         1780 ns           10 bytes_per_second=30.8956/s
FullTransaction/ModSecurity/Allow/repeats:10_cv            0.11 %          0.11 %            10 bytes_per_second=0.11%
FullTransaction/ModSecurity/Attack/repeats:10           1439946 ns      1439943 ns          967 bytes_per_second=30.5188Ki/s
FullTransaction/ModSecurity/Attack/repeats:10           1444064 ns      1444061 ns          967 bytes_per_second=30.4318Ki/s
FullTransaction/ModSecurity/Attack/repeats:10           1443993 ns      1443990 ns          967 bytes_per_second=30.4333Ki/s
FullTransaction/ModSecurity/Attack/repeats:10           1456572 ns      1456568 ns          967 bytes_per_second=30.1704Ki/s
FullTransaction/ModSecurity/Attack/repeats:10           1451037 ns      1451034 ns          967 bytes_per_second=30.2855Ki/s
FullTransaction/ModSecurity/Attack/repeats:10           1456137 ns      1456134 ns          967 bytes_per_second=30.1794Ki/s
FullTransaction/ModSecurity/Attack/repeats:10           1454639 ns      1454635 ns          967 bytes_per_second=30.2105Ki/s
FullTransaction/ModSecurity/Attack/repeats:10           1456469 ns      1456465 ns          967 bytes_per_second=30.1726Ki/s
FullTransaction/ModSecurity/Attack/repeats:10           1455961 ns      1455957 ns          967 bytes_per_second=30.1831Ki/s
FullTransaction/ModSecurity/Attack/repeats:10           1452410 ns      1452407 ns          967 bytes_per_second=30.2569Ki/s
FullTransaction/ModSecurity/Attack/repeats:10_mean      1451123 ns      1451119 ns           10 bytes_per_second=30.2842Ki/s
FullTransaction/ModSecurity/Attack/repeats:10_median    1453525 ns      1453521 ns           10 bytes_per_second=30.2337Ki/s
FullTransaction/ModSecurity/Attack/repeats:10_stddev       6204 ns         6204 ns           10 bytes_per_second=132.987/s
FullTransaction/ModSecurity/Attack/repeats:10_cv           0.43 %          0.43 %            10 bytes_per_second=0.43%
FullTransaction/Coraza/Allow/repeats:10                 1339239 ns      1283500 ns         1080 bytes_per_second=33.4778Ki/s
FullTransaction/Coraza/Allow/repeats:10                 1330531 ns      1278614 ns         1080 bytes_per_second=33.6057Ki/s
FullTransaction/Coraza/Allow/repeats:10                 1343129 ns      1288074 ns         1080 bytes_per_second=33.3589Ki/s
FullTransaction/Coraza/Allow/repeats:10                 1331661 ns      1279716 ns         1080 bytes_per_second=33.5768Ki/s
FullTransaction/Coraza/Allow/repeats:10                 1337341 ns      1282960 ns         1080 bytes_per_second=33.4919Ki/s
FullTransaction/Coraza/Allow/repeats:10                 1337938 ns      1282403 ns         1080 bytes_per_second=33.5064Ki/s
FullTransaction/Coraza/Allow/repeats:10                 1333453 ns      1280888 ns         1080 bytes_per_second=33.5461Ki/s
FullTransaction/Coraza/Allow/repeats:10                 1334522 ns      1280110 ns         1080 bytes_per_second=33.5664Ki/s
FullTransaction/Coraza/Allow/repeats:10                 1334263 ns      1279517 ns         1080 bytes_per_second=33.582Ki/s
FullTransaction/Coraza/Allow/repeats:10                 1329577 ns      1277655 ns         1080 bytes_per_second=33.6309Ki/s
FullTransaction/Coraza/Allow/repeats:10_mean            1335165 ns      1281344 ns           10 bytes_per_second=33.5343Ki/s
FullTransaction/Coraza/Allow/repeats:10_median          1334392 ns      1280499 ns           10 bytes_per_second=33.5563Ki/s
FullTransaction/Coraza/Allow/repeats:10_stddev             4237 ns         3027 ns           10 bytes_per_second=80.9364/s
FullTransaction/Coraza/Allow/repeats:10_cv                 0.32 %          0.24 %            10 bytes_per_second=0.24%
FullTransaction/Coraza/Attack/repeats:10                1239161 ns      1196832 ns         1159 bytes_per_second=36.718Ki/s
FullTransaction/Coraza/Attack/repeats:10                1224950 ns      1187321 ns         1159 bytes_per_second=37.0122Ki/s
FullTransaction/Coraza/Attack/repeats:10                1226589 ns      1188282 ns         1159 bytes_per_second=36.9822Ki/s
FullTransaction/Coraza/Attack/repeats:10                1239198 ns      1199038 ns         1159 bytes_per_second=36.6505Ki/s
FullTransaction/Coraza/Attack/repeats:10                1229609 ns      1190393 ns         1159 bytes_per_second=36.9166Ki/s
FullTransaction/Coraza/Attack/repeats:10                1226581 ns      1188661 ns         1159 bytes_per_second=36.9704Ki/s
FullTransaction/Coraza/Attack/repeats:10                1236006 ns      1195133 ns         1159 bytes_per_second=36.7702Ki/s
FullTransaction/Coraza/Attack/repeats:10                1224985 ns      1187623 ns         1159 bytes_per_second=37.0027Ki/s
FullTransaction/Coraza/Attack/repeats:10                1225270 ns      1187282 ns         1159 bytes_per_second=37.0134Ki/s
FullTransaction/Coraza/Attack/repeats:10                1224676 ns      1186952 ns         1159 bytes_per_second=37.0237Ki/s
FullTransaction/Coraza/Attack/repeats:10_mean           1229702 ns      1190752 ns           10 bytes_per_second=36.906Ki/s
FullTransaction/Coraza/Attack/repeats:10_median         1226585 ns      1188472 ns           10 bytes_per_second=36.9763Ki/s
FullTransaction/Coraza/Attack/repeats:10_stddev            6042 ns         4515 ns           10 bytes_per_second=142.845/s
FullTransaction/Coraza/Attack/repeats:10_cv                0.49 %          0.38 %            10 bytes_per_second=0.38%
```

### `micro_process_04.log`

Raw JSON: [`micro_process_04.json`](micro_process_04.json)

```text
2026-07-23T07:24:44+00:00
Running /srv/lumina-canonical/LuminaWAF/build/lumina_benchmark_harness
Run on (16 X 2996.19 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB (x16)
  L1 Instruction 32 KiB (x16)
  L2 Unified 1024 KiB (x16)
  L3 Unified 16384 KiB (x4)
Load Average: 1.17, 1.24, 0.94
---------------------------------------------------------------------------------------------------------------
Benchmark                                                     Time             CPU   Iterations UserCounters...
---------------------------------------------------------------------------------------------------------------
FullTransaction/LuminaWAF/Allow/repeats:10                54751 ns        54751 ns        25692 bytes_per_second=784.799Ki/s
FullTransaction/LuminaWAF/Allow/repeats:10                54901 ns        54901 ns        25692 bytes_per_second=782.654Ki/s
FullTransaction/LuminaWAF/Allow/repeats:10                54852 ns        54852 ns        25692 bytes_per_second=783.353Ki/s
FullTransaction/LuminaWAF/Allow/repeats:10                54898 ns        54898 ns        25692 bytes_per_second=782.698Ki/s
FullTransaction/LuminaWAF/Allow/repeats:10                55006 ns        55006 ns        25692 bytes_per_second=781.162Ki/s
FullTransaction/LuminaWAF/Allow/repeats:10                54980 ns        54980 ns        25692 bytes_per_second=781.533Ki/s
FullTransaction/LuminaWAF/Allow/repeats:10                54990 ns        54990 ns        25692 bytes_per_second=781.389Ki/s
FullTransaction/LuminaWAF/Allow/repeats:10                54970 ns        54970 ns        25692 bytes_per_second=781.673Ki/s
FullTransaction/LuminaWAF/Allow/repeats:10                54974 ns        54974 ns        25692 bytes_per_second=781.626Ki/s
FullTransaction/LuminaWAF/Allow/repeats:10                55137 ns        55137 ns        25692 bytes_per_second=779.311Ki/s
FullTransaction/LuminaWAF/Allow/repeats:10_mean           54946 ns        54946 ns           10 bytes_per_second=782.02Ki/s
FullTransaction/LuminaWAF/Allow/repeats:10_median         54972 ns        54972 ns           10 bytes_per_second=781.65Ki/s
FullTransaction/LuminaWAF/Allow/repeats:10_stddev           103 ns          103 ns           10 bytes_per_second=1.46607Ki/s
FullTransaction/LuminaWAF/Allow/repeats:10_cv              0.19 %          0.19 %            10 bytes_per_second=0.19%
FullTransaction/LuminaWAF/Attack/repeats:10               32340 ns        32340 ns        43351 bytes_per_second=1.32699Mi/s
FullTransaction/LuminaWAF/Attack/repeats:10               32323 ns        32323 ns        43351 bytes_per_second=1.32769Mi/s
FullTransaction/LuminaWAF/Attack/repeats:10               32295 ns        32295 ns        43351 bytes_per_second=1.32886Mi/s
FullTransaction/LuminaWAF/Attack/repeats:10               32324 ns        32324 ns        43351 bytes_per_second=1.32766Mi/s
FullTransaction/LuminaWAF/Attack/repeats:10               32305 ns        32305 ns        43351 bytes_per_second=1.32842Mi/s
FullTransaction/LuminaWAF/Attack/repeats:10               32289 ns        32289 ns        43351 bytes_per_second=1.32912Mi/s
FullTransaction/LuminaWAF/Attack/repeats:10               32437 ns        32437 ns        43351 bytes_per_second=1.32304Mi/s
FullTransaction/LuminaWAF/Attack/repeats:10               32403 ns        32403 ns        43351 bytes_per_second=1.32442Mi/s
FullTransaction/LuminaWAF/Attack/repeats:10               32339 ns        32339 ns        43351 bytes_per_second=1.32703Mi/s
FullTransaction/LuminaWAF/Attack/repeats:10               32088 ns        32088 ns        43351 bytes_per_second=1.33743Mi/s
FullTransaction/LuminaWAF/Attack/repeats:10_mean          32314 ns        32314 ns           10 bytes_per_second=1.32807Mi/s
FullTransaction/LuminaWAF/Attack/repeats:10_median        32324 ns        32324 ns           10 bytes_per_second=1.32767Mi/s
FullTransaction/LuminaWAF/Attack/repeats:10_stddev         92.3 ns         92.3 ns           10 bytes_per_second=3.90018Ki/s
FullTransaction/LuminaWAF/Attack/repeats:10_cv             0.29 %          0.29 %            10 bytes_per_second=0.29%
FullTransaction/ModSecurity/Allow/repeats:10            1587713 ns      1587709 ns          870 bytes_per_second=27.0634Ki/s
FullTransaction/ModSecurity/Allow/repeats:10            1587826 ns      1587824 ns          870 bytes_per_second=27.0614Ki/s
FullTransaction/ModSecurity/Allow/repeats:10            1585965 ns      1585962 ns          870 bytes_per_second=27.0932Ki/s
FullTransaction/ModSecurity/Allow/repeats:10            1594123 ns      1594120 ns          870 bytes_per_second=26.9545Ki/s
FullTransaction/ModSecurity/Allow/repeats:10            1594898 ns      1594894 ns          870 bytes_per_second=26.9414Ki/s
FullTransaction/ModSecurity/Allow/repeats:10            1594821 ns      1594818 ns          870 bytes_per_second=26.9427Ki/s
FullTransaction/ModSecurity/Allow/repeats:10            1595439 ns      1595435 ns          870 bytes_per_second=26.9323Ki/s
FullTransaction/ModSecurity/Allow/repeats:10            1595431 ns      1595428 ns          870 bytes_per_second=26.9324Ki/s
FullTransaction/ModSecurity/Allow/repeats:10            1593533 ns      1593530 ns          870 bytes_per_second=26.9645Ki/s
FullTransaction/ModSecurity/Allow/repeats:10            1597473 ns      1597469 ns          870 bytes_per_second=26.898Ki/s
FullTransaction/ModSecurity/Allow/repeats:10_mean       1592722 ns      1592719 ns           10 bytes_per_second=26.9784Ki/s
FullTransaction/ModSecurity/Allow/repeats:10_median     1594472 ns      1594469 ns           10 bytes_per_second=26.9486Ki/s
FullTransaction/ModSecurity/Allow/repeats:10_stddev        3997 ns         3997 ns           10 bytes_per_second=69.4372/s
FullTransaction/ModSecurity/Allow/repeats:10_cv            0.25 %          0.25 %            10 bytes_per_second=0.25%
FullTransaction/ModSecurity/Attack/repeats:10           1452338 ns      1452335 ns          963 bytes_per_second=30.2584Ki/s
FullTransaction/ModSecurity/Attack/repeats:10           1454019 ns      1454015 ns          963 bytes_per_second=30.2234Ki/s
FullTransaction/ModSecurity/Attack/repeats:10           1459853 ns      1459850 ns          963 bytes_per_second=30.1026Ki/s
FullTransaction/ModSecurity/Attack/repeats:10           1457489 ns      1457486 ns          963 bytes_per_second=30.1515Ki/s
FullTransaction/ModSecurity/Attack/repeats:10           1456524 ns      1456521 ns          963 bytes_per_second=30.1714Ki/s
FullTransaction/ModSecurity/Attack/repeats:10           1457414 ns      1457411 ns          963 bytes_per_second=30.153Ki/s
FullTransaction/ModSecurity/Attack/repeats:10           1457942 ns      1457938 ns          963 bytes_per_second=30.1421Ki/s
FullTransaction/ModSecurity/Attack/repeats:10           1456231 ns      1456227 ns          963 bytes_per_second=30.1775Ki/s
FullTransaction/ModSecurity/Attack/repeats:10           1456070 ns      1456067 ns          963 bytes_per_second=30.1808Ki/s
FullTransaction/ModSecurity/Attack/repeats:10           1458237 ns      1458234 ns          963 bytes_per_second=30.136Ki/s
FullTransaction/ModSecurity/Attack/repeats:10_mean      1456612 ns      1456608 ns           10 bytes_per_second=30.1697Ki/s
FullTransaction/ModSecurity/Attack/repeats:10_median    1456969 ns      1456966 ns           10 bytes_per_second=30.1622Ki/s
FullTransaction/ModSecurity/Attack/repeats:10_stddev       2154 ns         2154 ns           10 bytes_per_second=45.7303/s
FullTransaction/ModSecurity/Attack/repeats:10_cv           0.15 %          0.15 %            10 bytes_per_second=0.15%
FullTransaction/Coraza/Allow/repeats:10                 1343715 ns      1286678 ns         1064 bytes_per_second=33.3951Ki/s
FullTransaction/Coraza/Allow/repeats:10                 1333688 ns      1281819 ns         1064 bytes_per_second=33.5217Ki/s
FullTransaction/Coraza/Allow/repeats:10                 1339327 ns      1281829 ns         1064 bytes_per_second=33.5214Ki/s
FullTransaction/Coraza/Allow/repeats:10                 1336945 ns      1282857 ns         1064 bytes_per_second=33.4946Ki/s
FullTransaction/Coraza/Allow/repeats:10                 1342034 ns      1288110 ns         1064 bytes_per_second=33.358Ki/s
FullTransaction/Coraza/Allow/repeats:10                 1346944 ns      1292947 ns         1064 bytes_per_second=33.2332Ki/s
FullTransaction/Coraza/Allow/repeats:10                 1335987 ns      1284593 ns         1064 bytes_per_second=33.4493Ki/s
FullTransaction/Coraza/Allow/repeats:10                 1337088 ns      1286373 ns         1064 bytes_per_second=33.403Ki/s
FullTransaction/Coraza/Allow/repeats:10                 1336153 ns      1283543 ns         1064 bytes_per_second=33.4767Ki/s
FullTransaction/Coraza/Allow/repeats:10                 1336897 ns      1285147 ns         1064 bytes_per_second=33.4349Ki/s
FullTransaction/Coraza/Allow/repeats:10_mean            1338878 ns      1285390 ns           10 bytes_per_second=33.4288Ki/s
FullTransaction/Coraza/Allow/repeats:10_median          1337016 ns      1284870 ns           10 bytes_per_second=33.4421Ki/s
FullTransaction/Coraza/Allow/repeats:10_stddev             4112 ns         3384 ns           10 bytes_per_second=89.8973/s
FullTransaction/Coraza/Allow/repeats:10_cv                 0.31 %          0.26 %            10 bytes_per_second=0.26%
FullTransaction/Coraza/Attack/repeats:10                1237644 ns      1197534 ns         1097 bytes_per_second=36.6965Ki/s
FullTransaction/Coraza/Attack/repeats:10                1248003 ns      1204258 ns         1097 bytes_per_second=36.4916Ki/s
FullTransaction/Coraza/Attack/repeats:10                1229482 ns      1190225 ns         1097 bytes_per_second=36.9219Ki/s
FullTransaction/Coraza/Attack/repeats:10                1236816 ns      1194865 ns         1097 bytes_per_second=36.7785Ki/s
FullTransaction/Coraza/Attack/repeats:10                1228601 ns      1188445 ns         1097 bytes_per_second=36.9772Ki/s
FullTransaction/Coraza/Attack/repeats:10                1226540 ns      1188106 ns         1097 bytes_per_second=36.9877Ki/s
FullTransaction/Coraza/Attack/repeats:10                1237862 ns      1196193 ns         1097 bytes_per_second=36.7377Ki/s
FullTransaction/Coraza/Attack/repeats:10                1227444 ns      1188374 ns         1097 bytes_per_second=36.9794Ki/s
FullTransaction/Coraza/Attack/repeats:10                1233012 ns      1191099 ns         1097 bytes_per_second=36.8948Ki/s
FullTransaction/Coraza/Attack/repeats:10                1226755 ns      1188285 ns         1097 bytes_per_second=36.9821Ki/s
FullTransaction/Coraza/Attack/repeats:10_mean           1233216 ns      1192738 ns           10 bytes_per_second=36.8447Ki/s
FullTransaction/Coraza/Attack/repeats:10_median         1231247 ns      1190662 ns           10 bytes_per_second=36.9083Ki/s
FullTransaction/Coraza/Attack/repeats:10_stddev            6894 ns         5374 ns           10 bytes_per_second=169.283/s
FullTransaction/Coraza/Attack/repeats:10_cv                0.56 %          0.45 %            10 bytes_per_second=0.45%
```

### `overhead_micro.log`

Raw JSON: [`overhead_micro.json`](overhead_micro.json)

```text
2026-07-23T07:26:10+00:00
Running /srv/lumina-canonical/LuminaWAF/build/lumina_benchmark_harness
Run on (16 X 2999.27 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB (x16)
  L1 Instruction 32 KiB (x16)
  L2 Unified 1024 KiB (x16)
  L3 Unified 16384 KiB (x4)
Load Average: 1.17, 1.21, 0.96
-----------------------------------------------------------------------------------------------------------------------------
Benchmark                                                                   Time             CPU   Iterations UserCounters...
-----------------------------------------------------------------------------------------------------------------------------
Overhead/LuminaWAF/BundleBuild/AllowRotation/repeats:10                  64.6 ns         64.6 ns     21715091 bytes_per_second=538.666Mi/s
Overhead/LuminaWAF/BundleBuild/AllowRotation/repeats:10                  64.6 ns         64.6 ns     21715091 bytes_per_second=538.79Mi/s
Overhead/LuminaWAF/BundleBuild/AllowRotation/repeats:10                  64.6 ns         64.6 ns     21715091 bytes_per_second=538.446Mi/s
Overhead/LuminaWAF/BundleBuild/AllowRotation/repeats:10                  64.7 ns         64.7 ns     21715091 bytes_per_second=538.126Mi/s
Overhead/LuminaWAF/BundleBuild/AllowRotation/repeats:10                  64.5 ns         64.5 ns     21715091 bytes_per_second=539.265Mi/s
Overhead/LuminaWAF/BundleBuild/AllowRotation/repeats:10                  64.6 ns         64.6 ns     21715091 bytes_per_second=538.773Mi/s
Overhead/LuminaWAF/BundleBuild/AllowRotation/repeats:10                  64.6 ns         64.6 ns     21715091 bytes_per_second=538.615Mi/s
Overhead/LuminaWAF/BundleBuild/AllowRotation/repeats:10                  64.5 ns         64.5 ns     21715091 bytes_per_second=539.666Mi/s
Overhead/LuminaWAF/BundleBuild/AllowRotation/repeats:10                  64.6 ns         64.6 ns     21715091 bytes_per_second=538.722Mi/s
Overhead/LuminaWAF/BundleBuild/AllowRotation/repeats:10                  64.6 ns         64.6 ns     21715091 bytes_per_second=538.527Mi/s
Overhead/LuminaWAF/BundleBuild/AllowRotation/repeats:10_mean             64.6 ns         64.6 ns           10 bytes_per_second=538.76Mi/s
Overhead/LuminaWAF/BundleBuild/AllowRotation/repeats:10_median           64.6 ns         64.6 ns           10 bytes_per_second=538.694Mi/s
Overhead/LuminaWAF/BundleBuild/AllowRotation/repeats:10_stddev          0.052 ns        0.052 ns           10 bytes_per_second=440.246Ki/s
Overhead/LuminaWAF/BundleBuild/AllowRotation/repeats:10_cv               0.08 %          0.08 %            10 bytes_per_second=0.08%
Overhead/LuminaWAF/InspectPrebuilt/AllowRotation/repeats:10             46823 ns        46823 ns        29919 bytes_per_second=761.258Ki/s
Overhead/LuminaWAF/InspectPrebuilt/AllowRotation/repeats:10             46867 ns        46867 ns        29919 bytes_per_second=760.553Ki/s
Overhead/LuminaWAF/InspectPrebuilt/AllowRotation/repeats:10             46887 ns        46887 ns        29919 bytes_per_second=760.217Ki/s
Overhead/LuminaWAF/InspectPrebuilt/AllowRotation/repeats:10             47196 ns        47196 ns        29919 bytes_per_second=755.247Ki/s
Overhead/LuminaWAF/InspectPrebuilt/AllowRotation/repeats:10             47136 ns        47136 ns        29919 bytes_per_second=756.208Ki/s
Overhead/LuminaWAF/InspectPrebuilt/AllowRotation/repeats:10             47244 ns        47244 ns        29919 bytes_per_second=754.473Ki/s
Overhead/LuminaWAF/InspectPrebuilt/AllowRotation/repeats:10             47234 ns        47234 ns        29919 bytes_per_second=754.634Ki/s
Overhead/LuminaWAF/InspectPrebuilt/AllowRotation/repeats:10             47159 ns        47159 ns        29919 bytes_per_second=755.839Ki/s
Overhead/LuminaWAF/InspectPrebuilt/AllowRotation/repeats:10             47144 ns        47144 ns        29919 bytes_per_second=756.076Ki/s
Overhead/LuminaWAF/InspectPrebuilt/AllowRotation/repeats:10             47206 ns        47206 ns        29919 bytes_per_second=755.088Ki/s
Overhead/LuminaWAF/InspectPrebuilt/AllowRotation/repeats:10_mean        47090 ns        47090 ns           10 bytes_per_second=756.959Ki/s
Overhead/LuminaWAF/InspectPrebuilt/AllowRotation/repeats:10_median      47151 ns        47151 ns           10 bytes_per_second=755.957Ki/s
Overhead/LuminaWAF/InspectPrebuilt/AllowRotation/repeats:10_stddev        164 ns          164 ns           10 bytes_per_second=2.6381Ki/s
Overhead/LuminaWAF/InspectPrebuilt/AllowRotation/repeats:10_cv           0.35 %          0.35 %            10 bytes_per_second=0.35%
Overhead/LuminaWAF/FullDirect/AllowRotation/repeats:10                  47155 ns        47155 ns        29684 bytes_per_second=755.901Ki/s
Overhead/LuminaWAF/FullDirect/AllowRotation/repeats:10                  47286 ns        47286 ns        29684 bytes_per_second=753.807Ki/s
Overhead/LuminaWAF/FullDirect/AllowRotation/repeats:10                  47228 ns        47228 ns        29684 bytes_per_second=754.735Ki/s
Overhead/LuminaWAF/FullDirect/AllowRotation/repeats:10                  47206 ns        47206 ns        29684 bytes_per_second=755.079Ki/s
Overhead/LuminaWAF/FullDirect/AllowRotation/repeats:10                  47299 ns        47299 ns        29684 bytes_per_second=753.599Ki/s
Overhead/LuminaWAF/FullDirect/AllowRotation/repeats:10                  47268 ns        47268 ns        29684 bytes_per_second=754.1Ki/s
Overhead/LuminaWAF/FullDirect/AllowRotation/repeats:10                  47251 ns        47251 ns        29684 bytes_per_second=754.358Ki/s
Overhead/LuminaWAF/FullDirect/AllowRotation/repeats:10                  47256 ns        47256 ns        29684 bytes_per_second=754.282Ki/s
Overhead/LuminaWAF/FullDirect/AllowRotation/repeats:10                  47360 ns        47360 ns        29684 bytes_per_second=752.636Ki/s
Overhead/LuminaWAF/FullDirect/AllowRotation/repeats:10                  47268 ns        47268 ns        29684 bytes_per_second=754.094Ki/s
Overhead/LuminaWAF/FullDirect/AllowRotation/repeats:10_mean             47258 ns        47258 ns           10 bytes_per_second=754.259Ki/s
Overhead/LuminaWAF/FullDirect/AllowRotation/repeats:10_median           47262 ns        47262 ns           10 bytes_per_second=754.191Ki/s
Overhead/LuminaWAF/FullDirect/AllowRotation/repeats:10_stddev            55.0 ns         55.0 ns           10 bytes_per_second=898.545/s
Overhead/LuminaWAF/FullDirect/AllowRotation/repeats:10_cv                0.12 %          0.12 %            10 bytes_per_second=0.12%
```

### `overhead_micro_process_01.log`

Raw JSON: [`overhead_micro_process_01.json`](overhead_micro_process_01.json)

```text
2026-07-23T07:26:54+00:00
Running /srv/lumina-canonical/LuminaWAF/build/lumina_benchmark_harness
Run on (16 X 2999.45 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB (x16)
  L1 Instruction 32 KiB (x16)
  L2 Unified 1024 KiB (x16)
  L3 Unified 16384 KiB (x4)
Load Average: 1.09, 1.18, 0.96
-----------------------------------------------------------------------------------------------------------------------------
Benchmark                                                                   Time             CPU   Iterations UserCounters...
-----------------------------------------------------------------------------------------------------------------------------
Overhead/LuminaWAF/BundleBuild/AllowRotation/repeats:10                  64.1 ns         64.1 ns     21801938 bytes_per_second=542.954Mi/s
Overhead/LuminaWAF/BundleBuild/AllowRotation/repeats:10                  64.3 ns         64.3 ns     21801938 bytes_per_second=541.411Mi/s
Overhead/LuminaWAF/BundleBuild/AllowRotation/repeats:10                  64.2 ns         64.2 ns     21801938 bytes_per_second=541.901Mi/s
Overhead/LuminaWAF/BundleBuild/AllowRotation/repeats:10                  64.1 ns         64.1 ns     21801938 bytes_per_second=543.408Mi/s
Overhead/LuminaWAF/BundleBuild/AllowRotation/repeats:10                  64.1 ns         64.1 ns     21801938 bytes_per_second=542.856Mi/s
Overhead/LuminaWAF/BundleBuild/AllowRotation/repeats:10                  64.2 ns         64.2 ns     21801938 bytes_per_second=542.21Mi/s
Overhead/LuminaWAF/BundleBuild/AllowRotation/repeats:10                  64.2 ns         64.2 ns     21801938 bytes_per_second=542.378Mi/s
Overhead/LuminaWAF/BundleBuild/AllowRotation/repeats:10                  64.2 ns         64.2 ns     21801938 bytes_per_second=542.187Mi/s
Overhead/LuminaWAF/BundleBuild/AllowRotation/repeats:10                  64.1 ns         64.1 ns     21801938 bytes_per_second=542.907Mi/s
Overhead/LuminaWAF/BundleBuild/AllowRotation/repeats:10                  64.5 ns         64.5 ns     21801938 bytes_per_second=539.915Mi/s
Overhead/LuminaWAF/BundleBuild/AllowRotation/repeats:10_mean             64.2 ns         64.2 ns           10 bytes_per_second=542.213Mi/s
Overhead/LuminaWAF/BundleBuild/AllowRotation/repeats:10_median           64.2 ns         64.2 ns           10 bytes_per_second=542.294Mi/s
Overhead/LuminaWAF/BundleBuild/AllowRotation/repeats:10_stddev          0.118 ns        0.118 ns           10 bytes_per_second=1019.57Ki/s
Overhead/LuminaWAF/BundleBuild/AllowRotation/repeats:10_cv               0.18 %          0.18 %            10 bytes_per_second=0.18%
Overhead/LuminaWAF/InspectPrebuilt/AllowRotation/repeats:10             46890 ns        46890 ns        29860 bytes_per_second=760.177Ki/s
Overhead/LuminaWAF/InspectPrebuilt/AllowRotation/repeats:10             47095 ns        47095 ns        29860 bytes_per_second=756.868Ki/s
Overhead/LuminaWAF/InspectPrebuilt/AllowRotation/repeats:10             47138 ns        47138 ns        29860 bytes_per_second=756.17Ki/s
Overhead/LuminaWAF/InspectPrebuilt/AllowRotation/repeats:10             47101 ns        47101 ns        29860 bytes_per_second=756.775Ki/s
Overhead/LuminaWAF/InspectPrebuilt/AllowRotation/repeats:10             47199 ns        47199 ns        29860 bytes_per_second=755.202Ki/s
Overhead/LuminaWAF/InspectPrebuilt/AllowRotation/repeats:10             47130 ns        47130 ns        29860 bytes_per_second=756.306Ki/s
Overhead/LuminaWAF/InspectPrebuilt/AllowRotation/repeats:10             47198 ns        47198 ns        29860 bytes_per_second=755.219Ki/s
Overhead/LuminaWAF/InspectPrebuilt/AllowRotation/repeats:10             47226 ns        47226 ns        29860 bytes_per_second=754.772Ki/s
Overhead/LuminaWAF/InspectPrebuilt/AllowRotation/repeats:10             47328 ns        47328 ns        29860 bytes_per_second=753.139Ki/s
Overhead/LuminaWAF/InspectPrebuilt/AllowRotation/repeats:10             47512 ns        47512 ns        29860 bytes_per_second=750.216Ki/s
Overhead/LuminaWAF/InspectPrebuilt/AllowRotation/repeats:10_mean        47182 ns        47182 ns           10 bytes_per_second=755.484Ki/s
Overhead/LuminaWAF/InspectPrebuilt/AllowRotation/repeats:10_median      47168 ns        47168 ns           10 bytes_per_second=755.694Ki/s
Overhead/LuminaWAF/InspectPrebuilt/AllowRotation/repeats:10_stddev        162 ns          162 ns           10 bytes_per_second=2.59615Ki/s
Overhead/LuminaWAF/InspectPrebuilt/AllowRotation/repeats:10_cv           0.34 %          0.34 %            10 bytes_per_second=0.34%
Overhead/LuminaWAF/FullDirect/AllowRotation/repeats:10                  47444 ns        47444 ns        29504 bytes_per_second=751.294Ki/s
Overhead/LuminaWAF/FullDirect/AllowRotation/repeats:10                  47341 ns        47341 ns        29504 bytes_per_second=752.937Ki/s
Overhead/LuminaWAF/FullDirect/AllowRotation/repeats:10                  47358 ns        47358 ns        29504 bytes_per_second=752.659Ki/s
Overhead/LuminaWAF/FullDirect/AllowRotation/repeats:10                  47352 ns        47352 ns        29504 bytes_per_second=752.75Ki/s
Overhead/LuminaWAF/FullDirect/AllowRotation/repeats:10                  47324 ns        47324 ns        29504 bytes_per_second=753.204Ki/s
Overhead/LuminaWAF/FullDirect/AllowRotation/repeats:10                  47276 ns        47276 ns        29504 bytes_per_second=753.966Ki/s
Overhead/LuminaWAF/FullDirect/AllowRotation/repeats:10                  47248 ns        47248 ns        29504 bytes_per_second=754.41Ki/s
Overhead/LuminaWAF/FullDirect/AllowRotation/repeats:10                  47273 ns        47273 ns        29504 bytes_per_second=754.013Ki/s
Overhead/LuminaWAF/FullDirect/AllowRotation/repeats:10                  47301 ns        47301 ns        29504 bytes_per_second=753.567Ki/s
Overhead/LuminaWAF/FullDirect/AllowRotation/repeats:10                  47258 ns        47258 ns        29504 bytes_per_second=754.259Ki/s
Overhead/LuminaWAF/FullDirect/AllowRotation/repeats:10_mean             47318 ns        47318 ns           10 bytes_per_second=753.306Ki/s
Overhead/LuminaWAF/FullDirect/AllowRotation/repeats:10_median           47312 ns        47312 ns           10 bytes_per_second=753.385Ki/s
Overhead/LuminaWAF/FullDirect/AllowRotation/repeats:10_stddev            59.5 ns         59.5 ns           10 bytes_per_second=968.503/s
Overhead/LuminaWAF/FullDirect/AllowRotation/repeats:10_cv                0.13 %          0.13 %            10 bytes_per_second=0.13%
```

### `overhead_micro_process_02.log`

Raw JSON: [`overhead_micro_process_02.json`](overhead_micro_process_02.json)

```text
2026-07-23T07:27:37+00:00
Running /srv/lumina-canonical/LuminaWAF/build/lumina_benchmark_harness
Run on (16 X 2997.55 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB (x16)
  L1 Instruction 32 KiB (x16)
  L2 Unified 1024 KiB (x16)
  L3 Unified 16384 KiB (x4)
Load Average: 1.04, 1.16, 0.97
-----------------------------------------------------------------------------------------------------------------------------
Benchmark                                                                   Time             CPU   Iterations UserCounters...
-----------------------------------------------------------------------------------------------------------------------------
Overhead/LuminaWAF/BundleBuild/AllowRotation/repeats:10                  64.3 ns         64.3 ns     21788983 bytes_per_second=541.171Mi/s
Overhead/LuminaWAF/BundleBuild/AllowRotation/repeats:10                  64.2 ns         64.2 ns     21788983 bytes_per_second=542.618Mi/s
Overhead/LuminaWAF/BundleBuild/AllowRotation/repeats:10                  64.3 ns         64.3 ns     21788983 bytes_per_second=541.492Mi/s
Overhead/LuminaWAF/BundleBuild/AllowRotation/repeats:10                  64.2 ns         64.2 ns     21788983 bytes_per_second=541.857Mi/s
Overhead/LuminaWAF/BundleBuild/AllowRotation/repeats:10                  64.1 ns         64.1 ns     21788983 bytes_per_second=543.098Mi/s
Overhead/LuminaWAF/BundleBuild/AllowRotation/repeats:10                  64.2 ns         64.2 ns     21788983 bytes_per_second=541.785Mi/s
Overhead/LuminaWAF/BundleBuild/AllowRotation/repeats:10                  64.2 ns         64.2 ns     21788983 bytes_per_second=541.999Mi/s
Overhead/LuminaWAF/BundleBuild/AllowRotation/repeats:10                  64.3 ns         64.3 ns     21788983 bytes_per_second=541.489Mi/s
Overhead/LuminaWAF/BundleBuild/AllowRotation/repeats:10                  64.2 ns         64.2 ns     21788983 bytes_per_second=542.319Mi/s
Overhead/LuminaWAF/BundleBuild/AllowRotation/repeats:10                  64.3 ns         64.3 ns     21788983 bytes_per_second=541.7Mi/s
Overhead/LuminaWAF/BundleBuild/AllowRotation/repeats:10_mean             64.2 ns         64.2 ns           10 bytes_per_second=541.953Mi/s
Overhead/LuminaWAF/BundleBuild/AllowRotation/repeats:10_median           64.2 ns         64.2 ns           10 bytes_per_second=541.821Mi/s
Overhead/LuminaWAF/BundleBuild/AllowRotation/repeats:10_stddev          0.069 ns        0.069 ns           10 bytes_per_second=594.108Ki/s
Overhead/LuminaWAF/BundleBuild/AllowRotation/repeats:10_cv               0.11 %          0.11 %            10 bytes_per_second=0.11%
Overhead/LuminaWAF/InspectPrebuilt/AllowRotation/repeats:10             46958 ns        46958 ns        29893 bytes_per_second=759.075Ki/s
Overhead/LuminaWAF/InspectPrebuilt/AllowRotation/repeats:10             47039 ns        47039 ns        29893 bytes_per_second=757.762Ki/s
Overhead/LuminaWAF/InspectPrebuilt/AllowRotation/repeats:10             47228 ns        47228 ns        29893 bytes_per_second=754.739Ki/s
Overhead/LuminaWAF/InspectPrebuilt/AllowRotation/repeats:10             47250 ns        47250 ns        29893 bytes_per_second=754.381Ki/s
Overhead/LuminaWAF/InspectPrebuilt/AllowRotation/repeats:10             47214 ns        47214 ns        29893 bytes_per_second=754.951Ki/s
Overhead/LuminaWAF/InspectPrebuilt/AllowRotation/repeats:10             47154 ns        47154 ns        29893 bytes_per_second=755.923Ki/s
Overhead/LuminaWAF/InspectPrebuilt/AllowRotation/repeats:10             47228 ns        47228 ns        29893 bytes_per_second=754.728Ki/s
Overhead/LuminaWAF/InspectPrebuilt/AllowRotation/repeats:10             47276 ns        47276 ns        29893 bytes_per_second=753.967Ki/s
Overhead/LuminaWAF/InspectPrebuilt/AllowRotation/repeats:10             47239 ns        47239 ns        29893 bytes_per_second=754.553Ki/s
Overhead/LuminaWAF/InspectPrebuilt/AllowRotation/repeats:10             47197 ns        47197 ns        29893 bytes_per_second=755.228Ki/s
Overhead/LuminaWAF/InspectPrebuilt/AllowRotation/repeats:10_mean        47178 ns        47178 ns           10 bytes_per_second=755.531Ki/s
Overhead/LuminaWAF/InspectPrebuilt/AllowRotation/repeats:10_median      47221 ns        47221 ns           10 bytes_per_second=754.845Ki/s
Overhead/LuminaWAF/InspectPrebuilt/AllowRotation/repeats:10_stddev        102 ns          102 ns           10 bytes_per_second=1.63691Ki/s
Overhead/LuminaWAF/InspectPrebuilt/AllowRotation/repeats:10_cv           0.22 %          0.22 %            10 bytes_per_second=0.22%
Overhead/LuminaWAF/FullDirect/AllowRotation/repeats:10                  47372 ns        47372 ns        29573 bytes_per_second=752.437Ki/s
Overhead/LuminaWAF/FullDirect/AllowRotation/repeats:10                  47257 ns        47257 ns        29573 bytes_per_second=754.263Ki/s
Overhead/LuminaWAF/FullDirect/AllowRotation/repeats:10                  47208 ns        47208 ns        29573 bytes_per_second=755.047Ki/s
Overhead/LuminaWAF/FullDirect/AllowRotation/repeats:10                  47259 ns        47259 ns        29573 bytes_per_second=754.243Ki/s
Overhead/LuminaWAF/FullDirect/AllowRotation/repeats:10                  47171 ns        47171 ns        29573 bytes_per_second=755.638Ki/s
Overhead/LuminaWAF/FullDirect/AllowRotation/repeats:10                  47066 ns        47066 ns        29573 bytes_per_second=757.331Ki/s
Overhead/LuminaWAF/FullDirect/AllowRotation/repeats:10                  46871 ns        46871 ns        29573 bytes_per_second=760.474Ki/s
Overhead/LuminaWAF/FullDirect/AllowRotation/repeats:10                  46895 ns        46895 ns        29573 bytes_per_second=760.093Ki/s
Overhead/LuminaWAF/FullDirect/AllowRotation/repeats:10                  46891 ns        46891 ns        29573 bytes_per_second=760.156Ki/s
Overhead/LuminaWAF/FullDirect/AllowRotation/repeats:10                  46968 ns        46968 ns        29573 bytes_per_second=758.914Ki/s
Overhead/LuminaWAF/FullDirect/AllowRotation/repeats:10_mean             47096 ns        47096 ns           10 bytes_per_second=756.86Ki/s
Overhead/LuminaWAF/FullDirect/AllowRotation/repeats:10_median           47119 ns        47119 ns           10 bytes_per_second=756.485Ki/s
Overhead/LuminaWAF/FullDirect/AllowRotation/repeats:10_stddev             182 ns          182 ns           10 bytes_per_second=2.92021Ki/s
Overhead/LuminaWAF/FullDirect/AllowRotation/repeats:10_cv                0.39 %          0.39 %            10 bytes_per_second=0.39%
```

### `overhead_micro_process_03.log`

Raw JSON: [`overhead_micro_process_03.json`](overhead_micro_process_03.json)

```text
2026-07-23T07:28:21+00:00
Running /srv/lumina-canonical/LuminaWAF/build/lumina_benchmark_harness
Run on (16 X 3009.58 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB (x16)
  L1 Instruction 32 KiB (x16)
  L2 Unified 1024 KiB (x16)
  L3 Unified 16384 KiB (x4)
Load Average: 1.02, 1.13, 0.97
-----------------------------------------------------------------------------------------------------------------------------
Benchmark                                                                   Time             CPU   Iterations UserCounters...
-----------------------------------------------------------------------------------------------------------------------------
Overhead/LuminaWAF/BundleBuild/AllowRotation/repeats:10                  64.2 ns         64.2 ns     21799288 bytes_per_second=542.154Mi/s
Overhead/LuminaWAF/BundleBuild/AllowRotation/repeats:10                  64.3 ns         64.3 ns     21799288 bytes_per_second=541.238Mi/s
Overhead/LuminaWAF/BundleBuild/AllowRotation/repeats:10                  64.3 ns         64.3 ns     21799288 bytes_per_second=541.399Mi/s
Overhead/LuminaWAF/BundleBuild/AllowRotation/repeats:10                  64.3 ns         64.3 ns     21799288 bytes_per_second=541.347Mi/s
Overhead/LuminaWAF/BundleBuild/AllowRotation/repeats:10                  64.2 ns         64.2 ns     21799288 bytes_per_second=542.317Mi/s
Overhead/LuminaWAF/BundleBuild/AllowRotation/repeats:10                  64.2 ns         64.2 ns     21799288 bytes_per_second=542.402Mi/s
Overhead/LuminaWAF/BundleBuild/AllowRotation/repeats:10                  64.1 ns         64.1 ns     21799288 bytes_per_second=543.224Mi/s
Overhead/LuminaWAF/BundleBuild/AllowRotation/repeats:10                  64.1 ns         64.1 ns     21799288 bytes_per_second=542.7Mi/s
Overhead/LuminaWAF/BundleBuild/AllowRotation/repeats:10                  64.3 ns         64.3 ns     21799288 bytes_per_second=541.738Mi/s
Overhead/LuminaWAF/BundleBuild/AllowRotation/repeats:10                  64.4 ns         64.4 ns     21799288 bytes_per_second=540.868Mi/s
Overhead/LuminaWAF/BundleBuild/AllowRotation/repeats:10_mean             64.2 ns         64.2 ns           10 bytes_per_second=541.939Mi/s
Overhead/LuminaWAF/BundleBuild/AllowRotation/repeats:10_median           64.2 ns         64.2 ns           10 bytes_per_second=541.946Mi/s
Overhead/LuminaWAF/BundleBuild/AllowRotation/repeats:10_stddev          0.088 ns        0.088 ns           10 bytes_per_second=759.702Ki/s
Overhead/LuminaWAF/BundleBuild/AllowRotation/repeats:10_cv               0.14 %          0.14 %            10 bytes_per_second=0.14%
Overhead/LuminaWAF/InspectPrebuilt/AllowRotation/repeats:10             47057 ns        47057 ns        29798 bytes_per_second=757.472Ki/s
Overhead/LuminaWAF/InspectPrebuilt/AllowRotation/repeats:10             47132 ns        47132 ns        29798 bytes_per_second=756.277Ki/s
Overhead/LuminaWAF/InspectPrebuilt/AllowRotation/repeats:10             47241 ns        47241 ns        29798 bytes_per_second=754.527Ki/s
Overhead/LuminaWAF/InspectPrebuilt/AllowRotation/repeats:10             47295 ns        47295 ns        29798 bytes_per_second=753.67Ki/s
Overhead/LuminaWAF/InspectPrebuilt/AllowRotation/repeats:10             47197 ns        47197 ns        29798 bytes_per_second=755.236Ki/s
Overhead/LuminaWAF/InspectPrebuilt/AllowRotation/repeats:10             47096 ns        47096 ns        29798 bytes_per_second=756.848Ki/s
Overhead/LuminaWAF/InspectPrebuilt/AllowRotation/repeats:10             47164 ns        47164 ns        29798 bytes_per_second=755.757Ki/s
Overhead/LuminaWAF/InspectPrebuilt/AllowRotation/repeats:10             47292 ns        47292 ns        29798 bytes_per_second=753.71Ki/s
Overhead/LuminaWAF/InspectPrebuilt/AllowRotation/repeats:10             47378 ns        47378 ns        29798 bytes_per_second=752.343Ki/s
Overhead/LuminaWAF/InspectPrebuilt/AllowRotation/repeats:10             47406 ns        47406 ns        29798 bytes_per_second=751.901Ki/s
Overhead/LuminaWAF/InspectPrebuilt/AllowRotation/repeats:10_mean        47226 ns        47226 ns           10 bytes_per_second=754.774Ki/s
Overhead/LuminaWAF/InspectPrebuilt/AllowRotation/repeats:10_median      47219 ns        47219 ns           10 bytes_per_second=754.882Ki/s
Overhead/LuminaWAF/InspectPrebuilt/AllowRotation/repeats:10_stddev        117 ns          117 ns           10 bytes_per_second=1.87384Ki/s
Overhead/LuminaWAF/InspectPrebuilt/AllowRotation/repeats:10_cv           0.25 %          0.25 %            10 bytes_per_second=0.25%
Overhead/LuminaWAF/FullDirect/AllowRotation/repeats:10                  47219 ns        47219 ns        29547 bytes_per_second=754.88Ki/s
Overhead/LuminaWAF/FullDirect/AllowRotation/repeats:10                  47197 ns        47197 ns        29547 bytes_per_second=755.227Ki/s
Overhead/LuminaWAF/FullDirect/AllowRotation/repeats:10                  47106 ns        47106 ns        29547 bytes_per_second=756.691Ki/s
Overhead/LuminaWAF/FullDirect/AllowRotation/repeats:10                  47100 ns        47100 ns        29547 bytes_per_second=756.782Ki/s
Overhead/LuminaWAF/FullDirect/AllowRotation/repeats:10                  47197 ns        47197 ns        29547 bytes_per_second=755.23Ki/s
Overhead/LuminaWAF/FullDirect/AllowRotation/repeats:10                  47203 ns        47203 ns        29547 bytes_per_second=755.137Ki/s
Overhead/LuminaWAF/FullDirect/AllowRotation/repeats:10                  47420 ns        47420 ns        29547 bytes_per_second=751.678Ki/s
Overhead/LuminaWAF/FullDirect/AllowRotation/repeats:10                  47445 ns        47445 ns        29547 bytes_per_second=751.273Ki/s
Overhead/LuminaWAF/FullDirect/AllowRotation/repeats:10                  47498 ns        47498 ns        29547 bytes_per_second=750.436Ki/s
Overhead/LuminaWAF/FullDirect/AllowRotation/repeats:10                  47495 ns        47495 ns        29547 bytes_per_second=750.49Ki/s
Overhead/LuminaWAF/FullDirect/AllowRotation/repeats:10_mean             47288 ns        47288 ns           10 bytes_per_second=753.782Ki/s
Overhead/LuminaWAF/FullDirect/AllowRotation/repeats:10_median           47211 ns        47211 ns           10 bytes_per_second=755.008Ki/s
Overhead/LuminaWAF/FullDirect/AllowRotation/repeats:10_stddev             159 ns          159 ns           10 bytes_per_second=2.52638Ki/s
Overhead/LuminaWAF/FullDirect/AllowRotation/repeats:10_cv                0.34 %          0.34 %            10 bytes_per_second=0.34%
```

### `overhead_micro_process_04.log`

Raw JSON: [`overhead_micro_process_04.json`](overhead_micro_process_04.json)

```text
2026-07-23T07:29:05+00:00
Running /srv/lumina-canonical/LuminaWAF/build/lumina_benchmark_harness
Run on (16 X 2997.11 MHz CPU s)
CPU Caches:
  L1 Data 32 KiB (x16)
  L1 Instruction 32 KiB (x16)
  L2 Unified 1024 KiB (x16)
  L3 Unified 16384 KiB (x4)
Load Average: 1.01, 1.11, 0.98
-----------------------------------------------------------------------------------------------------------------------------
Benchmark                                                                   Time             CPU   Iterations UserCounters...
-----------------------------------------------------------------------------------------------------------------------------
Overhead/LuminaWAF/BundleBuild/AllowRotation/repeats:10                  64.7 ns         64.7 ns     21640749 bytes_per_second=538.135Mi/s
Overhead/LuminaWAF/BundleBuild/AllowRotation/repeats:10                  64.4 ns         64.4 ns     21640749 bytes_per_second=540.113Mi/s
Overhead/LuminaWAF/BundleBuild/AllowRotation/repeats:10                  64.6 ns         64.6 ns     21640749 bytes_per_second=538.553Mi/s
Overhead/LuminaWAF/BundleBuild/AllowRotation/repeats:10                  64.7 ns         64.7 ns     21640749 bytes_per_second=538.167Mi/s
Overhead/LuminaWAF/BundleBuild/AllowRotation/repeats:10                  64.6 ns         64.6 ns     21640749 bytes_per_second=538.902Mi/s
Overhead/LuminaWAF/BundleBuild/AllowRotation/repeats:10                  64.6 ns         64.6 ns     21640749 bytes_per_second=538.523Mi/s
Overhead/LuminaWAF/BundleBuild/AllowRotation/repeats:10                  64.6 ns         64.6 ns     21640749 bytes_per_second=538.7Mi/s
Overhead/LuminaWAF/BundleBuild/AllowRotation/repeats:10                  64.6 ns         64.6 ns     21640749 bytes_per_second=538.77Mi/s
Overhead/LuminaWAF/BundleBuild/AllowRotation/repeats:10                  64.7 ns         64.7 ns     21640749 bytes_per_second=538.071Mi/s
Overhead/LuminaWAF/BundleBuild/AllowRotation/repeats:10                  64.6 ns         64.6 ns     21640749 bytes_per_second=539.172Mi/s
Overhead/LuminaWAF/BundleBuild/AllowRotation/repeats:10_mean             64.6 ns         64.6 ns           10 bytes_per_second=538.711Mi/s
Overhead/LuminaWAF/BundleBuild/AllowRotation/repeats:10_median           64.6 ns         64.6 ns           10 bytes_per_second=538.627Mi/s
Overhead/LuminaWAF/BundleBuild/AllowRotation/repeats:10_stddev          0.073 ns        0.073 ns           10 bytes_per_second=621.65Ki/s
Overhead/LuminaWAF/BundleBuild/AllowRotation/repeats:10_cv               0.11 %          0.11 %            10 bytes_per_second=0.11%
Overhead/LuminaWAF/InspectPrebuilt/AllowRotation/repeats:10             47043 ns        47043 ns        29773 bytes_per_second=757.695Ki/s
Overhead/LuminaWAF/InspectPrebuilt/AllowRotation/repeats:10             47060 ns        47060 ns        29773 bytes_per_second=757.432Ki/s
Overhead/LuminaWAF/InspectPrebuilt/AllowRotation/repeats:10             47299 ns        47299 ns        29773 bytes_per_second=753.604Ki/s
Overhead/LuminaWAF/InspectPrebuilt/AllowRotation/repeats:10             47236 ns        47236 ns        29773 bytes_per_second=754.607Ki/s
Overhead/LuminaWAF/InspectPrebuilt/AllowRotation/repeats:10             47304 ns        47304 ns        29773 bytes_per_second=753.527Ki/s
Overhead/LuminaWAF/InspectPrebuilt/AllowRotation/repeats:10             47270 ns        47270 ns        29773 bytes_per_second=754.062Ki/s
Overhead/LuminaWAF/InspectPrebuilt/AllowRotation/repeats:10             47340 ns        47340 ns        29773 bytes_per_second=752.955Ki/s
Overhead/LuminaWAF/InspectPrebuilt/AllowRotation/repeats:10             47406 ns        47406 ns        29773 bytes_per_second=751.897Ki/s
Overhead/LuminaWAF/InspectPrebuilt/AllowRotation/repeats:10             47331 ns        47331 ns        29773 bytes_per_second=753.088Ki/s
Overhead/LuminaWAF/InspectPrebuilt/AllowRotation/repeats:10             47321 ns        47321 ns        29773 bytes_per_second=753.248Ki/s
Overhead/LuminaWAF/InspectPrebuilt/AllowRotation/repeats:10_mean        47261 ns        47261 ns           10 bytes_per_second=754.212Ki/s
Overhead/LuminaWAF/InspectPrebuilt/AllowRotation/repeats:10_median      47301 ns        47301 ns           10 bytes_per_second=753.565Ki/s
Overhead/LuminaWAF/InspectPrebuilt/AllowRotation/repeats:10_stddev        119 ns          119 ns           10 bytes_per_second=1.90474Ki/s
Overhead/LuminaWAF/InspectPrebuilt/AllowRotation/repeats:10_cv           0.25 %          0.25 %            10 bytes_per_second=0.25%
Overhead/LuminaWAF/FullDirect/AllowRotation/repeats:10                  47342 ns        47342 ns        29594 bytes_per_second=752.913Ki/s
Overhead/LuminaWAF/FullDirect/AllowRotation/repeats:10                  47284 ns        47284 ns        29594 bytes_per_second=753.847Ki/s
Overhead/LuminaWAF/FullDirect/AllowRotation/repeats:10                  47270 ns        47270 ns        29594 bytes_per_second=754.068Ki/s
Overhead/LuminaWAF/FullDirect/AllowRotation/repeats:10                  47256 ns        47256 ns        29594 bytes_per_second=754.286Ki/s
Overhead/LuminaWAF/FullDirect/AllowRotation/repeats:10                  47268 ns        47268 ns        29594 bytes_per_second=754.09Ki/s
Overhead/LuminaWAF/FullDirect/AllowRotation/repeats:10                  47246 ns        47246 ns        29594 bytes_per_second=754.439Ki/s
Overhead/LuminaWAF/FullDirect/AllowRotation/repeats:10                  47125 ns        47125 ns        29594 bytes_per_second=756.39Ki/s
Overhead/LuminaWAF/FullDirect/AllowRotation/repeats:10                  47144 ns        47144 ns        29594 bytes_per_second=756.084Ki/s
Overhead/LuminaWAF/FullDirect/AllowRotation/repeats:10                  47224 ns        47224 ns        29594 bytes_per_second=754.796Ki/s
Overhead/LuminaWAF/FullDirect/AllowRotation/repeats:10                  47182 ns        47182 ns        29594 bytes_per_second=755.473Ki/s
Overhead/LuminaWAF/FullDirect/AllowRotation/repeats:10_mean             47234 ns        47234 ns           10 bytes_per_second=754.639Ki/s
Overhead/LuminaWAF/FullDirect/AllowRotation/repeats:10_median           47251 ns        47251 ns           10 bytes_per_second=754.362Ki/s
Overhead/LuminaWAF/FullDirect/AllowRotation/repeats:10_stddev            66.8 ns         66.9 ns           10 bytes_per_second=1.06857Ki/s
Overhead/LuminaWAF/FullDirect/AllowRotation/repeats:10_cv                0.14 %          0.14 %            10 bytes_per_second=0.14%
```
