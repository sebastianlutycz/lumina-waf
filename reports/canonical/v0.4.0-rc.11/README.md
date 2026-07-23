# LuminaWAF v0.4.0-rc.11 Canonical Evidence

This bundle contains the compact publication evidence for the Benchmark Harness V1.0 canonical
run completed on 2026-07-23.

## Provenance

- Measurement tag: `v0.4.0-rc.11`
- Measurement commit: `2897a63c8b74912e8bc1d188080e63ad8a932f57`
- Run ID: `v0.4.0-rc.11-canonical-20260723T071816Z`
- Result: `CANONICAL`
- Exit status: `0`
- Wall time: `7h 34m 52s`
- Host: dedicated AMD EPYC 9124 bare metal, SMT disabled
- Isolated CPUs: `1-15`; CPU `0` retained for housekeeping
- CRS commit: `fe593879e90b34ac6cf3e63151d48df0a4784790`
- CRS manifest: `4123125ca52d7f0247179073cf1bedbb99fea40aeb9ec1fd1eebc6d1aea40994`
- Workload SHA256: `279e86a07fc480cb736122719e94ca4a8d34a56819e480201787deeda9032b01`

All canonical phases passed: manifest, artifact integrity, microbenchmarks, both CRS oracles,
outcome matrix, real execution preflight, fixed-rate E2E, saturation, overhead decomposition and
multi-worker scaling.

## Measurement Boundaries

The fixed-rate and saturation performance rotation contains six HTTP/1.1 `GET` requests with
empty bodies. Those results cover URI, query-string and request-header inspection. They are not a
request-body-ingestion benchmark.

The direct `FullTransaction` rows measure each engine's complete in-process inbound transaction
boundary for the benchmark fixture. Attack rows measure time to a blocking decision and may stop
earlier than allow rows.

The Lumina correctness gate is broader than the performance rotation. It evaluates 3,986 selected
CRS PL2 tests and checks exact matched rule IDs plus verdicts against the pinned ModSecurity
oracle. Coraza exposes verdicts, but not matched rule IDs, through its stock NGINX connector.

NAXSI is a native-WAF reference and is never presented as an OWASP CRS implementation.

## Headline Results

| Boundary | LuminaWAF | ModSecurity | Coraza |
|---|---:|---:|---:|
| Direct allow transaction CPU | 55.47 us | 1.58 ms | 1.28 ms |
| Fixed-rate p50 at 422 RPS | 733 us | 2.41 ms | 2.08 ms |
| Fixed-rate p99.9 at 422 RPS | 2.11 ms | 4.37 ms | 8.15 ms |
| Sustainable single-worker RPS | 9,570.88 | 704.01 | 774.17 |
| Eight-worker RPS | 75,966.78 | 5,682.75 | 6,047.31 |
| PMU cycles per allow transaction | 175,574 | 4,931,781 | 4,102,249 |
| PMU IPC | 3.151 | 2.999 | 3.068 |

LuminaWAF reached `99.75%` overall correctness across the selected Lumina-vs-ModSecurity CRS PL2
gate. This number is not interchangeable with source-rule coverage, the small outcome matrix or
Coraza's verdict-only result.

See [BENCHMARK_RESULTS.md](BENCHMARK_RESULTS.md) for confidence intervals, CV, sample counts,
overhead decomposition, PMU denominators, complete scaling tables and raw Google Benchmark
console output.

## Report Correction

The report generated during the measured run contained one presentation defect: its qualification
table displayed a hard-coded `client CPU <=85%`. The runner, methodology, persisted scaling plan
and qualification result all used `90%`.

The publication report reads the threshold from `e2e_scaling/results.json` and therefore displays
`client CPU <=90%`. Re-rendering from the retained artifacts changes exactly that one line:

- Original retained report SHA256:
  `2c295abce8f862d6a4d7b0ffb07e0018d25a77cf7b4b6a406ea6c973287c74ba`
- Corrected publication report SHA256:
  `e33a7ca475bfbbcabb0b122cb87867645554b4367e6469759a59a975a8b6012d`

No measurement, qualification decision, engine binary or raw artifact was changed. Even the
stricter displayed threshold would not affect any WAF row; LuminaWAF's maximum measured client
utilization at eight workers was `23.20%`.

## Benchmark Infrastructure

The LuminaWAF v0.4.0 canonical qualification was performed on a dedicated AMD EPYC 9124P
bare-metal server rented from Cherry Servers specifically for this benchmark.

Access to properly isolated bare-metal hardware made it possible to complete a defensible
qualification run that could not be obtained reliably on the author's heavily loaded homelab
machine.

This was a normal paid rental, not sponsorship. Cherry Servers had no involvement in LuminaWAF,
the benchmark protocol, its implementation or the interpretation of the results.

In plain homelabber terms: that EPYC box saved the release after the home server spent several
hours demonstrating exactly why noisy-host benchmark results should not be published.

## Evidence Index

- Canonical decision: [`run_manifest.json`](run_manifest.json)
- CRS inventory and hashes: [`crs_manifest.json`](crs_manifest.json)
- Artifact identity: [`artifacts.json`](artifacts.json)
- Pre/post artifact checks: [`artifact_preflight.json`](artifact_preflight.json),
  [`artifact_postflight.json`](artifact_postflight.json)
- Dependency and symbol audit: [`dependency_provenance.json`](dependency_provenance.json),
  [`symbol_isolation.json`](symbol_isolation.json)
- Lumina correctness: [`correctness_lumina.json`](correctness_lumina.json)
- Coraza correctness: [`correctness_coraza.json`](correctness_coraza.json)
- Fixed-rate E2E: [`e2e_fixed/results.json`](e2e_fixed/results.json)
- Saturation: [`e2e_saturation/results.json`](e2e_saturation/results.json)
- Scaling plan and result: [`e2e_scaling/plan.json`](e2e_scaling/plan.json),
  [`e2e_scaling/results.json`](e2e_scaling/results.json)
- Engine PMU: [`pmu_qualification.json`](pmu_qualification.json)
- Overhead PMU: [`overhead_pmu_qualification.json`](overhead_pmu_qualification.json)
- Complete raw archive: [`RAW/README.md`](RAW/README.md)

Run `sha256sum -c SHA256SUMS` from this directory to verify the compact bundle.
