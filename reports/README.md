# Published Evidence

This directory is reserved for immutable V1.0 Protocol benchmark evidence tied to a released
LuminaWAF commit.
The repository currently contains no RC benchmark bundle because the final `v0.4.0-rc.4` evidence
must be collected from the exact tagged source state.

## Layout

Publication bundles use a versioned path:

```text
reports/
└── benchmark_harness_v1/
    └── v0.4.0-rc.4/
        ├── BENCHMARK_RESULTS.md
        ├── artifacts.json
        ├── correctness_lumina.json
        ├── correctness_coraza.json
        ├── crs_manifest.json
        ├── micro_qualification.json
        ├── pmu_qualification.json
        ├── sampling_plan.json
        └── SHA256SUMS
```

Each bundle must identify the LuminaWAF commit, CRS commit and manifest, workload hash, host
profile, qualification class and raw artifact checksums. A `NON-CANONICAL` report must retain that
label in the report and any derived visual.

Large raw logs and histograms may be attached to the matching release instead of being committed,
but the report must link them by immutable URL and record their SHA256 checksums. OWASP CRS rule or
data files, generated AOT source and host-specific build caches must never be added here.

## Visual Summary

At most one release-summary SVG should appear in the top-level README. It must be generated from
the retained JSON evidence, identify the measurement boundaries, and include the report version or
manifest hash. Hand-entered benchmark values are not accepted.
