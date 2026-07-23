# Published Evidence

This directory contains immutable Benchmark Harness V1.0 evidence tied to released LuminaWAF
source states.

## Layout

Canonical publication bundles use a versioned path:

```text
reports/
└── canonical/
    └── v0.4.0-rc.11/
        ├── README.md
        ├── BENCHMARK_RESULTS.md
        ├── selected machine-readable evidence
        ├── SHA256SUMS
        └── RAW/
            └── README.md
```

The repository bundle contains the generated report and the compact JSON evidence needed to
review every headline result. Complete raw logs, histograms and host evidence are distributed as
one separately hashed release asset. Binary archives are intentionally rejected from Git history.

Each bundle identifies the LuminaWAF commit, CRS commit and manifest, workload hash, host profile,
qualification class and raw archive checksum. A `NON-CANONICAL` report must retain that label in
the report and every derived visual.

OWASP CRS rule or data files, generated AOT source, third-party source trees and host-specific
build caches must never be added here.

## Visual Summary

At most one release-summary SVG should appear in the top-level README. It must be generated from
the retained JSON evidence, identify the measurement boundaries, and include the report version or
manifest hash. Hand-entered benchmark values are not accepted.
