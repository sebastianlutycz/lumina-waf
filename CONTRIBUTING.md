# Contributing to LuminaWAF

LuminaWAF is in a single-maintainer, pre-1.0 phase. Issues, technical discussions, and focused pull
requests are welcome. Direct access to protected branches is not granted by default.

## Architecture Contract

Contributions must preserve the project's main boundaries:

- detection policy is compiled ahead of time;
- the NGINX request path does not parse CRS configuration files;
- runtime memory use and execution remain bounded for hostile input;
- benchmark-only shortcuts are not added to production paths;
- x86_64 and AArch64 remain supported targets;
- generated AOT sources and CRS rule or data files are not committed.

An architectural exception requires an issue describing its responsibility, data flow, allocation
boundary, hardware boundary, and effect on correctness.

## Development Workflow

Create a focused topic branch using a descriptive name such as:

```text
feature/<short-name>
fix/<short-name>
perf/<short-name>
bench/<short-name>
```

Keep commits focused and use an imperative subject. Do not combine unrelated cleanup with a
correctness, performance, benchmark, or release change. External contributions are normally
squash-merged after review.

## Build And Validation

The basic release build is:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j"$(nproc)"
```

Before opening a pull request, run the checks relevant to the change. The minimum source gates are:

```bash
python3 -m unittest discover -s tests/unit -p 'test_*.py'
python3 tools/verify_release_tree.py --root .
git diff --check
```

For changes affecting the runtime, generated policy, NGINX adapter, or benchmark harness, also run:

```bash
./bench/benchmark_harness/run.sh smoke
```

Smoke output is diagnostic. It must not be presented as canonical publication evidence.

## Correctness And Performance Changes

Behavioral fixes should include a regression test when practical. Parser, transform, and classifier
changes should include differential, sanitizer, or fuzz coverage appropriate to their risk.

Performance claims must identify:

- the measured boundary and workload;
- source commits and binary identity;
- host classification and CPU placement;
- before and after results;
- raw artifact location;
- correctness evidence showing no semantic regression.

Wall time alone is insufficient for hot-path optimization claims. Use fixed-work comparisons and
hardware counter evidence when the platform supports them. Keep direct engine CPU time, fixed-rate
NGINX latency, and saturation throughput as separate claims.

## Source And Dependency Policy

LuminaWAF v0.4 has zero third-party runtime dependencies beyond the platform C runtime and dynamic
loader. Build tools, the pinned CRS test input, and benchmark comparators are development-time inputs,
not runtime dependencies.

Do not copy third-party implementation code into the runtime. New source must be original work or
carry a license compatible with GNU AGPLv3 and include required attribution. The inbound contribution
policy is AGPLv3-inbound to AGPLv3-outbound. The project does not currently require copyright
assignment or a Contributor License Agreement.

## Pull Request Acceptance

A pull request may be merged when:

- it fits the current scope and architecture;
- relevant tests and repository gates pass;
- benchmark claims are supported by retained evidence;
- public documentation reflects contract changes;
- licensing and repository hygiene checks pass.

Changes to release provenance, benchmark qualification, licensing, the SQL injection classifier,
generated execution, the request hot path, or NGINX integration require explicit maintainer review.
The repository's `CODEOWNERS` rules request that review; branch protection enforces it where supported
by the hosting platform.

## Release Policy

Release candidates use immutable SemVer prerelease tags:

```text
v0.4.0-rc.1
v0.4.0-rc.2
v0.4.0
```

If a candidate is invalid, fix it in a new commit and create a new tag. Do not move a published tag
or replace benchmark evidence under an existing tag. Release creation and canonical benchmark
qualification remain maintainer responsibilities during the single-maintainer phase.
