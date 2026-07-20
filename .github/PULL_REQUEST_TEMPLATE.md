## Summary

Describe what changed and why. Keep the pull request focused on one coherent problem.

## Related Issue

Closes #ISSUE_NUMBER

For substantial architectural work, link the design or discussion issue.

## Change Type

- [ ] Correctness fix
- [ ] New functionality
- [ ] Performance change
- [ ] Refactor
- [ ] Test or fuzzing change
- [ ] Benchmark or methodology change
- [ ] Build or CI change
- [ ] Documentation
- [ ] Security hardening

## Architectural Contract

- [ ] The change preserves the build-time AOT policy model.
- [ ] It does not add runtime CRS rule parsing to the NGINX request path.
- [ ] It does not add an undocumented benchmark-only bypass to production code.
- [ ] Memory use and execution remain bounded for hostile input.
- [ ] Any intentional architectural exception is documented and linked to an approved issue.

## Validation

List the exact commands and tests that were run:

```text
# Example:
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j"$(nproc)"
python3 -m unittest discover -s tests/unit -p 'test_*.py'
python3 tools/verify_release_tree.py --root .
./bench/benchmark_harness/run.sh smoke
```

- [ ] Clean configure and build completed.
- [ ] Relevant unit or regression tests pass.
- [ ] Behavioral fixes include a regression test where practical.
- [ ] Parser or transform changes received sanitizer or fuzz coverage where practical.
- [ ] CRS semantic changes were checked against the relevant oracle cases.

## Benchmark And Evidence

Complete this section for performance, benchmark, or methodology changes.

```text
Measurement boundary:
Workload or corpus:
Source commit(s):
Host classification:
Before result:
After result:
Raw artifact location:
```

- [ ] No smoke result is presented as publication evidence.
- [ ] Measurement classes remain separate.
- [ ] Before and after measurements use the same workload and configuration, or differences are
      explicitly documented.
- [ ] Generated reports are derived from retained artifacts rather than manually edited values.

## Repository Hygiene

- [ ] No credentials, private keys, tokens, private hostnames, or personal absolute paths are included.
- [ ] No CRS rule or data files, generated AOT sources, object files, shared libraries, benchmark
      caches, or raw local telemetry are included.
- [ ] Third-party code or data has compatible licensing and required attribution.
- [ ] Public documentation was updated when the user-visible contract changed.

## Notes For Reviewers

Call out risky assumptions, known limitations, unsupported cases, or follow-up work.
