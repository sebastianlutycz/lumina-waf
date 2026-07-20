#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${BUILD_DIR:-$ROOT/build}"
LUMINA_WAF_SO="${LUMINA_WAF_SO:-$BUILD_DIR/libluminawaf.so}"
export LUMINA_WAF_SO
HARNESS="$ROOT/tests/eval_suite/crs_parity_harness.py"
REPORT="$ROOT/tests/eval_suite/crs_parity_report.txt"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-600}"
LIMIT="${LIMIT:-}"
MIN_OVERALL="${MIN_OVERALL:-99.70}"
SCOPE="${SCOPE:-inbound}"
JSON_OUTPUT="${JSON_OUTPUT:-}"

if [[ ! -f "$HARNESS" ]]; then
  echo "missing harness: $HARNESS" >&2
  exit 2
fi

if [[ ! -d "$ROOT/tests/eval_suite/coreruleset/tests/regression/tests" ]]; then
  echo "missing CRS regression tests; initialize the BYOR coreruleset input first" >&2
  exit 2
fi

cmake --build "$BUILD_DIR" -j"$(nproc)" --target luminawaf

generated_count="$(
  awk '/LUMINA_SHORT_RULE_COUNT/ {print $3; exit}' "$ROOT/src/generated/crs_short_rules.h" 2>/dev/null || true
)"
if [[ -z "$generated_count" ]]; then
  echo "missing generated rule count in src/generated/crs_short_rules.h" >&2
  exit 2
fi

cmd=(python3 "$HARNESS" --scope "$SCOPE")
if [[ -n "$LIMIT" ]]; then
  cmd+=(--limit "$LIMIT")
fi
if [[ -n "$JSON_OUTPUT" ]]; then
  cmd+=(--json-output "$JSON_OUTPUT")
fi

echo "commit=$(git -C "$ROOT" rev-parse --short HEAD)"
echo "branch=$(git -C "$ROOT" branch --show-current)"
echo "generated_rule_count=$generated_count"
echo "library=$LUMINA_WAF_SO"
echo "timeout_seconds=$TIMEOUT_SECONDS"
echo "min_overall=$MIN_OVERALL"
echo "scope=$SCOPE"
if [[ -n "$LIMIT" ]]; then
  echo "limit=$LIMIT"
else
  echo "limit=full"
fi
echo "command=${cmd[*]}"

set +e
timeout "$TIMEOUT_SECONDS" "${cmd[@]}" | tee "$REPORT"
rc=${PIPESTATUS[0]}
set -e

if [[ "$rc" -eq 124 ]]; then
  echo "CRS parity gate timed out after ${TIMEOUT_SECONDS}s" >&2
  exit 124
fi
if [[ "$rc" -ne 0 ]]; then
  echo "CRS parity gate failed with exit code $rc" >&2
  exit "$rc"
fi
if grep -Eq 'timeouts=[1-9]|exceptions=[1-9]' "$REPORT"; then
  echo "CRS parity gate failed: harness reported timeout or exception" >&2
  exit 1
fi

overall="$(
  awk '/OVERALL PARITY/ {gsub("%", "", $4); print $4; exit}' "$REPORT"
)"
if [[ -z "$overall" ]]; then
  echo "CRS parity gate failed: could not parse OVERALL PARITY" >&2
  exit 1
fi
if ! awk -v got="$overall" -v min="$MIN_OVERALL" 'BEGIN { exit !(got + 0 >= min + 0) }'; then
  echo "CRS parity gate failed: OVERALL PARITY ${overall}% < ${MIN_OVERALL}%" >&2
  exit 1
fi

echo "CRS parity gate completed without harness timeouts/exceptions"
