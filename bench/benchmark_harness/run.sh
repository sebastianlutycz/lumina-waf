#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
CACHE=${LUMINA_BENCH_V1_CACHE:-$ROOT/.cache/benchmark_harness_v1}

PYTHONDONTWRITEBYTECODE=1 python3 "$ROOT/tools/verify_release_tree.py" --root "$ROOT"
git -C "$ROOT" submodule update --init --depth 1 tests/eval_suite/coreruleset

if ! LUMINA_BENCH_V1_CACHE="$CACHE" "$SCRIPT_DIR/prepare_runtime.sh" --check-cache; then
    if [[ ${LUMINA_BENCH_V1_AUTO_BOOTSTRAP:-1} != 1 ]]; then
        echo "Benchmark Harness v1 cache is incomplete; run $SCRIPT_DIR/bootstrap.sh" >&2
        exit 2
    fi
    echo "Benchmark Harness v1 cache is incomplete; starting pinned bootstrap" >&2
    LUMINA_BENCH_V1_CACHE="$CACHE" "$SCRIPT_DIR/bootstrap.sh"
fi

LUMINA_BENCH_V1_CACHE="$CACHE" "$SCRIPT_DIR/materialize_runtime.sh"
LUMINA_BENCH_V1_CACHE="$CACHE" "$SCRIPT_DIR/prepare_runtime.sh"

# shellcheck disable=SC1090
source "$CACHE/env.sh"
exec python3 "$SCRIPT_DIR/run.py" "$@"
