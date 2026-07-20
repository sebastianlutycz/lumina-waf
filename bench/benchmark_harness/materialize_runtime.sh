#!/usr/bin/env bash
set -euo pipefail

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$HERE/../.." && pwd)
CACHE=${LUMINA_BENCH_V1_CACHE:-$ROOT/.cache/benchmark_harness_v1}
CRS=$ROOT/tests/eval_suite/coreruleset
RULES=$CRS/rules

git -C "$ROOT" submodule update --init --depth 1 tests/eval_suite/coreruleset

expected_commit=$(git -C "$ROOT" ls-tree HEAD tests/eval_suite/coreruleset | awk '{print $3}')
actual_commit=$(git -C "$CRS" rev-parse HEAD)
if [[ -z $expected_commit || $actual_commit != "$expected_commit" ]]; then
    echo "CRS submodule commit mismatch: expected=$expected_commit actual=$actual_commit" >&2
    exit 2
fi

generator_fingerprint=$(
    {
        printf '%s\n' "$actual_commit"
        sha256sum \
            "$ROOT/tools/sidecar_translator.py" \
            "$ROOT/tools/gen_rule_idx_map.py" \
            "$ROOT/tools/gen_transform_mask.py" \
            "$ROOT/tools/k4_chain_parse.py"
    } | sha256sum | awk '{print $1}'
)
stamp=$CACHE/generated-runtime.stamp

required=(
    src/parser_input.c
    src/crs_tx_rules.c
    src/generated/crs_short_rules.h
    src/generated/crs_shared_tables.h
    src/generated/rule_manifest.json
    src/generated/crs_rule_idx_map.h
    src/generated/crs_transform_mask.h
    src/generated/crs_transform_mask.c
    src/generated/crs_chains.h
    src/generated/crs_chains.c
    src/generated/crs_chain_manifest.json
)

complete=1
for path in "${required[@]}"; do
    [[ -f $ROOT/$path ]] || complete=0
done
parser_chunks=("$ROOT"/src/parser_rules_*.c)
if [[ ! -e ${parser_chunks[0]} || ${#parser_chunks[@]} -lt 2 ]]; then
    complete=0
fi
if (( complete )) && [[ -f $stamp ]] && [[ $(cat "$stamp") == "$generator_fingerprint" ]]; then
    echo "LuminaWAF AOT runtime already materialized"
    exit 0
fi

output=$CACHE/generated-runtime
rm -rf "$output"
mkdir -p "$output"

PYTHONDONTWRITEBYTECODE=1 python3 "$ROOT/tools/sidecar_translator.py" \
    "$RULES" "$output" --pl 2 --data-dir "$RULES"
PYTHONDONTWRITEBYTECODE=1 python3 "$ROOT/tools/gen_rule_idx_map.py" \
    --manifest "$output/generated/rule_manifest.json" \
    --out "$output/generated/crs_rule_idx_map.h"
PYTHONDONTWRITEBYTECODE=1 python3 "$ROOT/tools/gen_transform_mask.py" \
    --manifest "$output/generated/rule_manifest.json" \
    --rules-dir "$RULES" --out-dir "$output/generated"
PYTHONDONTWRITEBYTECODE=1 python3 "$ROOT/tools/k4_chain_parse.py" \
    --manifest "$output/generated/rule_manifest.json" \
    --rules-dir "$RULES" --out-dir "$output/generated"

for path in parser_input.c crs_tx_rules.c generated/crs_short_rules.h \
            generated/crs_shared_tables.h generated/rule_manifest.json \
            generated/crs_rule_idx_map.h generated/crs_transform_mask.h \
            generated/crs_transform_mask.c generated/crs_chains.h \
            generated/crs_chains.c generated/crs_chain_manifest.json; do
    [[ -f $output/$path ]] || { echo "generated runtime is missing $path" >&2; exit 2; }
done
generated_chunks=("$output"/parser_rules_*.c)
if [[ ! -e ${generated_chunks[0]} || ${#generated_chunks[@]} -lt 2 ]]; then
    echo "generated parser chunk set is incomplete" >&2
    exit 2
fi

rm -f "$ROOT"/src/parser_rules_*.c
install -m 0644 "$output/parser_input.c" "$ROOT/src/parser_input.c"
install -m 0644 "$output/crs_tx_rules.c" "$ROOT/src/crs_tx_rules.c"
install -m 0644 "${generated_chunks[@]}" "$ROOT/src/"
mkdir -p "$ROOT/src/generated"
for path in crs_short_rules.h crs_shared_tables.h rule_manifest.json crs_rule_idx_map.h \
            crs_transform_mask.h crs_transform_mask.c crs_chains.h crs_chains.c \
            crs_chain_manifest.json; do
    install -m 0644 "$output/generated/$path" "$ROOT/src/generated/$path"
done
printf '%s\n' "$generator_fingerprint" > "$stamp"

echo "LuminaWAF AOT runtime materialized from CRS $actual_commit"
