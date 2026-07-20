#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -d "$ROOT/tests/eval_suite/coreruleset/rules" ]]; then
  DEFAULT_RULES_DIR="$ROOT/tests/eval_suite/coreruleset/rules"
else
  DEFAULT_RULES_DIR="$ROOT/coreruleset/rules"
fi
RULES_DIR="${RULES_DIR:-$DEFAULT_RULES_DIR}"
DATA_DIR="${DATA_DIR:-$RULES_DIR}"
TRANSLATOR="${TRANSLATOR:-$ROOT/tools/sidecar_translator.py}"
PL="${PL:-2}"
OUT_DIR="${OUT_DIR:-}"
KEEP_OUT="${KEEP_OUT:-0}"

if [[ ! -f "$TRANSLATOR" ]]; then
  echo "missing translator: $TRANSLATOR" >&2
  exit 2
fi
if [[ ! -d "$RULES_DIR" ]]; then
  echo "missing CRS rules dir: $RULES_DIR" >&2
  exit 2
fi
if [[ ! -f "$ROOT/src/parser_rules_0000.c" ]]; then
  echo "missing current generated table: src/parser_rules_0000.c" >&2
  exit 2
fi
if [[ ! -f "$ROOT/src/generated/crs_short_rules.h" ]]; then
  echo "missing current generated header: src/generated/crs_short_rules.h" >&2
  exit 2
fi

if [[ -z "$OUT_DIR" ]]; then
  OUT_DIR="$(mktemp -d /tmp/luminawaf_translator_audit.XXXXXX)"
fi

cleanup() {
  if [[ "$KEEP_OUT" != "1" && "$OUT_DIR" == /tmp/luminawaf_translator_audit.* ]]; then
    rm -rf "$OUT_DIR"
  fi
}
trap cleanup EXIT

extract_ids() {
  local file="$1"
  rg -o 'lumina_scan_rule_[0-9]+' "$file" \
    | sed 's/.*_//' \
    | awk '$1 != 0 {print $1}' \
    | sort -n \
    | uniq
}

current_ids="$(mktemp)"
fresh_ids="$(mktemp)"
only_current="$(mktemp)"
only_fresh="$(mktemp)"
trap 'rm -f "$current_ids" "$fresh_ids" "$only_current" "$only_fresh"; cleanup' EXIT

current_count="$(
  awk '/LUMINA_SHORT_RULE_COUNT/ {print $3; exit}' "$ROOT/src/generated/crs_short_rules.h" 2>/dev/null || true
)"
if [[ -z "$current_count" ]]; then
  echo "could not parse current LUMINA_SHORT_RULE_COUNT" >&2
  exit 2
fi
extract_ids "$ROOT/src/parser_rules_0000.c" > "$current_ids"

echo "commit=$(git -C "$ROOT" rev-parse --short HEAD)"
echo "branch=$(git -C "$ROOT" branch --show-current)"
echo "translator=$TRANSLATOR"
echo "rules_dir=$RULES_DIR"
echo "data_dir=$DATA_DIR"
echo "pl=$PL"
echo "out_dir=$OUT_DIR"
echo "current_header_rule_count=$current_count"
echo "current_table_id_count=$(wc -l < "$current_ids")"

python3 "$TRANSLATOR" "$RULES_DIR" "$OUT_DIR" --pl "$PL" --data-dir "$DATA_DIR"
PYTHONDONTWRITEBYTECODE=1 python3 "$ROOT/tools/gen_rule_idx_map.py" \
  --manifest "$OUT_DIR/generated/rule_manifest.json" \
  --out "$OUT_DIR/generated/crs_rule_idx_map.h"
PYTHONDONTWRITEBYTECODE=1 python3 "$ROOT/tools/gen_transform_mask.py" \
  --manifest "$OUT_DIR/generated/rule_manifest.json" \
  --rules-dir "$RULES_DIR" --out-dir "$OUT_DIR/generated"
PYTHONDONTWRITEBYTECODE=1 python3 "$ROOT/tools/k4_chain_parse.py" \
  --manifest "$OUT_DIR/generated/rule_manifest.json" \
  --rules-dir "$RULES_DIR" --out-dir "$OUT_DIR/generated"

fresh_count="$(
  awk '/LUMINA_SHORT_RULE_COUNT/ {print $3; exit}' "$OUT_DIR/generated/crs_short_rules.h" 2>/dev/null || true
)"
if [[ -z "$fresh_count" ]]; then
  echo "could not parse fresh LUMINA_SHORT_RULE_COUNT" >&2
  exit 2
fi
extract_ids "$OUT_DIR/parser_rules_0000.c" > "$fresh_ids"

comm -23 "$current_ids" "$fresh_ids" > "$only_current"
comm -13 "$current_ids" "$fresh_ids" > "$only_fresh"

echo "fresh_header_rule_count=$fresh_count"
echo "fresh_table_id_count=$(wc -l < "$fresh_ids")"
echo "only_current_count=$(wc -l < "$only_current")"
echo "only_fresh_count=$(wc -l < "$only_fresh")"

if [[ -s "$only_current" ]]; then
  echo "only_current_ids=$(paste -sd, "$only_current")"
fi
if [[ -s "$only_fresh" ]]; then
  echo "only_fresh_ids=$(paste -sd, "$only_fresh")"
fi

if [[ "$current_count" != "$fresh_count" ]] || [[ -s "$only_current" ]] || [[ -s "$only_fresh" ]]; then
  echo "DRIFT: fresh translator output differs from current generated artifacts" >&2
  echo "Use KEEP_OUT=1 to inspect the temp output before changing src/." >&2
  exit 1
fi

artifact_drift=0
for fresh in "$OUT_DIR"/parser_input.c "$OUT_DIR"/parser_rules_*.c "$OUT_DIR"/crs_tx_rules.c; do
  current="$ROOT/src/$(basename "$fresh")"
  if [[ ! -f "$current" ]] || ! cmp -s "$current" "$fresh"; then
    echo "artifact_drift=$(basename "$fresh")"
    artifact_drift=$((artifact_drift + 1))
  fi
done
for current in "$ROOT"/src/parser_rules_*.c; do
  if [[ ! -f "$OUT_DIR/$(basename "$current")" ]]; then
    echo "stale_artifact=$(basename "$current")"
    artifact_drift=$((artifact_drift + 1))
  fi
done
for name in crs_short_rules.h crs_shared_tables.h rule_manifest.json crs_rule_idx_map.h \
            crs_transform_mask.h crs_transform_mask.c crs_chains.h \
            crs_chains.c crs_chain_manifest.json; do
  current="$ROOT/src/generated/$name"
  fresh="$OUT_DIR/generated/$name"
  if [[ ! -f "$current" ]] || ! cmp -s "$current" "$fresh"; then
    echo "artifact_drift=generated/$name"
    artifact_drift=$((artifact_drift + 1))
  fi
done

echo "artifact_drift_count=$artifact_drift"
if (( artifact_drift != 0 )); then
  echo "DRIFT: generated artifacts are not an atomic translator snapshot" >&2
  exit 1
fi

echo "NO_DRIFT: fresh translator output matches the complete generated artifact set"
