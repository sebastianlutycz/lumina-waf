#!/usr/bin/env bash
set -euo pipefail

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$HERE/../.." && pwd)
CACHE=${LUMINA_BENCH_V1_CACHE:-$ROOT/.cache/benchmark_harness_v1}
PREFIX=$CACHE/prefix
SOURCES=$CACHE/sources
PINS=$HERE/pins.json
MODE=${1:-prepare}

if [[ $MODE != prepare && $MODE != --check-cache ]]; then
    echo "usage: $0 [--check-cache]" >&2
    exit 2
fi

need_file() {
    [[ -f $1 ]] || { echo "missing cached Benchmark Harness v1 artifact: $1" >&2; return 1; }
}

need_exec() {
    [[ -x $1 ]] || { echo "missing cached Benchmark Harness v1 executable: $1" >&2; return 1; }
}

command -v jq >/dev/null 2>&1 || { echo "missing runtime dependency: jq" >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "missing runtime dependency: python3" >&2; exit 2; }

nginx_version=$(jq -r '.nginx.version' "$PINS")
module_dir=$SOURCES/nginx-$nginx_version/objs
naxsi_source=$SOURCES/naxsi
manifest=$CACHE/crs_manifest.json
reference_config=$CACHE/config/modsecurity_reference.conf

need_exec "$module_dir/nginx"
need_file "$module_dir/ngx_http_luminawaf_module.so"
need_file "$module_dir/ngx_http_modsecurity_module.so"
need_file "$module_dir/ngx_http_coraza_module.so"
need_file "$module_dir/ngx_http_naxsi_module.so"
need_file "$PREFIX/lib/libcoraza.so"
need_exec "$PREFIX/bin/go-ftw"
need_exec "$PREFIX/bin/wrk"
need_exec "$PREFIX/bin/wrk2"
need_file "$CACHE/dependency_provenance.json"
jq -e '
    .pcre2_jit == true and
    (.pcre2_sljit_commit | type == "string" and length == 40)
' "$CACHE/dependency_provenance.json" >/dev/null || {
    echo "Benchmark Harness v1 cache lacks the required PCRE2 JIT provenance" >&2
    exit 2
}
need_file "$naxsi_source/naxsi_rules/naxsi_core.rules"

if [[ $MODE == --check-cache ]]; then
    echo "Benchmark Harness v1 dependency cache is complete"
    exit 0
fi

mkdir -p "$CACHE/config"
python3 "$HERE/generate_reference_config.py" \
    --template "$ROOT/tests/eval_suite/modsec_crs_pl2.conf" \
    --crs "$ROOT/tests/eval_suite/coreruleset" --output "$reference_config"
python3 "$HERE/manifest.py" --strict --config "$reference_config" --output "$manifest"
python3 "$HERE/generate_configs.py" --manifest "$manifest" --output "$CACHE/config" \
    --module-dir "$module_dir" --naxsi-source "$naxsi_source"
python3 "$HERE/manifest.py" --strict --require-coraza \
    --config "$CACHE/config/modsecurity_crs_pl2.conf" \
    --coraza-config "$CACHE/config/coraza_crs_pl2.conf" --output "$manifest"

cat > "$CACHE/env.sh" <<EOF
export LUMINA_BENCH_V1_ENV_SCHEMA='2'
export LUMINA_BENCH_V1_CACHE='$CACHE'
export LUMINA_BENCH_V1_BENCHMARK_ROOT='$PREFIX'
export LUMINA_BENCH_V1_MODSEC_ROOT='$PREFIX'
export LUMINA_BENCH_V1_NGINX='$module_dir/nginx'
export LUMINA_BENCH_V1_MODULE_DIR='$module_dir'
export LUMINA_BENCH_V1_BASELINE_NGINX_CONFIG='$CACHE/config/nginx_baseline.conf'
export LUMINA_BENCH_V1_LUMINA_NGINX_CONFIG='$CACHE/config/nginx_luminawaf.conf'
export LUMINA_BENCH_V1_LUMINA_OFF_NGINX_CONFIG='$CACHE/config/nginx_luminawaf_loaded_off.conf'
export LUMINA_BENCH_V1_MODSEC_NGINX_CONFIG='$CACHE/config/nginx_modsecurity.conf'
export LUMINA_BENCH_V1_MODSEC_CONFIG='$CACHE/config/modsecurity_crs_pl2.conf'
export LUMINA_BENCH_V1_CORAZA_SO='$PREFIX/lib/libcoraza.so'
export LUMINA_BENCH_V1_CORAZA_CONFIG='$CACHE/config/coraza_crs_pl2.conf'
export LUMINA_BENCH_V1_CORAZA_NGINX_CONFIG='$CACHE/config/nginx_coraza.conf'
export LUMINA_BENCH_V1_NAXSI_NGINX_CONFIG='$CACHE/config/nginx_naxsi_stock.conf'
export LUMINA_BENCH_V1_NAXSI_CORE_RULES='$naxsi_source/naxsi_rules/naxsi_core.rules'
export LUMINA_BENCH_V1_GO_FTW='$PREFIX/bin/go-ftw'
export LUMINA_BENCH_V1_WRK='$PREFIX/bin/wrk'
export LUMINA_BENCH_V1_WRK2='$PREFIX/bin/wrk2'
export LUMINA_BENCH_V1_DEPENDENCY_PROVENANCE='$CACHE/dependency_provenance.json'
export LD_LIBRARY_PATH='$PREFIX/lib:$ROOT/build'
export PATH='$CACHE/go/bin:$PATH'
EOF

echo "Benchmark Harness v1 runtime prepared: $CACHE/env.sh"
