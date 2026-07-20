#!/usr/bin/env bash
set -euo pipefail

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$HERE/../.." && pwd)
CACHE=${LUMINA_BENCH_V1_CACHE:-$ROOT/.cache/benchmark_harness_v1}
PREFIX=$CACHE/prefix
SOURCES=$CACHE/sources
DOWNLOADS=$CACHE/downloads
PINS=$HERE/pins.json
mkdir -p "$PREFIX/bin" "$SOURCES" "$DOWNLOADS"

need() {
    command -v "$1" >/dev/null 2>&1 || { echo "missing build dependency: $1" >&2; exit 2; }
}
for tool in git curl jq python3 cmake make gcc g++ autoconf automake libtoolize \
            pkg-config perl unzip patch flex bison tar sha256sum readelf nm ldd taskset; do
    need "$tool"
done

LUMINA_BENCH_V1_CACHE="$CACHE" "$HERE/materialize_runtime.sh"

clone_pin() {
    local name=$1 url=$2 tag=$3 commit=$4
    local dir=$SOURCES/$name
    if [[ ! -d $dir/.git ]]; then
        git clone --filter=blob:none --no-checkout "$url" "$dir"
    fi
    git -C "$dir" fetch --force --depth=1 origin "refs/tags/$tag:refs/tags/$tag"
    git -C "$dir" checkout --detach "$commit"
    [[ $(git -C "$dir" rev-parse HEAD) == "$commit" ]] || exit 2
}

arch=$(uname -m)
case "$arch" in
    x86_64) go_arch=amd64 ;;
    aarch64|arm64) go_arch=arm64 ;;
    *) echo "unsupported architecture: $arch" >&2; exit 2 ;;
esac
go_version=$(jq -r '.go.version' "$PINS")
go_archive=go${go_version}.linux-${go_arch}.tar.gz
go_sha=$(jq -r ".go.linux_${go_arch}_sha256" "$PINS")
if [[ ! -f $DOWNLOADS/$go_archive ]]; then
    curl -fL "https://go.dev/dl/$go_archive" -o "$DOWNLOADS/$go_archive"
fi
echo "$go_sha  $DOWNLOADS/$go_archive" | sha256sum -c -
if [[ ! -x $CACHE/go/bin/go ]]; then
    mkdir -p "$CACHE/go"
    tar -C "$CACHE/go" --strip-components=1 -xzf "$DOWNLOADS/$go_archive"
fi
export PATH="$CACHE/go/bin:$PATH"
export PKG_CONFIG_PATH="$PREFIX/lib/pkgconfig:${PKG_CONFIG_PATH:-}"
export LD_LIBRARY_PATH="$PREFIX/lib:${LD_LIBRARY_PATH:-}"

clone_pin benchmark https://github.com/google/benchmark.git \
    "$(jq -r '.google_benchmark.tag' "$PINS")" "$(jq -r '.google_benchmark.commit' "$PINS")"
cmake -S "$SOURCES/benchmark" -B "$CACHE/build-benchmark" \
    -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$PREFIX" \
    -DBENCHMARK_ENABLE_GTEST_TESTS=OFF -DBENCHMARK_ENABLE_TESTING=OFF
cmake --build "$CACHE/build-benchmark" -j"$(nproc)" --target install

clone_pin wrk https://github.com/wg/wrk.git \
    "$(jq -r '.wrk.tag' "$PINS")" "$(jq -r '.wrk.commit' "$PINS")"
make -C "$SOURCES/wrk" -j"$(nproc)"
install -m 0755 "$SOURCES/wrk/wrk" "$PREFIX/bin/wrk"

wrk2_commit=$(jq -r '.wrk2.commit' "$PINS")
if [[ ! -d $SOURCES/wrk2/.git ]]; then
    git clone --filter=blob:none --no-checkout https://github.com/giltene/wrk2.git "$SOURCES/wrk2"
fi
git -C "$SOURCES/wrk2" fetch --force --depth=1 origin "$wrk2_commit"
git -C "$SOURCES/wrk2" checkout --detach "$wrk2_commit"
[[ $(git -C "$SOURCES/wrk2" rev-parse HEAD) == "$wrk2_commit" ]] || exit 2
make -C "$SOURCES/wrk2" -j"$(nproc)"
install -m 0755 "$SOURCES/wrk2/wrk" "$PREFIX/bin/wrk2"

clone_pin libcoraza https://github.com/corazawaf/libcoraza.git \
    "$(jq -r '.libcoraza.tag' "$PINS")" "$(jq -r '.libcoraza.commit' "$PINS")"
(cd "$SOURCES/libcoraza" && ./build.sh && ./configure --prefix="$PREFIX" && make -j"$(nproc)" && make install)

# PCRE2 belongs only to the pinned ModSecurity comparator. LuminaWAF never
# links or executes it; keeping it in the private prefix makes that boundary auditable.
clone_pin pcre2 https://github.com/PCRE2Project/pcre2.git \
    "$(jq -r '.pcre2_modsecurity_only.tag' "$PINS")" \
    "$(jq -r '.pcre2_modsecurity_only.commit' "$PINS")"
cmake -S "$SOURCES/pcre2" -B "$CACHE/build-pcre2" \
    -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$PREFIX" \
    -DBUILD_SHARED_LIBS=ON -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
    -DPCRE2_BUILD_PCRE2GREP=OFF -DPCRE2_BUILD_TESTS=OFF \
    -DPCRE2_BUILD_PCRE2_8=ON -DPCRE2_BUILD_PCRE2_16=OFF -DPCRE2_BUILD_PCRE2_32=OFF
cmake --build "$CACHE/build-pcre2" -j"$(nproc)" --target install

clone_pin modsecurity https://github.com/owasp-modsecurity/ModSecurity.git \
    "$(jq -r '.modsecurity.tag' "$PINS")" "$(jq -r '.modsecurity.commit' "$PINS")"
git -C "$SOURCES/modsecurity" submodule update --init --recursive
(cd "$SOURCES/modsecurity" && \
    ./build.sh && \
    CPPFLAGS="-I$PREFIX/include ${CPPFLAGS:-}" \
    LDFLAGS="-L$PREFIX/lib -Wl,-rpath,$PREFIX/lib ${LDFLAGS:-}" \
    PKG_CONFIG_PATH="$PREFIX/lib/pkgconfig:${PKG_CONFIG_PATH:-}" \
    ./configure --prefix="$PREFIX" --disable-examples && \
    make -j"$(nproc)" && make install)

modsecurity_so=$(find "$PREFIX/lib" -maxdepth 1 -type f -name 'libmodsecurity.so.*' | sort -V | tail -n1)
[[ -n $modsecurity_so ]] || { echo "private libmodsecurity.so was not installed" >&2; exit 2; }
pcre_version=$(jq -r '.pcre2_modsecurity_only.version' "$PINS")
if readelf -d "$modsecurity_so" | grep 'libpcre2-8.so' >/dev/null; then
    pcre_linkage=private-shared
    LD_LIBRARY_PATH="$PREFIX/lib" ldd "$modsecurity_so" | grep -Fq "$PREFIX/lib/libpcre2-8.so" || {
        echo "libmodsecurity.so resolved PCRE2 outside the private benchmark prefix" >&2
        exit 2
    }
else
    pcre_linkage=private-static-embedded
    nm -D "$modsecurity_so" | grep ' T pcre2_compile_8$' >/dev/null || {
        echo "libmodsecurity.so has neither a private PCRE2 dependency nor embedded PCRE2 symbols" >&2
        exit 2
    }
    grep -Fq "PCRE2 found via pkg-config: libpcre2-8 v$pcre_version" "$SOURCES/modsecurity/config.log" || {
        echo "ModSecurity did not configure against the pinned private PCRE2 version" >&2
        exit 2
    }
    grep -Fq "PCRE2_LDFLAGS='-L$PREFIX/lib " "$SOURCES/modsecurity/config.log" || {
        echo "ModSecurity PCRE2 link flags do not point at the private benchmark prefix" >&2
        exit 2
    }
fi

jq -n \
    --arg linkage "$pcre_linkage" \
    --arg modsecurity_sha256 "$(sha256sum "$modsecurity_so" | cut -d' ' -f1)" \
    --arg pcre2_static_sha256 "$(sha256sum "$PREFIX/lib/libpcre2-8.a" | cut -d' ' -f1)" \
    --arg pcre2_shared_sha256 "$(sha256sum "$PREFIX/lib/libpcre2-8.so.0.14.0" | cut -d' ' -f1)" \
    --arg modsecurity_commit "$(git -C "$SOURCES/modsecurity" rev-parse HEAD)" \
    --arg pcre2_commit "$(git -C "$SOURCES/pcre2" rev-parse HEAD)" \
    '{modsecurity_pcre2_linkage:$linkage,modsecurity_sha256:$modsecurity_sha256,
      pcre2_static_sha256:$pcre2_static_sha256,pcre2_shared_sha256:$pcre2_shared_sha256,
      modsecurity_commit:$modsecurity_commit,pcre2_commit:$pcre2_commit}' \
    > "$CACHE/dependency_provenance.json"

clone_pin modsecurity-nginx https://github.com/owasp-modsecurity/ModSecurity-nginx.git \
    "$(jq -r '.modsecurity_nginx.tag' "$PINS")" "$(jq -r '.modsecurity_nginx.commit' "$PINS")"
clone_pin coraza-nginx https://github.com/corazawaf/coraza-nginx.git \
    "$(jq -r '.coraza_nginx.tag' "$PINS")" "$(jq -r '.coraza_nginx.commit' "$PINS")"
clone_pin naxsi https://github.com/wargio/naxsi.git \
    "$(jq -r '.naxsi.tag' "$PINS")" "$(jq -r '.naxsi.commit' "$PINS")"
git -C "$SOURCES/naxsi" submodule update --init --recursive
clone_pin go-ftw https://github.com/coreruleset/go-ftw.git \
    "$(jq -r '.go_ftw.tag' "$PINS")" "$(jq -r '.go_ftw.commit' "$PINS")"
(cd "$SOURCES/go-ftw" && go build -trimpath -ldflags='-s -w' -o "$PREFIX/bin/go-ftw" .)

nginx_version=$(jq -r '.nginx.version' "$PINS")
nginx_url=$(jq -r '.nginx.url' "$PINS")
nginx_sha=$(jq -r '.nginx.sha256' "$PINS")
nginx_archive=$DOWNLOADS/nginx-${nginx_version}.tar.gz
if [[ ! -f $nginx_archive ]]; then curl -fL "$nginx_url" -o "$nginx_archive"; fi
echo "$nginx_sha  $nginx_archive" | sha256sum -c -
if [[ ! -f $SOURCES/nginx-$nginx_version/configure ]]; then
    tar -C "$SOURCES" -xzf "$nginx_archive"
fi

cmake -S "$ROOT" -B "$ROOT/build" -DCMAKE_BUILD_TYPE=Release \
    -DLUMINA_BENCH_V1_BENCHMARK_ROOT="$PREFIX" -DLUMINA_BENCH_V1_MODSEC_ROOT="$PREFIX"
cmake --build "$ROOT/build" -j"$(nproc)" --target luminawaf lumina_benchmark_harness

(cd "$SOURCES/nginx-$nginx_version" && \
    ./configure --prefix="$PREFIX/nginx" --with-compat \
      --with-cc-opt="-O3 -DNDEBUG -Wno-error=unused-function -I$PREFIX/include" \
      --with-ld-opt="-L$PREFIX/lib -Wl,-rpath,$PREFIX/lib" \
      --add-dynamic-module="$ROOT/nginx_module" \
      --add-dynamic-module="$SOURCES/modsecurity-nginx" \
      --add-dynamic-module="$SOURCES/coraza-nginx" \
      --add-dynamic-module="$SOURCES/naxsi/naxsi_src" && \
    make -j"$(nproc)" build modules)

module_dir=$SOURCES/nginx-$nginx_version/objs
mkdir -p "$PREFIX/nginx/logs" "$PREFIX/nginx/client_body_temp" \
    "$PREFIX/nginx/proxy_temp" "$PREFIX/nginx/fastcgi_temp" \
    "$PREFIX/nginx/uwsgi_temp" "$PREFIX/nginx/scgi_temp"
LUMINA_BENCH_V1_CACHE="$CACHE" "$HERE/prepare_runtime.sh"
echo "Bootstrap complete. Load: source $CACHE/env.sh"
