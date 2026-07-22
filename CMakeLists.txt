cmake_minimum_required(VERSION 3.20)
project(lumina-waf VERSION 0.4.1 LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Keep release binaries profileable while selecting only architecture-valid
# instruction sets. Native tuning is explicit because published artifacts must
# not silently depend on the CPU that happened to build them.
option(LUMINA_NATIVE_TUNING "Enable -march=native for a host-local build" OFF)
option(LUMINA_LOCAL_FUNCTION_BINDING
    "Bind calls between functions defined by libluminawaf locally on ELF platforms"
    ON)
string(TOLOWER "${CMAKE_SYSTEM_PROCESSOR}" LUMINA_SYSTEM_PROCESSOR)
set(LUMINA_ARCH_COMPILE_OPTIONS)
if(LUMINA_SYSTEM_PROCESSOR MATCHES "^(x86_64|amd64)$")
    list(APPEND LUMINA_ARCH_COMPILE_OPTIONS -mavx2 -mbmi -mpopcnt)
elseif(LUMINA_SYSTEM_PROCESSOR MATCHES "^(aarch64|arm64)$")
    # Advanced SIMD/NEON is part of the AArch64 baseline ISA.
    message(WARNING
        "AArch64 support is experimental in v0.4 and is not release-qualified")
else()
    message(FATAL_ERROR
        "Unsupported architecture '${CMAKE_SYSTEM_PROCESSOR}'; expected x86_64 or AArch64")
endif()
if(LUMINA_NATIVE_TUNING)
    list(APPEND LUMINA_ARCH_COMPILE_OPTIONS -march=native)
endif()
add_compile_options(
    -Wall -Wextra -pedantic -O3 -flto -g -fno-omit-frame-pointer
    ${LUMINA_ARCH_COMPILE_OPTIONS})
add_link_options(-flto)

add_compile_definitions(NDEBUG)

# Safety (zero dynamic exceptions/RTTI on the hot path; disabled for comparator builds).
# set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-exceptions -fno-rtti")

set(PARSER_INPUT "${CMAKE_CURRENT_SOURCE_DIR}/src/parser_input.c")

set(LUMINA_PARSER_SRC_OPT_LEVEL "-O1" CACHE STRING
    "Optimization level for source-built generated parser objects")
set(LUMINA_BENCH_V1_BENCHMARK_ROOT "" CACHE PATH "Pinned Google Benchmark installation for Benchmark Harness v1")
set(LUMINA_BENCH_V1_MODSEC_ROOT "" CACHE PATH "Pinned libModSecurity installation for Benchmark Harness v1")
if(LUMINA_BENCH_V1_BENCHMARK_ROOT)
    find_package(benchmark CONFIG REQUIRED PATHS
        "${LUMINA_BENCH_V1_BENCHMARK_ROOT}/lib/cmake/benchmark"
        NO_DEFAULT_PATH)
    set(LUMINA_BENCH_V1_BENCHMARK_TARGET benchmark::benchmark)
else()
    set(LUMINA_BENCH_V1_BENCHMARK_TARGET benchmark)
endif()
if(LUMINA_BENCH_V1_MODSEC_ROOT)
    find_library(LUMINA_BENCH_V1_MODSEC_LIBRARY modsecurity
        PATHS "${LUMINA_BENCH_V1_MODSEC_ROOT}/lib" NO_DEFAULT_PATH REQUIRED)
    set(LUMINA_BENCH_V1_MODSEC_TARGET "${LUMINA_BENCH_V1_MODSEC_LIBRARY}")
else()
    set(LUMINA_BENCH_V1_MODSEC_TARGET modsecurity)
endif()

# Discover all locally materialized parser chunks.
file(GLOB PARSER_RULES_SOURCES CONFIGURE_DEPENDS src/parser_rules_*.c)

if(NOT EXISTS "${PARSER_INPUT}" OR
   NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/src/crs_tx_rules.c" OR
   NOT PARSER_RULES_SOURCES)
    message(FATAL_ERROR
        "The BYOR AOT runtime is not materialized. Run "
        "./bench/benchmark_harness/materialize_runtime.sh after fetching the "
        "pinned CRS input, or use ./bench/benchmark_harness/run.sh smoke.")
endif()

# Compile every materialized parser source into a position-independent object
# with the C compiler selected by the configured toolchain.
set(PARSER_SRC_OBJS "")
foreach(r ${PARSER_RULES_SOURCES} ${PARSER_INPUT})
    get_filename_component(r_name ${r} NAME_WE)
    set(r_obj "${CMAKE_CURRENT_BINARY_DIR}/parser_src_${r_name}.o")
    add_custom_command(
        OUTPUT ${r_obj}
        COMMAND ${CMAKE_C_COMPILER}
            -fPIC
            ${LUMINA_PARSER_SRC_OPT_LEVEL}
            ${LUMINA_ARCH_COMPILE_OPTIONS}
            -I ${CMAKE_CURRENT_SOURCE_DIR}/src
            -c ${r}
            -o ${r_obj}
        DEPENDS ${r}
        COMMENT "Compiling parser source with ${CMAKE_C_COMPILER_ID} (${LUMINA_PARSER_SRC_OPT_LEVEL}) ${r}"
        COMMAND_EXPAND_LISTS
        VERBATIM
    )
    list(APPEND PARSER_SRC_OBJS ${r_obj})
endforeach()
set(ACTIVE_PARSER_OBJ ${PARSER_SRC_OBJS})

# LuminaWAF shared library used by the NGINX dynamic module.
# Collect all runtime C sources. The AOT parser pieces are already represented
# by ACTIVE_PARSER_OBJ, so they are excluded here to avoid duplicate symbols.
file(GLOB LUMINA_ALL_C CONFIGURE_DEPENDS
    ${CMAKE_CURRENT_SOURCE_DIR}/src/*.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/generated/*.c)
list(FILTER LUMINA_ALL_C EXCLUDE REGEX "/parser_input\\.c$")
list(FILTER LUMINA_ALL_C EXCLUDE REGEX "/parser_rules_[0-9]+\\.c$")
# The legacy Bloom dispatcher is no longer called by the typed generated-rule
# path. Its generated tables are intentionally absent from a clean BYOR build.
list(FILTER LUMINA_ALL_C EXCLUDE REGEX "/crs_bloom_filter\\.c$")
list(FILTER LUMINA_ALL_C EXCLUDE REGEX "/crs_bloom_bitmask\\.c$")
add_library(luminawaf SHARED
    src/luminawaf.cpp
    src/lumina_markers.cpp
    src/crs_tx_rules.c
    ${LUMINA_ALL_C}
    ${ACTIVE_PARSER_OBJ}
)
# The SQL injection operator is implemented by src/lumina_sqli.c and is part of
# the Lumina-owned runtime. No external SQL classifier enters this target.
set_source_files_properties(
    src/lumina_sqli.c
    PROPERTIES COMPILE_OPTIONS "-fvisibility=hidden"
)
# Generated sources (src/generated/*.c) use includes rooted at src/
# (e.g. "generated/crs_transform_mask.h", "lumina_transforms.h"). Without
# this include root the generated transform-mask translation unit fails to
# compile. Every other target already sets this; the library was missing it.
target_include_directories(luminawaf PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)
if(UNIX AND NOT APPLE)
    # The C++ driver is used for the mixed C/C++ target, but the runtime does
    # not consume libstdc++ symbols. Drop unused driver defaults and reject any
    # unresolved internal ABI at link time.
    target_link_options(luminawaf PRIVATE -Wl,--as-needed,-z,defs)
    if(LUMINA_LOCAL_FUNCTION_BINDING)
        # LuminaWAF does not support interposing its internal calls. Binding
        # functions locally removes avoidable PLT/GOT traffic while retaining
        # the current dynamic symbol set for the v0.4.1 ABI review.
        target_link_options(luminawaf PRIVATE -Wl,-Bsymbolic-functions)

        if(CMAKE_READELF)
            set(LUMINA_READELF "${CMAKE_READELF}")
        else()
            find_program(LUMINA_READELF NAMES llvm-readelf readelf REQUIRED)
        endif()
        add_custom_command(TARGET luminawaf POST_BUILD
            COMMAND python3 ${CMAKE_CURRENT_SOURCE_DIR}/tools/verify_luminawaf_elf.py
                --binary $<TARGET_FILE:luminawaf>
                --readelf ${LUMINA_READELF}
            COMMENT "Verifying LuminaWAF ELF ABI and local function binding"
            VERBATIM)
    endif()
endif()

# Test bit-perfect parity was removed because lumina_unescape_uri_avx2 is no longer exported.
# We now rely on lumina_fuzzer for testing the entire pipeline.

# Microarchitecture Layer (Google Benchmark)
add_executable(micro_bench
    tests/eval_suite/micro_bench.cpp
)
target_link_libraries(micro_bench PRIVATE benchmark pthread modsecurity luminawaf)

# LuminaWAF Benchmark Harness v1: equivalent full inbound request transactions. Coraza is
# resolved with dlopen so the core project remains buildable without Go/libcoraza;
# canonical benchmark mode requires the pinned library at runtime.
set(LUMINA_BENCH_V1_WORKLOAD_HEADER
    "${CMAKE_CURRENT_BINARY_DIR}/generated/benchmark_harness_v1_workload.h")
add_custom_command(
    OUTPUT ${LUMINA_BENCH_V1_WORKLOAD_HEADER}
    COMMAND python3 ${CMAKE_CURRENT_SOURCE_DIR}/bench/benchmark_harness/generate_workload_header.py
        --input ${CMAKE_CURRENT_SOURCE_DIR}/bench/benchmark_harness/workloads/requests.json
        --output ${LUMINA_BENCH_V1_WORKLOAD_HEADER}
    DEPENDS
        ${CMAKE_CURRENT_SOURCE_DIR}/bench/benchmark_harness/generate_workload_header.py
        ${CMAKE_CURRENT_SOURCE_DIR}/bench/benchmark_harness/workloads/requests.json
    COMMENT "Generating immutable Benchmark Harness v1 request descriptors"
)
add_executable(lumina_benchmark_harness
    bench/benchmark_harness/lumina_benchmark_harness.cpp
    ${LUMINA_BENCH_V1_WORKLOAD_HEADER}
)
target_include_directories(lumina_benchmark_harness PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_BINARY_DIR}/generated
    $<$<BOOL:${LUMINA_BENCH_V1_MODSEC_ROOT}>:${LUMINA_BENCH_V1_MODSEC_ROOT}/include>
)
target_compile_definitions(lumina_benchmark_harness PRIVATE
    LUMINA_BENCH_V1_DEFAULT_MODSEC_CONFIG="${CMAKE_CURRENT_SOURCE_DIR}/tests/eval_suite/modsec_crs_pl2.conf"
)
target_link_libraries(lumina_benchmark_harness PRIVATE ${LUMINA_BENCH_V1_BENCHMARK_TARGET} pthread ${LUMINA_BENCH_V1_MODSEC_TARGET} luminawaf dl)

# Corpus Benchmark (Mmap large access logs)
add_executable(corpus_bench
    bench/corpus_bench.cpp
)
target_include_directories(corpus_bench PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(corpus_bench PRIVATE benchmark pthread luminawaf)

# Synthetic Benchmark (Scaling malicious load)
add_executable(synthetic_bench
    bench/synthetic_bench.cpp
)
target_include_directories(synthetic_bench PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src ${CMAKE_CURRENT_SOURCE_DIR}/bench)
target_link_libraries(synthetic_bench PRIVATE benchmark pthread luminawaf)

# Parity Audit (LuminaWAF vs ModSecurity parity on dataset)
add_executable(parity_audit
    tests/eval_suite/parity_audit.cpp
)
target_include_directories(parity_audit PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(parity_audit PRIVATE benchmark pthread modsecurity luminawaf)

# Public-ABI regression checks for lifecycle, short values and metadata-only bundles.
add_executable(rc_runtime_sanity
    tests/eval_suite/rc_runtime_sanity.c
)
target_include_directories(rc_runtime_sanity PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(rc_runtime_sanity PRIVATE luminawaf)

# Fuzzer (LLVM libFuzzer)
# To run this, compile with Clang and enable Fuzzer sanitizers.
# We make it optional depending on compiler support.
if (CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    add_executable(lumina_fuzzer
        tests/fuzz_harness.cpp
        ${ACTIVE_PARSER_OBJ}
    )
    target_include_directories(lumina_fuzzer PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
    target_link_libraries(lumina_fuzzer PRIVATE luminawaf)
    target_compile_options(lumina_fuzzer PRIVATE -fsanitize=fuzzer,address,undefined)
    target_link_options(lumina_fuzzer PRIVATE -fsanitize=fuzzer,address,undefined)
endif()

# Treat materialized parser objects as generated external objects.
set_source_files_properties(${ACTIVE_PARSER_OBJ} PROPERTIES EXTERNAL_OBJECT true GENERATED true)
