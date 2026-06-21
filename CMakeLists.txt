cmake_minimum_required(VERSION 3.20)
project(lumina-waf LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Rygorystyczne flagi
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -pedantic -Werror")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -flto -march=native -mavx2 -g -fno-omit-frame-pointer")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -pedantic -Werror")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3 -flto -march=native -mavx2 -g -fno-omit-frame-pointer")
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} ")

add_compile_definitions(NDEBUG)

# Safety (Zero Dynamic Exceptions/RTTI on hot path - temporarily disabled for ModSecurity benchmark)
# set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-exceptions -fno-rtti")

# Definiujemy ścieżkę do kompilatora LuminaC (założenie: znajduje się obok w katalogu build)
set(LUMINAC_EXEC "${CMAKE_CURRENT_SOURCE_DIR}/../LuminaC/build/luminac")
set(PARSER_INPUT "${CMAKE_CURRENT_SOURCE_DIR}/src/parser_input.c")
set(PARSER_BC "${CMAKE_CURRENT_BINARY_DIR}/parser_input.bc")
set(PARSER_OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/parser_v3.o")
set(PRECOMPILED_AOT "${CMAKE_CURRENT_SOURCE_DIR}/src/precompiled/parser_v3.o")

option(ENABLE_GENETIC_COMPILER "Run true LuminaC genetic evolution" OFF)

if (ENABLE_GENETIC_COMPILER)
    add_custom_command(
        OUTPUT ${PARSER_OUTPUT}
        COMMAND clang -O3 -mavx2 -march=native -emit-llvm -c ${PARSER_INPUT} -I ${CMAKE_CURRENT_SOURCE_DIR}/src -o ${PARSER_BC}
        COMMAND ${LUMINAC_EXEC} ${PARSER_BC} --run-v3-e2e --emit-aot=${PARSER_OUTPUT}
        DEPENDS ${PARSER_INPUT}
        COMMENT "Uruchamiam PRAWDZIWY LuminaC Genetic Compiler na ${PARSER_INPUT}..."
    )
    set(ACTIVE_PARSER_OBJ ${PARSER_OUTPUT})
else()
    # Ścieżka benchmarku używa prekompilowanego pliku .o udostępnionego przez nas
    set(ACTIVE_PARSER_OBJ ${PRECOMPILED_AOT})
endif()

# Biblioteka lumina-waf (.so) dla NGINX
add_library(luminawaf SHARED
    src/luminawaf.cpp
    src/parser_scalar.c
    ${ACTIVE_PARSER_OBJ}
)

# Test bit-perfect parity was removed because lumina_unescape_uri_avx2 is no longer exported.
# We now rely on lumina_fuzzer for testing the entire pipeline.

# Microarchitecture Layer (Google Benchmark)
add_executable(micro_bench
    tests/eval_suite/micro_bench.cpp
    ${ACTIVE_PARSER_OBJ}
)
target_link_libraries(micro_bench PRIVATE benchmark pthread modsecurity)

# Corpus Benchmark (Mmap large access logs)
add_executable(corpus_bench
    bench/corpus_bench.cpp
    ${ACTIVE_PARSER_OBJ}
)
target_include_directories(corpus_bench PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(corpus_bench PRIVATE benchmark pthread luminawaf)

# Synthetic Benchmark (Scaling malicious load)
add_executable(synthetic_bench
    bench/synthetic_bench.cpp
    ${ACTIVE_PARSER_OBJ}
)
target_include_directories(synthetic_bench PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src ${CMAKE_CURRENT_SOURCE_DIR}/bench)
target_link_libraries(synthetic_bench PRIVATE benchmark pthread luminawaf)

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

# Wymuszamy na bibliotece użycie wygenerowanego obiektu
set_source_files_properties(${ACTIVE_PARSER_OBJ} PROPERTIES EXTERNAL_OBJECT true GENERATED true)
