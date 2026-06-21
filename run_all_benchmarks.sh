#!/bin/bash
set -e

GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}==========================================${NC}"
echo -e "${BLUE} LuminaWAF: Reproducible Evaluation Suite ${NC}"
echo -e "${BLUE}==========================================${NC}"

echo -e "\n${GREEN}[*] Step 1: Building project (CMake & LuminaC AOT)${NC}"
mkdir -p build && cd build
cmake ..
make clean
make -j$(nproc)
cd ..

echo -e "\n${GREEN}[*] Step 2: Running Differential Parity Audit (libFuzzer vs ModSecurity)${NC}"
echo "    Executing 100,000 fuzzing mutations against the baseline..."
./build/parity_test -runs=100000 || { echo "Parity Test Failed"; exit 1; }

echo -e "\n${GREEN}[*] Step 3: Running Microarchitecture Benchmarks (Google Benchmark)${NC}"
./build/micro_bench --benchmark_format=console

echo -e "\n${GREEN}[*] Step 4: End-to-End Saturation Test Verification${NC}"
echo "    (Note: Full saturation curve requires NGINX compilation with module."
echo "     Run tests/eval_suite/run_wrk_bench.sh separately on dedicated hardware)."

echo -e "\n${BLUE}==========================================${NC}"
echo -e "${GREEN}  All Core Benchmarks Passed Successfully!  ${NC}"
echo -e "${BLUE}==========================================${NC}"
