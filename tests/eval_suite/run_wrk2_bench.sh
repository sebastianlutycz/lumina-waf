#!/bin/bash
set -e

RATES=(1000 5000 10000 20000)
PORTS=(8090 8081 8082)
NAMES=("Baseline" "LuminaWAF" "ModSecurity")
WRK="/home/sebastian/workspace/wrk2/wrk"

mkdir -p /home/sebastian/workspace/lumina-waf/tests/eval_suite/results
OUT="/home/sebastian/workspace/lumina-waf/tests/eval_suite/results/wrk2_saturation.txt"
echo "=== wrk2 Saturation Benchmark ===" > $OUT

for R in "${RATES[@]}"; do
    echo "Testing Rate: ${R} RPS" | tee -a $OUT
    for i in 0 1 2; do
        PORT=${PORTS[$i]}
        NAME=${NAMES[$i]}
        echo "  Server: ${NAME} (Port ${PORT})" | tee -a $OUT
        $WRK -t4 -c100 -d10s -R${R} --latency http://localhost:${PORT}/ >> $OUT 2>&1
        echo "-----------------------------------" >> $OUT
        sleep 2
    done
done
