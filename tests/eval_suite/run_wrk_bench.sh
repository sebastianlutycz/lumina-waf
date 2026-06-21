#!/bin/bash

ulimit -n 65535 || true

RATES=(100 500 1000)
PORTS=(8090 8081 8082)
NAMES=("Baseline" "LuminaWAF" "ModSecurity")
WRK="/usr/bin/wrk"

mkdir -p /home/sebastian/workspace/lumina-waf/tests/eval_suite/results
OUT="/home/sebastian/workspace/lumina-waf/tests/eval_suite/results/wrk2_saturation.txt"
echo "=== wrk Saturation Benchmark ===" > $OUT

for R in "${RATES[@]}"; do
    echo "Testing Connections: ${R}" | tee -a $OUT
    for i in 0 1 2; do
        PORT=${PORTS[$i]}
        NAME=${NAMES[$i]}
        echo "  Server: ${NAME} (Port ${PORT})" | tee -a $OUT
        $WRK -t2 -c${R} -d5s --latency http://localhost:${PORT}/?foo=bar%20baz >> $OUT 2>&1 || echo "wrk failed" >> $OUT
        echo "-----------------------------------" >> $OUT
        sleep 1
    done
done
