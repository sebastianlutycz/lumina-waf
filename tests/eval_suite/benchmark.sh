#!/bin/bash
echo "====================================="
echo " LUEF: Hardware & Latency Benchmarks "
echo "====================================="

echo "[*] Benchmarking ModSecurity (Baseline)..."
wrk -t4 -c100 -d10s -s /home/sebastian/workspace/lumina-waf/tests/eval_suite/latency.lua "http://localhost:8085/modsec/index.html?q=safe_payload_string_here"

echo ""
echo "[*] Benchmarking LuminaWAF..."
wrk -t4 -c100 -d10s -s /home/sebastian/workspace/lumina-waf/tests/eval_suite/latency.lua "http://localhost:8085/index.html?q=safe_payload_string_here"
