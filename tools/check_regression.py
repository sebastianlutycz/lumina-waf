#!/usr/bin/env python3
import json
import sys
import os
import argparse

HISTORY_FILE = "docs/history.json"

def load_json(filepath):
    if not os.path.exists(filepath):
        return None
    with open(filepath, 'r') as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return None

def save_json(filepath, data):
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=2)

def check_regression(current_bench, baseline_bench):
    regressed = False
    
    curr_tps = current_bench.get("items_per_second", current_bench.get("bytes_per_second", 0))
    base_tps = baseline_bench.get("items_per_second", baseline_bench.get("bytes_per_second", 0))
    
    if base_tps > 0 and curr_tps < base_tps * 0.97:
        print(f"❌ Throughput REGRESSION: {curr_tps:.2f} < {base_tps * 0.97:.2f} (baseline: {base_tps:.2f})")
        regressed = True
    else:
        print(f"✅ Throughput OK: {curr_tps:.2f} (baseline: {base_tps:.2f})")

    # Assuming we have IPC and cache_misses if configured in Google Benchmark via Perf
    curr_ipc = current_bench.get("IPC", 0)
    base_ipc = baseline_bench.get("IPC", 0)
    if base_ipc > 0 and curr_ipc < base_ipc * 0.98:
        print(f"❌ IPC REGRESSION: {curr_ipc:.2f} < {base_ipc * 0.98:.2f} (baseline: {base_ipc:.2f})")
        regressed = True
    elif base_ipc > 0:
        print(f"✅ IPC OK: {curr_ipc:.2f} (baseline: {base_ipc:.2f})")
        
    curr_cm = current_bench.get("cache_misses", 0)
    base_cm = baseline_bench.get("cache_misses", 0)
    if base_cm > 0 and curr_cm > base_cm * 1.05:
        print(f"❌ Cache Misses REGRESSION: {curr_cm:.2f} > {base_cm * 1.05:.2f} (baseline: {base_cm:.2f})")
        regressed = True
    elif base_cm > 0:
        print(f"✅ Cache Misses OK: {curr_cm:.2f} (baseline: {base_cm:.2f})")

    return regressed

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("benchmark_json")
    args = parser.parse_args()

    bench_data = load_json(args.benchmark_json)
    if not bench_data or "benchmarks" not in bench_data:
        print(f"Error: Invalid benchmark json: {args.benchmark_json}")
        sys.exit(1)

    # We use the first benchmark or an aggregate. Let's just focus on the main parser.
    # We find the BM_LuminaWAF_AVX2 benchmark or similar
    target_bench = bench_data["benchmarks"][0]
    for b in bench_data["benchmarks"]:
        if "AVX2" in b["name"] or "Lumina" in b["name"]:
            target_bench = b
            break
            
    print(f"Analyzing benchmark: {target_bench['name']}")

    history = load_json(HISTORY_FILE) or []
    
    is_regression = False
    
    if len(history) > 0:
        baseline = history[-1]["benchmark"]
        print(f"Comparing against baseline from {history[-1]['date']}...")
        is_regression = check_regression(target_bench, baseline)
    else:
        print("No baseline history found. This will be the first entry.")
        
    if is_regression:
        print("\nPipeline failed due to performance regression.")
        sys.exit(1)
        
    print("\nAdding to history.json...")
    
    commit_sha = os.environ.get("GITHUB_SHA", os.environ.get("GITEA_SHA", "dev"))
    history.append({
        "commit": commit_sha[:7],
        "date": bench_data.get("context", {}).get("date", "unknown"),
        "benchmark": target_bench
    })
    
    save_json(HISTORY_FILE, history)
    print("Success. History updated.")

if __name__ == "__main__":
    main()
