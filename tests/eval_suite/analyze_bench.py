import json
import sys
import numpy as np
from collections import defaultdict

def main():
    if len(sys.argv) < 2:
        print("Usage: python analyze_bench.py <results.json>")
        sys.exit(1)

    with open(sys.argv[1], 'r') as f:
        data = json.load(f)

    # Group by benchmark name
    runs = defaultdict(list)
    for b in data['benchmarks']:
        # if it's an aggregate (mean, median, etc), ignore it, we calculate our own
        if 'run_type' in b and b['run_type'] == 'aggregate':
            continue
        name = b['name']
        runs[name].append(b['real_time'])

    print(f"{'Benchmark':<35} | {'p50 (ns)':<10} | {'p95 (ns)':<10} | {'p99 (ns)':<10} | {'Min (ns)':<10} | {'Max (ns)':<10} | {'StdDev':<10}")
    print("-" * 105)

    for name, times in runs.items():
        if not times:
            continue
        times = np.array(times)
        p50 = np.percentile(times, 50)
        p95 = np.percentile(times, 95)
        p99 = np.percentile(times, 99)
        val_min = np.min(times)
        val_max = np.max(times)
        stddev = np.std(times)
        
        print(f"{name:<35} | {p50:<10.2f} | {p95:<10.2f} | {p99:<10.2f} | {val_min:<10.2f} | {val_max:<10.2f} | {stddev:<10.2f}")

if __name__ == "__main__":
    main()
