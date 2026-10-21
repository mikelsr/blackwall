#!/usr/bin/env bash
# Is an 8 s measured window as good as 15 s for a sweep's pass/fail? The same
# fixed rate at the edge of a server's capacity (its 1-vCPU limit in
# aebdca3-sweep), REPEATS times with each window and a fresh server each time,
# with the main runs' layout. If p99's spread across repeats does not grow
# with the shorter window, sweeps can use it. Writes
# bench/results/window-test/<server>-<window>/.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.." || exit 1
OUT=bench/results/window-test
export SERVER_CPUS=0 BACKEND_CPUS=1,5 LOADGEN_CPUS=2,3,6,7 BODY_SIZES=1024 MODE=fixed
REPEATS="${REPEATS:-5}"

# server policy scenario rate
CELLS=("anubis realistic allow 2000" "blackwall minimal allow 24000")

for window in 15s 8s; do
	for cell in "${CELLS[@]}"; do
		read -r server policy scenario rate <<<"$cell"
		echo "=== $server $policy $scenario $rate req/s, $window ($(date -u +%H:%M:%SZ))"
		env SERVERS="$server" POLICIES="$policy" SCENARIOS="$scenario" FIXED_RATE="$rate" \
			DURATION="$window" REPEATS="$REPEATS" OUT="$OUT/$server-$window" bench/run.sh >/dev/null 2>&1
	done
done
python3 - "$OUT" <<'EOF'
import json, statistics, sys
from pathlib import Path
for d in sorted(Path(sys.argv[1]).iterdir()):
    recs = [json.loads(l) for l in open(d / "results.jsonl")]
    p99 = [r["p99_ms"] for r in recs]
    if p99:
        print(f"{d.name:20} p99 ms {' '.join(f'{v:5.2f}' for v in p99)}  "
              f"median {statistics.median(p99):5.2f}  stdev {statistics.stdev(p99):4.2f}  "
              f"pass {sum(r['pass'] for r in recs)}/{len(recs)}")
EOF
