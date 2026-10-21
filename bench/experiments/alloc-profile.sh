#!/usr/bin/env bash
# Where Anubis's allocations (and so its GC work) come from, and what its idle
# memory is made of. Fixed-rate cells at Anubis's max rates, PROFILE=anubis so
# /debug/pprof is served; next to each run this grabs:
#   heap-idle.txt   heap profile and MemStats before any load (debug=1)
#   allocs-0/1.pb   cumulative allocation profiles at the start and end of the
#                   measured window (diff them with -diff_base)
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.." || exit 1
OUT=bench/results/alloc-profile
METRICS=127.0.0.1:29090
rm -rf "$OUT"
export SERVERS=anubis SERVER_CPUS=0 BACKEND_CPUS=1,5 LOADGEN_CPUS=2,3,6,7
export MODE=fixed REPEATS=1 DURATION=30s WARMUP=3s PROFILE=anubis BODY_SIZES=1024

cell() {
	local policy="$1" scenario="$2" rate="$3" dir="$OUT/$1-$2-$3"
	mkdir -p "$dir"
	echo "=== alloc-profile $policy $scenario $rate ($(date -u +%H:%M:%SZ))"
	env POLICIES="$policy" SCENARIOS="$scenario" FIXED_RATE="$rate" OUT="$dir/run" \
		bench/run.sh >"$dir/run.log" 2>&1 &
	local run=$!
	until curl -fs -o "$dir/heap-idle.txt" "http://$METRICS/debug/pprof/heap?debug=1"; do sleep 0.1; done
	sleep 4
	curl -fs -o "$dir/allocs-0.pb" "http://$METRICS/debug/pprof/allocs"
	sleep 28
	curl -fs -o "$dir/allocs-1.pb" "http://$METRICS/debug/pprof/allocs"
	curl -fs -o "$dir/heap-load.txt" "http://$METRICS/debug/pprof/heap?debug=1"
	wait "$run"
}

cell minimal allow 5000
cell realistic allow 2000
cell minimal flood 5000
cell realistic pass 1500
echo "[alloc-profile finished]"
