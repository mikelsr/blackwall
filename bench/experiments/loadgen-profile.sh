#!/usr/bin/env bash
# Where the load generator's own CPU goes. The rig (load generator and
# backend) caps the direct baseline at 16-24k req/s on the two cores a
# 4-thread server leaves free, against 48k on three cores, and the backend
# stays under one thread, so the load generator is the limit. This runs the
# direct scenario at a fixed rate with the 24k split (backend CPU 6, load
# generator 2,3,7), samples the load generator's user and kernel time over the
# measured window and records a user-space profile of it.
# Usage: loadgen-profile.sh [rate] (default 16000). Writes
# bench/results/loadgen-profile/ (or OUT, relative to bench/): cpu.txt, perf.txt
# and the loadgen output.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1
RATE="${1:-16000}"
OUT="${OUT:-results/loadgen-profile}"
WARMUP_S=3 WINDOW_S=15
mkdir -p "$OUT"
ulimit -n 524288 || exit 1
GOMAXPROCS=1 taskset -c 6 bin/backend -addr 127.0.0.1:18080 >/dev/null 2>&1 &
backend=$!
until curl -fs -o /dev/null http://127.0.0.1:18080/; do sleep 0.2; done

GOMAXPROCS=3 taskset -c 2,3,7 bin/loadgen run -server backend -flavor "" -policy - -scenario direct \
	-target "" -backend http://127.0.0.1:18080 -pid "$backend" -size 1024 -rates "$RATE" \
	-duration "${WINDOW_S}s" -warmup "${WARMUP_S}s" -slo 10ms -workers 1024 -tokens 256 -repeat 1 \
	-cores 1 -out "$OUT/results.jsonl" -mode fixed -stop-on-fail=false -refine 0 >"$OUT/loadgen.txt" 2>&1 &
loadgen=$!

# utime and stime of a process, in clock ticks (fields 14 and 15 of
# /proc/<pid>/stat; the command name in field 2 has no spaces here).
ticks() { awk '{ print $14, $15 }' "/proc/$1/stat"; }

sleep $((WARMUP_S + 1))
read -r u0 s0 < <(ticks "$loadgen")
perf record -q -e cycles:u -F 999 --call-graph fp -p "$loadgen" -o "$OUT/perf.data" \
	-- sleep $((WINDOW_S - 2)) >/dev/null 2>&1
read -r u1 s1 < <(ticks "$loadgen")
hz=$(getconf CLK_TCK)
awk -v u=$((u1 - u0)) -v s=$((s1 - s0)) -v hz="$hz" -v secs=$((WINDOW_S - 2)) -v rate="$RATE" 'BEGIN {
	printf "load generator at %d req/s: %.0f us user + %.0f us kernel per request, %.2f threads busy\n",
		rate, u / hz / secs / rate * 1e6, s / hz / secs / rate * 1e6, (u + s) / hz / secs
}' | tee "$OUT/cpu.txt"
wait "$loadgen"
perf report -i "$OUT/perf.data" --no-children --sort dso,symbol --stdio --percent-limit 0.7 -g none \
	>"$OUT/perf.txt" 2>/dev/null
perf report -i "$OUT/perf.data" --children --sort symbol --stdio --percent-limit 3 -g none \
	>"$OUT/perf-children.txt" 2>/dev/null
kill "$backend"
