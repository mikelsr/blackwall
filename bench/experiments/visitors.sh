#!/usr/bin/env bash
# What real visitors see during a bot flood, on kelpie. Both servers face the
# same flood rates (bots don't slow down for a slower server) while 100
# visitors per second either return with a cookie (pass) or arrive new and
# go through the challenge (solve). Stock rules. Each repeat walks every
# flood rate, so drift hits all rates alike.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.." || exit 1

export SERVER_CPUS=0 BACKEND_CPUS=1,5 LOADGEN_CPUS=2,3,6,7
export MODE=fixed REPEATS=1 POLICIES=realistic SCENARIOS="pass solve" BODY_SIZES=1024
export FIXED_RATE=100 DURATION=30s

for r in 1 2 3; do
	for flood in 500 1000 2000 4000 8000; do
		echo "=== flood $flood r$r ($(date -u +%H:%M:%SZ))"
		FLOOD_RATE=$flood OUT="bench/results/visitors/flood$flood-r$r" bench/run.sh
	done
done
echo "[visitors finished]"
