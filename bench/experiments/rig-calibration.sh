#!/usr/bin/env bash
# How much load the rig (load generator and backend, no proxy) can offer on
# the two cores (CPUs 2,3,6,7) left free by a server on CPUs 0,1,4,5, for
# each way of dividing them. The multi-core runs (multicore.sh) use the best
# split; a server whose capacity comes near the rig's is reported as "at
# least". Siblings: (2,6) and (3,7). Writes
# bench/results/rig-calibration/backend-<cpus>-loadgen-<cpus>/ and
# rig-calibration/console.txt. Settings: OUT (relative to the repository,
# default bench/results/rig-calibration).
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.." || exit 1
OUT="${OUT:-bench/results/rig-calibration}"
rm -rf "$OUT"
mkdir -p "$OUT"
for split in "2,6:3,7" "6:2,3,7" "2:3,6,7" "2,3:6,7"; do
	backend=${split%%:*} loadgen=${split#*:}
	env SCENARIOS=direct SERVERS=blackwall BODY_SIZES=1024 REPEATS=1 REFINE=3 \
		RATES=4000,8000,16000,24000,32000,48000,64000,96000,128000 \
		SERVER_CPUS=0,1 BACKEND_CPUS="$backend" LOADGEN_CPUS="$loadgen" \
		OUT="$OUT/backend-${backend//,/_}-loadgen-${loadgen//,/_}" bench/run.sh
done >"$OUT/console.txt" 2>&1
grep -E "^pinning|^# max" "$OUT/console.txt"
