#!/usr/bin/env bash
# Blackwall CPU profiles at the equal-load rates of the fixed run, and at
# 5000 req/s with minimal rules. perf's DWARF unwinder fails on most
# Blackwall samples, so this profiles the same code built with frame pointers,
# in its own target dir; bench/bin/blackwall is restored afterwards.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.." || exit 1
export SERVER_CPUS=0 BACKEND_CPUS=1,5 LOADGEN_CPUS=2,3,6,7

RUSTFLAGS="-C force-frame-pointers=yes" cargo build -q --release -p cli --bin blackwall \
	--target-dir target/frame-pointers || exit 1
cp bench/bin/blackwall bench/bin/blackwall-saved || exit 1
trap 'mv bench/bin/blackwall-saved bench/bin/blackwall' EXIT
cp --remove-destination target/frame-pointers/release/blackwall bench/bin/blackwall || exit 1
rm -rf bench/results/bw-profile bench/results/bw-profile-5000

env SERVERS=blackwall MODE=fixed PROFILE=blackwall DURATION=60s REPEATS=1 BODY_SIZES=1024 \
	SCENARIOS="allow deny flood solve pass" FIXED_RATE=750 FIXED_RATE_DENY=1500 \
	FIXED_RATE_FLOOD=1000 FIXED_RATE_SOLVE=500 OUT=bench/results/bw-profile bench/run.sh
env SERVERS=blackwall MODE=fixed PROFILE=blackwall DURATION=60s REPEATS=1 BODY_SIZES=1024 \
	POLICIES=minimal SCENARIOS=allow FIXED_RATE=5000 OUT=bench/results/bw-profile-5000 bench/run.sh
echo "[bw-profile finished]"
