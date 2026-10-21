#!/usr/bin/env bash
# The challenge page after the benchmarks: Blackwall with the page as
# benchmarked (bench/bin/blackwall, built before the redesign) against a build
# of this tree (the redesigned page, stripped by proxy/build.rs), on the same
# day, taking turns. Blackwall only: Anubis didn't change. Three tests:
#   sweep  flood and solve capacity, as aebdca3-sweep
#   fixed  CPU per request at the same traffic, as aebdca3-fixed
#   busy   flood at the published capacities, as page-profile, so the
#          core is busy and the difference is the page's cost
# bench/bin/blackwall is restored afterwards.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.." || exit 1
OUT=bench/results/page-after

cargo build -q --release -p cli --bin blackwall || exit 1
rm -rf "$OUT"
mkdir -p "$OUT"
LOG="$OUT/console.txt"
cp bench/bin/blackwall bench/bin/blackwall-before || exit 1
trap 'mv bench/bin/blackwall-before bench/bin/blackwall' EXIT

export SERVERS=blackwall SERVER_CPUS=0 BACKEND_CPUS=1,5 LOADGEN_CPUS=2,3,6,7 REPEATS=3

# both <test> VAR=val...: runs run.sh with the page before, then after.
both() {
	local test="$1"
	shift
	for build in before after; do
		echo "=== page-after $test $build ($(date -u +%H:%M:%SZ))" | tee -a "$LOG"
		local bin=bench/bin/blackwall-before
		[[ "$build" == after ]] && bin=target/release/blackwall
		cp --remove-destination "$bin" bench/bin/blackwall || exit 1
		env "$@" OUT="$OUT/$test-$build" bench/run.sh >>"$LOG" 2>&1
	done
}

# The published ladder from 2,000 up, so the sweep refines at the same rates.
both sweep MODE=sweep SCENARIOS="flood solve" RATES=2000,4000,8000,16000,32000
both fixed MODE=fixed SCENARIOS="flood solve" FIXED_RATE_FLOOD=1000 FIXED_RATE_SOLVE=500
both busy-minimal MODE=fixed SCENARIOS=flood POLICIES=minimal FIXED_RATE=7000
both busy-realistic MODE=fixed SCENARIOS=flood POLICIES=realistic FIXED_RATE=6000
echo "[page-after finished]" | tee -a "$LOG"
