#!/usr/bin/env bash
# What the challenge page costs each server with its core busy. The 1000 req/s
# profiles (aebdca3-profile, bw-profile) leave the core asleep most of the
# time, and the cost of waking it lands on whatever runs first, which makes
# Anubis's page cost 90 µs with minimal rules and 43 with the stock rules.
# Here each server floods at its highest passing rate (aebdca3-sweep).
# Blackwall is profiled on a frame-pointer build (see bw-profile.sh);
# bench/bin/blackwall is restored afterwards.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.." || exit 1
OUT=bench/results/page-profile

RUSTFLAGS="-C force-frame-pointers=yes" cargo build -q --release -p cli --bin blackwall \
	--target-dir target/frame-pointers || exit 1
rm -rf "$OUT"
mkdir -p "$OUT"
LOG="$OUT/console.txt"

export SERVER_CPUS=0 BACKEND_CPUS=1,5 LOADGEN_CPUS=2,3,6,7
export MODE=fixed REPEATS=1 DURATION=30s SCENARIOS=flood

profile() {
	local server="$1" policy="$2" rate="$3"
	echo "=== page-profile $server $policy $rate ($(date -u +%H:%M:%SZ))" | tee -a "$LOG"
	env SERVERS="$server" PROFILE="$server" POLICIES="$policy" FIXED_RATE="$rate" \
		OUT="$OUT/$server-$policy" bench/run.sh >>"$LOG" 2>&1
}

profile anubis minimal 5000
profile anubis realistic 2500
cp bench/bin/blackwall bench/bin/blackwall-saved || exit 1
trap 'mv bench/bin/blackwall-saved bench/bin/blackwall' EXIT
cp --remove-destination target/frame-pointers/release/blackwall bench/bin/blackwall || exit 1
profile blackwall minimal 7000
profile blackwall realistic 6000

bench/profile-split.sh "$OUT"/*/profiles/*.{pprof,perf.data} >"$OUT/split.md" 2>>"$LOG"
echo "[page-profile finished]" | tee -a "$LOG"
