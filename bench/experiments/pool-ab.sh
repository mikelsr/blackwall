#!/usr/bin/env bash
# Pool A/B on kelpie: Blackwall as built (base) vs. Blackwall with Anubis's
# backend pool of 2 idle connections (pool2). Same commit otherwise.
# Expects bench/bin/blackwall-base (bench/build.sh) and bench/bin/blackwall-pool2
# (the same with patches/pool2.patch applied).
# Repeats run in ABBA order so slow drift hits both builds alike.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.." || exit 1

export SERVER_CPUS=0 BACKEND_CPUS=1,5 LOADGEN_CPUS=2,3,6,7
export SERVERS=blackwall SCENARIOS="allow pass upload"
OUT=bench/results/pool-ab

for v in base pool2; do
	if [[ ! -x "bench/bin/blackwall-$v" ]]; then
		echo "missing bench/bin/blackwall-$v" >&2
		exit 1
	fi
done

run() {
	local variant="$1"
	shift
	cp --remove-destination "bench/bin/blackwall-$variant" bench/bin/blackwall || exit 1
	echo "=== $variant $* ($(date -u +%H:%M:%SZ))"
	env "$@" bench/run.sh
}

order() {
	case "$1" in
	2) echo "pool2 base" ;;
	*) echo "base pool2" ;;
	esac
}

# CPU per request at the equal-load rates of aebdca3-fixed, and at 5000 req/s
# (the rate of Anubis's profile with 12% reconnects), where reuse matters more.
for r in 1 2 3; do
	for v in $(order $r); do
		run "$v" MODE=fixed REPEATS=1 FIXED_RATE=750 FIXED_RATE_LARGE=400 OUT="$OUT/$v-fixed-r$r"
		run "$v" MODE=fixed REPEATS=1 FIXED_RATE=5000 BODY_SIZES=1024 OUT="$OUT/$v-fixed5000-r$r"
	done
done

for r in 1 2 3; do
	for v in $(order $r); do
		run "$v" REPEATS=1 OUT="$OUT/$v-sweep-r$r"
	done
done

cp --remove-destination bench/bin/blackwall-base bench/bin/blackwall
echo "[pool-ab finished]"
