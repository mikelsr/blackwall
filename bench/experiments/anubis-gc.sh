#!/usr/bin/env bash
# Diagnostic, not for published numbers: is Go's garbage collector why
# Anubis's p99 crosses 10 ms while its core is only ~60% busy? Anubis at its
# own max rates (aebdca3 sweep), as shipped (GOGC=100) vs. collecting 10x less
# often (GOGC=1000; turning the GC off would add page faults as the heap grows
# by GBs), plus one run with GC tracing to count collections. Variants
# alternate per repeat.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.." || exit 1

export SERVER_CPUS=0 BACKEND_CPUS=1,5 LOADGEN_CPUS=2,3,6,7
export SERVERS=anubis MODE=fixed REPEATS=1 SCENARIOS=allow BODY_SIZES=1024
OUT=bench/results/anubis-gc

cells=("minimal 5000" "realistic 2000")
for r in 1 2 3; do
	for c in "${cells[@]}"; do
		read -r policy rate <<<"$c"
		for variant in default gc1000; do
			env=""
			[[ "$variant" == gc1000 ]] && env="GOGC=1000"
			echo "=== $variant $policy $rate r$r ($(date -u +%H:%M:%SZ))"
			SERVER_ENV="$env" POLICIES=$policy FIXED_RATE=$rate OUT="$OUT/$variant-$policy-r$r" bench/run.sh
		done
	done
done
for c in "${cells[@]}"; do
	read -r policy rate <<<"$c"
	SERVER_ENV="GODEBUG=gctrace=1" POLICIES=$policy FIXED_RATE=$rate OUT="$OUT/gctrace-$policy" bench/run.sh
done
echo "[anubis-gc finished]"
