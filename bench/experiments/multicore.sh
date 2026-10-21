#!/usr/bin/env bash
# Scaling with vCPUs: the reference scenarios on the server sizes a cloud VM
# would usually give Anubis or Blackwall, where a vCPU is one hardware thread.
# On kelpie (i7-6700K, SMT pairs (0,4) (1,5) (2,6) (3,7)):
#   1vcpu   CPU 0, its sibling idle: the main runs' layout, measured again so
#           every layout uses the same load generator, ladder and window
#   2vcpu   CPUs 0,4: one physical core, both threads (a cloud "2 vCPU")
#   4vcpu   CPUs 0,1,4,5: two cores, both threads (a cloud "4 vCPU")
#   2core   CPUs 0,1, their siblings idle: two cores without SMT, to separate
#           cores from hyperthreads
# 1vcpu and 2vcpu leave the rig (backend and load generator) three cores, with
# the main runs' pinning. 4vcpu and 2core leave it two, the best split of
# which (rig-calibration.sh) is the backend on one core's two threads and the
# load generator on the other's.
#
# run.sh gives each server one scheduler thread per CPU (GOMAXPROCS,
# TOKIO_WORKER_THREADS), as a VM's CPU count would. Per repeat and layout:
# the rig alone (direct), sweeps of the reference cells, fixed-rate runs at
# the main fixed run's rates, and idle memory. The layout order alternates per
# repeat. Every layout has at least the CPU of 1 vCPU, so each sweep starts at
# half the cell's 1-vCPU capacity and climbs in multiples of it, then bisects
# once between the last passing and the first failing rate. Writes
# bench/results/multicore/<layout>-<sweep|fixed>-<server>-<policy>-<scenario>-r<repeat>/,
# <layout>-direct-r<repeat>/ and <layout>-idle-mem-r<repeat>/. Settings:
# DURATION (the sweeps' measured window, default 8s, as good as 15s for
# pass/fail (window-test.sh); fixed-rate runs always use 15s) and REPEATS
# (default 3).
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.." || exit 1
OUT=bench/results/multicore
SWEEP_DURATION="${DURATION:-8s}"
unset DURATION

# layout -> "server CPUs;backend CPUs;load generator CPUs"
declare -A LAYOUT=(
	[1vcpu]="0;1,5;2,3,6,7"
	[2vcpu]="0,4;1,5;2,3,6,7"
	[4vcpu]="0,1,4,5;2,6;3,7"
	[2core]="0,1;2,6;3,7"
)

# The reference cells: stock rules allowed, returning visitor and bot flood;
# minimal rules allowed; 1 KiB bodies. "server policy scenario capacity", the
# capacity being the median of aebdca3-sweep (1 vCPU); it only scales the
# sweep's ladder.
CELLS=(
	"blackwall realistic allow 14000" "anubis realistic allow 2000"
	"blackwall realistic pass 8000" "anubis realistic pass 1500"
	"blackwall realistic flood 6000" "anubis realistic flood 2000"
	"blackwall minimal allow 24000" "anubis minimal allow 5000"
)

# ladder <capacity> <multiples...>: comma-separated rates.
ladder() {
	local c="$1"
	shift
	awk -v c="$c" -v m="$*" 'BEGIN { n = split(m, f, " "); for (i = 1; i <= n; i++) printf "%s%d", (i > 1 ? "," : ""), c * f[i] }'
}
SWEEP_MULTIPLES="0.5 1 1.5 2 2.5 3 4 5 6 8"

# run_sh <out> <settings...>: run.sh with the layout's pinning and settings.
run_sh() {
	local out="$1"
	shift
	env "$@" BODY_SIZES=1024 REPEATS=1 OUT="$OUT/$out" bench/run.sh >"$OUT/$out.log" 2>&1
}

# run <layout> <repeat>
run() {
	local layout="$1" r="$2" server backend loadgen cell policy scenario capacity
	IFS=";" read -r server backend loadgen <<<"${LAYOUT[$layout]}"
	export SERVER_CPUS="$server" BACKEND_CPUS="$backend" LOADGEN_CPUS="$loadgen"
	echo "=== $layout direct r$r ($(date -u +%H:%M:%SZ))"
	run_sh "$layout-direct-r$r" MODE=sweep SERVERS=blackwall POLICIES=minimal SCENARIOS=direct REFINE=2 \
		DURATION="$SWEEP_DURATION" RATES_DIRECT="$(ladder 8000 2 3 4 5 6 7 8 9 10 12)"
	for cell in "${CELLS[@]}"; do
		read -r server policy scenario capacity <<<"$cell"
		local upper
		upper=$(tr '[:lower:]' '[:upper:]' <<<"$scenario")
		echo "=== $layout $server $policy $scenario r$r ($(date -u +%H:%M:%SZ))"
		run_sh "$layout-sweep-$server-$policy-$scenario-r$r" MODE=sweep SERVERS="$server" POLICIES="$policy" \
			SCENARIOS="$scenario" REFINE=1 DURATION="$SWEEP_DURATION" \
			"RATES_$upper=$(ladder "$capacity" $SWEEP_MULTIPLES)"
		run_sh "$layout-fixed-$server-$policy-$scenario-r$r" MODE=fixed SERVERS="$server" POLICIES="$policy" \
			SCENARIOS="$scenario" FIXED_RATE=750 FIXED_RATE_FLOOD=1000
	done
	echo "=== $layout idle memory r$r ($(date -u +%H:%M:%SZ))"
	REPEATS=1 OUT="results/multicore/$layout-idle-mem-r$r" bench/experiments/idle-mem.sh >/dev/null 2>&1
}

mkdir -p "$OUT"
layouts=(1vcpu 2vcpu 4vcpu 2core)
for r in $(seq "${REPEATS:-3}"); do
	order=("${layouts[@]}")
	((r % 2)) || order=(2core 4vcpu 2vcpu 1vcpu)
	for layout in "${order[@]}"; do run "$layout" "$r"; done
done
echo "[multicore finished]"
