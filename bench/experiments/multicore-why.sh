#!/usr/bin/env bash
# Why the vCPU layouts of multicore.sh scale the way they do. Fixed-rate runs
# on its layouts:
#   lowload    1vcpu, both servers and policies, allowed requests at 750 req/s
#              (the multicore fixed rate): user-space instructions per cycle
#              (run.sh COUNTERS=1) of a core that sleeps between requests.
#   busy       1vcpu, the multicore cells, each at the first rate its 1vcpu
#              sweeps failed (the core 80-97% busy): instructions per cycle of
#              warm code. Code that stalls (low IPC) leaves the core's units
#              idle for an SMT sibling to use.
#   profiles   Anubis, stock rules, allowed, 750 req/s, a CPU profile per
#              layout: where the extra CPU per request on more threads goes.
#   procs1     the same with GOMAXPROCS=1 on the larger layouts: one scheduler
#              thread on the same CPUs, to tell Go's scheduler apart from the
#              hardware.
#   sibling    procs1's cells again, next to stock GOMAXPROCS on 1vcpu and
#              2vcpu, with run.sh COUNTERS' per-CPU, sleep-state and per-thread
#              snapshots: what runs on the core's second thread when Go has one
#              scheduler thread (Go's profiler can't see threads such as sysmon),
#              with 2core as the control where the second CPU is another core.
#              Then 1vcpu with a process that isn't Go on CPU 4, the core's
#              second thread: one that wakes ~5,000 times a second for a few
#              µs (as Anubis's second thread does on 2vcpu), and one that spins.
#   gc         Anubis, stock rules, allowed: sweeps as in multicore.sh with
#              collections 10 times rarer (GOGC=1000) on 1vcpu, 2core and
#              4vcpu, to see whether the garbage collector is what keeps Anubis
#              from using more of fewer CPUs.
# Writes bench/results/multicore-why/<part>-<layout>[-<cell>]/. REPEATS
# (default 3) is per cell, except for profiles, which run once. PARTS (default
# all, in the order above) picks the parts.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.." || exit 1
OUT=bench/results/multicore-why
REPEATS="${REPEATS:-3}"
PARTS="${PARTS:-lowload busy profiles procs1 sibling gc}"

# The layouts of multicore.sh: "server CPUs;backend CPUs;load generator CPUs".
declare -A LAYOUT=(
	[1vcpu]="0;1,5;2,3,6,7"
	[2vcpu]="0,4;1,5;2,3,6,7"
	[4vcpu]="0,1,4,5;2,6;3,7"
	[2core]="0,1;2,6;3,7"
)

# The multicore cells at their first failing 1vcpu rate (multicore/1vcpu-sweep-*):
# "server policy scenario rate".
BUSY=(
	"blackwall realistic allow 21000" "anubis realistic allow 3000"
	"blackwall realistic pass 10000" "anubis realistic pass 2250"
	"blackwall realistic flood 7500" "anubis realistic flood 3000"
	"blackwall minimal allow 30000" "anubis minimal allow 7500"
)

# run <dir> <layout> <settings...>: run.sh in fixed mode, 1 KiB bodies,
# allowed requests at 750 req/s unless the settings say otherwise.
run() {
	local dir="$1" layout="$2" server backend loadgen
	shift 2
	IFS=";" read -r server backend loadgen <<<"${LAYOUT[$layout]}"
	echo "=== $dir ($(date -u +%H:%M:%SZ))"
	env MODE=fixed SCENARIOS=allow BODY_SIZES=1024 FIXED_RATE=750 REPEATS="$REPEATS" "$@" \
		SERVER_CPUS="$server" BACKEND_CPUS="$backend" LOADGEN_CPUS="$loadgen" \
		OUT="$OUT/$dir" bench/run.sh >"$OUT/$dir.log" 2>&1
}

part() { [[ " $PARTS " == *" $1 "* ]]; }

# sibling_load wake|spin: start a process on CPU 4 (the server's sibling on
# 1vcpu) that wakes every ~150 µs, or never sleeps. Prints its pid.
sibling_load() {
	local code='import time
while True: time.sleep(0.00015)'
	[[ "$1" == spin ]] && code='while True: pass'
	taskset -c 4 python3 -c "$code" >/dev/null 2>&1 &
	echo $!
}

mkdir -p "$OUT"
if part lowload; then
	run lowload-1vcpu 1vcpu COUNTERS=1 SERVERS="blackwall anubis" POLICIES="minimal realistic"
fi
if part busy; then
	for cell in "${BUSY[@]}"; do
		read -r server policy scenario rate <<<"$cell"
		run "busy-1vcpu-$server-$policy-$scenario" 1vcpu COUNTERS=1 SERVERS="$server" POLICIES="$policy" \
			SCENARIOS="$scenario" FIXED_RATE="$rate"
	done
fi
if part profiles; then
	for layout in 1vcpu 2vcpu 2core 4vcpu; do
		run "profiles-$layout" "$layout" PROFILE=anubis SERVERS=anubis POLICIES=realistic REPEATS=1
	done
fi
if part procs1; then
	for layout in 2vcpu 2core 4vcpu; do
		run "procs1-$layout" "$layout" COUNTERS=1 SERVER_ENV=GOMAXPROCS=1 SERVERS=anubis POLICIES=realistic
	done
fi
if part sibling; then
	run sibling-1vcpu 1vcpu COUNTERS=1 SERVERS=anubis POLICIES=realistic
	run sibling-2vcpu 2vcpu COUNTERS=1 SERVERS=anubis POLICIES=realistic
	run sibling-2vcpu-procs1 2vcpu COUNTERS=1 SERVER_ENV=GOMAXPROCS=1 SERVERS=anubis POLICIES=realistic
	run sibling-2core-procs1 2core COUNTERS=1 SERVER_ENV=GOMAXPROCS=1 SERVERS=anubis POLICIES=realistic
	for load in wake spin; do
		load_pid="$(sibling_load "$load")"
		run "sibling-1vcpu-$load" 1vcpu COUNTERS=1 SERVERS=anubis POLICIES=realistic
		kill "$load_pid"
	done
fi
if part gc; then
	# multicore.sh's ladder for this cell: multiples of its 1-vCPU capacity, 2000.
	for layout in 1vcpu 2core 4vcpu; do
		run "gc-$layout" "$layout" MODE=sweep REFINE=1 DURATION=8s SERVER_ENV=GOGC=1000 SERVERS=anubis \
			POLICIES=realistic RATES_ALLOW=1000,2000,3000,4000,5000,6000,8000,10000,12000,16000
	done
fi
echo "[multicore-why finished]"
