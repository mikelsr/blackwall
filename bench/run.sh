#!/usr/bin/env bash
# Runs the Blackwall vs Anubis benchmark. See bench/RUNNING.md.
#
# Every (policy, scenario, server) combination gets a freshly started server so
# that state (challenge store, memory) from one run never leaks into another.
#
# Common knobs (environment variables):
#   MODE=sweep|fixed        sweep: find max rate at the SLO; fixed: same rate for both
#   SERVERS="blackwall anubis"
#   POLICIES="minimal realistic"
#   SCENARIOS="direct allow deny flood solve pass upload conns"
#   BODY_SIZES="1024 65536 1048576"  body sizes for direct/allow/pass/upload
#   CONNS="1000 5000 10000"  idle connection counts for the conns scenario
#   CORES=2                 cores given to the proxy under test
#   BACKEND_CORES=2         cores given to the backend
#   LOADGEN_CORES=          cores for the load generator (default: the rest)
#   SERVER_CPUS= BACKEND_CPUS= LOADGEN_CPUS=
#                           Linux only: explicit taskset CPU lists (e.g. "0", "1,5",
#                           "2-3,6-7"). Override the *_CORES counts. Use them to keep
#                           SMT siblings apart; see bench/RUNNING.md.
#   RATES="500,1000,..."    sweep rates; RATES_<SCENARIO> overrides per scenario
#   RATES_LARGE="50,..."    sweep rates for bodies >= 1 MiB
#   FIXED_RATE=2000         fixed mode rate; FIXED_RATE_<SCENARIO> overrides
#   FIXED_RATE_LARGE=200    fixed mode rate for bodies >= 1 MiB
#   DURATION=15s WARMUP=3s SLO=10ms REPEATS=1 WORKERS=1024 REFINE=2
#   PROFILE=anubis|blackwall  fixed mode only: save a CPU profile of that server
#                           per cell (blackwall: Linux only, with perf)
#   COUNTERS=1              fixed mode only, Linux with perf: count the server's
#                           user-space cycles and instructions per cell, and
#                           snapshot per-CPU and per-thread CPU time around them
#   FLOOD_RATE=4000         also run a bot flood at this rate during every proxy
#                           cell (not direct or conns); results then cover the
#                           other requests (visitors) only
#   SERVER_ENV="GOGC=off"   extra environment for the server under test, for
#                           diagnostics (both servers get it; set SERVERS to pick one)
#   LOADGEN=bin/loadgen     load generator binary, e.g. an older build to compare
#                           against
set -euo pipefail

BENCH_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="$BENCH_DIR/bin"
LOADGEN="${LOADGEN:-$BIN/loadgen}"

MODE="${MODE:-sweep}"
SERVERS="${SERVERS:-blackwall anubis}"
POLICIES="${POLICIES:-minimal realistic}"
SCENARIOS="${SCENARIOS:-direct allow deny flood solve pass upload conns}"
BODY_SIZES="${BODY_SIZES:-1024 65536 1048576}"
CONNS="${CONNS:-1000 5000 10000}"
CONNS_SETTLE="${CONNS_SETTLE:-3s}"
CORES="${CORES:-2}"
BACKEND_CORES="${BACKEND_CORES:-2}"
RATES="${RATES:-500,1000,2000,4000,8000,16000,32000,64000}"
RATES_LARGE="${RATES_LARGE:-50,100,200,400,800,1600,3200,6400}"
FIXED_RATE="${FIXED_RATE:-2000}"
FIXED_RATE_LARGE="${FIXED_RATE_LARGE:-200}"
DURATION="${DURATION:-15s}"
WARMUP="${WARMUP:-3s}"
SLO="${SLO:-10ms}"
REPEATS="${REPEATS:-1}"
WORKERS="${WORKERS:-1024}"
REFINE="${REFINE:-2}"
TOKENS="${TOKENS:-256}"
PROFILE="${PROFILE:-}"
COUNTERS="${COUNTERS:-}"
FLOOD_RATE="${FLOOD_RATE:-}"
read -ra SERVER_ENV_ARGS <<<"${SERVER_ENV:-}"

if [[ -n "$PROFILE$COUNTERS" ]]; then
	if [[ "$MODE" != fixed ]]; then
		echo "PROFILE and COUNTERS need MODE=fixed" >&2
		exit 1
	fi
	if [[ ! "$DURATION" =~ ^[0-9]+s$ || ! "$WARMUP" =~ ^[0-9]+s$ ]] || ((${DURATION%s} < 5)); then
		echo "PROFILE and COUNTERS need DURATION and WARMUP in whole seconds, DURATION >= 5s" >&2
		exit 1
	fi
fi
if [[ -n "$COUNTERS" ]] && { [[ "$(uname)" != Linux ]] || ! command -v perf >/dev/null; }; then
	echo "COUNTERS needs Linux and perf" >&2
	exit 1
fi
if [[ -n "$PROFILE" ]]; then
	if [[ "$PROFILE" != anubis && "$PROFILE" != blackwall ]]; then
		echo "PROFILE must be anubis or blackwall" >&2
		exit 1
	fi
	if [[ "$PROFILE" == blackwall ]]; then
		PROFILER=perf
		if [[ "$(uname)" != Linux ]] || ! command -v perf >/dev/null; then
			echo "PROFILE=blackwall needs Linux and perf" >&2
			exit 1
		fi
	# Go's profiler over-counts syscalls on macOS, so use Apple's Time Profiler there.
	elif [[ "$(uname)" == Darwin ]]; then
		PROFILER=xctrace
		if ! xcrun xctrace version >/dev/null 2>&1; then
			echo "PROFILE on macOS needs xctrace (Xcode)" >&2
			exit 1
		fi
	else
		PROFILER=pprof
	fi
fi

BACKEND_ADDR="127.0.0.1:18080"
BLACKWALL_ADDR="127.0.0.1:18923"
BLACKWALL_METRICS="127.0.0.1:19090"
ANUBIS_ADDR="127.0.0.1:28923"
ANUBIS_METRICS="127.0.0.1:29090"

# Same Ed25519 seed for both servers (bytes 0x00..0x1f), so JWT signing cost is identical.
SEED_HEX="000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
SEED_B64="AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="

for b in blackwall anubis loadgen backend; do
	if [[ ! -x "$BIN/$b" ]]; then
		echo "missing $BIN/$b, run bench/build.sh first" >&2
		exit 1
	fi
done

# Number of CPUs in a taskset list such as "0,2-3".
count_cpus() {
	local n=0 part a b
	local -a parts
	IFS=, read -ra parts <<<"$1"
	for part in "${parts[@]}"; do
		if [[ "$part" == *-* ]]; then
			a="${part%-*}" b="${part#*-}"
			n=$((n + b - a + 1))
		else
			n=$((n + 1))
		fi
	done
	echo "$n"
}

# Whether a port is in a list such as "8080,9000-9010".
in_port_list() {
	local port="$1" part
	local -a parts
	IFS=, read -ra parts <<<"$2"
	for part in "${parts[@]}"; do
		if [[ "$part" == *-* ]]; then
			((port >= ${part%-*} && port <= ${part#*-})) && return 0
		elif [[ -n "$part" ]]; then
			((port == part)) && return 0
		fi
	done
	return 1
}

# Linux gives outgoing connections local ports from ip_local_port_range. A
# listen port inside that range can be taken by one of them (Anubis opens
# thousands of upstream connections under load), and the next server then
# fails to bind. Such ports must be in ip_local_reserved_ports.
check_listen_ports() {
	local range=/proc/sys/net/ipv4/ip_local_port_range
	[[ -r "$range" ]] || return 0
	local lo hi reserved addr port
	local -a exposed=()
	read -r lo hi <"$range"
	reserved="$(cat /proc/sys/net/ipv4/ip_local_reserved_ports 2>/dev/null)"
	for addr in "$BACKEND_ADDR" "$BLACKWALL_ADDR" "$BLACKWALL_METRICS" "$ANUBIS_ADDR" "$ANUBIS_METRICS"; do
		port="${addr##*:}"
		if ((port >= lo && port <= hi)) && ! in_port_list "$port" "$reserved"; then
			exposed+=("$port")
		fi
	done
	if ((${#exposed[@]} > 0)); then
		local list
		list="$(
			IFS=,
			echo "${exposed[*]}"
		)"
		echo "listen ports $list are inside ip_local_port_range ($lo-$hi) and not reserved." >&2
		echo "Outgoing connections could take them. Reserve them first:" >&2
		echo "  sudo sysctl -w net.ipv4.ip_local_reserved_ports=$list" >&2
		exit 1
	fi
}

SERVER_CPUS="${SERVER_CPUS:-}"
BACKEND_CPUS="${BACKEND_CPUS:-}"
LOADGEN_CPUS="${LOADGEN_CPUS:-}"
[[ -n "$SERVER_CPUS" ]] && CORES="$(count_cpus "$SERVER_CPUS")"
[[ -n "$BACKEND_CPUS" ]] && BACKEND_CORES="$(count_cpus "$BACKEND_CPUS")"
[[ -n "$LOADGEN_CPUS" ]] && LOADGEN_CORES="$(count_cpus "$LOADGEN_CPUS")"

check_listen_ports

NCPU="$(getconf _NPROCESSORS_ONLN 2>/dev/null || sysctl -n hw.ncpu)"
LOADGEN_CORES="${LOADGEN_CORES:-$((NCPU - CORES - BACKEND_CORES))}"
if ((LOADGEN_CORES < 1)); then
	echo "not enough cores: ncpu=$NCPU server=$CORES backend=$BACKEND_CORES" >&2
	exit 1
fi

# CPU pinning (Linux only). Server, backend and load generator get disjoint cores.
PIN_SERVER=() PIN_BACKEND=() PIN_LOADGEN=()
if command -v taskset >/dev/null 2>&1; then
	SERVER_CPUS="${SERVER_CPUS:-0-$((CORES - 1))}"
	BACKEND_CPUS="${BACKEND_CPUS:-$CORES-$((CORES + BACKEND_CORES - 1))}"
	LOADGEN_CPUS="${LOADGEN_CPUS:-$((CORES + BACKEND_CORES))-$((CORES + BACKEND_CORES + LOADGEN_CORES - 1))}"
	PIN_SERVER=(taskset -c "$SERVER_CPUS")
	PIN_BACKEND=(taskset -c "$BACKEND_CPUS")
	PIN_LOADGEN=(taskset -c "$LOADGEN_CPUS")
	PINNING="taskset server=$SERVER_CPUS backend=$BACKEND_CPUS loadgen=$LOADGEN_CPUS"
else
	if [[ -n "$SERVER_CPUS$BACKEND_CPUS$LOADGEN_CPUS" ]]; then
		echo "warning: *_CPUS are ignored without taskset (Linux only)" >&2
	fi
	PINNING="none (no taskset; results are noisier, prefer a Linux box for final numbers)"
fi

# The conns scenario needs one descriptor per connection in both the server
# and the load generator. Take the highest limit the hard limit allows.
for limit in 1048576 524288 262144 65536 10240; do
	ulimit -n "$limit" 2>/dev/null && break
done

# Extra machine details for env.txt.
machine_info() {
	if [[ -r /proc/cpuinfo ]]; then
		echo "cpu:           $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | sed 's/^ //')"
		echo "governor:      $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo unknown)"
		echo "smt:           $(cat /sys/devices/system/cpu/smt/control 2>/dev/null || echo unknown)"
		echo "no_turbo:      $(cat /sys/devices/system/cpu/intel_pstate/no_turbo 2>/dev/null || echo n/a)"
		echo "port range:    $(cat /proc/sys/net/ipv4/ip_local_port_range 2>/dev/null | tr '\t' ' ')"
		echo "reserved:      $(cat /proc/sys/net/ipv4/ip_local_reserved_ports 2>/dev/null)"
		echo "conntrack max: $(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null || echo "n/a (not loaded)")"
	else
		echo "cpu:           $(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo unknown)"
		echo "low power:     $(pmset -g 2>/dev/null | awk '/lowpowermode/ {print $2}' | grep . || echo unknown)"
		echo "port range:    $(sysctl -n net.inet.ip.portrange.first 2>/dev/null)-$(sysctl -n net.inet.ip.portrange.last 2>/dev/null)"
	fi
	echo "nofile:        $(ulimit -n)"
}

OUT="${OUT:-$BENCH_DIR/results/$(date +%Y%m%d-%H%M%S)-$MODE}"
mkdir -p "$OUT/logs"
RESULTS="$OUT/results.jsonl"

{
	echo "date:          $(date -u +%Y-%m-%dT%H:%M:%SZ)"
	echo "host:          $(uname -srm), ncpu=$NCPU"
	machine_info
	echo "mode:          $MODE"
	echo "servers:       $SERVERS"
	echo "policies:      $POLICIES"
	echo "scenarios:     $SCENARIOS"
	echo "body sizes:    $BODY_SIZES"
	echo "conns:         $CONNS"
	echo "cores:         server=$CORES backend=$BACKEND_CORES loadgen=$LOADGEN_CORES"
	echo "pinning:       $PINNING"
	echo "duration:      $DURATION (warmup $WARMUP), slo p99=$SLO, repeats=$REPEATS"
	echo "profile:       ${PROFILE:-off} ${PROFILER:-}"
	echo "counters:      $([[ -n "$COUNTERS" ]] && echo on || echo off)"
	echo "flood:         ${FLOOD_RATE:-off}"
	echo "server env:    ${SERVER_ENV:-none}"
	echo "blackwall:     $("$BIN/blackwall" --version 2>/dev/null || echo unknown)"
	echo "revision:      $(cat "$BENCH_DIR/.revision" 2>/dev/null || git -C "$BENCH_DIR" describe --always --dirty 2>/dev/null || echo unknown)"
	echo "anubis:        $("$BIN/anubis" -version 2>/dev/null || echo unknown)"
	echo "loadgen:       $LOADGEN"
} | tee "$OUT/env.txt"
echo

PIDS=()
cleanup() {
	for pid in "${PIDS[@]:-}"; do
		[[ -n "$pid" ]] && kill "$pid" 2>/dev/null || true
	done
	wait 2>/dev/null || true
}
trap cleanup EXIT INT TERM

wait_ready() {
	local url="$1" pid="$2" log="$3"
	for _ in $(seq 1 200); do
		if ! kill -0 "$pid" 2>/dev/null; then
			local status=0
			wait "$pid" || status=$?
			# With logging off, an empty log plus exit 1 usually means a bind failure.
			echo "server exited during startup (exit $status), log:" >&2
			cat "$log" >&2
			exit 1
		fi
		if curl -s -o /dev/null -m 1 "$url"; then
			return 0
		fi
		sleep 0.05
	done
	echo "timed out waiting for $url" >&2
	cat "$log" >&2
	exit 1
}

stop_pid() {
	local pid="$1"
	kill "$pid" 2>/dev/null || true
	wait "$pid" 2>/dev/null || true
}

# --- backend -----------------------------------------------------------------
GOMAXPROCS="$BACKEND_CORES" ${PIN_BACKEND[@]+"${PIN_BACKEND[@]}"} "$BIN/backend" -addr "$BACKEND_ADDR" >"$OUT/logs/backend.log" 2>&1 &
BACKEND_PID=$!
PIDS+=("$BACKEND_PID")
wait_ready "http://$BACKEND_ADDR/" "$BACKEND_PID" "$OUT/logs/backend.log"

# --- servers -----------------------------------------------------------------
SERVER_PID=""
SERVER_URL=""

start_blackwall() {
	local policy_file="$1" log="$2"
	# Run from the bench dir so dotenvy does not pick up a stray .env.
	(
		cd "$BENCH_DIR"
		exec env \
			BIND="$BLACKWALL_ADDR" \
			BIND_NETWORK=tcp \
			METRICS_BIND="$BLACKWALL_METRICS" \
			TARGET="http://$BACKEND_ADDR" \
			DIFFICULTY=1 \
			POLICY_FNAME="$policy_file" \
			CHALLENGE_SECRET="$SEED_B64" \
			JWT_RESTRICTION_HEADER=X-Real-IP \
			USE_REMOTE_ADDRESS=false \
			XFF_STRIP_PRIVATE=false \
			COOKIE_SECURE=false \
			RUST_LOG=off \
			TOKIO_WORKER_THREADS="$CORES" \
			${SERVER_ENV_ARGS[@]+"${SERVER_ENV_ARGS[@]}"} \
			${PIN_SERVER[@]+"${PIN_SERVER[@]}"} "$BIN/blackwall"
	) >"$log" 2>&1 &
	SERVER_PID=$!
	SERVER_URL="http://$BLACKWALL_ADDR"
}

# With the pprof profiler, a copy of the policy that also serves /debug/pprof
# on the metrics port (Anubis only enables it from the policy file).
anubis_policy() {
	local policy_file="$1"
	if [[ "${PROFILER:-}" != pprof ]]; then
		echo "$policy_file"
		return
	fi
	mkdir -p "$OUT/policies"
	local copy
	copy="$(cd "$OUT/policies" && pwd)/$(basename "$policy_file")"
	if [[ ! -f "$copy" ]]; then
		{
			cat "$policy_file"
			printf '\n# Added by run.sh for PROFILE=anubis.\nmetrics:\n  bind: "%s"\n  network: tcp\n  debug: true\n' "$ANUBIS_METRICS"
		} >"$copy"
	fi
	echo "$copy"
}

start_anubis() {
	local policy_file log="$2"
	policy_file="$(anubis_policy "$1")"

	(
		cd "$BENCH_DIR"
		exec env GOMAXPROCS="$CORES" ${SERVER_ENV_ARGS[@]+"${SERVER_ENV_ARGS[@]}"} \
			${PIN_SERVER[@]+"${PIN_SERVER[@]}"} "$BIN/anubis" \
			-bind "$ANUBIS_ADDR" \
			-bind-network tcp \
			-metrics-bind "$ANUBIS_METRICS" \
			-target "http://$BACKEND_ADDR" \
			-difficulty 1 \
			-policy-fname "$policy_file" \
			-ed25519-private-key-hex "$SEED_HEX" \
			-jwt-restriction-header X-Real-IP \
			-use-remote-address=false \
			-xff-strip-private=false \
			-cookie-secure=false \
			-slog-level "ERROR+4"
	) >"$log" 2>&1 &
	SERVER_PID=$!
	SERVER_URL="http://$ANUBIS_ADDR"
}

is_sized() {
	case "$1" in
	direct | allow | pass | upload) return 0 ;;
	*) return 1 ;;
	esac
}

# Rates for a scenario and body size. Per-scenario variables win; bodies of
# 1 MiB and more fall back to the *_LARGE defaults.
rates_for() {
	local scn="$1" size="$2" var
	local upper
	upper="$(echo "$scn" | tr '[:lower:]' '[:upper:]')"
	if [[ "$MODE" == "fixed" ]]; then
		var="FIXED_RATE_$upper"
		if [[ -n "${!var:-}" ]]; then
			echo "${!var}"
		elif ((size >= 1048576)); then
			echo "$FIXED_RATE_LARGE"
		else
			echo "$FIXED_RATE"
		fi
	else
		var="RATES_$upper"
		if [[ -n "${!var:-}" ]]; then
			echo "${!var}"
		elif ((size >= 1048576)); then
			echo "$RATES_LARGE"
		else
			echo "$RATES"
		fi
	fi
}

run_loadgen() {
	local server="$1" flavor="$2" policy="$3" scenario="$4" target="$5" pid="$6" repeat="$7" size="$8"
	local mode_args=()
	if [[ "$MODE" == "fixed" ]]; then
		mode_args=(-mode fixed -stop-on-fail=false -refine 0)
	else
		mode_args=(-mode sweep -refine "$REFINE")
	fi
	# The backend baseline has no proxy to flood.
	if [[ -n "$FLOOD_RATE" && "$scenario" != direct ]]; then
		mode_args+=(-flood-rate "$FLOOD_RATE")
	fi
	# The profile covers the measured window, minus a second at each end.
	local profile_pid=""
	if [[ "$PROFILE" == "$server" ]]; then
		mkdir -p "$OUT/profiles"
		local secs=$((${DURATION%s} - 2)) file="$OUT/profiles/$server-$policy-$scenario-$size-r$repeat"
		(
			sleep $((${WARMUP%s} + 1))
			case "$PROFILER" in
			xctrace)
				xcrun xctrace record --quiet --no-prompt --template 'Time Profiler' --attach "$pid" \
					--time-limit "${secs}s" --output "$file.trace" >/dev/null
				;;
			pprof)
				curl -sf -m $((secs + 10)) -o "$file.pprof" "http://$ANUBIS_METRICS/debug/pprof/profile?seconds=$secs"
				;;
			perf)
				# Walks frame pointers: build the profiled binary with
				# RUSTFLAGS="-C force-frame-pointers=yes", or stacks stop at the
				# first frame. (DWARF unwinding needs no rebuild, but perf's libdw
				# unwinder fails on most Blackwall samples: "address range overlaps
				# an existing module".)
				# User space only (cycles:u, which also works without root);
				# kernel time is in the results' sys_us_per_op. 999 Hz, not 1000, so
				# sampling does not run in step with 1 ms timers.
				perf record -q -e cycles:u -F 999 --call-graph fp -p "$pid" -o "$file.perf.data" \
					-- sleep "$secs" >/dev/null 2>&1
				# Report now: perf needs the exact binary that ran.
				perf report -i "$file.perf.data" --no-children --sort dso,symbol --stdio \
					--percent-limit 0.5 -g none >"$file.txt" 2>/dev/null
				;;
			esac
		) &
		profile_pid=$!
	fi
	# Same window as the profile. User space only, like the profile (cycles:u
	# works without root; kernel-side events such as context switches would
	# count 0). CSV: value,unit,event,... Around it, .cpus.txt snapshots, all
	# cumulative counts:
	#   cpuN user nice system idle iowait irq softirq ...  /proc/stat, in ticks;
	#                                    includes kernel work billed to no process
	#   idle cpuN STATE usage time_us   time in each sleep state (cpuidle)
	#   task TID utime stime last-CPU migrations voluntary involuntary wchan
	#                                    each server thread (ticks; switch counts;
	#                                    the kernel function it is waiting in)
	local counters_pid=""
	if [[ -n "$COUNTERS" ]]; then
		mkdir -p "$OUT/counters"
		local secs=$((${DURATION%s} - 2)) file="$OUT/counters/$server-$policy-$scenario-$size-r$repeat"
		(
			snapshot() {
				echo "# $1"
				grep -E '^cpu[0-9]+ ' /proc/stat
				for state in /sys/devices/system/cpu/cpu[0-9]*/cpuidle/state[0-9]*; do
					local cpu="${state%/cpuidle/*}"
					echo "idle ${cpu##*/} $(<"$state/name") $(<"$state/usage") $(<"$state/time")"
				done
				for task in /proc/"$pid"/task/*; do
					echo "task ${task##*/} $(cut -d' ' -f14,15,39 "$task/stat")" \
						"$(awk '/^se.nr_migrations/ { print $3 }' "$task/sched")" \
						"$(awk '/ctxt_switches/ { printf "%s ", $2 }' "$task/status")$(<"$task/wchan")"
				done
			}
			sleep $((${WARMUP%s} + 1))
			snapshot before >"$file.cpus.txt"
			perf stat -x, -e cycles:u,instructions:u -p "$pid" -o "$file.csv" -- sleep "$secs" >/dev/null 2>&1
			snapshot after >>"$file.cpus.txt"
		) &
		counters_pid=$!
	fi
	GOMAXPROCS="$LOADGEN_CORES" ${PIN_LOADGEN[@]+"${PIN_LOADGEN[@]}"} "$LOADGEN" run \
		-server "$server" -flavor "$flavor" -policy "$policy" -scenario "$scenario" \
		-target "$target" -backend "http://$BACKEND_ADDR" -pid "$pid" -size "$size" \
		-rates "$(rates_for "$scenario" "$size")" -duration "$DURATION" -warmup "$WARMUP" \
		-slo "$SLO" -workers "$WORKERS" -tokens "$TOKENS" \
		-repeat "$repeat" -cores "$CORES" -out "$RESULTS" "${mode_args[@]}" \
		| tee -a "$OUT/console.txt"
	if [[ -n "$profile_pid" ]]; then
		wait "$profile_pid" || echo "warning: no profile for $server $policy $scenario $size" >&2
	fi
	if [[ -n "$counters_pid" ]]; then
		wait "$counters_pid" || echo "warning: no counters for $server $policy $scenario $size" >&2
	fi
}

run_conns() {
	local server="$1" policy="$2" target="$3" pid="$4" repeat="$5" conns="$6"
	GOMAXPROCS="$LOADGEN_CORES" ${PIN_LOADGEN[@]+"${PIN_LOADGEN[@]}"} "$LOADGEN" run \
		-server "$server" -flavor "$server" -policy "$policy" -scenario conns \
		-target "$target" -pid "$pid" -conns "$conns" -settle "$CONNS_SETTLE" \
		-repeat "$repeat" -cores "$CORES" -out "$RESULTS" \
		| tee -a "$OUT/console.txt"
}

# When the firewall's connection tracking is loaded, every loopback connection
# takes a slot in its table, and a closed one keeps it for 120 s (TIME_WAIT). A
# conns level right after a large one can fill the table, and the kernel then
# drops new SYNs ("nf_conntrack: table full"). Wait until there is room.
wait_conntrack_room() {
	local need="$1" count_file=/proc/sys/net/netfilter/nf_conntrack_count
	[[ -r "$count_file" ]] || return 0
	local max count waited=0
	max="$(cat /proc/sys/net/netfilter/nf_conntrack_max)"
	need=$((need + need / 10 + 1000))
	if ((need > max)); then
		echo "conns needs ~$need conntrack slots but nf_conntrack_max is $max." >&2
		echo "Raise it: sudo sysctl -w net.netfilter.nf_conntrack_max=$((need * 2))" >&2
		exit 1
	fi
	while count="$(cat "$count_file")" && ((count + need > max)); do
		if ((waited >= 300)); then
			echo "conntrack table still has $count of $max slots in use after ${waited}s" >&2
			exit 1
		fi
		((waited == 0)) && echo "waiting for conntrack slots to free up ($count of $max in use)"
		sleep 5
		waited=$((waited + 5))
	done
}

policy_path() {
	local f="$BENCH_DIR/policies/$1.yaml"
	if [[ ! -f "$f" ]]; then
		echo "missing $f" >&2
		exit 1
	fi
	echo "$f"
}

# Starts a fresh server and waits until it answers. Sets SERVER_PID/SERVER_URL.
start_server() {
	local server="$1" policy_file="$2" log="$3"
	case "$server" in
	blackwall) start_blackwall "$policy_file" "$log" ;;
	anubis) start_anubis "$policy_file" "$log" ;;
	*)
		echo "unknown server $server" >&2
		exit 1
		;;
	esac
	PIDS+=("$SERVER_PID")
	wait_ready "$SERVER_URL/allow/ready" "$SERVER_PID" "$log"
}

for repeat in $(seq 1 "$REPEATS"); do
	for scenario in $SCENARIOS; do
		sizes="0"
		if is_sized "$scenario"; then
			sizes="$BODY_SIZES"
		fi

		case "$scenario" in
		direct)
			# Baseline: independent of the proxy and the policy.
			for size in $sizes; do
				run_loadgen backend "" "-" direct "" "$BACKEND_PID" "$repeat" "$size"
			done
			;;

		conns)
			# The policy does not matter for idle connections: use the first one.
			# Fresh server per level so RSS baselines are clean and no connection
			# outlives a server's idle timeout (Anubis: 2 minutes).
			policy="${POLICIES%% *}"
			policy_file="$(policy_path "$policy")"
			for conns in $CONNS; do
				for server in $SERVERS; do
					log="$OUT/logs/$server-$policy-conns$conns-r$repeat.log"
					wait_conntrack_room "$conns"
					start_server "$server" "$policy_file" "$log"
					run_conns "$server" "$policy" "$SERVER_URL" "$SERVER_PID" "$repeat" "$conns"
					stop_pid "$SERVER_PID"
					sleep 2
				done
			done
			;;

		*)
			for policy in $POLICIES; do
				policy_file="$(policy_path "$policy")"
				for size in $sizes; do
					for server in $SERVERS; do
						log="$OUT/logs/$server-$policy-$scenario-$size-r$repeat.log"
						start_server "$server" "$policy_file" "$log"
						run_loadgen "$server" "$server" "$policy" "$scenario" "$SERVER_URL" "$SERVER_PID" "$repeat" "$size"
						stop_pid "$SERVER_PID"
						sleep 1
					done
				done
			done
			;;
		esac
	done
done

"$LOADGEN" summary "$RESULTS" | tee "$OUT/summary.md"
echo
echo "results: $OUT"
