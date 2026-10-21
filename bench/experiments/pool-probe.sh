#!/usr/bin/env bash
# Why pool2 Blackwall fails at 14k req/s (minimal allow 1 KiB) while it passes
# 12k at 0.46 cores: records new backend connections and server CPU every
# second of fixed-rate runs, to see whether reconnects start with a burst and
# grow (feedback) or are steady from the start. Uses pool-ab.sh's builds,
# bench/bin/blackwall-base and bench/bin/blackwall-pool2.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.." || exit 1
OUT=bench/results/pool-probe
mkdir -p "$OUT"
LOG="$OUT/console.txt"

export SERVER_CPUS=0 BACKEND_CPUS=1,5 LOADGEN_CPUS=2,3,6,7
export SERVERS=blackwall POLICIES=minimal SCENARIOS=allow BODY_SIZES=1024
export MODE=fixed REPEATS=1 DURATION=30s

# One line per second: seconds since start, new backend connections, open
# backend connections, server CPU in ms.
sample() {
	local pid="" t=0 prev_acc="" prev_cpu="" acc active cpu
	until pid="$(pgrep -x blackwall)"; do sleep 0.2; done
	until curl -fs http://127.0.0.1:18080/__bench/stats >/dev/null; do sleep 0.2; done
	echo "t new_conns open_conns cpu_ms"
	while kill -0 "$pid" 2>/dev/null; do
		read -r acc active < <(curl -fs http://127.0.0.1:18080/__bench/stats |
			jq -r '"\(.accepted) \(.active)"') || break
		cpu=$(awk '{print ($14 + $15) * 10}' "/proc/$pid/stat" 2>/dev/null) || break
		[[ -n "$prev_acc" ]] && echo "$t $((acc - prev_acc)) $active $((cpu - prev_cpu))"
		prev_acc=$acc prev_cpu=$cpu t=$((t + 1))
		sleep 1
	done
}

for v in pool2 base; do
	for r in 12000 14000; do
		[[ "$v" == base && "$r" == 12000 ]] && continue
		cp --remove-destination "bench/bin/blackwall-$v" bench/bin/blackwall || exit 1
		echo "=== probe $v $r ($(date -u +%H:%M:%SZ))" | tee -a "$LOG"
		taskset -c 1 bash -c "$(declare -f sample); sample" >"$OUT/$v-$r.tsv" 2>&1 &
		sampler=$!
		FIXED_RATE=$r OUT="$OUT/$v-$r" bench/run.sh >>"$LOG" 2>&1
		wait "$sampler"
	done
done

cp --remove-destination bench/bin/blackwall-base bench/bin/blackwall
echo "[probe finished]" | tee -a "$LOG"
