#!/usr/bin/env bash
# Per-core activity during single fixed-rate cells on kelpie, without root:
# busy share by kind (/proc/stat) and time in each sleep state (cpuidle).
# Answers two questions:
#   - Is the server's core full when its process shows < 1 core? (kernel
#     network work, softirq, is not always billed to the process)
#   - Do the cores sleep deeply at low load? (the low-load latency dip)
# Usage: core-check.sh OUT_DIR
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.." || exit 1
OUT="$1"
mkdir -p "$OUT"
export SERVER_CPUS=0 BACKEND_CPUS=1,5 LOADGEN_CPUS=2,3,6,7 MODE=fixed REPEATS=1 DURATION=30s

snapshot() {
	grep '^cpu[0-9]' /proc/stat
	for d in /sys/devices/system/cpu/cpu[0-9]*/cpuidle; do
		cpu=$(basename "$(dirname "$d")")
		for s in "$d"/state*; do
			echo "idle $cpu $(cat "$s/name") $(cat "$s/time")"
		done
	done
}

# report BEFORE AFTER: per CPU, % of the interval busy (user, system, softirq,
# irq) and % spent in each sleep state.
report() {
	awk '
		FNR == 1 { file++ }
		/^cpu/ {
			total = 0
			for (i = 2; i <= NF; i++) total += $i
			t[file, $1] = total; u[file, $1] = $2 + $3; s[file, $1] = $4
			irq[file, $1] = $7; sirq[file, $1] = $8
			cpus[$1] = 1
		}
		# States in the order the kernel lists them: shallow to deep.
		/^idle/ {
			idle[file, $2, $3] = $4
			if (!($3 in states)) { states[$3] = 1; names[++n] = $3 }
		}
		END {
			# /proc/stat counts USER_HZ ticks (1/100 s); cpuidle counts µs.
			printf "%-6s %6s %6s %6s %6s %6s", "cpu", "busy%", "user%", "sys%", "sirq%", "irq%"
			for (i = 1; i <= n; i++) printf " %6s", names[i]
			printf "\n"
			for (c = 0; c < 8; c++) {
				cpu = "cpu" c
				if (!(cpu in cpus)) continue
				dt = t[2, cpu] - t[1, cpu]
				if (dt <= 0) continue
				du = u[2, cpu] - u[1, cpu]; ds = s[2, cpu] - s[1, cpu]
				di = irq[2, cpu] - irq[1, cpu]; dsi = sirq[2, cpu] - sirq[1, cpu]
				printf "%-6s %6.1f %6.1f %6.1f %6.1f %6.1f", cpu, 100 * (du + ds + di + dsi) / dt, 100 * du / dt, 100 * ds / dt, 100 * dsi / dt, 100 * di / dt
				for (i = 1; i <= n; i++) printf " %6.1f", 100 * (idle[2, cpu, names[i]] - idle[1, cpu, names[i]]) / (dt * 10000)
				printf "\n"
			}
		}' "$1" "$2"
}

# Snapshots cover the measured window only: from a second after warm-up
# (3 s) to a second before its end, like run.sh's profiles.
cell() {
	local name="$1"
	shift
	(
		until pgrep -f "bin/loadgen run" >/dev/null; do sleep 0.2; done
		sleep 4
		snapshot >"$OUT/$name.before"
		sleep 28
		snapshot >"$OUT/$name.after"
	) &
	local snap=$!
	env "$@" OUT="$OUT/$name" bench/run.sh >"$OUT/$name.log" 2>&1
	wait "$snap"
	{
		echo "## $name ($*)"
		grep -E '^ +[0-9]+ ' "$OUT/$name.log" | head -1
		report "$OUT/$name.before" "$OUT/$name.after"
		echo
	} | tee -a "$OUT/report.txt"
}

one() { echo "SERVERS=$1 POLICIES=$2 SCENARIOS=$3 BODY_SIZES=$4 FIXED_RATE=$5 FIXED_RATE_LARGE=$5"; }

# Low-load latency dip: same cell at low and high load, both servers.
cell bw-allow-500 $(one blackwall realistic allow 1024 500)
cell bw-allow-8000 $(one blackwall realistic allow 1024 8000)
cell an-allow-500 $(one anubis realistic allow 1024 500)
cell an-allow-1500 $(one anubis realistic allow 1024 1500)
# Large bodies: is core 0 full at the limit?
cell bw-1mib-2000 $(one blackwall minimal allow 1048576 2000)
cell an-1mib-1600 $(one anubis minimal allow 1048576 1600)
# Minimal deny: Blackwall's core vs. the load generator's cores.
cell bw-deny-48000 $(one blackwall minimal deny 0 48000)
echo "[core-check finished]"
