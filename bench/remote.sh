#!/usr/bin/env bash
# Runs the benchmark on a remote Linux machine over SSH. See bench/RUNNING.md.
#
#   bench/remote.sh HOST sync              copy the working tree (incl. bench/anubis)
#   bench/remote.sh HOST check             show toolchain and machine settings
#   bench/remote.sh HOST build             bench/build.sh on the remote
#   bench/remote.sh HOST run [VAR=val...]  bench/run.sh in a detached tmux session
#   bench/remote.sh HOST status            tail the running benchmark's output
#   bench/remote.sh HOST attach            attach to the tmux session (Ctrl-b d to detach)
#   bench/remote.sh HOST stop              stop the running benchmark
#   bench/remote.sh HOST fetch             copy results to bench/results/remote-HOST/
#
# REMOTE_DIR (default: Code/github.com/mikelsr/blackwall, relative to the remote
# home, the same layout as locally) sets the remote checkout location.
set -euo pipefail

if [[ $# -lt 2 ]]; then
	sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'
	exit 2
fi

HOST="$1"
CMD="$2"
shift 2

BENCH_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$BENCH_DIR")"
REMOTE_DIR="${REMOTE_DIR:-Code/github.com/mikelsr/blackwall}"
SESSION="b7l-bench"

# Paths that are either rebuilt on the remote or are local output. .git has no
# trailing slash: in the bench/anubis submodule it is a file.
EXCLUDES=(
	--exclude=.git
	--exclude=/target/
	--exclude=/challenge-wasm/target/
	--exclude=/bench/bin/
	--exclude=/bench/results/
	--exclude=/bench/anubis/target/
	--exclude=/bench/anubis/node_modules/
	--exclude=/bench/anubis/var/
	--exclude=.DS_Store
)

remote() {
	ssh "$HOST" "cd $(printf %q "$REMOTE_DIR") && $*"
}

case "$CMD" in
sync)
	ssh "$HOST" "mkdir -p $(printf %q "$REMOTE_DIR")"
	# Excluded paths are never deleted on the remote, so remote builds and
	# results survive a re-sync.
	rsync -az --delete "${EXCLUDES[@]}" "$ROOT/" "$HOST:$REMOTE_DIR/"
	# .git is not copied, so record which commit was synced for run.sh's env.txt.
	rev="$(git -C "$ROOT" describe --always --dirty 2>/dev/null || echo unknown)"
	remote "echo $(printf %q "$rev") > bench/.revision"
	echo "synced $ROOT ($rev) -> $HOST:$REMOTE_DIR"
	;;

check)
	remote 'set +e
		echo "== toolchain"
		ver() { case "$1" in go) go version ;; tmux) tmux -V ;; *) "$1" --version ;; esac; }
		for t in cargo rustc go tmux taskset curl; do printf "%-8s " "$t"; command -v "$t" >/dev/null && ver "$t" 2>/dev/null | head -1 || echo MISSING; done
		echo "== cpu"
		grep -m1 "model name" /proc/cpuinfo
		lscpu -e=CPU,CORE,ONLINE 2>/dev/null
		echo "governor: $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null)"
		echo "no_turbo: $(cat /sys/devices/system/cpu/intel_pstate/no_turbo 2>/dev/null)"
		echo "smt:      $(cat /sys/devices/system/cpu/smt/control 2>/dev/null)"
		echo "== limits"
		echo "nofile soft/hard: $(ulimit -Sn)/$(ulimit -Hn)"
		echo "port range: $(cat /proc/sys/net/ipv4/ip_local_port_range)"
		echo "== load"
		uptime
		echo "== generated assets present"
		ls challenge-wasm/pkg/challenge_wasm_bg.wasm bench/anubis/lib/challenge/preact/static/app.js'
	;;

build)
	remote 'bench/build.sh'
	;;

run)
	if remote "tmux has-session -t $SESSION 2>/dev/null"; then
		echo "a benchmark is already running (bench/remote.sh $HOST status | attach | stop)" >&2
		exit 1
	fi
	vars=""
	for kv in "$@"; do
		[[ "$kv" == *=* ]] || {
			echo "expected VAR=value, got: $kv" >&2
			exit 2
		}
		vars+=" $(printf %q "$kv")"
	done
	inner="mkdir -p bench/results && env$vars bench/run.sh 2>&1 | tee bench/results/last-run.log; echo; echo '[benchmark finished]'"
	remote "tmux new-session -d -s $SESSION $(printf %q "$inner")"
	echo "started in tmux session '$SESSION' on $HOST"
	echo "  follow:  bench/remote.sh $HOST status   (or: attach)"
	echo "  results: bench/remote.sh $HOST fetch"
	;;

status)
	remote 'tail -n 40 bench/results/last-run.log 2>/dev/null || echo "no run log yet"'
	;;

attach)
	ssh -t "$HOST" "tmux attach -t $SESSION"
	;;

stop)
	remote "tmux kill-session -t $SESSION 2>/dev/null && echo stopped || echo 'not running'"
	;;

fetch)
	dest="$BENCH_DIR/results/remote-$HOST"
	mkdir -p "$dest"
	rsync -az "$HOST:$REMOTE_DIR/bench/results/" "$dest/"
	echo "fetched into $dest"
	ls -1 "$dest"
	;;

*)
	echo "unknown command: $CMD" >&2
	exit 2
	;;
esac
