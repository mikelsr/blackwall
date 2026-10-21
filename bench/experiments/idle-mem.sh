#!/usr/bin/env bash
# What each server's idle resident memory is made of: RSS per mapping kind,
# read from /proc/<pid>/smaps 3 s after one allowed request, with the same
# flags and policies as run.sh, a fresh process each repeat. Writes
# <OUT>/idle-mem.tsv: "<server> <policy> <repeat> <kind> <MB>", kind binary
# (the program's own file), files (other mapped files) or private (anonymous
# memory: heap, stacks). Settings: SERVER_CPUS (default 0; one scheduler
# thread per CPU, as run.sh), BACKEND_CPUS (default 1), OUT (relative to
# bench/, default results/idle-mem) and REPEATS (default 3).
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1
OUT="${OUT:-results/idle-mem}"
SERVER_CPUS="${SERVER_CPUS:-0}"
THREADS=$(tr , '\n' <<<"$SERVER_CPUS" | wc -l)
mkdir -p "$OUT"
SEED_HEX=$(grep -m1 '^SEED_HEX=' run.sh | cut -d'"' -f2)
SEED_B64=$(grep -m1 '^SEED_B64=' run.sh | cut -d'"' -f2)
taskset -c "${BACKEND_CPUS:-1}" bin/backend -addr 127.0.0.1:18080 >/dev/null 2>&1 &
backend=$!

# summary <pid> <server> <policy> <repeat>: one line per kind. Mappings named
# "[...]" are anonymous ([heap], [stack], Go's "[anon: ...]"), except the
# kernel's [vdso], [vvar] and [vsyscall] pages, counted as files.
summary() {
	awk -v server="$2" -v policy="$3" -v repeat="$4" '
		/^[0-9a-f]+-[0-9a-f]+ / {
			path = $6
			if (path == "" || (path ~ /^\[/ && path !~ /^\[v/)) kind = "private"
			else if (path ~ ("/" server "$")) kind = "binary"
			else kind = "files"
		}
		/^Rss:/ { kb[kind] += $2 }
		END { for (k in kb) printf "%s %s %s %s %.1f\n", server, policy, repeat, k, kb[k] / 1024 }
	' "/proc/$1/smaps"
}

# measure <server> <policy> <repeat> <url> <command...>: start the server,
# send one allowed request, wait 3 s and record its memory.
measure() {
	local server="$1" policy="$2" repeat="$3" url="$4"
	shift 4
	"$@" >/dev/null 2>&1 &
	local pid=$!
	until curl -fs -o /dev/null -H 'X-Real-IP: 10.0.0.1' "$url/allow/x"; do sleep 0.2; done
	sleep 3
	summary "$pid" "$server" "$policy" "$repeat" >>"$OUT/idle-mem.tsv"
	kill "$pid"
	wait "$pid" 2>/dev/null
}

echo "server policy repeat kind mb" >"$OUT/idle-mem.tsv"
for repeat in $(seq "${REPEATS:-3}"); do
	for policy in minimal realistic; do
		measure anubis "$policy" "$repeat" http://127.0.0.1:28923 \
			env GOMAXPROCS="$THREADS" taskset -c "$SERVER_CPUS" bin/anubis -bind 127.0.0.1:28923 -bind-network tcp -metrics-bind 127.0.0.1:29090 \
			-target http://127.0.0.1:18080 -difficulty 1 -policy-fname "policies/$policy.yaml" \
			-ed25519-private-key-hex "$SEED_HEX" -jwt-restriction-header X-Real-IP -use-remote-address=false \
			-xff-strip-private=false -cookie-secure=false -slog-level "ERROR+4"
		measure blackwall "$policy" "$repeat" http://127.0.0.1:18923 \
			env BIND=127.0.0.1:18923 BIND_NETWORK=tcp METRICS_BIND=127.0.0.1:19090 TARGET=http://127.0.0.1:18080 \
			DIFFICULTY=1 POLICY_FNAME="policies/$policy.yaml" CHALLENGE_SECRET="$SEED_B64" JWT_RESTRICTION_HEADER=X-Real-IP \
			USE_REMOTE_ADDRESS=false XFF_STRIP_PRIVATE=false COOKIE_SECURE=false RUST_LOG=off TOKIO_WORKER_THREADS="$THREADS" \
			taskset -c "$SERVER_CPUS" bin/blackwall
	done
done
kill "$backend"
