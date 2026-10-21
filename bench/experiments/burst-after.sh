#!/usr/bin/env bash
# What each server does with its memory after a burst of large bodies. The
# sweep only reads memory up to the moment the load stops; this repeats the
# sweep's 1 MiB burst (same rates, pinning and flags as run.sh) and then reads
# VmRSS every second for 180 s, which includes Go's forced GC (every 120 s).
# Writes bench/results/burst-after/: results.jsonl (the sweep steps) and
# rss.tsv, "<server> <policy> <scenario> <t_s> <rss_mb>", t from the end of
# the burst, t=-1 the idle server before it.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1
# As in run.sh: 1024 load generator connections need more descriptors than the
# default soft limit (1024) gives the server. Go programs raise their own limit
# at start-up; Blackwall doesn't.
ulimit -n 524288 || exit 1
OUT=results/burst-after
rm -rf "$OUT"
mkdir -p "$OUT"
SEED_HEX=$(grep -m1 '^SEED_HEX=' run.sh | cut -d'"' -f2)
SEED_B64=$(grep -m1 '^SEED_B64=' run.sh | cut -d'"' -f2)
AFTER_S=180
GOMAXPROCS=2 taskset -c 1,5 bin/backend -addr 127.0.0.1:18080 >/dev/null 2>&1 &
backend=$!

rss_mb() { awk '/^VmRSS:/ { printf "%.1f", $2 / 1024 }' "/proc/$1/status"; }

start() {
	local server="$1" policy="$2"
	if [[ "$server" == anubis ]]; then
		GOMAXPROCS=1 taskset -c 0 bin/anubis -bind 127.0.0.1:28923 -bind-network tcp -metrics-bind 127.0.0.1:29090 \
			-target http://127.0.0.1:18080 -difficulty 1 -policy-fname "policies/$policy.yaml" \
			-ed25519-private-key-hex "$SEED_HEX" -jwt-restriction-header X-Real-IP -use-remote-address=false \
			-xff-strip-private=false -cookie-secure=false -slog-level "ERROR+4" >/dev/null 2>&1 &
		URL=http://127.0.0.1:28923
	else
		env BIND=127.0.0.1:18923 BIND_NETWORK=tcp METRICS_BIND=127.0.0.1:19090 TARGET=http://127.0.0.1:18080 \
			DIFFICULTY=1 POLICY_FNAME="policies/$policy.yaml" CHALLENGE_SECRET="$SEED_B64" JWT_RESTRICTION_HEADER=X-Real-IP \
			USE_REMOTE_ADDRESS=false XFF_STRIP_PRIVATE=false COOKIE_SECURE=false RUST_LOG=off TOKIO_WORKER_THREADS=1 \
			taskset -c 0 bin/blackwall >/dev/null 2>&1 &
		URL=http://127.0.0.1:18923
	fi
	PID=$!
	until curl -fs -o /dev/null -H 'X-Real-IP: 10.0.0.1' "$URL/allow/x"; do sleep 0.2; done
	sleep 3
}

echo "server policy scenario t_s rss_mb" >"$OUT/rss.tsv"
for policy in minimal realistic; do
	for scenario in allow upload; do
		for server in blackwall anubis; do
			echo "=== $server $policy $scenario ($(date -u +%H:%M:%SZ))"
			start "$server" "$policy"
			echo "$server $policy $scenario -1 $(rss_mb "$PID")" >>"$OUT/rss.tsv"
			GOMAXPROCS=4 taskset -c 2,3,6,7 bin/loadgen run -server "$server" -flavor "$server" -policy "$policy" \
				-scenario "$scenario" -target "$URL" -backend http://127.0.0.1:18080 -pid "$PID" -size 1048576 \
				-rates 50,100,200,400,800,1600,3200,6400 -duration 15s -warmup 3s -slo 10ms -workers 1024 \
				-tokens 256 -repeat 1 -cores 1 -out "$OUT/results.jsonl" -mode sweep -refine 2 >/dev/null
			for ((t = 0; t <= AFTER_S; t++)); do
				echo "$server $policy $scenario $t $(rss_mb "$PID")" >>"$OUT/rss.tsv"
				sleep 1
			done
			kill "$PID"
			wait "$PID" 2>/dev/null
		done
	done
done
kill "$backend"
echo "[burst-after finished]"
