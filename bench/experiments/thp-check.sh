#!/usr/bin/env bash
# Why Anubis's memory rises again after Go's forced GC returns it: repeats the
# burst-after cell `minimal` `allow` 1 MiB for each server and samples, once a
# second, resident memory, anonymous huge pages (smaps_rollup), the kernel's
# huge page collapses (khugepaged, /proc/vmstat) and the thread count, during
# the burst and for 180 s after. Usage: thp-check.sh <out dir> <repeats>
# <server>... Writes bench/results/<out dir>/samples.tsv: "<server> <repeat>
# <phase> <t_s> <rss_mb> <anon_huge_mb> <thp_collapse_alloc> <threads>".
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1
ulimit -n 524288 || exit 1
OUT="results/$1"
REPEATS="$2"
shift 2
rm -rf "$OUT"
mkdir -p "$OUT"
SEED_HEX=$(grep -m1 '^SEED_HEX=' run.sh | cut -d'"' -f2)
SEED_B64=$(grep -m1 '^SEED_B64=' run.sh | cut -d'"' -f2)
GOMAXPROCS=2 taskset -c 1,5 bin/backend -addr 127.0.0.1:18080 >/dev/null 2>&1 &
backend=$!

sample() {
	local server="$1" phase="$2" t="$3" pid="$4"
	awk -v s="$server $repeat" -v p="$phase" -v t="$t" \
		-v c="$(awk '/^thp_collapse_alloc /{print $2}' /proc/vmstat)" \
		-v th="$(awk '/^Threads:/{print $2}' "/proc/$pid/status")" \
		'/^Rss:/{r=$2} /^AnonHugePages:/{h=$2} END{printf "%s %s %s %.1f %.1f %s %s\n", s, p, t, r/1024, h/1024, c, th}' \
		"/proc/$pid/smaps_rollup" >>"$OUT/samples.tsv"
}

echo "server repeat phase t_s rss_mb anon_huge_mb thp_collapse_alloc threads" >"$OUT/samples.tsv"
for repeat in $(seq "$REPEATS"); do
	for server in "$@"; do
		if [[ "$server" == anubis ]]; then
			GOMAXPROCS=1 taskset -c 0 bin/anubis -bind 127.0.0.1:28923 -bind-network tcp -metrics-bind 127.0.0.1:29090 \
				-target http://127.0.0.1:18080 -difficulty 1 -policy-fname policies/minimal.yaml \
				-ed25519-private-key-hex "$SEED_HEX" -jwt-restriction-header X-Real-IP -use-remote-address=false \
				-xff-strip-private=false -cookie-secure=false -slog-level "ERROR+4" >/dev/null 2>&1 &
			url=http://127.0.0.1:28923
		else
			env BIND=127.0.0.1:18923 BIND_NETWORK=tcp METRICS_BIND=127.0.0.1:19090 TARGET=http://127.0.0.1:18080 \
				DIFFICULTY=1 POLICY_FNAME=policies/minimal.yaml CHALLENGE_SECRET="$SEED_B64" JWT_RESTRICTION_HEADER=X-Real-IP \
				USE_REMOTE_ADDRESS=false XFF_STRIP_PRIVATE=false COOKIE_SECURE=false RUST_LOG=off TOKIO_WORKER_THREADS=1 \
				taskset -c 0 bin/blackwall >/dev/null 2>&1 &
			url=http://127.0.0.1:18923
		fi
		pid=$!
		until curl -fs -o /dev/null -H 'X-Real-IP: 10.0.0.1' "$url/allow/x"; do sleep 0.2; done
		sleep 3
		GOMAXPROCS=4 taskset -c 2,3,6,7 bin/loadgen run -server "$server" -flavor "$server" -policy minimal \
			-scenario allow -target "$url" -backend http://127.0.0.1:18080 -pid "$pid" -size 1048576 \
			-rates 50,100,200,400,800,1600,3200,6400 -duration 15s -warmup 3s -slo 10ms -workers 1024 \
			-tokens 256 -repeat "$repeat" -cores 1 -out "$OUT/results.jsonl" -mode sweep -refine 2 >/dev/null &
		load=$!
		t=0
		while kill -0 "$load" 2>/dev/null; do
			sample "$server" burst "$t" "$pid"
			sleep 1
			t=$((t + 1))
		done
		for ((t = 0; t <= 180; t++)); do
			sample "$server" after "$t" "$pid"
			sleep 1
		done
		kill "$pid"
		wait "$pid" 2>/dev/null
	done
done
kill "$backend"
echo "[thp-check finished]"
