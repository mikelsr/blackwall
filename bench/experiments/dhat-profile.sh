#!/usr/bin/env bash
# Counts Blackwall heap allocations per request: runs each scenario for N and
# 2N requests under dhat and prints the difference divided by N. Needs a build
# with the dhat feature (cargo build --release -p cli --features dhat-heap)
# and bench/build.sh's backend and loadgen. Profiles land in results/dhat/;
# compare call sites with dhat-diff.py.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
BW="$PWD/../target/release/blackwall"
WORK="$PWD/results/dhat"
SEED_B64=$(grep -m1 '^SEED_B64=' run.sh | cut -d'"' -f2)
RATE=500 N=2000
mkdir -p "$WORK"
bin/backend -addr 127.0.0.1:18080 >/dev/null 2>&1 &
BACKEND=$!
trap 'kill $BACKEND 2>/dev/null' EXIT
sleep 1
total() { # policy scenario size requests -> "blocks bytes"
	local policy=$1 scenario=$2 size=$3 reqs=$4 log=$WORK/$1-$2-$3-$4.log
	(cd "$WORK" && exec env BIND=127.0.0.1:18923 BIND_NETWORK=tcp METRICS_BIND=127.0.0.1:19090 \
		TARGET=http://127.0.0.1:18080 DIFFICULTY=1 POLICY_FNAME="$OLDPWD/policies/$policy.yaml" \
		CHALLENGE_SECRET="$SEED_B64" JWT_RESTRICTION_HEADER=X-Real-IP \
		USE_REMOTE_ADDRESS=false XFF_STRIP_PRIVATE=false COOKIE_SECURE=false RUST_LOG=off \
		TOKIO_WORKER_THREADS=1 "$BW") 2>"$log" &
	local pid=$!
	until curl -s -o /dev/null -m 1 http://127.0.0.1:18923/allow/ready; do sleep 0.1; done
	bin/loadgen run -server blackwall -flavor blackwall -policy "$policy" -scenario "$scenario" \
		-target http://127.0.0.1:18923 -size "$size" -rates "$RATE" -duration "$((reqs / RATE))s" \
		-warmup 0s -pause 0s -mode fixed -stop-on-fail=false -refine 0 -tokens 64 >/dev/null
	kill -INT "$pid"
	wait "$pid" || true
	mv "$WORK/dhat-heap.json" "${log%.log}.json"
	# "dhat: Total:     1,234 bytes in 56 blocks"
	grep 'dhat: Total:' "$log" | tr -d , | awk '{print $6, $3}'
}
printf "%-10s %-7s %-6s %12s %12s\n" policy scenario size allocs/req bytes/req
CELLS=${CELLS:-"minimal allow 1024|realistic allow 1024|minimal deny 0|realistic deny 0|minimal pass 1024|minimal allow 65536|minimal upload 65536"}
IFS="|" read -ra cells <<<"$CELLS"
for cell in "${cells[@]}"; do
	read -r policy scenario size <<<"$cell"
	read -r b1 y1 <<<"$(total "$policy" "$scenario" "$size" "$N")"
	read -r b2 y2 <<<"$(total "$policy" "$scenario" "$size" "$((2 * N))")"
	printf "%-10s %-7s %-6s %12.1f %12.0f\n" "$policy" "$scenario" "$size" "$(bc -l <<<"($b2-$b1)/$N")" "$(bc -l <<<"($y2-$y1)/$N")"
done
