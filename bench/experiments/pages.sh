#!/usr/bin/env bash
# Captures each server's challenge page, requested like loadgen's flood, with
# both policies: results/pages/<server>-<policy>-<n>.html (before compression)
# and .gz (as served). compbench/ takes these pages as input. Run after
# bench/build.sh, on a free machine (it uses run.sh's ports).
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1
OUT=results/pages
mkdir -p "$OUT"
UA=$(grep -m1 'benchUserAgent *=' loadgen/*.go | cut -d'"' -f2)
SEED_HEX=$(grep -m1 '^SEED_HEX=' run.sh | cut -d'"' -f2)
SEED_B64=$(grep -m1 '^SEED_B64=' run.sh | cut -d'"' -f2)
bin/backend -addr 127.0.0.1:18080 >/dev/null 2>&1 &
backend=$!
sleep 0.5

# fetch <name> <url>: three pages, each for a new client address.
fetch() {
	local i
	for i in 1 2 3; do
		curl -s -o "$OUT/$1-$i.gz" -H "User-Agent: $UA" -H 'Accept: text/html,application/xhtml+xml' \
			-H 'Accept-Encoding: gzip' -H 'Accept-Language: en' -H "X-Real-IP: 11.0.0.$i" "$2/bench/flood/$i"
		gunzip -c "$OUT/$1-$i.gz" >"$OUT/$1-$i.html"
		echo "$1 $i: $(wc -c <"$OUT/$1-$i.html") B, $(wc -c <"$OUT/$1-$i.gz") B gzipped"
	done
}

for policy in minimal realistic; do
	bin/anubis -bind 127.0.0.1:28923 -bind-network tcp -metrics-bind 127.0.0.1:29090 \
		-target http://127.0.0.1:18080 -difficulty 1 -policy-fname "policies/$policy.yaml" \
		-ed25519-private-key-hex "$SEED_HEX" -jwt-restriction-header X-Real-IP -use-remote-address=false \
		-xff-strip-private=false -cookie-secure=false -slog-level "ERROR+4" >/dev/null 2>&1 &
	anubis=$!
	env BIND=127.0.0.1:18923 BIND_NETWORK=tcp METRICS_BIND=127.0.0.1:19090 TARGET=http://127.0.0.1:18080 \
		DIFFICULTY=1 POLICY_FNAME="policies/$policy.yaml" CHALLENGE_SECRET="$SEED_B64" JWT_RESTRICTION_HEADER=X-Real-IP \
		USE_REMOTE_ADDRESS=false XFF_STRIP_PRIVATE=false COOKIE_SECURE=false RUST_LOG=off TOKIO_WORKER_THREADS=1 \
		bin/blackwall >/dev/null 2>&1 &
	blackwall=$!
	sleep 2
	fetch "anubis-$policy" http://127.0.0.1:28923
	fetch "blackwall-$policy" http://127.0.0.1:18923
	kill "$anubis" "$blackwall"
	wait "$anubis" "$blackwall" 2>/dev/null
done
kill "$backend"
