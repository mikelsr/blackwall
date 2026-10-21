#!/usr/bin/env bash
# The challenge page in a browser: what a visitor's browser downloads and
# waits for on each server's challenge page, at difficulty 1 and 4. Runs on a
# machine with Google Chrome, Node, Go and npm (a Mac here), not on the
# benchmark box, with no pinning. Writes bench/results/browser/visits.jsonl
# (see visit.mjs).
#
# Blackwall is a release build of this tree. Anubis is built from bench/anubis
# into bench/bin/anubis-web, in a temporary copy, with what a browser needs
# and bench/build.sh leaves out, since the benchmarks only fetch the HTML:
#   - its web files (make assets, minus the wasm2js fallback, which fails to
#     build and which Chrome doesn't use; the solver's wasm comes from
#     bench/anubis/web/static/wasm, built before),
#   - a release version, since Anubis only lets browsers cache its files for
#     a year when its version isn't "devel", which a build outside git is.
# Both run with policies/minimal.yaml as run.sh starts them, plus
# -cookie-partitioned=false for Anubis: Chrome drops partitioned cookies
# that aren't Secure, and this runs over plain HTTP.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BENCH="$(cd "$HERE/../.." && pwd)"
ROOT="$(dirname "$BENCH")"
OUT="$BENCH/results/browser"
BIN="$BENCH/bin"
SEED_HEX=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
SEED_B64=$(printf %s "$SEED_HEX" | xxd -r -p | base64)

(cd "$ROOT" && cargo build -q --release -p cli --bin blackwall)
[[ -x "$BIN/backend" ]] || (cd "$BENCH" && go build -trimpath -o "$BIN/backend" ./backend)
if [[ ! -x "$BIN/anubis-web" ]]; then
	tmp="$(mktemp -d)"
	rsync -a --exclude .git --exclude node_modules "$BENCH/anubis/" "$tmp/"
	version="$(git -C "$BENCH/anubis" describe --tags --always)"
	(
		cd "$tmp"
		# Anubis's build scripts need bash >= 4 (globstar); macOS ships 3.2.
		for dir in /opt/homebrew/bin /usr/local/bin; do
			if [[ -x "$dir/bash" ]] && [[ "$("$dir/bash" -c 'echo ${BASH_VERSINFO[0]}')" -ge 4 ]]; then
				PATH="$dir:$PATH"
				break
			fi
		done
		export PATH="$tmp/node_modules/.bin:$PATH"
		npm ci --silent
		go generate ./...
		./web/build.sh >/dev/null 2>&1 || true
		[[ -f web/static/js/main.mjs ]] || { echo "Anubis's web build failed" >&2; exit 1; }
		./xess/build.sh >/dev/null
		go build -trimpath -ldflags "-X github.com/TecharoHQ/anubis.Version=$version" -o "$BIN/anubis-web" ./cmd/anubis
	)
	rm -rf "$tmp"
fi
[[ -d "$HERE/node_modules" ]] || (cd "$HERE" && npm ci --silent)

mkdir -p "$OUT"
: >"$OUT/visits.jsonl"
pids=()
# ${pids[@]+...}: bash 3.2 calls an empty array unbound under set -u.
stop() { kill ${pids[@]+"${pids[@]}"} 2>/dev/null || true; wait 2>/dev/null || true; pids=(); }
trap stop EXIT
wait_for() { for _ in $(seq 50); do curl -s -o /dev/null "127.0.0.1:$1" && return; sleep 0.1; done; echo "port $1 never answered" >&2; exit 1; }

cd "$BENCH"
for difficulty in 1 4; do
	policy="$OUT/minimal-d$difficulty.yaml"
	sed "s/difficulty: 1/difficulty: $difficulty/" policies/minimal.yaml >"$policy"
	"$BIN/backend" -addr 127.0.0.1:18080 >/dev/null 2>&1 & pids+=($!)
	env BIND=127.0.0.1:18923 BIND_NETWORK=tcp METRICS_BIND=127.0.0.1:19090 TARGET=http://127.0.0.1:18080 \
		DIFFICULTY="$difficulty" POLICY_FNAME="$policy" CHALLENGE_SECRET="$SEED_B64" \
		JWT_RESTRICTION_HEADER=X-Real-IP USE_REMOTE_ADDRESS=false XFF_STRIP_PRIVATE=false \
		COOKIE_SECURE=false RUST_LOG=off "$ROOT/target/release/blackwall" >/dev/null 2>&1 & pids+=($!)
	"$BIN/anubis-web" -bind 127.0.0.1:28923 -bind-network tcp -metrics-bind 127.0.0.1:29090 \
		-target http://127.0.0.1:18080 -difficulty "$difficulty" -policy-fname "$policy" \
		-ed25519-private-key-hex "$SEED_HEX" -jwt-restriction-header X-Real-IP \
		-use-remote-address=false -xff-strip-private=false -cookie-secure=false \
		-cookie-partitioned=false -slog-level ERROR+4 >/dev/null 2>&1 & pids+=($!)
	for port in 18080 18923 28923; do wait_for $port; done
	node "$HERE/visit.mjs" "$difficulty" blackwall=http://127.0.0.1:18923/ anubis=http://127.0.0.1:28923/ >>"$OUT/visits.jsonl"
	stop
done
echo "wrote $OUT/visits.jsonl"
