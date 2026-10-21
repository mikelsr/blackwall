#!/usr/bin/env bash
# Builds everything the benchmark needs into bench/bin:
#   blackwall (release), anubis, loadgen, backend.
set -euo pipefail

BENCH_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$BENCH_DIR")"
ANUBIS_DIR="$BENCH_DIR/anubis"
BIN="$BENCH_DIR/bin"
mkdir -p "$BIN"

echo "==> blackwall (release)"
(cd "$ROOT" && cargo build --release -p cli --bin blackwall)
cp "$ROOT/target/release/blackwall" "$BIN/blackwall"

echo "==> anubis"
# The Go binary embeds generated frontend assets. Generate them once if they
# are missing (needs npm and network access the first time).
if [[ ! -f "$ANUBIS_DIR/lib/challenge/preact/static/app.js" ]]; then
	echo "    generated assets missing, running 'make assets' in $ANUBIS_DIR"
	# Anubis' build scripts need bash >= 4 (globstar); macOS ships 3.2.
	if [[ "$(bash -c 'echo ${BASH_VERSINFO[0]}')" -lt 4 ]]; then
		for dir in /opt/homebrew/bin /usr/local/bin; do
			if [[ -x "$dir/bash" ]] && [[ "$("$dir/bash" -c 'echo ${BASH_VERSINFO[0]}')" -ge 4 ]]; then
				export PATH="$dir:$PATH"
				break
			fi
		done
	fi
	# Its Makefile puts node_modules/.bin on PATH via $(PWD), so run it from
	# inside the directory rather than with make -C.
	(cd "$ANUBIS_DIR" && make assets)
fi
(cd "$ANUBIS_DIR" && go build -trimpath -o "$BIN/anubis" ./cmd/anubis)

echo "==> loadgen + backend"
(cd "$BENCH_DIR" && go build -trimpath -o "$BIN/loadgen" ./loadgen)
(cd "$BENCH_DIR" && go build -trimpath -o "$BIN/backend" ./backend)

echo "built: $(ls "$BIN" | tr '\n' ' ')"
