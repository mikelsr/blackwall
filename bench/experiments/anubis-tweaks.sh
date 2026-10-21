#!/usr/bin/env bash
# Experiment, not the reference: how much of the gap would three small changes
# to Anubis close? Each was found by profiling Anubis on this box:
#   bufpool   httputil.ReverseProxy gets a BufferPool (it allocates a 32 KiB
#             copy buffer per response otherwise: about two thirds of the
#             bytes Anubis allocates per proxied request, so of its GC work)
#   idlepool  keep every idle backend connection (Go's default keeps 2 per host)
#   regex1    match each header regex once (HeaderMatchesChecker matches a
#             single-valued header twice: the value, then the "joined" values)
#   all       the three together
#   ship      the same copy of Anubis without patches (the reference)
# The patches (patches/*.patch) are applied to a copy of bench/anubis;
# bench/bin/anubis is restored afterwards. Fixed rates for CPU per request
# (plus page faults, context switches and read/write syscalls per request from
# /proc), sweeps for the max rate. Blackwall runs the fixed cells too, in the
# same session.
#
#   anubis-tweaks.sh                   build the variants, run everything
#   anubis-tweaks.sh rerun <run>...    rerun fixed runs by name (e.g.
#                                      fixed-ship-realistic-allow-750-r1),
#                                      keeping the originals as <run>-perturbed
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.." || exit 1
OUT=bench/results/anubis-tweaks
PATCHES=bench/experiments/patches
BIN=bench/bin

# build <name> [patch...]: bench/anubis with the patches applied, built
# as $OUT/bin/anubis-<name>.
build() {
	local name="$1" work
	shift
	work="$(mktemp -d)" || exit 1
	cp -a bench/anubis "$work/src" || exit 1
	# The submodule's .git file points into this repository, which the copy is
	# outside of; without it Go builds the copy as plain source, as on the remote.
	rm -f "$work/src/.git"
	for p in "$@"; do patch -sp1 -d "$work/src" <"$PATCHES/$p.patch" || exit 1; done
	(cd "$work/src" && go build -trimpath -o "$OLDPWD/$OUT/bin/anubis-$name" ./cmd/anubis) || exit 1
	rm -rf "$work"
}

export SERVER_CPUS=0 BACKEND_CPUS=1,5 LOADGEN_CPUS=2,3,6,7 BODY_SIZES=1024 REPEATS=1

# One line per second of each server process: seconds since start, then the
# process's cumulative minor faults, voluntary and involuntary context
# switches (all threads), read and write syscalls, and CPU ms.
sample() {
	local name="$1" pid="" t=0
	until pid="$(pgrep -x "$name")"; do sleep 0.1; done
	echo "t minflt vcsw nvcsw syscr syscw cpu_ms"
	while kill -0 "$pid" 2>/dev/null; do
		{
			awk '{printf "%s ", $10}' "/proc/$pid/stat"
			cat /proc/"$pid"/task/*/status | awk '/^voluntary_ctxt/ {v += $2} /^nonvoluntary_ctxt/ {n += $2} END {printf "%d %d ", v, n}'
			awk '/^syscr/ {r = $2} /^syscw/ {w = $2} END {printf "%s %s ", r, w}' "/proc/$pid/io"
			awk '{print ($14 + $15) * 10}' "/proc/$pid/stat"
		} 2>/dev/null | sed "s/^/$t /" || break
		t=$((t + 1))
		sleep 1
	done
}

# fixed <variant|blackwall> <policy> <scenario> <rate> <repeat>
fixed() {
	local v="$1" policy="$2" scenario="$3" rate="$4" r="$5" server=anubis
	[[ "$v" == blackwall ]] && server=blackwall
	[[ "$server" == anubis ]] && cp --remove-destination "$OUT/bin/anubis-$v" "$BIN/anubis"
	local dir="$OUT/fixed-$v-$policy-$scenario-$rate-r$r"
	echo "=== fixed $v $policy $scenario $rate r$r ($(date -u +%H:%M:%SZ))"
	taskset -c 1 bash -c "$(declare -f sample); sample $server" >"$dir.tsv" 2>&1 &
	local sampler=$!
	env SERVERS="$server" MODE=fixed DURATION=20s POLICIES="$policy" SCENARIOS="$scenario" \
		FIXED_RATE="$rate" OUT="$dir" bench/run.sh >"$dir.log" 2>&1
	wait "$sampler"
}

# sweep <variant> <policy> <scenario> <repeat>
sweep() {
	local v="$1" policy="$2" scenario="$3" r="$4"
	cp --remove-destination "$OUT/bin/anubis-$v" "$BIN/anubis"
	local dir="$OUT/sweep-$v-$policy-$scenario-r$r"
	echo "=== sweep $v $policy $scenario r$r ($(date -u +%H:%M:%SZ))"
	env SERVERS=anubis MODE=sweep POLICIES="$policy" SCENARIOS="$scenario" OUT="$dir" \
		bench/run.sh >"$dir.log" 2>&1
}

# Variant order alternates per repeat (forward, backward, forward).
order() {
	local r="$1"
	shift
	if ((r % 2)); then echo "$@"; else echo "$@" | tr ' ' '\n' | tac | tr '\n' ' '; fi
}

if [[ "${1:-}" == rerun ]]; then
	shift
	for run in "$@"; do
		[[ "$run" =~ ^fixed-([a-z0-9]+)-([a-z]+)-([a-z]+)-([0-9]+)-r([0-9]+)$ ]] || { echo "not a fixed run: $run" >&2; exit 1; }
		for f in "$OUT/$run" "$OUT/$run.tsv" "$OUT/$run.log"; do mv "$f" "${f/$run/$run-perturbed}"; done
		fixed "${BASH_REMATCH[@]:1}"
	done
	cp --remove-destination "$OUT/bin/anubis-ref" "$BIN/anubis"
	exit
fi

rm -rf "$OUT"
mkdir -p "$OUT/bin"
build ship
build bufpool bufpool
build idlepool idlepool
build regex1 regex1
build all bufpool idlepool regex1
cp --remove-destination "$BIN/anubis" "$OUT/bin/anubis-ref"
sha1sum "$OUT"/bin/* >"$OUT/bin/sha1.txt"

fixed_cells=("minimal allow 750" "realistic allow 750" "minimal pass 750" "realistic pass 750"
	"minimal allow 5000" "realistic allow 2000")
for r in 1 2 3; do
	for c in "${fixed_cells[@]}"; do
		read -r policy scenario rate <<<"$c"
		variants="ship bufpool idlepool regex1 all blackwall"
		[[ "$policy" == minimal ]] && variants="ship bufpool idlepool all blackwall"
		for v in $(order "$r" $variants); do fixed "$v" "$policy" "$scenario" "$rate" "$r"; done
	done
done

for r in 1 2 3; do
	for c in "minimal allow" "realistic allow" "minimal pass" "realistic pass"; do
		read -r policy scenario <<<"$c"
		variants="ship bufpool idlepool regex1 all"
		[[ "$policy" == minimal ]] && variants="ship bufpool idlepool all"
		for v in $(order "$r" $variants); do sweep "$v" "$policy" "$scenario" "$r"; done
	done
done

cp --remove-destination "$OUT/bin/anubis-ref" "$BIN/anubis"
echo "[anubis-tweaks finished]"
