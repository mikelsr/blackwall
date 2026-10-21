#!/usr/bin/env bash
# Splits CPU profiles (from run.sh PROFILE=anubis or PROFILE=blackwall) into
# what each part of the server costs. Prints one markdown table per profile.
#
#   bench/profile-split.sh bench/results/<run>/profiles/*.{pprof,trace,perf.data}
#
# Reads Go profiles (.pprof, Linux), Time Profiler recordings (.trace, macOS;
# needs Xcode and python3) and perf recordings (.perf.data, Linux; needs perf
# and the binary that was recorded, so run it on the machine that ran them).
#
# Every sample goes to the first bucket, in the order below, whose pattern
# matches any frame of its stack. Kinds:
#   extra    work Blackwall doesn't do (per-request metrics and logger,
#            translations, honeypot, HTML deny page)
#   config   opening upstream connections an idle pool would have reused
#            (Go's default keeps 2)
#   core     work both do
#   runtime  GC and scheduler; background GC can't be traced to the code
#            that allocated
# Extras come first, so their cost includes everything they call (allocation,
# syscalls).
#
# Blackwall's parts use the same names where both do the same work.
#
# With jq and the run's results.jsonl next to profiles/, it also prints each
# part in µs per request and, for Anubis, its cost without its extras and
# reconnects, and Blackwall's cost in the same cell. perf samples Blackwall's
# user space only, so its parts split user time and kernel time is one line.
set -euo pipefail

if (($# == 0)); then
	echo "usage: $0 profile.pprof|profile.trace|profile.perf.data..." >&2
	exit 1
fi

# name|kind|pattern (ERE, matched against "frame;frame;...", root first)
ANUBIS_BUCKETS='metrics (Prometheus)|extra|prometheus
request logger (slog)|extra|log/slog
localization|extra|anubis/lib/localization|golang\.org/x/text|go-i18n
threshold identity (JSON + hash per request)|core|Server\)\.check;([^;]*;)*encoding/json|FastHash
honeypot network weight|extra|honeypot
HTML deny page, cookie clearing|extra|respondWithStatus|respondWithError|ClearCookie
new upstream connections|config|Transport\)\.dialConn(;|$)|net\.\(\*Dialer\)|persistConn\)\.close|connect$
policy rules (CEL, regex)|core|Server\)\.check;|cel-go|anubis/lib/policy
JWT (Ed25519)|core|golang-jwt|crypto/ed25519
challenge (issue, store, verify)|core|anubis/lib/challenge|anubis/lib/store|crypto/sha256|PassChallenge
challenge page (templates, gzip)|core|a-h/templ|anubis/web|compress/
reverse proxy|core|httputil|net/http\.\(\*Transport\)|persistConn
other Anubis request handling|core|TecharoHQ/anubis
HTTP server|core|net/http\.
GC (background)|runtime|gcBgMarkWorker|bgsweep|bgscavenge|gcDrain
runtime (scheduler, netpoll)|runtime|runtime\.'

# Rust frames name their generic parameters (a hyper frame can mention
# proxy::handler), so these match the start of a frame only, with one
# exception: each backend connection runs as its own task, whose frames start
# with futures_util or hyper::proto and name hyper::client::conn or
# dispatch::Client only in their parameters. Every client connection runs
# under proxy::server, so that module is not request handling; proxy::client
# is the client's address.
BLACKWALL_BUCKETS='new upstream connections|config|(^|;)<?hyper_util::client::legacy::connect
policy rules (CEL, regex)|core|(^|;)<?(shared::policy|cel::|regex|ipnet)
JWT (Ed25519)|core|(^|;)<?(jsonwebtoken|ed25519|curve25519|proxy::auth)
challenge (issue, store, verify)|core|(^|;)<?(shared::challenge|shared::store|challenge::|sha2::)
challenge page (templates, gzip)|core|(^|;)<?(proxy::handler::serve_challenge_page|flate2|miniz_oxide)
reverse proxy|core|(^|;)<?(hyper_util::client|hyper::client|proxy::handler_proxy)|hyper::client::conn|dispatch::Client<
other Blackwall request handling|core|(^|;)<?(proxy::(handler|headers|embed|upgrade|client)|shared::)
HTTP server|core|(^|;)<?(hyper::|hyper_util::|axum|httparse|http::|tower)
runtime (scheduler, netpoll)|runtime|(^|;)<?(tokio::|mio::)'

# Time Profiler XML -> folded stacks. Frames and backtraces are written once
# with an id and referenced by it afterwards.
FOLD_XCTRACE='
import sys, xml.etree.ElementTree as ET
frames, weights, stacks, out = {}, {}, {}, {}
def ref(el):
    return el.get("id") or el.get("ref")
for _, el in ET.iterparse(sys.stdin.buffer):
    if el.tag == "frame" and el.get("id"):
        frames[el.get("id")] = el.get("name") or el.get("addr", "?")
    elif el.tag == "weight" and el.get("id"):
        weights[el.get("id")] = int(el.text)
    elif el.tag == "tagged-backtrace" and el.get("id"):
        stacks[el.get("id")] = ";".join(frames[ref(f)] for f in reversed(el.findall("frame")))
    elif el.tag == "row":
        w, bt = el.find("weight"), el.find("tagged-backtrace")
        if w is not None and bt is not None:
            stack = stacks[ref(bt)]
            out[stack] = out.get(stack, 0) + weights[ref(w)]
        el.clear()
for stack, ns in out.items():
    print(stack, ns)
'

# Prints "frame;frame;... nanoseconds" lines, root first.
fold() {
	case "$1" in
	*.trace)
		xcrun xctrace export --input "$1" \
			--xpath '/trace-toc/run[@number="1"]/data/table[@schema="time-profile"]' 2>/dev/null |
			python3 -I -c "$FOLD_XCTRACE"
		;;
	*.pprof)
		go tool pprof -traces "$1" 2>/dev/null | awk '
			function ns(v) {
				if (v ~ /ms$/) return v * 1e6
				if (v ~ /us$/) return v * 1e3
				if (v ~ /ns$/) return v + 0
				return v * 1e9
			}
			function flush(   i, stack) {
				if (nframes == 0) return
				stack = frames[nframes]
				for (i = nframes - 1; i >= 1; i--) stack = stack ";" frames[i]
				print stack, value
				nframes = 0
			}
			/^-+\+-+$/ { flush(); next }
			/^ +[0-9.]+[a-z]+ +/ { flush(); value = ns($1); $1 = "" }
			value != "" && NF {
				sub(/^ +/, "")
				sub(/ \(inline\)$/, "")
				frames[++nframes] = $0
			}
			END { flush() }'
		;;
	*.perf.data)
		# Weighted by cycles: perf varies the period to keep its sampling
		# rate. Each sample is a line with its thread name and period, then
		# its frames, leaf first.
		perf script -i "$1" -F comm,period,ip,sym 2>/dev/null | awk '
			function flush(   i, stack) {
				if (nframes == 0) return
				stack = frames[nframes]
				for (i = nframes - 1; i >= 1; i--) stack = stack ";" frames[i]
				print stack, period
				nframes = 0
			}
			/^[^ \t]/ { flush(); period = $NF; next }
			NF >= 2 {
				sub(/^[ \t]*[0-9a-f]+ /, "")
				frames[++nframes] = $0
			}
			END { flush() }'
		;;
	*)
		echo "unknown profile type: $1" >&2
		return 1
		;;
	esac
}

# A cost of one cell (default cpu_us_per_op), median over repeats; empty if
# unknown.
cell_cpu() {
	local results="$1" server="$2" policy="$3" scenario="$4" size="$5" field="${6:-cpu_us_per_op}"
	[[ -f "$results" ]] && command -v jq >/dev/null || return 0
	jq -rs --arg s "$server" --arg p "$policy" --arg c "$scenario" --argjson b "$size" --arg f "$field" '
		[.[] | select(.server == $s and .policy == $p and .scenario == $c and (.size_bytes // 0) == $b) | .[$f] | select(. != null)]
		| sort | if length == 0 then "" else .[length / 2 | floor] end' "$results"
}

for profile in "$@"; do
	echo "### $(basename "$profile")"
	echo
	cpu="" kernel="" blackwall_cpu="" unit="s"
	name="$(basename "$profile")"
	name="${name%.perf.data}"
	name="${name%.*}"
	buckets="$ANUBIS_BUCKETS" server=anubis
	if [[ "$name" == blackwall-* ]]; then
		buckets="$BLACKWALL_BUCKETS" server=blackwall
	fi
	if [[ "$profile" == *.perf.data ]]; then
		unit="G cycles"
	fi
	if [[ "$name" =~ ^[a-z]+-(.+)-([a-z]+)-([0-9]+)-r[0-9]+$ ]]; then
		results="$(dirname "$(dirname "$profile")")/results.jsonl"
		cell=("$results" "$server" "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}")
		if [[ "$server" == anubis ]]; then
			cpu="$(cell_cpu "${cell[@]}")"
			cell[1]=blackwall
			blackwall_cpu="$(cell_cpu "${cell[@]}")"
		else
			# perf samples user space only: split user time, show kernel time apart.
			cpu="$(cell_cpu "${cell[@]}" user_us_per_op)"
			kernel="$(cell_cpu "${cell[@]}" sys_us_per_op)"
		fi
	fi
	fold "$profile" | BUCKETS="$buckets" awk -v server="$server" -v cpu="$cpu" -v kernel="$kernel" -v bw="$blackwall_cpu" -v unit="$unit" '
		BEGIN {
			n = split(ENVIRON["BUCKETS"], lines, "\n")
			for (i = 1; i <= n; i++) {
				split(lines[i], f, "|")
				name[i] = f[1]
				kind[i] = f[2]
				pat[i] = substr(lines[i], length(f[1]) + length(f[2]) + 3)
			}
			name[n + 1] = "other"
			kind[n + 1] = "-"
		}
		{
			value = $NF
			stack = $0
			sub(/ [0-9.e+]+$/, "", stack)
			b = n + 1
			for (i = 1; i <= n; i++) if (stack ~ pat[i]) { b = i; break }
			sum[b] += value
			total += value
		}
		END {
			if (total == 0) { print "no samples\n"; exit }
			printf "%.1f %s of samples\n\n", total / 1e9, unit
			print "| part | kind | % | µs/op |"
			print "|---|---|---|---|"
			for (i = 1; i <= n + 1; i++) {
				if (sum[i] == 0) continue
				share = sum[i] / total
				us = (cpu == "") ? "-" : sprintf("%.1f", share * cpu)
				printf "| %s | %s | %.1f | %s |\n", name[i], kind[i], 100 * share, us
				if (kind[i] == "extra" || kind[i] == "config") extra += share
				if (name[i] ~ /^GC/) gc = share
			}
			if (kernel != "") printf "| kernel (not sampled) | - | - | %.1f |\n", kernel
			print ""
			if (kernel != "") {
				printf "Blackwall %.1f µs/op: %.1f user, split above, and %.1f kernel.\n\n", cpu + kernel, cpu, kernel
			} else if (cpu != "") {
				printf "Anubis %.1f µs/op. Without extras and reconnects: %.1f (also without background GC: %.1f).", cpu, cpu * (1 - extra), cpu * (1 - extra - gc)
				if (bw != "") printf " Blackwall: %.1f.", bw
				print "\n"
			}
		}'
done
