# Running the benchmark

How to run the full benchmark on this Mac and on the remote Arch Linux box
(i7-6700K, 32 GB) over SSH. For what is measured and why, see
[REPORT.md](REPORT.md).

## How long it takes

Each sweep step is `WARMUP + DURATION + pause` ≈ 20 s with the defaults. A
sweep usually takes 6–10 steps (doubling, then 2 bisection steps).

| run | rough time per repeat |
|---|---|
| `MODE=sweep`, all defaults (~50 sweeps + `conns`) | 2–3 h |
| `MODE=fixed`, all defaults (one step each) | ~25 min |

`REPEATS=3` triples it. To test the setup first, run something small:

```sh
SERVERS="blackwall anubis" POLICIES=minimal SCENARIOS="direct allow" \
  BODY_SIZES=1024 DURATION=3s WARMUP=1s REFINE=0 bench/run.sh
```

---

## 1. On this Mac (M4 Pro, 10P + 4E cores)

macOS can't pin processes to cores, and the scheduler may put the proxy on an
efficiency core. Numbers here are good for development and relative
comparisons. Use the Linux box for anything you publish.

### Prepare

- Plug in the charger, turn Low Power Mode off, and close heavy apps (browsers,
  Docker, indexing).
- Use `caffeinate` (below) so the machine doesn't sleep.

### Build (once, or after changing code)

```sh
git submodule update --init   # once: Anubis's source, at the tested commit
bench/build.sh
```

The first build generates Anubis's frontend assets (`make assets` in
`bench/anubis`). That needs network access and npm. It's already done on
this machine, so later builds skip it.

### Run

From the repository root:

```sh
# Full sweep: max sustainable rate for every scenario, policy and body size.
caffeinate -dims env REPEATS=3 bench/run.sh

# Fixed rate: CPU cost per request at the same load for both servers.
# Choose rates around half of the slower server's max from the sweep.
caffeinate -dims env MODE=fixed REPEATS=3 FIXED_RATE=8000 FIXED_RATE_LARGE=400 \
  FIXED_RATE_SOLVE=4000 bench/run.sh
```

Defaults on 14 cores: proxy 2 cores (`CORES=2`), backend 2, load generator 10.
Keep `CONNS` at 15000 or below on macOS: one source address only has about
16k ephemeral ports (49152–65535). The default `1000 5000 10000` is fine.

Results go to `bench/results/<timestamp>-<mode>/summary.md`.

---

## 2. On the remote Linux box over SSH

`bench/remote.sh` copies the working tree with rsync, builds on the remote and
runs the benchmark in a detached `tmux` session, so it keeps going if SSH
drops. The commands below use `arch` as the SSH host; use whatever alias you
have in `~/.ssh/config`.

### Why rsync and not git

The generated assets (`challenge-wasm/pkg`, Anubis's `static/` files) are
gitignored, so a clone would lack them. `sync` copies them, with the
`bench/anubis` submodule, from this machine, so the remote only needs Rust and Go. It doesn't need npm,
wasm-pack or binaryen. Build output (`target/`, `node_modules/`, `bench/bin`,
`bench/results`) is excluded, so a re-sync never wipes remote results.

### Prerequisites on the Arch box (once)

```sh
sudo pacman -S --needed base-devel rustup go tmux rsync curl util-linux cpupower
rustup default stable
rustup update stable   # dependencies need rustc >= 1.89; an old stable fails the build
```

`util-linux` provides `taskset` and `lscpu`. Go downloads Anubis's modules on
the first build, so the box needs internet access then. If its `go` is older
than Anubis's `go.mod` requirement (1.26.3), Go fetches the right toolchain
automatically.

### Core layout for the i7-6700K

The 6700K has 4 physical cores with 2 threads each (8 logical CPUs). Two
logical CPUs on the same physical core share execution units. If the proxy and
the load generator land on siblings, they slow each other down and the numbers
are meaningless. Check the topology:

```sh
ssh arch lscpu -e=CPU,CORE
```

The usual numbering pairs CPU *n* with CPU *n+4* (0/4, 1/5, 2/6, 3/7). If yours
differs, adjust the lists below.

**Recommended: proxy on one physical core**

| role | CPUs | physical core |
|---|---|---|
| proxy under test | `0` (sibling `4` left idle) | 0 |
| backend | `1,5` | 1 |
| load generator | `2,3,6,7` | 2 and 3 |

```
SERVER_CPUS=0 BACKEND_CPUS=1,5 LOADGEN_CPUS=2,3,6,7
```

Setting `*_CPUS` derives the core counts from the lists (`GOMAXPROCS` /
`TOKIO_WORKER_THREADS` = 1 for the proxy). The main results are therefore
**per core**.

For a proxy on two physical cores (or on two cores with both threads), the
rig gets the other two. The best split of them is the backend on one core's
two threads and the load generator on the other's: `direct` reaches ~62,000
req/s, against ~34,000 with a single backend thread (`REPORT.md`,
"Validation"). Check the `direct` baseline against the proxy's numbers (see "Is
the harness the bottleneck?"):

```
SERVER_CPUS=0,1 BACKEND_CPUS=2,6 LOADGEN_CPUS=3,7      # 4 and 5 left idle
SERVER_CPUS=0,1,4,5 BACKEND_CPUS=2,6 LOADGEN_CPUS=3,7  # both threads
```

`experiments/multicore.sh` runs these layouts and one core with both threads.

### System tuning (root; revert afterwards)

Run these on the box before a run:

```sh
# Fixed clock speed, so results don't depend on turbo or temperature.
sudo cpupower frequency-set -g performance
echo 1 | sudo tee /sys/devices/system/cpu/intel_pstate/no_turbo

# More ephemeral ports. Matters for Anubis, which reconnects upstream under load.
sudo sysctl -w net.ipv4.ip_local_port_range="1024 65535"
# The wider range now covers the bench's listen ports. Reserve them so that
# outgoing connections can't take them (run.sh refuses to start otherwise).
sudo sysctl -w net.ipv4.ip_local_reserved_ports=18080,18923,19090,28923,29090

# Optional: drop the desktop and other services for a quieter machine.
# sudo systemctl isolate multi-user.target
```

Disabling turbo lowers absolute numbers but makes repeats consistent.
`run.sh` records the governor, turbo, SMT, port-range and conntrack settings in `env.txt`, along with the synced commit (`-dirty` if tracked files had local changes)
so you can tell runs apart. Check temperatures with `sensors` if a run looks
odd.

The open-file limit needs no change: Arch's default hard limit (524288) is
plenty, and `run.sh` raises the soft limit itself.

To revert, reboot (none of these settings persist unless `cpupower.service` or a
`sysctl.d` file sets them), or:

```sh
sudo cpupower frequency-set -g powersave   # or schedutil, whatever you had
echo 0 | sudo tee /sys/devices/system/cpu/intel_pstate/no_turbo
sudo sysctl -w net.ipv4.ip_local_port_range="32768 60999"
sudo sysctl -w net.ipv4.ip_local_reserved_ports=""
```

### Run

```sh
bench/remote.sh arch sync       # copy the tree (repeat after local changes)
bench/remote.sh arch check      # toolchain, CPU topology, limits, generated assets
bench/remote.sh arch build      # bench/build.sh on the remote

# Full sweep, 3 repeats, pinned, with large connection counts.
bench/remote.sh arch run REPEATS=3 \
  SERVER_CPUS=0 BACKEND_CPUS=1,5 LOADGEN_CPUS=2,3,6,7 \
  CONNS="10000 50000 100000"

bench/remote.sh arch status     # last 40 lines of output
bench/remote.sh arch attach     # live view; detach with Ctrl-b d
bench/remote.sh arch fetch      # results -> bench/results/remote-arch/
```

After the sweep, run the fixed-rate pass with rates around half of the slower
server's max from the sweep summary:

```sh
bench/remote.sh arch run MODE=fixed REPEATS=3 \
  SERVER_CPUS=0 BACKEND_CPUS=1,5 LOADGEN_CPUS=2,3,6,7 \
  FIXED_RATE=4000 FIXED_RATE_LARGE=200 FIXED_RATE_SOLVE=2000 SCENARIOS="allow deny flood solve pass upload"
```

To see what each part of Anubis costs, repeat the fixed-rate pass with
profiles. Use the same rates, so the profiles line up with its CPU µs/op, and
longer windows for more samples. Then split them locally (needs Go):

```sh
bench/remote.sh arch run MODE=fixed PROFILE=anubis DURATION=60s \
  SERVER_CPUS=0 BACKEND_CPUS=1,5 LOADGEN_CPUS=2,3,6,7 BODY_SIZES=1024 \
  FIXED_RATE=4000 FIXED_RATE_SOLVE=2000 SCENARIOS="allow deny flood solve pass"
bench/remote.sh arch fetch
bench/profile-split.sh bench/results/remote-arch/<run>/profiles/*
```

Each `status` call (or any SSH session) runs on unpinned CPUs, possibly the
proxy's, and can show up in tail latency. Check sparingly during a run, and
leave the box otherwise idle.

Any `run.sh` variable can be passed as `VAR=value`. Only one benchmark runs at
a time: `run` refuses to start while the tmux session exists, and
`bench/remote.sh arch stop` kills it.

On Linux, `conns` spreads connections over 16 loopback source addresses, so
100k connections work. Memory isn't a concern on 32 GB: at ~30 KB per
connection, 100k is about 3 GB per process.

### Without remote.sh

The same steps by hand:

```sh
rsync -az --delete --exclude=.git --exclude=/target/ --exclude=/bench/bin/ \
  --exclude=/bench/results/ --exclude=/bench/anubis/target/ \
  --exclude=/bench/anubis/node_modules/ --exclude=/bench/anubis/var/ \
  ./ arch:Code/github.com/mikelsr/blackwall/
ssh arch
cd Code/github.com/mikelsr/blackwall
bench/build.sh
tmux new -s b7l-bench
REPEATS=3 SERVER_CPUS=0 BACKEND_CPUS=1,5 LOADGEN_CPUS=2,3,6,7 bench/run.sh
```

---

## Settings

All are environment variables for `run.sh`:

| variable | default | |
|---|---|---|
| `MODE` | `sweep` | `sweep` finds the max rate; `fixed` runs `FIXED_RATE` only |
| `SERVERS` | `blackwall anubis` | |
| `POLICIES` | `minimal realistic` | file names in `policies/` |
| `SCENARIOS` | `direct allow deny flood solve pass upload conns` | |
| `BODY_SIZES` | `1024 65536 1048576` | bytes; for `direct`, `allow`, `pass`, `upload` |
| `CONNS` | `1000 5000 10000` | idle connection counts for `conns` (see "Getting trustworthy numbers") |
| `CONNS_SETTLE` | `3s` | wait before reading RSS in `conns` |
| `CORES` | `2` | cores for the proxy under test |
| `BACKEND_CORES` | `2` | |
| `LOADGEN_CORES` | the rest | |
| `SERVER_CPUS` / `BACKEND_CPUS` / `LOADGEN_CPUS` | | Linux: explicit `taskset` lists, override the counts (keeps SMT siblings apart) |
| `RATES` | `500,…,64000` | sweep rates; `RATES_FLOOD=…` etc. override per scenario |
| `RATES_LARGE` | `50,…,6400` | sweep rates for bodies ≥ 1 MiB |
| `FIXED_RATE` | `2000` | `FIXED_RATE_SOLVE=…` etc. override per scenario |
| `FIXED_RATE_LARGE` | `200` | fixed rate for bodies ≥ 1 MiB |
| `DURATION` / `WARMUP` | `15s` / `3s` | per rate step |
| `SLO` | `10ms` | p99 objective |
| `REPEATS` | `1` | the published runs used 3; the summary reports medians |
| `REFINE` | `2` | bisection steps after the first failing rate |
| `WORKERS` | `1024` | maximum in-flight operations |
| `TOKENS` | `256` | auth cookies minted for `pass` |
| `PROFILE` | | `anubis` or `blackwall` (with `MODE=fixed`): save that server's CPU profile per cell in `profiles/` (see below) |
| `COUNTERS` | | `1` (with `MODE=fixed`, Linux with `perf`): count the server's user-space cycles and instructions over the same window as `PROFILE`, per cell, into `counters/` (`perf stat` CSV), plus `.cpus.txt`: snapshots before and after of each CPU's time and sleep states, and each server thread's CPU time, last CPU, migrations and context switches |
| `SERVER_ENV` | | extra environment for the server under test, for diagnostics (e.g. `SERVERS=anubis SERVER_ENV=GOGC=off`). Not for published numbers: both servers run with their defaults |
| `FLOOD_RATE` | | run a `flood` at this rate, on its own connections and client addresses, during every proxy cell (not `direct` or `conns`). Latency and errors then cover the cell's own requests only, so `MODE=fixed FIXED_RATE=100 SCENARIOS="pass solve"` measures what real visitors see during a bot flood. CPU per request counts the flood's requests too |
| `LOADGEN` | `bin/loadgen` | load generator binary, e.g. an older build to compare against |

Every (policy, scenario, server) combination gets a freshly started server, so
the challenge store and memory never carry over between runs.

The load generator can also be used on its own:

```sh
bench/bin/loadgen run -flavor blackwall -target http://127.0.0.1:18923 \
  -scenario flood -rates 2000,4000,8000 -pid <server pid> -out /tmp/r.jsonl
bench/bin/loadgen summary /tmp/r.jsonl
```

---

## Reading and comparing results

Each run directory contains:

- `summary.md`: the tables.
- `results.jsonl`: one JSON line per measured step.
- `console.txt`: the live output.
- `env.txt`: machine, settings and versions.
- `logs/`: server output (empty unless something failed, since logging is off).

Re-summarise one or more runs from the same machine with:

```sh
bench/bin/loadgen summary bench/results/<run>/results.jsonl
```

Don't merge results from different machines into one summary: rows are keyed
by server name, so the Mac and the Linux box would be mixed together.

### Summary columns

The CPU and RSS numbers come from the proxy process only (the backend is a
separate process). So for the proxied scenarios they are pure proxy cost. The
summary rescales them into deployment terms:

- **cores/10k**: proxy cores needed per 10,000 req/s (`cpu µs/op / 100`).
- **cpu ms/GB**: proxy CPU per GB of body moved, for bodies of 64 KiB and
  up. Shows how efficiently data is copied through.
- **RSS vs body size**: flat RSS as bodies grow means the proxy streams;
  growth means it buffers.
- **up/1k**: upstream connections the proxy opened per 1,000 requests, read
  from the backend's accepted-connection counter (`/__bench/stats`). Near 0
  means upstream connections are reused. High values cost CPU and ephemeral
  ports, and explain CPU differences.
- **KB/conn** (`conns`): `(RSS with N idle connections − baseline) / N`.
  Each connection first completes one request on the DENY path, so it sits in
  the keep-alive state without holding an upstream connection. The run also
  probes the latency of new requests while the N connections are open, and
  re-uses a sample of them at the end to confirm the server didn't close them.
  Each N gets a fresh server.

### Known behaviours that show up in results

- **Both challenge stores are capped and drop the oldest entry when full.**
  Both keep 10,000 pending challenges for 30 min. Under `flood`, RSS rises
  until the store is full (~2.3 MB of challenges for Blackwall), then stays
  flat.
- **Anubis's upstream transport keeps only 2 idle connections per host** (Go's
  `http.DefaultTransport` default). Under concurrency it opens and closes
  backend connections, which costs CPU and can run out of ephemeral ports in
  `allow`/`pass` at high rates (especially on macOS). That's how Anubis ships,
  so it's measured as-is. `up/1k` makes it visible: in a smoke run Anubis
  opened 89 upstream connections per 1,000 requests at 16k req/s and returned
  502s at 24k, while Blackwall stayed near 0.
- **Both servers close idle client connections after 2 minutes.** `conns`
  finishes well within that window (100k connections open in ~4–8 s), but keep
  it in mind if you raise `CONNS_SETTLE` or the counts a lot.
- Blackwall skips GeoIP/ASN rules. Anubis skips them without a GeoIP database.
  Neither evaluates them in the `realistic` policy.

## Getting trustworthy numbers

- **Use Linux.** `run.sh` pins the server, backend and load generator to
  separate cores with `taskset` when it's available. macOS can't pin, so results
  there are fine for development but noisy.
- **Check the bottleneck isn't the harness.** Compare each proxy result with
  the `direct` baseline at the same body size. If a proxy reaches more than
  ~70% of the backend's own max rate, the backend or the load generator is the
  limit: give them more cores or lower `CORES`. Also watch the load generator
  in `top`: at 100% of its CPUs, its numbers are capped. Large bodies reach
  several GB/s over loopback, so run `direct` at the same sizes.
- **Connection counts are limited by ephemeral ports.** One source address can
  open about 16k connections to one destination on macOS and about 28k on
  Linux. On Linux, `conns` spreads connections over 16 loopback source
  addresses (`127.0.0.1`–`127.0.0.16`), so `CONNS="10000 50000 100000"` works
  if `ulimit -n` allows it. On macOS, stay at 15k or below.
- **Repeat.** `REPEATS=3` or more, and compare medians. Differences smaller than the
  spread between repeats aren't real.
- **Explain the gap with profiles.** For Anubis, `MODE=fixed PROFILE=anubis`
  saves a CPU profile of each cell's measured window: Go's profiler on Linux,
  Apple's Time Profiler (`xctrace`) on macOS, where Go's profiler over-counts
  syscalls. `bench/profile-split.sh <run>/profiles/*` splits each profile into
  what each part of Anubis costs, extras Blackwall lacks first. On macOS, keep
  Anubis busy (~70% of a core or more): Time Profiler misses short bursts on an
  idle core. For Blackwall, `PROFILE=blackwall` (Linux) records each cell with
  `perf` and writes a report of where the time goes next to it (`*.txt`).
  `profile-split.sh` splits `*.perf.data` into the same parts as Anubis's; it
  needs call stacks, so profile a build with frame pointers
  (`RUSTFLAGS="-C force-frame-pointers=yes"`). perf reads symbols from the
  binary that ran, so split on the same machine and before rebuilding.

## Troubleshooting

| symptom | cause / fix |
|---|---|
| `preflight failed` | Server misconfigured or failed to start. Check `logs/` in the run directory. |
| `server exited during startup (exit 1)` with an empty log | Usually a bind failure: logging is off, so Blackwall's metrics-bind error is swallowed. Check that nothing holds the bench ports (`ss -tanp \| grep -E ':(18080\|18923\|19090\|28923\|29090)\b'`). |
| `listen ports ... are inside ip_local_port_range` | Reserve them with the `ip_local_reserved_ports` command it prints (see "System tuning"). |
| `missing bench/bin/...` | Run `bench/build.sh` (or `bench/remote.sh HOST build`). |
| `pattern static/app.js: no matching files` | Anubis assets missing. Re-run `sync` from this Mac, or install npm, binaryen and the `wasm32-unknown-unknown` target on the remote so `build.sh` can generate them. |
| `can't assign requested address` | Out of ephemeral ports. Widen `ip_local_port_range` (Linux) or lower rates/`CONNS` (macOS). |
| Anubis `502` at high rates in `allow`/`pass` | Its upstream transport keeps 2 idle connections per host and reconnects under load (see `up/1k`). That's real Anubis behaviour, not a harness bug. |
| `too many open files` | Raise the hard limit (`ulimit -Hn`) for your user; `run.sh` can only raise the soft limit up to it. |
| `conns` stops early with `dial ...: i/o timeout` | The kernel dropped SYNs because the firewall's connection-tracking table was full (`journalctl -k \| grep conntrack`). Closed connections keep their slot for 120 s, so a large level right after another can overflow it. `run.sh` now waits for free slots before each level. |
| `conns` shows `alive` below 100% | The server closed idle connections. Both servers do so after 2 minutes; keep `CONNS_SETTLE` short. |
| Large run-to-run variance | Check `env.txt` for governor and turbo, check thermals, stop background services. |
