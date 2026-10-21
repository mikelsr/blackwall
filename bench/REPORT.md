# Blackwall vs Anubis: report

> [!NOTE]
> Written by an AI (Claude) from the benchmark's working notes, and checked against the raw results. The article ["Benchmarking Blackwall Against Anubis"](https://mikelsr.github.io/posts/benchmarking-blackwall-against-anubis/) tells the same story for readers; this file is the reference behind it: how it was measured, how the measurements were checked, and what came out.

Every section names the script that produced it (`experiments/` unless it says `run.sh`) and the folder its raw results went to under `bench/results/`. Raw results aren't in the repository; the numbers the article's graphs use are in the blog's `src/assets/graphs/articles/2026-10-21/data.json`, which `blogdata/` builds from them.

## In short

- **Capacity:** on one core, Blackwall serves 1.25 to 8 times Anubis's requests per second before its slowest 1% take over 10 ms. Most of it comes from cheaper requests, and the rest from using more of the core before the tail grows.
- **CPU at the same load:** Blackwall uses 0.29 to 0.79 of Anubis's CPU per request.
- **Why:** with Anubis's stock rules, most of the gap is Go's regex engine (~140 µs of Anubis's ~160 µs of rules per request, against ~5 µs). Anubis's tail grows early from three causes that feed each other: garbage collection, reconnecting to the backend (it keeps only 2 idle connections), and plain CPU per request.
- **Anubis with three small patches** (a buffer pool, more idle connections, one regex pass instead of two) halves the capacity gap with the stock rules (7× → 3.5×). Blackwall stays ahead.
- **Memory:** Blackwall idles at ~16 MB against ~60, and holds an idle connection in half the memory. After a burst of 1 MiB bodies, Anubis gives memory back within ~2 minutes and Blackwall keeps it.
- **Where Anubis is better:** it does far more (translations, metrics, other stores, a full HTML deny page), bounds memory per request more tightly by default, and returns memory after a burst.

## 1. Setup

| | |
|---|---|
| Blackwall | aebdca3 plus a7c604f, release build (`bench/bin/blackwall`) |
| Anubis | 1.28.1 plus ten commits of `main` (207f9eb8), unpatched, the `bench/anubis` submodule |
| Machine | "kelpie": Intel i7-6700K (4 cores, 8 threads), 32 GB, Arch Linux. Performance governor, turbo off, wide ephemeral port range with the bench's ports reserved (`RUNNING.md`) |
| Layout | server on CPU 0 with its SMT sibling (4) idle; backend on 1,5; load generator on 2,3,6,7. One scheduler thread in the server (`GOMAXPROCS=1`, `TOKIO_WORKER_THREADS=1`) |
| Network | loopback, plain HTTP/1.1 |
| Repeats | 3, reported as medians. Fixed-rate windows 15 s, sweep steps 15 s (8 s in the vCPU runs, see "Validation") |

The browser test (section 4.7) ran on an Apple M4 Pro instead.

## 2. Method

### Scenarios

| scenario | one operation | why it matters |
|---|---|---|
| `direct` | GET to the backend, no proxy | the rig's own limit; no proxy can beat it |
| `allow` | GET matching an ALLOW rule, proxied | policy and proxy cost |
| `deny` | GET matching a DENY rule, answered 403 | the cheapest rejection |
| `flood` | GET matching CHALLENGE, never solved, a new IP per request | what scrapers do |
| `solve` | challenge page, solve, `pass-challenge`, redirect with a cookie | completed verifications |
| `pass` | GET matching CHALLENGE with a valid cookie, proxied | a returning visitor |
| `upload` | POST with a body to an ALLOW path, proxied | request-body streaming |
| `conns` | hold N idle keep-alive connections | memory per connection |

`direct`, `allow`, `pass` and `upload` run with 1 KiB, 64 KiB and 1 MiB bodies. Two policies (`policies/`): `minimal` (allow, deny, catch-all challenge) isolates the servers; `realistic` imports each server's stock rules, the same 43 for both (41 evaluated: neither has GeoIP or ASN data).

Difficulty is 1 everywhere. The server checks a solution with one SHA-256 at any difficulty, so a higher one only adds client work, and the load generator solves challenges itself.

### Metrics

- **Capacity:** the highest offered rate with p99 ≤ 10 ms, ≤ 0.1% errors and nothing dropped. The sweep doubles the rate until a step fails, then bisects twice.
- **CPU per request** (user + kernel, from `getrusage` of the server process) at the same offered rate for both servers: 750 req/s (1 KiB and 64 KiB), 400 (1 MiB), 1,500 (`deny`), 1,000 (`flood`), 500 (`solve`). The rates had to be low enough for Anubis with the stock rules.
- **Latency** p50 to p99.9, measured from each request's scheduled send time (open loop), so a stalled server can't hide behind a slower request rate.
- **Memory:** RSS at the start, peak and end of each step; KB per idle connection in `conns`.
- **New backend connections per 1,000 requests** (`up/1k`), counted by the backend.

### Fairness

| | Blackwall | Anubis |
|---|---|---|
| build | `cargo build --release` | `go build -trimpath` |
| logging | `RUST_LOG=off` | `-slog-level ERROR+4`, and the same in the policy |
| challenge store | in memory, 10,000 pending, 30 min | `store.backend: memory`, the same limits |
| JWT | Ed25519, one fixed seed | Ed25519, the same seed |
| challenge | `fast` (SHA-256), difficulty 1 | `fast`, difficulty 1 |
| cookie bound to | `X-Real-IP` | `X-Real-IP` (`-jwt-restriction-header`) |
| deny status | 403 | 403 (`status_codes.DENY`) |
| extras | none | DNSBL, OpenGraph and GeoIP off |

- **Memory per request:** Blackwall's read buffers are capped at 64 KiB per connection (`MAX_READ_BUF` in `proxy/src/lib.rs`), the same order as Go's (~50 KiB per request in flight). hyper's default grows them to 408 KiB, which on 1 MiB bodies used ~4× Anubis's memory for ~20% less CPU. The cap holds memory equal, so the CPU numbers compare the code.
- **Checked and equal:** both gzip the challenge page at their fastest level, both turn off Nagle's algorithm (Blackwall's first runs didn't; fixed in 26e8614), both speak HTTP/1, both evaluate the same rules in the same order.
- **Left in on purpose,** as the cost of Anubis's features: translations, Prometheus metrics, a request logger built per request even with logging off, the HTML deny page, and re-running the policy on `pass-challenge`.
- **Not changed:** Anubis keeps Go's default of 2 idle backend connections per host, with no flag to change it. That is how it ships, so it's measured as is; section 4.4 measures what it costs.
- The load generator sends `Accept-Encoding: gzip` (without it Anubis rejects 1 in 64 challenge requests) and an `X-Real-IP` from `11.0.0.0/8`, which neither server treats as private.

## 3. Validation

How each kind of error was ruled out. Script and results folder in brackets.

- **The rig isn't the limit.** `direct` reaches 48,000 req/s (1 KiB) on the backend's and load generator's CPUs, well above any proxy result but one. That one, Blackwall's `minimal` `deny`, sat at the rig's limit (48,000 req/s); it was rerun with the lean load generator below and reached 80,000 in all 3 repeats, 84,000 failing in all 3 with its core at 0.83 (`run.sh`, `deny-rerun/`).
- **A lean load generator.** For the vCPU runs the rig had only two cores, and Go's `net/http` client cost 2.6× the backend per request (78 µs: three goroutines per request, stack regrowth, GC). `loadgen/rawclient.go` sends the same bytes with one `writev` and parses only what the checks need, at 29 µs; the rig went from 16,000 to 62,000 req/s on two cores. Its tests check that servers receive byte-identical requests from both clients. Switched back to back on the 1-vCPU cells, capacities moved by at most one step, CPU per request rose 2.5–6.5% for both servers (not explained) and the ratios between them by ≤ 4% (`rig-calibration.sh`, `loadgen-profile.sh`; `rig-calibration/`, `loadgen-ab/`).
- **Repeatability.** Anubis's three repeats land on the same sweep step in every cell; Blackwall's differ by one step in 7 cells, with 2 of 3 agreeing. Three extra repeats from the pool experiment confirm the medians. CPU per request repeats within ±4%; Anubis didn't move by more than 2% between runs a day apart.
- **Shorter windows.** Five runs at the edge of capacity with 15 s and 8 s windows had the same p99 spread and CPU within 2%, so the vCPU sweeps use 8 s (`window-test.sh`, `window-test/`).
- **The same rules.** Blackwall's `data/` was an older copy of Anubis's (34 rules against 43), which overstated Anubis's cost by ~5% with the stock rules. It was replaced with the submodule's before the published runs, and a test compiles every bundled rule file (`countrules.py`).
- **The binaries tested are the ones described.** The unpatched Anubis built for the patch experiment has the same SHA-1 as `bench/bin/anubis`; the sweep's Blackwall binary is byte-identical to a build of b84097c.
- **Profiles cover the CPU.** Anubis's profiles caught 91–99% of the CPU `getrusage` measured, and profiling changed its CPU per request by under 2%. Blackwall's `perf` profiles cover 80–90% of its user time; they need a frame-pointer build, as perf's DWARF unwinding failed on most samples.
- **The machine's own effects.** At low load, cores sleep deeply between requests: with sleep states disabled, Blackwall's CPU per request halves (111 → 56 µs) and Anubis's falls 23%, so the equal-load ratios are the conservative ones (`core-check.sh`; `core-check/`, `cstate-default/`, `cstate-poll/`). With 1 MiB bodies a quarter of the server's core goes to packet processing (softirq) that no process is billed for.
- **An independent review** of the results corrected two things: one run's user/kernel split is noisy (Linux splits by tick samples), so `blogdata` splits the median total by the median kernel share; and capacity ratios depend on the objective, since Anubis degrades gradually and Blackwall falls off a cliff: at p99 ≤ 50 ms they would be 1.2–7× instead of 1.25–8×.

## 4. Results

### 4.1 Capacity

Requests per second at p99 ≤ 10 ms, median of 3 (`run.sh`, `aebdca3-sweep/`). "Cheaper" is Anubis's CPU per request over Blackwall's at each one's limit; "more of the core" is the cores Blackwall used there over Anubis's. The two multiply to the ratio.

| policy | scenario | body | Anubis | Blackwall | ratio | cheaper | more of the core |
|---|---|---|---|---|---|---|---|
| realistic | allow | 1 KiB | 2,000 | 14,000 | 7.0 | 4.93 | 1.42 |
| realistic | allow | 1 MiB | 800 | 2,000 | 2.5 | 1.75 | 1.43 |
| realistic | deny | | 3,500 | 28,000 | 8.0 | 6.00 | 1.33 |
| realistic | flood | | 2,000 | 6,000 | 3.0 | 2.08 | 1.45 |
| realistic | solve | | 1,000 | 4,000 | 4.0 | 2.56 | 1.56 |
| realistic | pass | 1 KiB | 1,500 | 8,000 | 5.3 | 3.55 | 1.50 |
| minimal | allow | 1 KiB | 5,000 | 24,000 | 4.8 | 3.35 | 1.43 |
| minimal | allow | 1 MiB | 1,600 | 2,000 | 1.25 | 1.34 | 0.94 |
| minimal | deny | | 16,000 | 80,000 | 5.0 | | |
| minimal | flood | | 5,000 | 7,000 | 1.4 | 1.33 | 1.05 |
| minimal | solve | | 2,500 | 4,000 | 1.6 | 1.41 | 1.13 |
| minimal | pass | 1 KiB | 4,000 | 12,000 | 3.0 | 2.54 | 1.18 |
| minimal | upload | 1 MiB | 1,600 | 2,000 | 1.25 | 1.30 | 0.96 |

- **They fail differently.** Past its limit, Blackwall's p99 jumps from a few ms to tens or thousands, at 0.76–0.97 of the core: a queue at a full core. Anubis's p99 drifts past 10 ms at 0.52–0.83 of the core with no errors: something other than a full core (4.4).
- **1 MiB bodies are close** because most of the cost is the kernel moving data.
- **`flood` and `solve` are close** because both servers do the same expensive work: compressing the challenge page and, in `solve`, an Ed25519 signature.

### 4.2 CPU per request at the same load

µs per request, user + kernel, median of 3 (`run.sh MODE=fixed`, `aebdca3-fixed/`).

| policy | scenario | body | Blackwall | Anubis | Blackwall ÷ Anubis |
|---|---|---|---|---|---|
| minimal | allow | 1 KiB | 97 | 166 | 0.58 |
| minimal | allow | 1 MiB | 327 | 433 | 0.75 |
| realistic | allow | 1 KiB | 122 | 290 | 0.42 |
| minimal | deny | | 32 | 83 | 0.39 |
| realistic | deny | | 59 | 203 | 0.29 |
| minimal | flood | | 165 | 209 | 0.79 |
| realistic | flood | | 191 | 343 | 0.56 |
| minimal | solve | | 268 | 373 | 0.72 |
| realistic | solve | | 293 | 640 | 0.46 |
| minimal | pass | 1 KiB | 146 | 248 | 0.59 |
| realistic | pass | 1 KiB | 170 | 388 | 0.44 |

Kernel time is close in most cells (Anubis's is 1.0–1.6× Blackwall's, 2–2.5× in `flood` and `solve`); most of the difference is in the servers' own code. Both cost more at these low rates than when busy (Blackwall's `minimal` `allow` is 44 µs at 5,000 req/s), mostly from waking sleeping cores (section 3).

### 4.3 Where the time goes

CPU profiles at the equal-load rates, split into the same parts for both servers by `profile-split.sh` (Anubis: Go's profiler, `aebdca3-profile/`; Blackwall: `perf`, `bw-profile.sh`, `bw-profile/`). µs per request, `realistic`:

| part | `allow` Blackwall | `allow` Anubis | `pass` Blackwall | `pass` Anubis |
|---|---|---|---|---|
| policy rules | 24 | 160 | 24 | 162 |
| JWT (Ed25519) | | | 51 | 71 |
| reverse proxy | 21 | 41 | 20 | 46 |
| HTTP server | 17 | 31 | 20 | 40 |
| runtime (Anubis: + GC) | 11 | 40 | 11 | 37 |
| Anubis's extras and reconnects | | 12 | | 14 |

- **Rules are Go's regex engine.** ~140 of Anubis's 160 µs are Go's `regexp` against ~5 µs in Blackwall; CEL and IP lists cost about the same in both. Alone, the 24 stock user-agent patterns take 48 µs in Go and 0.48 µs in Rust's `regex`, which finds each pattern's literals first. Anubis also matches every single-valued header twice (`HeaderMatchesChecker`) (`regexbench/`, with results in `regexbench/`).
- **Anubis's extra features** (translations, logger, metrics, HTML deny page, honeypot weight) are 3–17% of its CPU with the stock rules and up to 43% of a `minimal` denied request. Without them and without reconnects, Blackwall still uses 0.35–0.66 of Anubis's CPU with the stock rules and 0.61–0.94 with `minimal` (`aebdca3-profile-split.md`).
- **Other design differences:** Anubis re-runs the whole policy on `pass-challenge` (~150 µs of a 640 µs stock-rules solve), stores each challenge as JSON with the visitor's details (15 µs and ~1.5 KB, against 2 µs and ~230 B), and allocates a new 32 KiB copy buffer per proxied response.

### 4.4 Why Anubis's tail grows early

- **Garbage collection.** Anubis allocates ~45 KB per request, two thirds of it the proxy's copy buffer (`alloc-profile.sh`, `alloc-profile/`). With one core, the collector runs every ~27 ms at 5,000 req/s for 6–10 ms each time. Collecting 10× less often (`GOGC=1000`) cuts its CPU per request by 19–24% and its p99 at the limit by 39–51% (`anubis-gc.sh`, `anubis-gc/`).
- **Reconnects.** With 2 idle backend connections, overlapping requests open new ones and close them afterwards: ~250 per 1,000 requests near Anubis's limit. Blackwall built with the same limit (`patches/pool2.patch`) lost 14–50% of its small-body capacity and spent ~25 µs per new connection, though at the equal-load rates it changed nothing. A per-second probe shows a feedback loop: queued requests open many connections at once, which costs CPU, which grows the queue (`pool-ab.sh`, `pool-probe.sh`; `pool-ab/`, `pool-probe/`).
- **Anubis with three patches** (`anubis-tweaks.sh`, `patches/`, `anubis-tweaks/`): `bufpool` (a pool of copy buffers), `idlepool` (keep every idle connection) and `regex1` (match a single-valued header once).

  | cell | as shipped | all three | Blackwall | ratio, shipped → all three |
  |---|---|---|---|---|
  | `realistic` `allow`, CPU at 750 req/s (µs) | 293 | 215 | 122 | 0.42 → 0.57 |
  | `minimal` `allow`, CPU at 5,000 req/s (µs) | 109 | 77 | 42 | 0.39 → 0.55 |
  | `realistic` `allow`, capacity | 2,000 | 4,000 | 14,000 | 7.0× → 3.5× |
  | `realistic` `pass`, capacity | 1,500 | 2,500 | 8,000 | 5.3× → 3.2× |
  | `minimal` `allow`, capacity | 5,000 | 8,000 | 24,000 | 4.8× → 3.0× |

  The causes interact: with `minimal`, `idlepool` or `bufpool` alone breaks the reconnect loop; with the stock rules, it takes all three. What remains is mostly Go's `regexp` with the stock rules, and the runtime and `net/http` with `minimal`.

### 4.5 Latency, and visitors during a bot flood

At equal load p50 is the same for both; with the stock rules Anubis's p99.9 is 2.5–4.2 ms against 1.6–2.4. Both answer in ~0.7 ms at low load against 0.21 ms for Blackwall when busy; sleep states explain about a third of that, the rest isn't pinned down (section 6).

Visitors at 100 req/s while a flood of challenge requests hits the same server, stock rules, p99 in ms (`visitors.sh`, `visitors/`):

| flood (req/s) | returning, Blackwall | returning, Anubis | new, Blackwall | new, Anubis |
|---|---|---|---|---|
| 1,000 | 1.8 | 4.0 | 2.5 | 4.0 |
| 2,000 | 2.0 | 14.9 | 2.6 | 13.2 |
| 4,000 | 2.3 | 917 | 2.6 | 750 |
| 8,000 | 542 | 917 | 548 | 750 |

Neither server serves cookie holders ahead of bots, so once a flood fills the core, visitors queue with it. Blackwall takes a flood at least twice as large before visitors notice (it passes 4,000 req/s, Anubis fails at 2,000).

### 4.6 The challenge page, on the server

- **At a busy core** the page costs Blackwall 104–106 µs and Anubis 84–90, because Blackwall's page as benchmarked was 2.6× larger (18.6 KB, with its script and CSS inline). Per byte, Blackwall's costs less than half as much (`page-profile/`).
- **Not the compressor:** on the same input, Rust's `miniz_oxide` and Go's `compress/flate` are within ~10%. Content matters more than the library, and Anubis's writer pool saves it ~45 µs per page (`pages.sh` and `compbench/`, with results in `compbench/`).
- **After the benchmarks** the page was redesigned and stripped to 9.5 KB. On kelpie it costs 24–27 µs less at a busy core, and Blackwall's `flood` capacity rose to 8,000 (both policies) and `minimal` `solve` to 5,000. The old binary reproduced every published capacity in the same session. Anubis and the article's charts weren't rerun (`page-after.sh`; `page-after/`, `page-after-compbench/`).

### 4.7 The challenge page, in a browser

Headless Chrome on an M4 Pro, both servers on the same machine, 7 visits per cell, desktop and an emulated phone (100 ms per request, 5 Mbit/s down, CPU 4× slower). Anubis needed its web files built, a release version (or it doesn't let browsers cache them) and `-cookie-partitioned=false` over plain HTTP; `run.sh` does all three without changing its code (`browser/run.sh`, `results/browser/visits.jsonl`).

| median of 7 | Blackwall | Anubis |
|---|---|---|
| first visit, downloaded | 14.1 KB in 3 requests | 283.3 KB in 8 |
| returning visit, downloaded | 5.5 KB | 5.1 KB |
| phone, first visit: first paint | 160 ms | 672–680 ms |
| phone, first visit: website reached (difficulty 1 / 4) | 500 / 499 ms | 1,173 / 1,222 ms |
| phone, returning: website reached | 373 / 372 ms | 410 / 459 ms |
| desktop, first visit: website reached | 38 / 40 ms | 34 / 82 ms |

Anubis's first visit carries a 195 KB stylesheet with its fonts inline, two mascot images and a translation file, sent uncompressed, and the stylesheet blocks the first paint. Part of Blackwall's advantage is a missing feature: it has no translations yet.

### 4.8 Scaling with vCPUs

Four layouts of the server: 1 vCPU (one hardware thread, the main layout), 2 vCPUs (one core's two threads), 2 cores, and 4 vCPUs (two cores, both threads) (`multicore.sh`, `multicore/`). Capacity, Blackwall / Anubis:

| cell | 1 vCPU | 2 vCPUs | 2 cores | 4 vCPUs |
|---|---|---|---|---|
| `realistic` `allow` | 17,500 / 2,000 | 17,500 / 2,500 | 31,500 / 4,000 | 42,000 / 7,000 |
| `realistic` `pass` | 8,000 / 1,500 | 12,000 / 1,875 | 18,000 / 3,375 | 24,000 / 5,250 |
| `realistic` `flood` | 6,000 / 2,000 | 7,500 / 2,500 | 12,000 / 4,500 | 16,500 / 7,000 |
| `minimal` `allow` | 24,000 / 5,000 | 30,000 / 7,500 | ≥ 54,000 / 10,000 | ≥ 54,000 / 15,000 |

"≥": the rig's limit, not Blackwall's. The 1-vCPU capacity of `realistic` `allow` is 17,500 here against 14,000 in the main sweep, which is the next step of this ladder.

- **Two cores** give both servers about twice their 1-vCPU capacity. **A core's second thread** adds 8–45%, for both.
- **Anubis gains more on 4 vCPUs** (3–3.5× against 2.4–3×): its tail follows how busy its CPUs are, and more threads absorb more of that queueing. Collecting less often didn't change it (`multicore-why.sh`, `multicore-why/`).
- **Anubis costs more per request on two threads of one core** even with `GOMAXPROCS=1`: Go's sysmon thread wakes ~5,000 times a second on the sibling, and any thread waking that often there slows Anubis's ~30%, as a fully busy sibling does. Tokio has no such thread.

### 4.9 Memory

| | Blackwall | Anubis |
|---|---|---|
| idle | 15–17 MB | 57–62 MB |
| of which the program's file | 12.5 MB | 38.6 MB |
| of which private (heap, stacks) | 0.5–1.7 MB | 19.5–21.8 MB |
| 10,000 pending challenges (`flood`) | 19–21 MB | 73–75 MB |
| per idle connection | 12.3 KiB | 23–28 KiB |
| 1 MiB burst, peak (`allow` / `upload`) | 136–150 / 214–226 MB | 152–163 MB |
| after that burst | keeps its peak | 80–86 MB after ~2 minutes (partly refilled in 3 of 8 runs) |

(`idle-mem.sh`, `idle-mem/`; `run.sh` sweeps; `burst-after.sh`, `thp-check.sh`, `burst-after/`, `thp-check/`, `thp-check-anubis/`.)

- **Idle:** most of the difference is Anubis's larger binary, whose code pages are shared and can be dropped by the kernel; private memory is 13–39× larger in Anubis (the Go heap and the collector's headroom).
- **After a burst:** Go's forced collection runs after 2 minutes without load and its scavenger returns the pages; Blackwall's allocator (glibc) keeps freed memory for reuse. In 3 of 8 Anubis runs, the kernel's huge-page collapsing (THP `always` on kelpie) made part of the released memory resident again.
- **Uploads** peak 45% above Anubis in Blackwall; not profiled.

### 4.10 What benchmarking changed in Blackwall

The first version was no faster than Anubis on Linux, though 25–40% cheaper on macOS. The fixes found by these measurements, with CPU per request at the time (`cpusplit-linux-*`, `celvars-linux-*`, `regexcache-fixed`, `celcontext-fixed`):

| problem | fix |
|---|---|
| The CEL standard library rebuilt on every request; 42% of user CPU in libc, a third of it in glibc's allocator, which macOS's allocator had hidden | built once (3123e3e): `minimal` `allow` 119 → 58 µs |
| Every CEL variable copied per request | bind only the variables rules read (db1384d) |
| CEL `matches()` compiled its regex on every call | a bounded cache of compiled regexes (9024433) |
| Request data copied into CEL values | borrowed (9024433): stock-rules `deny` 72 → 50 µs |
| Nagle's algorithm on: 1 MiB responses waited 40 ms for delayed ACKs | `TCP_NODELAY` on both sides (26e8614) |
| No timeouts for slow clients | own accept loop, HTTP/1 only, header timeout (fda4529) |
| Unbounded challenge store, ~1 KB per challenge | 10,000 pending, 30 min, ~230 B each, like Anubis (88dba9b) |
| Read buffers up to 408 KiB per connection | capped at 64 KiB (a336fe4) |

Allocations per request were counted with dhat (`cargo build --release -p cli --features dhat-heap`, then `dhat-profile.sh` and `dhat-diff.py`): stock-rules `allow` went from 248 to 79.

## 5. What is the language and what isn't

| difference | cause |
|---|---|
| Rules: ~140 µs of Go `regexp` against ~5 µs | **library** (Go's engine has no DFA or literal prefilters) and a **design** detail (matching each header twice) |
| Reconnects | **default setting:** Go's 2 idle connections per host |
| Garbage collection | **runtime**, made worse by a **configuration** choice (no buffer pool) |
| Re-running the policy on a solve, JSON challenge records | **design** |
| Extra features | **features** Blackwall doesn't have |
| Idle memory | **runtime and dependencies:** Go's binary and heap |
| Memory after a burst | **runtime and allocator:** Go's scavenger against glibc |
| Two threads of one core | **runtime and hardware:** sysmon's wake-ups on the sibling |

Patching three of these brings Anubis halfway, and the rest is mostly Go's regex engine, its runtime and `net/http`.

## 6. Limits and open questions

- One machine, mostly one core, loopback only: no network delay, slow clients or TLS. Larger machines and cloud neighbours aren't covered.
- The equal-load rates are low, so cores sleep between requests, which inflates both servers' costs and Blackwall's proportionally more.
- The bench user agent matches no stock rule, so every request walks every pattern: the worst case for the regex gap, and also what an ordinary browser causes.
- Profiles are single runs (differences under ~4% are noise).
- **Not explained yet:** the remaining ~0.7 ms of latency at low load for both servers; `jwt.SignedString` costing Anubis 84 µs per stock-rules solve against 20 with `minimal`; Anubis's p99.9 rising with sleep states off; Blackwall's `upload` peak; servers costing 2.5–6.5% more CPU per request with the lean load generator.
- **Found in Blackwall, not fixed:** it doesn't raise its open-file limit at start-up as Go does, so under a default soft limit of 1,024 it can't hold more than ~1,000 connections (`run.sh` raises it for both servers); slow request headers get 2 minutes, against Anubis's 10 s.
