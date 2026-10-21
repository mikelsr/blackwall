# Experiments

The scripts behind the investigations in [`../REPORT.md`](../REPORT.md), listed by the section they feed. Unless noted, they run on the benchmark box after `bench/build.sh`, from any directory, use `run.sh`'s pinning (server on CPU 0, backend on 1,5, load generator on 2,3,6,7), and write to `bench/results/<name>/`. Run them one at a time: they share ports and CPUs.

| script | REPORT.md section |
|---|---|
| `core-check.sh <out dir>` | 3, the machine's own effects |
| `rig-calibration.sh`, `loadgen-profile.sh [rate]` | 3, a lean load generator |
| `window-test.sh` | 3, shorter windows |
| `countrules.py <data dir>` | 3, the same rules |
| `bw-profile.sh` | 4.3, where the time goes |
| `rulesplit.py`, `ruleleaf.py` | 4.3: split Blackwall's rules part (`perf script -F period,ip,sym` on stdin) |
| `regexbench/` | 4.3, rules are Go's regex engine |
| `anubis-gc.sh`, `alloc-profile.sh` | 4.4, garbage collection |
| `pool-ab.sh`, `pool-probe.sh`, `patches/pool2.patch` | 4.4, reconnects |
| `anubis-tweaks.sh`, `patches/{bufpool,idlepool,regex1}.patch` | 4.4, Anubis with three patches |
| `visitors.sh` | 4.5, visitors during a bot flood |
| `page-profile.sh`, `pages.sh`, `compbench/` | 4.6, the challenge page on the server |
| `page-after.sh` | 4.6, after the benchmarks: `bin/blackwall` (the page as benchmarked) against a build of this tree |
| `browser/run.sh` (on a workstation with Chrome, Node, Go and npm; not on the box) | 4.7, the challenge page in a browser |
| `multicore.sh`, `multicore-why.sh` | 4.8, scaling with vCPUs |
| `idle-mem.sh`, `burst-after.sh`, `thp-check.sh <out dir> <repeats> <server>...` | 4.9, memory |
| `dhat-profile.sh`, `dhat-diff.py` (locally) | 4.10, allocations per request in Blackwall |

The two microbenchmarks run anywhere, pinned with `taskset -c 0` on the box:

```sh
python3 regexbench/extract.py ../anubis/data > rules.json
(cd regexbench/go && go run . ../../rules.json)
(cd regexbench/rs && cargo run --release -- ../../rules.json)

./pages.sh   # on the box, writes ../results/pages/
(cd compbench/go && go run . ../../../results/pages/blackwall-realistic-1.html ../../../results/pages/anubis-realistic-1.html)
(cd compbench/rs && cargo run --release -- ../../../results/pages/blackwall-realistic-1.html ../../../results/pages/anubis-realistic-1.html)
```
