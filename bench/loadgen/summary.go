package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
)

// rowKey identifies one row of the result tables.
type rowKey struct {
	policy, scenario string
	size             int
}

func cmdSummary(files []string) error {
	if len(files) == 0 {
		return fmt.Errorf("no input files")
	}
	var recs []Record
	for _, f := range files {
		r, err := readRecords(f)
		if err != nil {
			return err
		}
		recs = append(recs, r...)
	}
	if len(recs) == 0 {
		return fmt.Errorf("no records found")
	}

	var rows []rowKey
	var servers []string
	for _, r := range recs {
		if r.Scenario == "direct" || r.Mode == "conns" {
			continue
		}
		k := rowKey{r.Policy, r.Scenario, r.SizeBytes}
		if !slices.Contains(rows, k) {
			rows = append(rows, k)
		}
		if !slices.Contains(servers, r.Server) {
			servers = append(servers, r.Server)
		}
	}
	for _, r := range recs {
		if r.Mode == "conns" && !slices.Contains(servers, r.Server) {
			servers = append(servers, r.Server)
		}
	}

	printBaseline(recs)
	printSweepSummary(recs, rows, servers)
	printFootprint(recs, rows, servers)
	printFixedSummary(recs, rows, servers)
	printConnsSummary(recs, servers)
	return nil
}

func readRecords(path string) ([]Record, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	var recs []Record
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var r Record
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		recs = append(recs, r)
	}
	return recs, sc.Err()
}

func sizeCell(size int) string {
	if size == 0 {
		return "-"
	}
	return humanBytes(size)
}

func matches(r Record, k rowKey, server string) bool {
	return r.Policy == k.policy && r.Scenario == k.scenario && r.SizeBytes == k.size && r.Server == server
}

// bestPerRepeat returns, per repeat, the passing sweep record with the
// highest rate. Repeats where nothing passed yield a zero record.
func bestPerRepeat(recs []Record, k rowKey, server string) []Record {
	best := map[int]Record{}
	for _, r := range recs {
		if r.Mode != "sweep" || !matches(r, k, server) {
			continue
		}
		cur, ok := best[r.Repeat]
		if !ok {
			best[r.Repeat] = Record{}
		}
		if r.Pass && r.Rate > cur.Rate {
			best[r.Repeat] = r
		}
	}
	out := make([]Record, 0, len(best))
	for _, r := range best {
		out = append(out, r)
	}
	return out
}

func medianBy(rs []Record, key func(Record) float64) (Record, int) {
	if len(rs) == 0 {
		return Record{}, 0
	}
	slices.SortFunc(rs, func(a, b Record) int {
		switch ka, kb := key(a), key(b); {
		case ka < kb:
			return -1
		case ka > kb:
			return 1
		}
		return 0
	})
	return rs[len(rs)/2], len(rs)
}

func byRate(r Record) float64 { return r.Rate }

func upstreamCell(r Record) string {
	if r.UpstreamConnsPer1k == nil {
		return "-"
	}
	return fmt.Sprintf("%.1f", *r.UpstreamConnsPer1k)
}

func printBaseline(recs []Record) {
	var direct []Record
	var sizes []int
	for _, r := range recs {
		if r.Scenario == "direct" {
			direct = append(direct, r)
			if !slices.Contains(sizes, r.SizeBytes) {
				sizes = append(sizes, r.SizeBytes)
			}
		}
	}
	if len(direct) == 0 {
		return
	}
	slices.Sort(sizes)
	fmt.Println("## Baseline: backend without a proxy")
	fmt.Println()
	fmt.Println("If a proxy gets close to these numbers, the backend or load generator is the limit, not the proxy.")
	fmt.Println()
	printMarkdownRow([]string{"body", "mode", "rate ops/s", "p50 ms", "p99 ms", "MB/s"})
	printMarkdownSep(6)
	for _, size := range sizes {
		k := rowKey{"-", "direct", size}
		var rs []Record
		for _, r := range direct {
			if r.SizeBytes == size {
				k.policy = r.Policy
				rs = append(rs, r)
			}
		}
		if slices.ContainsFunc(rs, func(r Record) bool { return r.Mode == "sweep" }) {
			m, _ := medianBy(bestPerRepeat(direct, k, rs[0].Server), byRate)
			printMarkdownRow([]string{sizeCell(size), "max", fmt.Sprintf("%.0f", m.Rate), fmt.Sprintf("%.2f", m.P50), fmt.Sprintf("%.2f", m.P99), fmt.Sprintf("%.1f", m.MBps)})
		}
		for _, r := range rs {
			if r.Mode == "fixed" {
				printMarkdownRow([]string{sizeCell(size), "fixed", fmt.Sprintf("%.0f", r.Rate), fmt.Sprintf("%.2f", r.P50), fmt.Sprintf("%.2f", r.P99), fmt.Sprintf("%.1f", r.MBps)})
				break
			}
		}
	}
	fmt.Println()
}

func printSweepSummary(recs []Record, rows []rowKey, servers []string) {
	if !slices.ContainsFunc(recs, func(r Record) bool { return r.Mode == "sweep" && r.Scenario != "direct" }) {
		return
	}
	fmt.Printf("## Max sustainable rate (p99 <= %.0f ms, errors <= 0.1%%)\n\n", recs[0].SLOms)
	fmt.Println("Median over repeats of the highest passing offered rate. CPU and RSS are measured at that rate.")
	fmt.Println()

	header := []string{"policy", "scenario", "body"}
	for _, s := range servers {
		header = append(header, s+" ops/s", s+" p99 ms", s+" cpu µs/op", s+" rss peak MB")
	}
	if len(servers) == 2 {
		header = append(header, servers[0]+"/"+servers[1])
	}
	printMarkdownRow(header)
	printMarkdownSep(len(header))

	for _, k := range rows {
		row := []string{k.policy, k.scenario, sizeCell(k.size)}
		var rates []float64
		found := false
		for _, srv := range servers {
			m, n := medianBy(bestPerRepeat(recs, k, srv), byRate)
			if n == 0 {
				row = append(row, "-", "-", "-", "-")
				rates = append(rates, 0)
				continue
			}
			found = true
			rate := fmt.Sprintf("%.0f", m.Rate)
			if n > 1 {
				rate += fmt.Sprintf(" (n=%d)", n)
			}
			row = append(row, rate, fmt.Sprintf("%.2f", m.P99), fmt.Sprintf("%.1f", m.CPUUsPerOp), fmt.Sprintf("%.1f", m.RSSPeakMB))
			rates = append(rates, m.Rate)
		}
		if !found {
			continue
		}
		if len(servers) == 2 {
			if rates[1] > 0 {
				row = append(row, fmt.Sprintf("%.2fx", rates[0]/rates[1]))
			} else {
				row = append(row, "-")
			}
		}
		printMarkdownRow(row)
	}
	fmt.Println()
}

// printFootprint shows resources per unit of throughput for the proxied
// scenarios: what it costs to run each proxy for a given amount of traffic.
func printFootprint(recs []Record, rows []rowKey, servers []string) {
	proxied := func(s string) bool { return s == "allow" || s == "pass" || s == "upload" }
	if !slices.ContainsFunc(rows, func(k rowKey) bool { return proxied(k.scenario) }) {
		return
	}
	fmt.Println("## Proxy footprint per throughput")
	fmt.Println()
	fmt.Println("Proxied scenarios only. `cores/10k` is the proxy's CPU in cores per 10,000 req/s (backend excluded).")
	fmt.Println("`cpu ms/GB` is proxy CPU per GB of body moved (bodies >= 64 KiB). `up/1k` is upstream connections opened per 1,000 requests")
	fmt.Println("(≈0 means connections are reused). Sweep rows are taken at the max sustainable rate; fixed rows at the fixed rate.")
	fmt.Println()
	header := []string{"policy", "scenario", "body", "mode", "server", "ops/s", "MB/s", "cores/10k", "cpu ms/GB", "rss peak MB", "up/1k"}
	printMarkdownRow(header)
	printMarkdownSep(len(header))

	for _, mode := range []string{"sweep", "fixed"} {
		for _, k := range rows {
			if !proxied(k.scenario) {
				continue
			}
			for _, srv := range servers {
				var m Record
				var n int
				if mode == "sweep" {
					m, n = medianBy(bestPerRepeat(recs, k, srv), byRate)
				} else {
					var rs []Record
					for _, r := range recs {
						if r.Mode == "fixed" && matches(r, k, srv) {
							rs = append(rs, r)
						}
					}
					m, n = medianBy(rs, func(r Record) float64 { return r.CPUUsPerOp })
				}
				if n == 0 || m.Rate == 0 {
					continue
				}
				// Below 64 KiB per-request overhead dominates and per-GB numbers mislead.
				cpuPerGB := "-"
				if k.size >= 64<<10 {
					cpuPerGB = fmt.Sprintf("%.1f", m.CPUUsPerOp/1e3*(1e9/float64(k.size)))
				}
				printMarkdownRow([]string{
					k.policy, k.scenario, sizeCell(k.size), mode, srv,
					fmt.Sprintf("%.0f", m.Rate),
					fmt.Sprintf("%.1f", m.MBps),
					fmt.Sprintf("%.2f", m.CPUUsPerOp/100),
					cpuPerGB,
					fmt.Sprintf("%.1f", m.RSSPeakMB),
					upstreamCell(m),
				})
			}
		}
	}
	fmt.Println()
}

func printFixedSummary(recs []Record, rows []rowKey, servers []string) {
	if !slices.ContainsFunc(recs, func(r Record) bool { return r.Mode == "fixed" && r.Scenario != "direct" }) {
		return
	}
	fmt.Println("## Fixed-rate efficiency")
	fmt.Println()
	fmt.Println("Same offered rate for both servers. Lower CPU µs/op is better. Medians over repeats.")
	fmt.Println("`user` is the server's own code, `kernel` its syscalls and network stack (they sum to cpu µs/op).")
	fmt.Println()
	header := []string{"policy", "scenario", "body", "server", "rate", "achieved", "p50 ms", "p99 ms", "p99.9 ms", "err %", "cpu µs/op", "user µs/op", "kernel µs/op", "cores used", "rss start MB", "rss peak MB", "rss end MB", "up/1k"}
	printMarkdownRow(header)
	printMarkdownSep(len(header))
	for _, k := range rows {
		for _, srv := range servers {
			var rs []Record
			for _, r := range recs {
				if r.Mode == "fixed" && matches(r, k, srv) {
					rs = append(rs, r)
				}
			}
			m, n := medianBy(rs, func(r Record) float64 { return r.CPUUsPerOp })
			if n == 0 {
				continue
			}
			printMarkdownRow([]string{
				k.policy, k.scenario, sizeCell(k.size), srv,
				fmt.Sprintf("%.0f", m.Rate),
				fmt.Sprintf("%.0f", m.Achieved),
				fmt.Sprintf("%.2f", m.P50),
				fmt.Sprintf("%.2f", m.P99),
				fmt.Sprintf("%.2f", m.P999),
				fmt.Sprintf("%.3f", m.ErrorRate*100),
				fmt.Sprintf("%.1f", m.CPUUsPerOp),
				fmt.Sprintf("%.1f", m.UserUsPerOp),
				fmt.Sprintf("%.1f", m.SysUsPerOp),
				fmt.Sprintf("%.2f", m.CoresUsed),
				fmt.Sprintf("%.1f", m.RSSStartMB),
				fmt.Sprintf("%.1f", m.RSSPeakMB),
				fmt.Sprintf("%.1f", m.RSSEndMB),
				upstreamCell(m),
			})
		}
	}
	fmt.Println()
}

func printConnsSummary(recs []Record, servers []string) {
	var levels []int
	for _, r := range recs {
		if r.Mode == "conns" && !slices.Contains(levels, r.Conns) {
			levels = append(levels, r.Conns)
		}
	}
	if len(levels) == 0 {
		return
	}
	slices.Sort(levels)
	fmt.Println("## Idle connection footprint")
	fmt.Println()
	fmt.Println("N keep-alive client connections held open after one request each (DENY path, no upstream).")
	fmt.Println("`KB/conn` = (RSS with N open − baseline RSS) / N. Probe latency is for fresh requests while they are open.")
	fmt.Println("`alive` is a sample of the idle connections re-used at the end; anything below 100% means the server closed them.")
	fmt.Println()
	header := []string{"server", "conns", "opened", "rss base MB", "rss at N MB", "KB/conn", "MB per 1k conns", "probe p50 ms", "probe p99 ms", "alive"}
	printMarkdownRow(header)
	printMarkdownSep(len(header))
	for _, lvl := range levels {
		for _, srv := range servers {
			var rs []Record
			for _, r := range recs {
				if r.Mode == "conns" && r.Server == srv && r.Conns == lvl {
					rs = append(rs, r)
				}
			}
			m, n := medianBy(rs, func(r Record) float64 { return r.KBPerConn })
			if n == 0 {
				continue
			}
			printMarkdownRow([]string{
				srv,
				fmt.Sprintf("%d", m.Conns),
				fmt.Sprintf("%d", m.ConnsOpened),
				fmt.Sprintf("%.1f", m.RSSBaselineMB),
				fmt.Sprintf("%.1f", m.RSSEndMB),
				fmt.Sprintf("%.1f", m.KBPerConn),
				fmt.Sprintf("%.1f", m.KBPerConn*1000/1024),
				fmt.Sprintf("%.2f", m.P50),
				fmt.Sprintf("%.2f", m.P99),
				m.AliveSample,
			})
		}
	}
	fmt.Println()
}

func printMarkdownRow(cells []string) {
	fmt.Println("| " + strings.Join(cells, " | ") + " |")
}

func printMarkdownSep(n int) {
	parts := make([]string, n)
	for i := range parts {
		parts[i] = "---"
	}
	fmt.Println("|" + strings.Join(parts, "|") + "|")
}
