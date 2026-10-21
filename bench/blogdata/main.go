// Command blogdata builds the data behind the benchmark graphs of the
// "Benchmarking Blackwall Against Anubis" article (mikelsr.github.io,
// src/assets/graphs/articles/2026-10-21/data.json) from benchmark results,
// so no number in its graphs is copied by hand.
//
//	cd bench && go run ./blogdata -out <blog>/src/assets/graphs/articles/2026-10-21/data.json
//
// Which run and which cells feed each graph is set in the variables below.
// The browser visits (experiments/browser/run.sh) run on a workstation, not
// the benchmark box, so they are read from -browser (results/browser).
// It runs profile-split.sh for the Anubis CPU breakdown, which needs Go's
// pprof and jq, and Go's pprof for Anubis's allocation profiles.
package main

import (
	"bufio"
	"bytes"
	"cmp"
	"encoding/json"
	"flag"
	"fmt"
	"maps"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Runs under -results.
const (
	sweepRun = "aebdca3-sweep"
	fixedRun = "aebdca3-fixed"
)

// Anubis CPU profiles, one directory per rate.
var profileRuns = []string{"aebdca3-profile", "aebdca3-profile-5000"}

// Visitors during a bot flood: one run per flood rate and repeat, named
// flood<rate>-r<repeat>.
const visitorRuns = "visitors"

// Challenge page profiles: a bot flood at each server's highest passing rate,
// one run per server and policy (<server>-<policy>), and split.md, the
// profile-split.sh output of all of them (perf needs the machine that ran
// Blackwall's).
const pageRun = "page-profile"

type cell struct {
	Policy   string `json:"policy"`
	Scenario string `json:"scenario"`
	Size     int    `json:"size"`
}

const kib, mib = 1024, 1024 * 1024

// Cells of the capacity and equal-load graphs.
var cells = []cell{
	{"realistic", "allow", kib}, {"realistic", "deny", 0}, {"realistic", "flood", 0},
	{"realistic", "solve", 0}, {"realistic", "pass", kib},
	{"minimal", "allow", kib}, {"minimal", "deny", 0}, {"minimal", "flood", 0},
	{"minimal", "solve", 0}, {"minimal", "pass", kib},
	{"minimal", "allow", mib}, {"minimal", "upload", mib},
}

// Capacity cells whose Blackwall sweep comes from a later run, with the cell's
// run: in minimal deny the main sweep's load generator was the limit at
// 48–56k req/s, and the rerun with the raw client measured Blackwall's
// (bench/REPORT.md, "Validation").
var blackwallReruns = map[cell]string{{"minimal", "deny", 0}: "deny-rerun"}

// The sweep drawn step by step in the latency-vs-load graph.
var sweepCell = cell{"realistic", "allow", kib}

// Cells of the latency percentiles graph.
var latencyCells = []cell{
	{"realistic", "allow", kib}, {"realistic", "deny", 0}, {"realistic", "flood", 0},
	{"realistic", "solve", 0}, {"realistic", "pass", kib},
}

// Cells of the burst memory graph.
var burstCells = []cell{{"minimal", "allow", mib}, {"minimal", "upload", mib}}

// Each optimization panel follows one Blackwall cell through the fixed-rate
// runs taken after each fix, all at the same rate.
type panel struct {
	title  string
	cell   cell
	anubis string // run with Anubis's number for reference
	steps  []step
}

type step struct{ label, run string }

var panels = []panel{
	{
		title:  "Minimal rules, allowed, 4,000 req/s",
		cell:   cell{"minimal", "allow", kib},
		anubis: "cpusplit-linux-1core",
		steps: []step{
			{"First version", "cpusplit-linux-1core"},
			{"CEL library built once", "cpusplit-fix-linux-1core"},
			{"Bind only the variables rules read", "celvars-linux-minimal"},
		},
	},
	{
		title:  "Stock rules, denied, 1,500 req/s",
		cell:   cell{"realistic", "deny", 0},
		anubis: fixedRun,
		steps: []step{
			// Blackwall shipped an older copy of Anubis's rules until the
			// last step, which adds work rather than removing it.
			{"Before these fixes (34 rules)", "20261019-084107-fixed"},
			{"Cache compiled regexes", "regexcache-fixed"},
			{"Borrow request data", "celcontext-fixed"},
			{"Rules updated to Anubis's 43", fixedRun},
		},
	},
}

// record holds the fields of loadgen's results.jsonl that are used here.
type record struct {
	Server    string  `json:"server"`
	Policy    string  `json:"policy"`
	Scenario  string  `json:"scenario"`
	Mode      string  `json:"mode"`
	Repeat    int     `json:"repeat"`
	Size      int     `json:"size_bytes"`
	SLOms     float64 `json:"slo_ms"`
	Rate      float64 `json:"rate"`
	Pass      bool    `json:"pass"`
	ErrorRate float64 `json:"error_rate"`
	P50       float64 `json:"p50_ms"`
	P90       float64 `json:"p90_ms"`
	P99       float64 `json:"p99_ms"`
	P999      float64 `json:"p999_ms"`
	CPU       float64 `json:"cpu_us_per_op"`
	User      float64 `json:"user_us_per_op"`
	Sys       float64 `json:"sys_us_per_op"`
	RSSPeak   float64 `json:"rss_peak_mb"`
	RSSEnd    float64 `json:"rss_end_mb"`
	Conns     int     `json:"conns"`
	RSSBase   float64 `json:"rss_baseline_mb"`
	PageBytes int     `json:"page_bytes"`
	Flood     *struct {
		Rate      float64 `json:"rate"`
		Achieved  float64 `json:"achieved"`
		ErrorRate float64 `json:"error_rate"`
	} `json:"flood"`
}

func (r record) in(server string, c cell) bool {
	return r.Server == server && r.Policy == c.Policy && r.Scenario == c.Scenario && r.Size == c.Size
}

var servers = []string{"blackwall", "anubis"}

func main() {
	results := flag.String("results", "results/remote-kelpie-local", "directory with the runs")
	out := flag.String("out", "", "data.json to write")
	browser := flag.String("browser", "results/browser", "experiments/browser/run.sh's output, which runs on a workstation")
	flag.Parse()
	if *out == "" {
		fmt.Fprintln(os.Stderr, "usage: blogdata [-results dir] [-browser dir] -out data.json")
		os.Exit(2)
	}
	if err := run(*results, *browser, *out); err != nil {
		fmt.Fprintln(os.Stderr, "blogdata:", err)
		os.Exit(1)
	}
}

func run(results, browser, out string) error {
	load := func(name string) ([]record, error) { return readRecords(filepath.Join(results, name, "results.jsonl")) }
	sweep, err := load(sweepRun)
	if err != nil {
		return err
	}
	fixed, err := load(fixedRun)
	if err != nil {
		return err
	}

	var reruns []string
	for c, run := range blackwallReruns {
		reruns = append(reruns, fmt.Sprintf("Blackwall's %s %s from %s", c.Policy, c.Scenario, run))
	}
	slices.Sort(reruns)
	data := map[string]any{
		"placeholder": false,
		"source": fmt.Sprintf("bench/blogdata from %s (%s), %s and %s (median of each cell's repeats), Anubis profiles %s, challenge page profiles %s, patched Anubis %s, Anubis allocation profiles %s, idle memory %s, vCPU scaling %s, browser visits %s, and the optimization runs in its panels.",
			sweepRun, strings.Join(reruns, ", "), fixedRun, visitorRuns, strings.Join(profileRuns, " and "), pageRun, patchedRun, allocRun, idleMemRun, multicoreRun, browser),
	}
	steps := []struct {
		key   string
		build func() (any, error)
	}{
		{"capacity", func() (any, error) { return capacity(sweep, load) }},
		{"sweep", func() (any, error) { return sweepSteps(sweep) }},
		{"equalLoad", func() (any, error) { return equalLoad(fixed) }},
		{"latency", func() (any, error) { return latency(fixed) }},
		{"idleConns", func() (any, error) { return idleConns(sweep) }},
		{"burst", func() (any, error) { return burst(sweep) }},
		{"anubisCpu", func() (any, error) { return anubisCPU(results) }},
		{"challengePage", func() (any, error) { return challengePage(filepath.Join(results, pageRun)) }},
		{"optimizations", func() (any, error) { return optimizations(load) }},
		{"visitors", func() (any, error) { return visitors(filepath.Join(results, visitorRuns)) }},
		{"anubisPatched", func() (any, error) { return anubisPatched(filepath.Join(results, patchedRun), sweep) }},
		{"anubisAllocs", func() (any, error) { return anubisAllocs(filepath.Join(results, allocRun)) }},
		{"idleMemory", func() (any, error) { return idleMemory(filepath.Join(results, idleMemRun)) }},
		{"multicore", func() (any, error) { return multicore(filepath.Join(results, multicoreRun)) }},
		{"browserPage", func() (any, error) { return browserPage(browser) }},
	}
	for _, s := range steps {
		v, err := s.build()
		if err != nil {
			return fmt.Errorf("%s: %w", s.key, err)
		}
		data[s.key] = v
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(data); err != nil {
		return err
	}
	return os.WriteFile(out, buf.Bytes(), 0o644)
}

func readRecords(path string) ([]record, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	var recs []record
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		if strings.TrimSpace(sc.Text()) == "" {
			continue
		}
		var r record
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		recs = append(recs, r)
	}
	return recs, sc.Err()
}

// byRepeat groups a cell's records per repeat, in the order they ran.
func byRepeat(recs []record, mode, server string, c cell) [][]record {
	groups := map[int][]record{}
	for _, r := range recs {
		if r.Mode == mode && r.in(server, c) {
			groups[r.Repeat] = append(groups[r.Repeat], r)
		}
	}
	out := make([][]record, 0, len(groups))
	for _, rep := range slices.Sorted(maps.Keys(groups)) {
		out = append(out, groups[rep])
	}
	return out
}

// maxRate is the highest passing rate of one sweep, 0 if none passed.
func maxRate(steps []record) float64 {
	best := 0.0
	for _, r := range steps {
		if r.Pass {
			best = max(best, r.Rate)
		}
	}
	return best
}

// median of an odd count is the middle value; of an even count, the upper of
// the two middle ones, so it is always a measured value.
func median[T cmp.Ordered](values []T) T {
	s := slices.Sorted(slices.Values(values))
	return s[len(s)/2]
}

// medianRecord is the record with the median key, so its fields come from
// one measurement.
func medianRecord(recs []record, key func(record) float64) record {
	s := slices.Clone(recs)
	slices.SortFunc(s, func(a, b record) int { return cmpFloat(key(a), key(b)) })
	return s[len(s)/2]
}

func cmpFloat(a, b float64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func round(v float64, digits int) float64 {
	p := math.Pow(10, float64(digits))
	return math.Round(v*p) / p
}

func capacity(sweep []record, load func(string) ([]record, error)) (any, error) {
	type row struct {
		cell
		Blackwall []float64 `json:"blackwall"`
		Anubis    []float64 `json:"anubis"`
		Rerun     bool      `json:"rerun,omitempty"` // Blackwall's from blackwallReruns
	}
	var rows []row
	for _, c := range cells {
		rerun, ok := blackwallReruns[c]
		r := row{cell: c, Rerun: ok}
		for _, srv := range servers {
			recs := sweep
			if ok && srv == "blackwall" {
				var err error
				if recs, err = load(rerun); err != nil {
					return nil, err
				}
			}
			reps := byRepeat(recs, "sweep", srv, c)
			if len(reps) == 0 {
				return nil, fmt.Errorf("no sweep for %s %v", srv, c)
			}
			rates := make([]float64, len(reps))
			for i, steps := range reps {
				rates[i] = maxRate(steps)
			}
			if srv == "blackwall" {
				r.Blackwall = rates
			} else {
				r.Anubis = rates
			}
		}
		rows = append(rows, r)
	}
	return rows, nil
}

// sweepSteps draws, for each server, the repeat whose max rate is the median.
func sweepSteps(sweep []record) (any, error) {
	type point struct {
		Rate float64 `json:"rate"`
		P99  float64 `json:"p99"`
		Pass bool    `json:"pass"`
	}
	out := map[string]any{
		"policy": sweepCell.Policy, "scenario": sweepCell.Scenario, "size": sweepCell.Size,
	}
	for _, srv := range servers {
		reps := byRepeat(sweep, "sweep", srv, sweepCell)
		if len(reps) == 0 {
			return nil, fmt.Errorf("no sweep for %s %v", srv, sweepCell)
		}
		slices.SortStableFunc(reps, func(a, b []record) int { return cmpFloat(maxRate(a), maxRate(b)) })
		typical := slices.Clone(reps[len(reps)/2])
		// Runs are in the order the sweep tried them, refinements last. The
		// line ends at the first failing rate.
		slices.SortFunc(typical, func(a, b record) int { return cmpFloat(a.Rate, b.Rate) })
		var points []point
		for _, r := range typical {
			points = append(points, point{r.Rate, round(r.P99, 2), r.Pass})
			if !r.Pass {
				break
			}
		}
		out[srv] = points
		out["sloMs"] = typical[0].SLOms // the same in every run of the sweep
	}
	return out, nil
}

type cpuSplit struct {
	User float64 `json:"user"`
	Sys  float64 `json:"sys"`
}

// splitOf gives the median CPU per request of recs, divided into user and
// kernel time by the median kernel share. Linux measures a process's total CPU
// time precisely but divides it into user and kernel time from timer-tick
// samples, so one run's split is far noisier than its total.
func splitOf(recs []record) cpuSplit {
	totals := make([]float64, len(recs))
	shares := make([]float64, len(recs))
	for i, r := range recs {
		totals[i], shares[i] = r.CPU, r.Sys/r.CPU
	}
	total := median(totals)
	sys := total * median(shares)
	return cpuSplit{round(total-sys, 1), round(sys, 1)}
}

func fixedCell(fixed []record, server string, c cell) ([]record, error) {
	var recs []record
	for _, reps := range byRepeat(fixed, "fixed", server, c) {
		recs = append(recs, reps...)
	}
	if len(recs) == 0 {
		return nil, fmt.Errorf("no fixed-rate run for %s %v", server, c)
	}
	return recs, nil
}

func equalLoad(fixed []record) (any, error) {
	type row struct {
		cell
		Rate      float64  `json:"rate"`
		Blackwall cpuSplit `json:"blackwall"`
		Anubis    cpuSplit `json:"anubis"`
	}
	var rows []row
	for _, c := range cells {
		r := row{cell: c}
		for _, srv := range servers {
			recs, err := fixedCell(fixed, srv, c)
			if err != nil {
				return nil, err
			}
			split := splitOf(recs)
			if err := sameRate(&r.Rate, recs[0], c); err != nil {
				return nil, err
			}
			if srv == "blackwall" {
				r.Blackwall = split
			} else {
				r.Anubis = split
			}
		}
		rows = append(rows, r)
	}
	return rows, nil
}

// sameRate sets *rate from the first server's record and checks the second
// ran at the same one: the equal-load graphs compare at one rate.
func sameRate(rate *float64, m record, c cell) error {
	if *rate != 0 && *rate != m.Rate {
		return fmt.Errorf("%v: servers ran at %.0f and %.0f req/s", c, *rate, m.Rate)
	}
	*rate = m.Rate
	return nil
}

func latency(fixed []record) (any, error) {
	type percentiles struct {
		P50  float64 `json:"p50"`
		P90  float64 `json:"p90"`
		P99  float64 `json:"p99"`
		P999 float64 `json:"p999"`
	}
	type row struct {
		Policy    string      `json:"policy"`
		Scenario  string      `json:"scenario"`
		Rate      float64     `json:"rate"`
		Blackwall percentiles `json:"blackwall"`
		Anubis    percentiles `json:"anubis"`
	}
	var rows []row
	for _, c := range latencyCells {
		r := row{Policy: c.Policy, Scenario: c.Scenario}
		for _, srv := range servers {
			recs, err := fixedCell(fixed, srv, c)
			if err != nil {
				return nil, err
			}
			m := medianRecord(recs, func(r record) float64 { return r.P99 })
			p := percentiles{round(m.P50, 2), round(m.P90, 2), round(m.P99, 2), round(m.P999, 2)}
			if err := sameRate(&r.Rate, m, c); err != nil {
				return nil, err
			}
			if srv == "blackwall" {
				r.Blackwall = p
			} else {
				r.Anubis = p
			}
		}
		rows = append(rows, r)
	}
	return rows, nil
}

// idleConns gives [connections, resident MiB] points per server, starting
// from the server with no connections open.
func idleConns(sweep []record) (any, error) {
	out := map[string][][2]float64{}
	for _, srv := range servers {
		var bases []float64
		at := map[int][]float64{}
		for _, r := range sweep {
			if r.Mode == "conns" && r.Server == srv {
				bases = append(bases, r.RSSBase)
				at[r.Conns] = append(at[r.Conns], r.RSSEnd)
			}
		}
		if len(bases) == 0 {
			return nil, fmt.Errorf("no conns runs for %s", srv)
		}
		points := [][2]float64{{0, round(median(bases), 1)}}
		for _, n := range slices.Sorted(maps.Keys(at)) {
			points = append(points, [2]float64{float64(n), round(median(at[n]), 1)})
		}
		out[srv] = points
	}
	return out, nil
}

// burst gives each server's resident memory in a sweep with large bodies:
// before the overload (at the highest passing step that ran before the first
// failing one), the peak over the whole sweep, and at the end of the last
// step. The server is not restarted between steps, so the end shows what it
// kept. Median of the repeats.
func burst(sweep []record) (any, error) {
	type phases struct {
		Before float64 `json:"before"`
		Peak   float64 `json:"peak"`
		After  float64 `json:"after"`
	}
	type row struct {
		Scenario  string `json:"scenario"`
		Size      int    `json:"size"`
		Blackwall phases `json:"blackwall"`
		Anubis    phases `json:"anubis"`
	}
	var rows []row
	for _, c := range burstCells {
		r := row{Scenario: c.Scenario, Size: c.Size}
		for _, srv := range servers {
			var before, peak, after []float64
			for _, steps := range byRepeat(sweep, "sweep", srv, c) {
				b, p := 0.0, 0.0
				failed := false
				for _, s := range steps {
					failed = failed || !s.Pass
					if !failed {
						b = s.RSSPeak
					}
					p = max(p, s.RSSPeak)
				}
				if b == 0 {
					return nil, fmt.Errorf("%s %v: the first step already failed", srv, c)
				}
				before = append(before, b)
				peak = append(peak, p)
				after = append(after, steps[len(steps)-1].RSSEnd)
			}
			if len(peak) == 0 {
				return nil, fmt.Errorf("no sweep for %s %v", srv, c)
			}
			ph := phases{round(median(before), 1), round(median(peak), 1), round(median(after), 1)}
			if srv == "blackwall" {
				r.Blackwall = ph
			} else {
				r.Anubis = ph
			}
		}
		rows = append(rows, r)
	}
	return rows, nil
}

// Groups of profile-split.sh's parts, as the anubis-cpu graph shows them.
// Parts not listed go by their kind: extra, config (reconnects), runtime.
var partGroup = map[string]string{
	"policy rules (CEL, regex)":                    "policy",
	"threshold identity (JSON + hash per request)": "policy",
	"JWT (Ed25519)":                                "challenge",
	"challenge (issue, store, verify)":             "challenge",
	"challenge page (templates, gzip)":             "challenge",
	"reverse proxy":                                "http",
	"other Anubis request handling":                "http",
	"HTTP server":                                  "http",
}

var kindGroup = map[string]string{"extra": "extras", "config": "reconnects", "runtime": "runtime"}

var profileName = regexp.MustCompile(`^anubis-(\w+)-(\w+)-(\d+)-r\d+\.pprof$`)

func anubisCPU(results string) (any, error) {
	type row struct {
		Policy   string             `json:"policy"`
		Scenario string             `json:"scenario"`
		Rate     float64            `json:"rate"`
		Parts    map[string]float64 `json:"parts"`
	}
	var rows []row
	for _, run := range profileRuns {
		dir := filepath.Join(results, run)
		recs, err := readRecords(filepath.Join(dir, "results.jsonl"))
		if err != nil {
			return nil, err
		}
		profiles, err := filepath.Glob(filepath.Join(dir, "profiles", "*.pprof"))
		if err != nil || len(profiles) == 0 {
			return nil, fmt.Errorf("no profiles in %s", dir)
		}
		cmd := exec.Command("./profile-split.sh", profiles...)
		cmd.Stderr = os.Stderr
		split, err := cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("profile-split.sh %s: %w", dir, err)
		}

		for _, t := range parseSplit(string(split)) {
			m := profileName.FindStringSubmatch(t.profile)
			if m == nil {
				continue
			}
			size, _ := strconv.Atoi(m[3])
			c := cell{m[1], m[2], size}
			anubis, err := fixedCell(recs, "anubis", c)
			if err != nil {
				return nil, err
			}
			r := row{Policy: c.Policy, Scenario: c.Scenario, Rate: anubis[0].Rate, Parts: map[string]float64{
				"policy": 0, "http": 0, "challenge": 0, "runtime": 0, "extras": 0, "reconnects": 0,
			}}
			for _, p := range t.parts {
				group, ok := partGroup[p.name]
				if !ok {
					group, ok = kindGroup[p.kind]
				}
				if !ok {
					if p.kind == "core" {
						return nil, fmt.Errorf("core part %q has no group", p.name)
					}
					continue // unattributed samples ("other")
				}
				r.Parts[group] = round(r.Parts[group]+p.share, 1)
			}
			rows = append(rows, r)
		}
	}
	return rows, nil
}

// splitTable is one profile's table in profile-split.sh's output.
type splitTable struct {
	profile string // file name
	parts   []splitPart
}

type splitPart struct {
	name, kind string
	share      float64 // % of the profile's samples
	us         float64 // µs per request; 0 if the run's CPU is unknown
}

// parseSplit reads profile-split.sh's output, in its order.
func parseSplit(out string) []splitTable {
	var tables []splitTable
	for line := range strings.Lines(out) {
		line = strings.TrimSpace(line)
		if name, ok := strings.CutPrefix(line, "### "); ok {
			tables = append(tables, splitTable{profile: name})
			continue
		}
		// | part | kind | % | µs/op |
		cols := strings.Split(strings.Trim(line, "|"), "|")
		if len(tables) == 0 || len(cols) != 4 {
			continue
		}
		share, err := strconv.ParseFloat(strings.TrimSpace(cols[2]), 64)
		if err != nil {
			continue // header, separator and kernel rows
		}
		us, _ := strconv.ParseFloat(strings.TrimSpace(cols[3]), 64)
		t := &tables[len(tables)-1]
		t.parts = append(t.parts, splitPart{strings.TrimSpace(cols[0]), strings.TrimSpace(cols[1]), share, us})
	}
	return tables
}

// The part of profile-split.sh that builds and compresses the challenge page.
const pagePart = "challenge page (templates, gzip)"

// challengePage gives each server's CPU per challenge page and the page's
// size, per policy.
func challengePage(dir string) (any, error) {
	type cost struct {
		Rate  float64 `json:"rate"`
		Us    float64 `json:"us"`    // CPU per page
		Bytes int     `json:"bytes"` // the page before compression
	}
	type row struct {
		Policy    string `json:"policy"`
		Blackwall cost   `json:"blackwall"`
		Anubis    cost   `json:"anubis"`
	}
	split, err := os.ReadFile(filepath.Join(dir, "split.md"))
	if err != nil {
		return nil, err
	}
	tables := parseSplit(string(split))
	pageCost := func(server, policy string) (cost, error) {
		run := server + "-" + policy
		recs, err := readRecords(filepath.Join(dir, run, "results.jsonl"))
		if err != nil {
			return cost{}, err
		}
		if len(recs) != 1 || recs[0].Scenario != "flood" || recs[0].PageBytes == 0 {
			return cost{}, fmt.Errorf("%s: want one flood record with page_bytes", run)
		}
		for _, t := range tables {
			if !strings.HasPrefix(t.profile, run+"-flood-") {
				continue
			}
			for _, p := range t.parts {
				if p.name == pagePart && p.us > 0 {
					return cost{recs[0].Rate, p.us, recs[0].PageBytes}, nil
				}
			}
		}
		return cost{}, fmt.Errorf("%s: no %q in split.md", run, pagePart)
	}
	var rows []row
	for _, policy := range []string{"realistic", "minimal"} {
		r := row{Policy: policy}
		if r.Blackwall, err = pageCost("blackwall", policy); err != nil {
			return nil, err
		}
		if r.Anubis, err = pageCost("anubis", policy); err != nil {
			return nil, err
		}
		rows = append(rows, r)
	}
	return rows, nil
}

func optimizations(load func(string) ([]record, error)) (any, error) {
	type stepOut struct {
		Label string  `json:"label"`
		Value float64 `json:"value"`
	}
	type panelOut struct {
		Title  string    `json:"title"`
		Anubis float64   `json:"anubis"`
		Steps  []stepOut `json:"steps"`
	}
	cpuIn := func(run, server string, c cell) (record, error) {
		recs, err := load(run)
		if err != nil {
			return record{}, err
		}
		cellRecs, err := fixedCell(recs, server, c)
		if err != nil {
			return record{}, fmt.Errorf("%s: %w", run, err)
		}
		return medianRecord(cellRecs, func(r record) float64 { return r.CPU }), nil
	}
	var out []panelOut
	for _, p := range panels {
		an, err := cpuIn(p.anubis, "anubis", p.cell)
		if err != nil {
			return nil, err
		}
		po := panelOut{Title: p.title, Anubis: round(an.CPU, 0)}
		for _, s := range p.steps {
			bw, err := cpuIn(s.run, "blackwall", p.cell)
			if err != nil {
				return nil, err
			}
			if bw.Rate != an.Rate {
				return nil, fmt.Errorf("%q: %s ran at %.0f req/s, Anubis at %.0f", p.title, s.run, bw.Rate, an.Rate)
			}
			po.Steps = append(po.Steps, stepOut{s.label, round(bw.CPU, 0)})
		}
		out = append(out, po)
	}
	return out, nil
}

// visitors gives, per visitor scenario and server, the visitors' latency at
// each flood rate (median of the repeats by p99), and how much of the flood
// the server answered.
func visitors(dir string) (any, error) {
	files, err := filepath.Glob(filepath.Join(dir, "flood*-r*", "results.jsonl"))
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no runs in %s", dir)
	}
	var recs []record
	for _, f := range files {
		r, err := readRecords(f)
		if err != nil {
			return nil, err
		}
		recs = append(recs, r...)
	}

	type point struct {
		Flood         float64 `json:"flood"`
		FloodAchieved float64 `json:"floodAchieved"`
		P50           float64 `json:"p50"`
		P99           float64 `json:"p99"`
		ErrorRate     float64 `json:"errorRate"`
		Pass          bool    `json:"pass"`
	}
	type key struct {
		scenario, server string
		flood            float64
	}
	groups := map[key][]record{}
	for _, r := range recs {
		if r.Flood != nil {
			k := key{r.Scenario, r.Server, r.Flood.Rate}
			groups[k] = append(groups[k], r)
		}
	}
	out := map[string]any{"sloMs": recs[0].SLOms}
	for _, scenario := range []string{"pass", "solve"} {
		perServer := map[string][]point{}
		for _, srv := range servers {
			for k, g := range groups {
				if k.scenario != scenario || k.server != srv {
					continue
				}
				m := medianRecord(g, func(r record) float64 { return r.P99 })
				perServer[srv] = append(perServer[srv], point{
					Flood: k.flood, FloodAchieved: round(m.Flood.Achieved, 0),
					P50: round(m.P50, 2), P99: round(m.P99, 2), ErrorRate: m.ErrorRate, Pass: m.Pass,
				})
			}
			slices.SortFunc(perServer[srv], func(a, b point) int { return cmpFloat(a.Flood, b.Flood) })
		}
		out[scenario] = perServer
	}
	return out, nil
}
