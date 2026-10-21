package main

// Diagnostic runs that look inside the two servers rather than compare them
// as shipped: Anubis with small patches, where Anubis's allocations come
// from, and what each server's idle memory is made of.

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Anubis with patches found by profiling (bench/results/<run>/bin holds the
// builds): one run per variant, cell and repeat, named
// fixed-<variant>-<policy>-<scenario>-<rate>-r<repeat> and
// sweep-<variant>-<policy>-<scenario>-r<repeat>, each fixed run with a
// per-second sample of the server's kernel counters in <run>.tsv. Runs
// renamed *-perturbed overlapped other work on the box and were rerun.
const patchedRun = "anubis-tweaks"

// Anubis variants in the order the graphs show them; "blackwall" is
// Blackwall in the same session, for reference.
var patchedVariants = []string{"ship", "bufpool", "idlepool", "regex1", "all"}

// Seconds of a fixed run's <run>.tsv that are inside the load (warm-up 3 s
// and window 20 s, starting about a second after the server).
const sampleFrom, sampleTo = 6, 20

var patchedFixedName = regexp.MustCompile(`^fixed-(\w+)-(\w+)-(\w+)-(\d+)-r(\d+)$`)
var patchedSweepName = regexp.MustCompile(`^sweep-(\w+)-(\w+)-(\w+)-r(\d+)$`)

// anubisPatched gives, per cell, each variant's CPU and context switches per
// request at a fixed rate (median of the repeats) and each variant's max rate
// per sweep repeat. Blackwall's max rates come from the main sweep.
func anubisPatched(dir string, sweep []record) (any, error) {
	type load struct {
		cpuSplit
		Voluntary   float64 `json:"voluntary"`   // context switches per request
		Involuntary float64 `json:"involuntary"` // preemptions per request
	}
	type fixedRow struct {
		Policy   string          `json:"policy"`
		Scenario string          `json:"scenario"`
		Rate     float64         `json:"rate"`
		Variants map[string]load `json:"variants"`
	}
	type sweepRow struct {
		Policy   string               `json:"policy"`
		Scenario string               `json:"scenario"`
		Variants map[string][]float64 `json:"variants"`
	}
	runs, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	type fixedKey struct {
		policy, scenario string
		rate             float64
	}
	type sample struct {
		rec      record
		vol, inv float64
	}
	fixed := map[fixedKey]map[string][]sample{}
	sweeps := map[[2]string]map[string][]float64{}
	for _, e := range runs {
		name := e.Name()
		// Skips logs, counters, the builds (bin) and the runs an unpinned
		// process overlapped (*-perturbed, rerun under the plain name).
		if !e.IsDir() || !patchedFixedName.MatchString(name) && !patchedSweepName.MatchString(name) {
			continue
		}
		recs, err := readRecords(filepath.Join(dir, name, "results.jsonl"))
		if err != nil {
			return nil, err
		}
		if m := patchedFixedName.FindStringSubmatch(name); m != nil {
			if len(recs) != 1 {
				return nil, fmt.Errorf("%s: want one record, got %d", name, len(recs))
			}
			vol, inv, err := switchesPerRequest(filepath.Join(dir, name+".tsv"), recs[0].Rate)
			if err != nil {
				return nil, err
			}
			k := fixedKey{m[2], m[3], recs[0].Rate}
			if fixed[k] == nil {
				fixed[k] = map[string][]sample{}
			}
			fixed[k][m[1]] = append(fixed[k][m[1]], sample{recs[0], vol, inv})
		} else if m := patchedSweepName.FindStringSubmatch(name); m != nil {
			k := [2]string{m[2], m[3]}
			if sweeps[k] == nil {
				sweeps[k] = map[string][]float64{}
			}
			sweeps[k][m[1]] = append(sweeps[k][m[1]], maxRate(recs))
		}
	}
	if len(fixed) == 0 || len(sweeps) == 0 {
		return nil, fmt.Errorf("no fixed or sweep runs in %s", dir)
	}

	var fixedRows []fixedRow
	for k, byVariant := range fixed {
		r := fixedRow{Policy: k.policy, Scenario: k.scenario, Rate: k.rate, Variants: map[string]load{}}
		for v, samples := range byVariant {
			recs := make([]record, len(samples))
			var vol, inv []float64
			for i, s := range samples {
				recs[i], vol, inv = s.rec, append(vol, s.vol), append(inv, s.inv)
			}
			r.Variants[v] = load{splitOf(recs), round(median(vol), 2), round(median(inv), 2)}
		}
		fixedRows = append(fixedRows, r)
	}
	slices.SortFunc(fixedRows, func(a, b fixedRow) int {
		return cmpCell(a.Policy, a.Scenario, a.Rate, b.Policy, b.Scenario, b.Rate)
	})

	var sweepRows []sweepRow
	for k, byVariant := range sweeps {
		c := cell{k[0], k[1], kib}
		reps := byRepeat(sweep, "sweep", "blackwall", c)
		if len(reps) == 0 {
			return nil, fmt.Errorf("no Blackwall sweep for %v", c)
		}
		for _, steps := range reps {
			byVariant["blackwall"] = append(byVariant["blackwall"], maxRate(steps))
		}
		sweepRows = append(sweepRows, sweepRow{k[0], k[1], byVariant})
	}
	slices.SortFunc(sweepRows, func(a, b sweepRow) int {
		return cmpCell(a.Policy, a.Scenario, 0, b.Policy, b.Scenario, 0)
	})
	return map[string]any{"variants": patchedVariants, "fixed": fixedRows, "sweep": sweepRows}, nil
}

// cmpCell orders stock rules before minimal ones, then by scenario and rate.
func cmpCell(policyA, scenarioA string, rateA float64, policyB, scenarioB string, rateB float64) int {
	if policyA != policyB {
		return -strings.Compare(policyA, policyB) // "realistic" first
	}
	if scenarioA != scenarioB {
		return strings.Compare(scenarioA, scenarioB)
	}
	return cmpFloat(rateA, rateB)
}

// switchesPerRequest reads a fixed run's per-second counters (t minflt vcsw
// nvcsw syscr syscw cpu_ms, cumulative) and gives the voluntary and
// involuntary context switches per request between sampleFrom and sampleTo.
func switchesPerRequest(path string, rate float64) (vol, inv float64, err error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, 0, err
	}
	defer func() { _ = f.Close() }()
	at := map[int][]float64{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		cols := strings.Fields(sc.Text())
		if len(cols) != 7 {
			continue
		}
		t, err := strconv.Atoi(cols[0])
		if err != nil {
			continue // header
		}
		vals := make([]float64, len(cols))
		for i, c := range cols {
			if vals[i], err = strconv.ParseFloat(c, 64); err != nil {
				return 0, 0, fmt.Errorf("%s: %w", path, err)
			}
		}
		at[t] = vals
	}
	a, b := at[sampleFrom], at[sampleTo]
	if a == nil || b == nil {
		return 0, 0, fmt.Errorf("%s: no samples at %d s and %d s", path, sampleFrom, sampleTo)
	}
	requests := rate * (sampleTo - sampleFrom)
	return (b[2] - a[2]) / requests, (b[3] - a[3]) / requests, sc.Err()
}

// Anubis's allocation profiles: one directory per cell
// (<policy>-<scenario>-<rate>), each with the cumulative allocation profiles
// at the start and end of a window of allocWindow seconds (allocs-0.pb,
// allocs-1.pb) and the run's results under run/.
const allocRun = "alloc-profile"

const allocWindow = 28

// Every allocated byte goes to the first part, in this order, that matches
// any frame of its stack.
var allocParts = []struct {
	key     string
	pattern *regexp.Regexp
}{
	{"copyBuffer", regexp.MustCompile(`httputil\.\(\*ReverseProxy\)\.copyBuffer`)},
	{"extras", regexp.MustCompile(`log/slog|anubis/lib/localization|golang\.org/x/text|go-i18n|prometheus`)},
	{"newConns", regexp.MustCompile(`net/http\.\(\*Transport\)\.dialConn`)},
	{"challenge", regexp.MustCompile(`anubis/lib/challenge|anubis/lib/store|a-h/templ|anubis/web|compress/|golang-jwt|issueChallenge|RenderIndex|PassChallenge`)},
	{"http", regexp.MustCompile(`net/http|net/textproto|httputil|context\.`)},
}

var allocCellName = regexp.MustCompile(`^(\w+)-(\w+)-(\d+)$`)

// anubisAllocs gives Anubis's bytes allocated per request, per part, for each
// profiled cell.
func anubisAllocs(dir string) (any, error) {
	type row struct {
		Policy   string             `json:"policy"`
		Scenario string             `json:"scenario"`
		Rate     float64            `json:"rate"`
		KiB      map[string]float64 `json:"kib"` // per request, per part; "other" is the rest
	}
	cellDirs, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var rows []row
	for _, e := range cellDirs {
		m := allocCellName.FindStringSubmatch(e.Name())
		if !e.IsDir() || m == nil {
			continue
		}
		rate, _ := strconv.ParseFloat(m[3], 64)
		start, err := allocBytes(filepath.Join(dir, e.Name(), "allocs-0.pb"))
		if err != nil {
			return nil, err
		}
		end, err := allocBytes(filepath.Join(dir, e.Name(), "allocs-1.pb"))
		if err != nil {
			return nil, err
		}
		r := row{Policy: m[1], Scenario: m[2], Rate: rate, KiB: map[string]float64{}}
		for part, bytes := range end {
			r.KiB[part] = round((bytes-start[part])/(rate*allocWindow)/1024, 2)
		}
		rows = append(rows, r)
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("no allocation profiles in %s", dir)
	}
	slices.SortFunc(rows, func(a, b row) int { return cmpCell(a.Policy, a.Scenario, a.Rate, b.Policy, b.Scenario, b.Rate) })
	return rows, nil
}

// allocBytes sums an allocation profile's bytes per part of allocParts.
func allocBytes(path string) (map[string]float64, error) {
	out, err := exec.Command("go", "tool", "pprof", "-traces", "-sample_index=alloc_space", path).Output()
	if err != nil {
		return nil, fmt.Errorf("pprof %s: %w", path, err)
	}
	sums := map[string]float64{"other": 0}
	for _, p := range allocParts {
		sums[p.key] = 0
	}
	// Each sample: a separator line, "bytes: <size>", then "<value> <frame>"
	// and one frame per line after it, leaf first.
	var value float64
	var frames []string
	flush := func() {
		if value == 0 {
			return
		}
		part := "other"
		for _, p := range allocParts {
			if slices.ContainsFunc(frames, p.pattern.MatchString) {
				part = p.key
				break
			}
		}
		sums[part] += value
		value, frames = 0, nil
	}
	for line := range strings.Lines(string(out)) {
		fields := strings.Fields(line)
		switch {
		case strings.HasPrefix(line, "-----------+"):
			flush()
		case len(fields) == 0 || fields[0] == "bytes:":
		case value == 0:
			v, err := parseBytes(fields[0])
			if err != nil {
				continue // the header before the first sample
			}
			value, frames = v, []string{strings.Join(fields[1:], " ")}
		default:
			frames = append(frames, strings.Join(fields, " "))
		}
	}
	flush()
	return sums, nil
}

// parseBytes reads pprof's sizes ("512.01kB", "1.50MB"), which count in 1024s.
func parseBytes(s string) (float64, error) {
	for i, unit := range []string{"GB", "MB", "kB", "B"} {
		if num, ok := strings.CutSuffix(s, unit); ok {
			v, err := strconv.ParseFloat(num, 64)
			if err != nil {
				return 0, err
			}
			for range 3 - i {
				v *= 1024
			}
			return v, nil
		}
	}
	return 0, fmt.Errorf("not a size: %q", s)
}

// Idle memory per mapping kind, from idle-mem.sh: lines of
// "<server> <policy> <repeat> <kind> <MB>", kind binary (the program's own
// file), files (other mapped files) or private (anonymous memory).
const idleMemRun = "idle-mem"

func idleMemory(dir string) (any, error) {
	rows, err := readIdleMem(filepath.Join(dir, "idle-mem.tsv"))
	if err != nil {
		return nil, err
	}
	type key struct{ policy, server, kind string }
	repeats := map[key][]float64{}
	for _, r := range rows {
		k := key{r.policy, r.server, r.kind}
		repeats[k] = append(repeats[k], r.mb)
	}
	out := map[string]map[string]map[string]float64{} // policy, server, kind: median MB
	for k, mbs := range repeats {
		if out[k.policy] == nil {
			out[k.policy] = map[string]map[string]float64{}
		}
		if out[k.policy][k.server] == nil {
			out[k.policy][k.server] = map[string]float64{}
		}
		out[k.policy][k.server][k.kind] = round(median(mbs), 1)
	}
	return out, nil
}

type idleMemRow struct {
	server, policy, kind string
	mb                   float64
}

// readIdleMem reads an idle-mem.tsv.
func readIdleMem(path string) ([]idleMemRow, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	var rows []idleMemRow
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		cols := strings.Fields(sc.Text())
		if len(cols) != 5 {
			continue
		}
		mb, err := strconv.ParseFloat(cols[4], 64)
		if err != nil {
			continue // header
		}
		rows = append(rows, idleMemRow{cols[0], cols[1], cols[3], mb})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("no rows in %s", path)
	}
	return rows, nil
}
