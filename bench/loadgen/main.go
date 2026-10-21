// Command loadgen is an open-loop HTTP load generator that benchmarks
// Blackwall and Anubis on equal terms.
//
//	loadgen run -flavor blackwall -target http://127.0.0.1:18923 -scenario flood -rates 1000,2000,4000
//	loadgen run -flavor blackwall -target http://127.0.0.1:18923 -scenario pass -rates 100 -flood-rate 4000
//	loadgen summary results/*/results.jsonl
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "run":
		err = cmdRun(os.Args[2:])
	case "summary":
		err = cmdSummary(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: loadgen run [flags] | loadgen summary FILE...")
	fmt.Fprintln(os.Stderr, "scenarios:")
	for _, name := range []string{"direct", "allow", "deny", "flood", "solve", "pass", "upload", "conns"} {
		fmt.Fprintf(os.Stderr, "  %-7s %s\n", name, scenarioDescriptions[name])
	}
}

// floodAddrOffset moves the flood's client addresses (ipFor) past the ones
// visitors use: sequence numbers from 0, and the 1<<22 and 1<<23 blocks.
const floodAddrOffset = 1 << 20

// FloodStats is how the bot flood itself fared.
type FloodStats struct {
	Rate      float64 `json:"rate"`
	Achieved  float64 `json:"achieved"`
	ErrorRate float64 `json:"error_rate"`
	P99       float64 `json:"p99_ms"`
}

// Record is one measured phase, written as a JSON line.
type Record struct {
	Server     string  `json:"server"`
	Flavor     string  `json:"flavor"`
	Policy     string  `json:"policy"`
	Scenario   string  `json:"scenario"`
	Mode       string  `json:"mode"`
	Repeat     int     `json:"repeat"`
	Cores      int     `json:"cores"`
	SizeBytes  int     `json:"size_bytes,omitempty"`
	SLOms      float64 `json:"slo_ms"`
	Rate       float64 `json:"rate"`
	Achieved   float64 `json:"achieved"`
	WindowS    float64 `json:"window_s"`
	Sent       uint64  `json:"sent"`
	OK         uint64  `json:"ok"`
	Errors     uint64  `json:"errors"`
	Dropped    uint64  `json:"dropped"`
	ErrorRate  float64 `json:"error_rate"`
	P50        float64 `json:"p50_ms"`
	P90        float64 `json:"p90_ms"`
	P99        float64 `json:"p99_ms"`
	P999       float64 `json:"p999_ms"`
	Max        float64 `json:"max_ms"`
	ExtraP50   float64 `json:"extra_p50_ms,omitempty"`
	ExtraP99   float64 `json:"extra_p99_ms,omitempty"`
	CPUSeconds float64 `json:"cpu_s"`
	CPUUsPerOp float64 `json:"cpu_us_per_op"`
	// CPUUsPerOp split into the server's own code and the kernel.
	UserUsPerOp float64 `json:"user_us_per_op"`
	SysUsPerOp  float64 `json:"sys_us_per_op"`
	CoresUsed   float64 `json:"cores_used"`
	RSSStartMB  float64 `json:"rss_start_mb"`
	RSSPeakMB   float64 `json:"rss_peak_mb"`
	RSSEndMB    float64 `json:"rss_end_mb"`
	ProcErr     string  `json:"proc_err,omitempty"`
	// Throughput in body bytes (sized scenarios only).
	MBps float64 `json:"mb_per_s,omitempty"`
	// flood: the challenge page's size before compression.
	PageBytes int `json:"page_bytes,omitempty"`
	// Upstream connections the proxy opened per 1000 operations.
	UpstreamConnsPer1k *float64 `json:"upstream_conns_per_1k,omitempty"`
	// conns scenario.
	Conns         int     `json:"conns,omitempty"`
	ConnsOpened   int     `json:"conns_opened,omitempty"`
	RSSBaselineMB float64 `json:"rss_baseline_mb,omitempty"`
	KBPerConn     float64 `json:"kb_per_conn,omitempty"`
	AliveSample   string  `json:"alive_sample,omitempty"`
	OpenSeconds   float64 `json:"open_s,omitempty"`
	// The bot flood that ran alongside (-flood-rate). The rest of the record
	// covers the other scenario's requests (the visitors) only.
	Flood      *FloodStats    `json:"flood,omitempty"`
	Pass       bool           `json:"pass"`
	ErrSamples map[string]int `json:"err_samples,omitempty"`
}

func cmdRun(args []string) (err error) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	var (
		flavor     = fs.String("flavor", "", "challenge page format: blackwall | anubis")
		target     = fs.String("target", "", "proxy base URL, e.g. http://127.0.0.1:18923")
		backend    = fs.String("backend", "http://127.0.0.1:18080", "backend base URL (direct scenario)")
		scenario   = fs.String("scenario", "flood", "direct | allow | deny | flood | solve | pass | upload | conns")
		ratesFlag  = fs.String("rates", "1000,2000,4000,8000,16000", "comma-separated offered rates (ops/s), ascending")
		window     = fs.Duration("duration", 15*time.Second, "measured window per rate")
		warmup     = fs.Duration("warmup", 3*time.Second, "warm-up per rate (not measured)")
		pause      = fs.Duration("pause", 2*time.Second, "pause between rates")
		slo        = fs.Duration("slo", 10*time.Millisecond, "p99 latency objective")
		maxErrRate = fs.Float64("max-error-rate", 0.001, "maximum error ratio for a rate to pass")
		workers    = fs.Int("workers", 1024, "maximum in-flight operations")
		pid        = fs.Int("pid", 0, "server PID to sample CPU/RSS from (0 = off)")
		tokens     = fs.Int("tokens", 256, "auth cookies to mint for the pass scenario")
		stopOnFail = fs.Bool("stop-on-fail", true, "stop the sweep at the first failing rate")
		refine     = fs.Int("refine", 2, "bisection steps between the last passing and first failing rate")
		out        = fs.String("out", "", "append JSON lines to this file")
		server     = fs.String("server", "", "label for the server (defaults to flavor)")
		policy     = fs.String("policy", "", "label for the policy")
		mode       = fs.String("mode", "sweep", "label: sweep | fixed")
		repeat     = fs.Int("repeat", 1, "label: repeat number")
		cores      = fs.Int("cores", 0, "label: cores given to the server")
		size       = fs.Int("size", 512, "body size in bytes for direct/allow/pass (response) and upload (request)")
		conns      = fs.Int("conns", 1000, "conns scenario: idle connections to open")
		settle     = fs.Duration("settle", 3*time.Second, "conns scenario: wait before reading RSS")
		probes     = fs.Int("probes", 200, "conns scenario: latency probes while connections are open")
		floodRate  = fs.Float64("flood-rate", 0, "also run a bot flood (the flood scenario) at this rate, on its own connections; the record covers the -scenario requests")
	)
	_ = fs.Parse(args)

	fl := Flavor(*flavor)
	if *scenario != "direct" && fl != FlavorBlackwall && fl != FlavorAnubis {
		return fmt.Errorf("-flavor must be blackwall or anubis")
	}
	if *scenario != "direct" && *target == "" {
		return fmt.Errorf("-target is required")
	}
	if *server == "" {
		*server = string(fl)
	}
	rates, err := parseRates(*ratesFlag)
	if err != nil {
		return err
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	var outFile *os.File
	if *out != "" {
		outFile, err = os.OpenFile(*out, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
		// Records are written as they come; a failed close may mean the last ones were lost.
		defer func() { err = errors.Join(err, outFile.Close()) }()
	}
	writeRecord := func(rec Record) error {
		if outFile == nil {
			return nil
		}
		b, _ := json.Marshal(rec)
		_, err := outFile.Write(append(b, '\n'))
		return err
	}

	client := newHTTPClient(*workers)

	if *scenario == "conns" {
		fmt.Printf("# %s / %s / conns: %s\n", *server, *policy, scenarioDescriptions["conns"])
		rec, err := runConns(ctx, connsConfig{
			target:   strings.TrimRight(*target, "/"),
			conns:    *conns,
			pid:      *pid,
			settle:   *settle,
			probes:   *probes,
			parallel: 64,
			client:   newHTTPClient(8),
		})
		if err != nil {
			return err
		}
		rec.Server, rec.Flavor, rec.Policy = *server, string(fl), *policy
		rec.Repeat, rec.Cores = *repeat, *cores
		printConnsRow(rec)
		return writeRecord(rec)
	}

	if !sizedScenarios[*scenario] {
		*size = 0
	}
	prepared, err := buildScenario(ctx, scenarioConfig{
		name:    *scenario,
		flavor:  fl,
		target:  *target,
		backend: *backend,
		tokens:  *tokens,
		size:    *size,
		client:  client,
	})
	if err != nil {
		return err
	}

	// The flood gets its own connections and client addresses, as bots and
	// visitors share neither.
	var floodOp opFunc
	if *floodRate > 0 {
		flood, err := buildScenario(ctx, scenarioConfig{
			name:   "flood",
			flavor: fl,
			target: *target,
			client: newHTTPClient(*workers),
		})
		if err != nil {
			return fmt.Errorf("flood: %w", err)
		}
		floodOp = func(ctx context.Context, seq uint64) (time.Duration, error) {
			return flood.op(ctx, seq+floodAddrOffset)
		}
	}

	// Upstream connection counting only makes sense when the request goes
	// through a proxy to the backend.
	countUpstream := *scenario == "allow" || *scenario == "pass" || *scenario == "upload"
	statsClient := newHTTPClient(1)

	sizeLabel := ""
	if *size > 0 {
		sizeLabel = " [" + humanBytes(*size) + "]"
	}
	fmt.Printf("# %s / %s / %s%s: %s\n", *server, *policy, *scenario, sizeLabel, scenarioDescriptions[*scenario])
	fmt.Printf("# loadgen GOMAXPROCS=%d workers=%d window=%s warmup=%s slo(p99)=%s\n",
		runtime.GOMAXPROCS(0), *workers, *window, *warmup, *slo)
	cols := rowColumns{solve: *scenario == "solve", sized: *size > 0, upstream: countUpstream}
	printHeader(cols)

	runRate := func(rate float64) (Record, error) {
		var before int64 = -1
		if countUpstream {
			if v, err := backendAccepted(ctx, statsClient, *backend); err == nil {
				before = v
			}
		}
		var flood PhaseResult
		var floodWG sync.WaitGroup
		if floodOp != nil {
			floodWG.Go(func() { flood = runPhase(ctx, floodOp, *floodRate, *warmup, *window, *workers, 0) })
		}
		res := runPhase(ctx, prepared.op, rate, *warmup, *window, *workers, *pid)
		floodWG.Wait()
		rec := makeRecord(res, *slo, *maxErrRate)
		if floodOp != nil {
			f := makeRecord(flood, *slo, *maxErrRate)
			rec.Flood = &FloodStats{Rate: f.Rate, Achieved: f.Achieved, ErrorRate: f.ErrorRate, P99: f.P99}
			// The server's CPU went to visitors and bots alike.
			if res.Proc != nil {
				setPerOp(&rec, res.Proc, res.OK+res.Errors+flood.OK+flood.Errors)
			}
		}
		rec.Server, rec.Flavor, rec.Policy, rec.Scenario = *server, string(fl), *policy, *scenario
		rec.Mode, rec.Repeat, rec.Cores = *mode, *repeat, *cores
		rec.SizeBytes = *size
		rec.PageBytes = prepared.pageBytes
		if *size > 0 {
			rec.MBps = rec.Achieved * float64(*size) / 1e6
		}
		if before >= 0 && res.Issued > 0 {
			if after, err := backendAccepted(ctx, statsClient, *backend); err == nil {
				v := float64(after-before) * 1000 / float64(res.Issued)
				rec.UpstreamConnsPer1k = &v
			}
		}
		printRow(rec, cols)
		if err := writeRecord(rec); err != nil {
			return rec, err
		}
		if ctx.Err() != nil {
			return rec, ctx.Err()
		}
		time.Sleep(*pause)
		return rec, nil
	}

	var lastPass, firstFail float64
	for _, rate := range rates {
		rec, err := runRate(rate)
		if err != nil {
			return err
		}
		if rec.Pass {
			lastPass = rate
			continue
		}
		firstFail = rate
		if *stopOnFail {
			break
		}
	}

	for step := 0; step < *refine && firstFail > 0; step++ {
		mid := (lastPass + firstFail) / 2
		if firstFail-lastPass < firstFail*0.05 {
			break
		}
		mid = float64(int64(mid))
		rec, err := runRate(mid)
		if err != nil {
			return err
		}
		if rec.Pass {
			lastPass = mid
		} else {
			firstFail = mid
		}
	}

	if *mode == "sweep" {
		fmt.Printf("# max sustainable rate (p99 <= %s, errors <= %.2f%%): %.0f ops/s\n\n",
			*slo, *maxErrRate*100, lastPass)
	}
	return nil
}

func printConnsRow(r Record) {
	result := "PASS"
	if !r.Pass {
		result = "FAIL"
	}
	fmt.Printf("%8s %8s %8s %10s %10s %9s %9s %8s %7s %s\n",
		"conns", "opened", "open_s", "rss_base", "rss_at_n", "kb/conn", "probe50", "probe99", "alive", "result")
	fmt.Printf("%8d %8d %8.1f %10.1f %10.1f %9.1f %9.2f %8.2f %7s %s\n",
		r.Conns, r.ConnsOpened, r.OpenSeconds, r.RSSBaselineMB, r.RSSEndMB, r.KBPerConn, r.P50, r.P99, r.AliveSample, result)
	for msg, n := range r.ErrSamples {
		fmt.Printf("          error x%d: %s\n", n, msg)
	}
	fmt.Println()
}

func humanBytes(n int) string {
	switch {
	case n >= 1<<20 && n%(1<<20) == 0:
		return fmt.Sprintf("%dMiB", n>>20)
	case n >= 1<<10 && n%(1<<10) == 0:
		return fmt.Sprintf("%dKiB", n>>10)
	}
	return fmt.Sprintf("%dB", n)
}

func parseRates(s string) ([]float64, error) {
	var rates []float64
	for part := range strings.SplitSeq(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		v, err := strconv.ParseFloat(part, 64)
		if err != nil || v <= 0 {
			return nil, fmt.Errorf("invalid rate %q", part)
		}
		rates = append(rates, v)
	}
	if len(rates) == 0 {
		return nil, fmt.Errorf("no rates given")
	}
	slices.Sort(rates)
	return rates, nil
}

func makeRecord(res PhaseResult, slo time.Duration, maxErrRate float64) Record {
	rec := Record{
		SLOms:    ms(slo),
		Rate:     res.Rate,
		WindowS:  res.Window.Seconds(),
		Sent:     res.Sent,
		OK:       res.OK,
		Errors:   res.Errors,
		Dropped:  res.Dropped,
		Achieved: float64(res.OK) / res.Window.Seconds(),
		P50:      ms(percentile(res.Latencies, 0.50)),
		P90:      ms(percentile(res.Latencies, 0.90)),
		P99:      ms(percentile(res.Latencies, 0.99)),
		P999:     ms(percentile(res.Latencies, 0.999)),
		ExtraP50: ms(percentile(res.Extra, 0.50)),
		ExtraP99: ms(percentile(res.Extra, 0.99)),
	}
	if n := len(res.Latencies); n > 0 {
		rec.Max = ms(res.Latencies[n-1])
	}
	if res.Sent > 0 {
		rec.ErrorRate = float64(res.Errors+res.Dropped) / float64(res.Sent)
	}
	if len(res.ErrSamples) > 0 {
		rec.ErrSamples = res.ErrSamples
	}
	if p := res.Proc; p != nil {
		rec.ProcErr = p.Err
		rec.CPUSeconds = p.CPUSeconds
		if p.Span > 0 {
			rec.CoresUsed = p.CPUSeconds / p.Span.Seconds()
		}
		setPerOp(&rec, p, res.OK+res.Errors)
		rec.RSSStartMB = float64(p.RSSStartKB) / 1024
		rec.RSSPeakMB = float64(p.RSSPeakKB) / 1024
		rec.RSSEndMB = float64(p.RSSEndKB) / 1024
	}
	rec.Pass = res.OK > 0 && res.Dropped == 0 && rec.ErrorRate <= maxErrRate && rec.P99 <= rec.SLOms
	return rec
}

// setPerOp spreads the server's CPU time over the `done` operations it served.
func setPerOp(rec *Record, p *procWindow, done uint64) {
	if done == 0 {
		return
	}
	rec.CPUUsPerOp = p.CPUSeconds * 1e6 / float64(done)
	rec.UserUsPerOp = p.UserSeconds * 1e6 / float64(done)
	rec.SysUsPerOp = rec.CPUUsPerOp - rec.UserUsPerOp
}

type rowColumns struct {
	solve, sized, upstream bool
}

func printHeader(c rowColumns) {
	fmt.Printf("%9s %9s %8s %8s %8s %8s %7s %7s %9s %7s %7s %6s %8s",
		"rate", "achieved", "p50ms", "p99ms", "p99.9ms", "maxms", "err%", "drop", "cpu_us/op", "usr_us", "sys_us", "cores", "rss_pk")
	if c.solve {
		fmt.Printf(" %10s", "pass_p99ms")
	}
	if c.sized {
		fmt.Printf(" %9s", "MB/s")
	}
	if c.upstream {
		fmt.Printf(" %8s", "up/1k")
	}
	fmt.Printf(" %s\n", "result")
}

func printRow(r Record, c rowColumns) {
	result := "PASS"
	if !r.Pass {
		result = "FAIL"
	}
	fmt.Printf("%9.0f %9.0f %8.2f %8.2f %8.2f %8.2f %7.3f %7d %9.1f %7.1f %7.1f %6.2f %8.1f",
		r.Rate, r.Achieved, r.P50, r.P99, r.P999, r.Max, r.ErrorRate*100, r.Dropped,
		r.CPUUsPerOp, r.UserUsPerOp, r.SysUsPerOp, r.CoresUsed, r.RSSPeakMB)
	if c.solve {
		fmt.Printf(" %10.2f", r.ExtraP99)
	}
	if c.sized {
		fmt.Printf(" %9.1f", r.MBps)
	}
	if c.upstream {
		if r.UpstreamConnsPer1k != nil {
			fmt.Printf(" %8.1f", *r.UpstreamConnsPer1k)
		} else {
			fmt.Printf(" %8s", "-")
		}
	}
	fmt.Printf(" %s\n", result)
	for msg, n := range r.ErrSamples {
		fmt.Printf("          error x%d: %s\n", n, msg)
	}
	if r.ProcErr != "" {
		fmt.Printf("          proc sampling: %s\n", r.ProcErr)
	}
	if f := r.Flood; f != nil {
		fmt.Printf("          flood: rate %.0f, achieved %.0f, err %.3f%%, p99 %.2f ms\n", f.Rate, f.Achieved, f.ErrorRate*100, f.P99)
	}
}
