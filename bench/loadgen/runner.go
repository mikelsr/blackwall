package main

import (
	"context"
	"math"
	"slices"
	"sync"
	"time"
)

type job struct {
	seq      uint64
	intended time.Time
}

type workerStats struct {
	ok, errs   uint64
	lat, extra []time.Duration
	errSamples map[string]int
}

func (ws *workerStats) recordErr(err error) {
	ws.errs++
	msg := err.Error()
	if len(msg) > 160 {
		msg = msg[:160]
	}
	if _, seen := ws.errSamples[msg]; seen || len(ws.errSamples) < 8 {
		ws.errSamples[msg]++
	}
}

// PhaseResult is the outcome of running one operation at one fixed rate.
type PhaseResult struct {
	Rate       float64
	Window     time.Duration // measured window (excludes warm-up)
	Sent       uint64        // operations scheduled inside the window
	Issued     uint64        // operations queued, warm-up included
	OK         uint64
	Errors     uint64
	Dropped    uint64 // could not even be queued: the server fell far behind
	Latencies  []time.Duration
	Extra      []time.Duration
	ErrSamples map[string]int
	Proc       *procWindow
}

// runPhase drives op open-loop at `rate` operations per second. Operations
// are scheduled at fixed intervals regardless of how fast responses come
// back, and latency is measured from the scheduled start time, which avoids
// coordinated omission: if the server stalls, queued operations accumulate
// that stall in their latency instead of silently lowering the offered load.
func runPhase(ctx context.Context, op opFunc, rate float64, warmup, window time.Duration, workers, pid int) PhaseResult {
	total := warmup + window
	n := uint64(rate * total.Seconds())

	queueCap := int(rate) // up to ~1s of backlog before we start dropping
	queueCap = max(queueCap, 1024)
	queueCap = min(queueCap, 1<<20)
	jobs := make(chan job, queueCap)

	start := time.Now().Add(20 * time.Millisecond)
	measureStart := start.Add(warmup)

	stats := make([]*workerStats, workers)
	var wg sync.WaitGroup
	for w := range workers {
		ws := &workerStats{errSamples: map[string]int{}}
		stats[w] = ws
		wg.Go(func() {
			for j := range jobs {
				if ctx.Err() != nil {
					continue
				}
				extra, err := op(ctx, j.seq)
				done := time.Now()
				if j.intended.Before(measureStart) {
					continue
				}
				if err != nil {
					ws.recordErr(err)
					continue
				}
				ws.ok++
				ws.lat = append(ws.lat, done.Sub(j.intended))
				if extra > 0 {
					ws.extra = append(ws.extra, extra)
				}
			}
		})
	}

	var sampler *procSampler
	if pid > 0 {
		sampler = startProcSampler(pid, measureStart)
	}

	var sent, dropped, issued uint64
	nanosPerOp := float64(time.Second) / rate
	for i := uint64(0); i < n && ctx.Err() == nil; {
		now := time.Now()
		if now.Before(start) {
			time.Sleep(start.Sub(now))
			continue
		}
		due := min(uint64(float64(now.Sub(start))/nanosPerOp)+1, n)
		for ; i < due; i++ {
			intended := start.Add(time.Duration(float64(i) * nanosPerOp))
			inWindow := !intended.Before(measureStart)
			if inWindow {
				sent++
			}
			select {
			case jobs <- job{seq: i, intended: intended}:
				issued++
			default:
				if inWindow {
					dropped++
				}
			}
		}
		time.Sleep(100 * time.Microsecond)
	}
	close(jobs)
	wg.Wait()

	res := PhaseResult{
		Rate:       rate,
		Window:     window,
		Sent:       sent,
		Issued:     issued,
		Dropped:    dropped,
		ErrSamples: map[string]int{},
	}
	if sampler != nil {
		res.Proc = sampler.stop()
	}
	for _, ws := range stats {
		res.OK += ws.ok
		res.Errors += ws.errs
		res.Latencies = append(res.Latencies, ws.lat...)
		res.Extra = append(res.Extra, ws.extra...)
		for k, v := range ws.errSamples {
			res.ErrSamples[k] += v
		}
	}
	slices.Sort(res.Latencies)
	slices.Sort(res.Extra)
	return res
}

func percentile(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(math.Ceil(p*float64(len(sorted)))) - 1
	idx = max(idx, 0)
	idx = min(idx, len(sorted)-1)
	return sorted[idx]
}

func ms(d time.Duration) float64 {
	return float64(d) / float64(time.Millisecond)
}
