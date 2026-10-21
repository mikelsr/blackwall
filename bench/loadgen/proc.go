package main

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// procWindow is the server-side resource usage from the start of a measured
// window until every in-flight request has finished. On an overloaded step the
// drain can take seconds, so Span (the sampled wall time) is longer than the
// window.
type procWindow struct {
	CPUSeconds float64
	// UserSeconds is the part of CPUSeconds spent in the process's own code;
	// the rest is kernel time (syscalls, and on Linux loopback TCP processing).
	UserSeconds float64
	Span        time.Duration
	RSSStartKB  int64
	RSSPeakKB   int64
	RSSEndKB    int64
	Err         string
}

type procSample struct {
	cpuSeconds  float64
	userSeconds float64
	rssKB       int64
}

// Linux reports CPU time in clock ticks; USER_HZ is 100 on every mainstream
// distribution and architecture.
const linuxClockTicks = 100

func readProc(pid int) (procSample, error) {
	if b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid)); err == nil {
		s := string(b)
		// The command name may contain spaces, skip past its closing paren.
		idx := strings.LastIndexByte(s, ')')
		if idx < 0 || idx+2 > len(s) {
			return procSample{}, fmt.Errorf("unexpected /proc stat format")
		}
		f := strings.Fields(s[idx+2:])
		// f[0] is field 3 (state); utime=14, stime=15, rss=24.
		if len(f) < 22 {
			return procSample{}, fmt.Errorf("short /proc stat")
		}
		utime, _ := strconv.ParseFloat(f[11], 64)
		stime, _ := strconv.ParseFloat(f[12], 64)
		rssPages, _ := strconv.ParseInt(f[21], 10, 64)
		return procSample{
			cpuSeconds:  (utime + stime) / linuxClockTicks,
			userSeconds: utime / linuxClockTicks,
			rssKB:       rssPages * int64(os.Getpagesize()) / 1024,
		}, nil
	}

	// macOS / BSD fallback (10ms CPU resolution).
	out, err := exec.Command("ps", "-o", "rss=,utime=,time=", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		return procSample{}, fmt.Errorf("ps: %w", err)
	}
	fields := strings.Fields(string(out))
	if len(fields) < 3 {
		return procSample{}, fmt.Errorf("unexpected ps output %q", out)
	}
	rss, err := strconv.ParseInt(fields[0], 10, 64)
	if err != nil {
		return procSample{}, fmt.Errorf("ps rss: %w", err)
	}
	user, err := parseCPUTime(fields[1])
	if err != nil {
		return procSample{}, err
	}
	cpu, err := parseCPUTime(fields[2])
	if err != nil {
		return procSample{}, err
	}
	return procSample{cpuSeconds: cpu, userSeconds: user, rssKB: rss}, nil
}

// parseCPUTime parses ps time formats: "1:02.34", "1:02:03.45", "1-02:03:04".
func parseCPUTime(s string) (float64, error) {
	var days float64
	if d, rest, ok := strings.Cut(s, "-"); ok {
		v, err := strconv.ParseFloat(d, 64)
		if err != nil {
			return 0, fmt.Errorf("cpu time %q: %w", s, err)
		}
		days, s = v, rest
	}
	var total float64
	for part := range strings.SplitSeq(s, ":") {
		v, err := strconv.ParseFloat(part, 64)
		if err != nil {
			return 0, fmt.Errorf("cpu time %q: %w", s, err)
		}
		total = total*60 + v
	}
	return days*86400 + total, nil
}

type procSampler struct {
	pid  int
	done chan struct{}
	wg   sync.WaitGroup
	res  procWindow
}

func startProcSampler(pid int, at time.Time) *procSampler {
	s := &procSampler{pid: pid, done: make(chan struct{})}
	s.wg.Add(1)
	go s.run(at)
	return s
}

func (s *procSampler) run(at time.Time) {
	defer s.wg.Done()
	select {
	case <-time.After(time.Until(at)):
	case <-s.done:
		s.res.Err = "window never started"
		return
	}
	first, err := readProc(s.pid)
	if err != nil {
		s.res.Err = err.Error()
		return
	}
	firstAt := time.Now()
	s.res.RSSStartKB = first.rssKB
	s.res.RSSPeakKB = first.rssKB

	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if smp, err := readProc(s.pid); err == nil {
				s.res.RSSPeakKB = max(s.res.RSSPeakKB, smp.rssKB)
			}
		case <-s.done:
			last, err := readProc(s.pid)
			if err != nil {
				s.res.Err = err.Error()
				return
			}
			s.res.CPUSeconds = last.cpuSeconds - first.cpuSeconds
			s.res.UserSeconds = last.userSeconds - first.userSeconds
			s.res.Span = time.Since(firstAt)
			s.res.RSSEndKB = last.rssKB
			s.res.RSSPeakKB = max(s.res.RSSPeakKB, last.rssKB)
			return
		}
	}
}

func (s *procSampler) stop() *procWindow {
	close(s.done)
	s.wg.Wait()
	return &s.res
}
