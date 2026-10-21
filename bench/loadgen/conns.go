package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// connsConfig drives the idle-connection footprint measurement.
type connsConfig struct {
	target   string
	conns    int
	pid      int
	settle   time.Duration
	probes   int
	parallel int
	client   *http.Client
}

// Each idle connection first completes one request on a DENY path, so it
// sits in the server's keep-alive state without holding an upstream
// connection. That isolates the cost of a client connection in the proxy.
const connsPath = "/deny/conns"

// localAddrs returns source addresses to spread connections over. Linux
// routes all of 127.0.0.0/8 to loopback, so using several source IPs lifts
// the ~28k ephemeral-port limit of a single (src, dst) pair. Other systems
// only get the default address.
func localAddrs(targetHost string) []*net.TCPAddr {
	if runtime.GOOS != "linux" || !strings.HasPrefix(targetHost, "127.") {
		return []*net.TCPAddr{nil}
	}
	addrs := make([]*net.TCPAddr, 16)
	for i := range addrs {
		addrs[i] = &net.TCPAddr{IP: net.IPv4(127, 0, 0, byte(i+1))}
	}
	return addrs
}

func rawRequest(host, ip string) []byte {
	return []byte("GET " + connsPath + " HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"User-Agent: " + benchUserAgent + "\r\n" +
		"Accept-Encoding: gzip\r\n" +
		"X-Real-IP: " + ip + "\r\n" +
		"\r\n")
}

// roundTrip sends one request on a raw connection and reads the full response.
func roundTrip(conn net.Conn, req []byte) error {
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	defer func() { _ = conn.SetDeadline(time.Time{}) }()
	if _, err := conn.Write(req); err != nil {
		return err
	}
	resp, err := http.ReadResponse(bufio.NewReaderSize(conn, 4096), nil)
	if err != nil {
		return err
	}
	_, err = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusForbidden {
		return fmt.Errorf("status %d, want 403", resp.StatusCode)
	}
	if resp.Close {
		return errors.New("server closed the connection after the response")
	}
	return nil
}

func medianRSS(pid int, samples int) (int64, error) {
	var vals []int64
	for range samples {
		s, err := readProc(pid)
		if err != nil {
			return 0, err
		}
		vals = append(vals, s.rssKB)
		time.Sleep(200 * time.Millisecond)
	}
	slices.Sort(vals)
	return vals[len(vals)/2], nil
}

func runConns(ctx context.Context, cfg connsConfig) (Record, error) {
	if cfg.pid <= 0 {
		return Record{}, errors.New("conns scenario needs -pid")
	}
	u, err := url.Parse(cfg.target)
	if err != nil {
		return Record{}, err
	}
	host := u.Host
	targetHost, _, _ := net.SplitHostPort(host)

	// Warm the server up (allocator, runtime, policy caches) with regular
	// requests, then let it settle before taking the baseline.
	for i := range 2000 {
		if err := simpleGet(ctx, cfg.client, cfg.target+connsPath, ipFor(uint64(i)), "", check{status: http.StatusForbidden, bodyLen: -1}); err != nil {
			return Record{}, fmt.Errorf("warm-up: %w", err)
		}
	}
	cfg.client.CloseIdleConnections()
	time.Sleep(cfg.settle)
	baseKB, err := medianRSS(cfg.pid, 5)
	if err != nil {
		return Record{}, err
	}

	// Open the connections.
	locals := localAddrs(targetHost)
	conns := make([]net.Conn, cfg.conns)
	var opened atomic.Int64
	var firstErr atomic.Value
	next := atomic.Int64{}
	var wg sync.WaitGroup
	start := time.Now()
	for range cfg.parallel {
		wg.Go(func() {
			for ctx.Err() == nil && firstErr.Load() == nil {
				i := int(next.Add(1) - 1)
				if i >= cfg.conns {
					return
				}
				d := net.Dialer{Timeout: 5 * time.Second, LocalAddr: locals[i%len(locals)]}
				conn, err := d.DialContext(ctx, "tcp", host)
				if err != nil {
					firstErr.CompareAndSwap(nil, fmt.Errorf("dial #%d: %w", i, err))
					return
				}
				if err := roundTrip(conn, rawRequest(host, ipFor(uint64(i)))); err != nil {
					_ = conn.Close()
					firstErr.CompareAndSwap(nil, fmt.Errorf("conn #%d: %w", i, err))
					return
				}
				conns[i] = conn
				opened.Add(1)
			}
		})
	}
	wg.Wait()
	openTime := time.Since(start)
	defer func() {
		for _, c := range conns {
			if c != nil {
				_ = c.Close()
			}
		}
	}()

	rec := Record{Scenario: "conns", Mode: "conns", Conns: cfg.conns}
	rec.ConnsOpened = int(opened.Load())
	if v := firstErr.Load(); v != nil {
		rec.ErrSamples = map[string]int{v.(error).Error(): 1}
	}

	time.Sleep(cfg.settle)
	atKB, err := medianRSS(cfg.pid, 5)
	if err != nil {
		return rec, err
	}

	// Latency of fresh requests while the idle connections are held open.
	var lat []time.Duration
	for i := range cfg.probes {
		t0 := time.Now()
		err := simpleGet(ctx, cfg.client, cfg.target+connsPath, ipFor(uint64(1<<20+i)), "", check{status: http.StatusForbidden, bodyLen: -1})
		if err != nil {
			rec.Errors++
			continue
		}
		lat = append(lat, time.Since(t0))
	}
	slices.Sort(lat)

	// Check a spread-out sample of the idle connections is still usable.
	sample := min(100, rec.ConnsOpened)
	alive := 0
	if sample > 0 {
		step := max(1, cfg.conns/sample)
		checked := 0
		for i := 0; i < cfg.conns && checked < sample; i += step {
			if conns[i] == nil {
				continue
			}
			checked++
			if roundTrip(conns[i], rawRequest(host, ipFor(uint64(i)))) == nil {
				alive++
			}
		}
		sample = checked
	}

	rec.RSSBaselineMB = float64(baseKB) / 1024
	rec.RSSEndMB = float64(atKB) / 1024
	if rec.ConnsOpened > 0 {
		rec.KBPerConn = float64(atKB-baseKB) / float64(rec.ConnsOpened)
	}
	rec.P50 = ms(percentile(lat, 0.50))
	rec.P99 = ms(percentile(lat, 0.99))
	if n := len(lat); n > 0 {
		rec.Max = ms(lat[n-1])
	}
	rec.AliveSample = fmt.Sprintf("%d/%d", alive, sample)
	rec.OpenSeconds = openTime.Seconds()
	rec.Pass = rec.ConnsOpened == cfg.conns && alive == sample && rec.Errors == 0
	return rec, nil
}

// backendAccepted reads the backend's accepted-connection counter.
func backendAccepted(ctx context.Context, client *http.Client, backend string) (int64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(backend, "/")+"/__bench/stats", nil)
	if err != nil {
		return 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	var stats struct {
		Accepted int64 `json:"accepted"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&stats); err != nil {
		return 0, err
	}
	return stats.Accepted, nil
}
