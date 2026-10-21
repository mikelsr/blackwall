// Command backend is a minimal upstream for the benchmark. It answers every
// request with a fixed body so that it never becomes the bottleneck and its
// cost is identical for both proxies.
//
//   - ?size=N selects the response body size (bytes), so one backend serves
//     every body-size step without restarting.
//   - GET /__bench/stats returns {"accepted":N,"active":M}, the number of TCP
//     connections accepted so far and currently open. The load generator uses
//     it to report how many upstream connections a proxy opens per request.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

const (
	statsPath = "/__bench/stats"
	maxSize   = 64 << 20
)

type bodyCache struct {
	m sync.Map // int -> []byte
}

func (c *bodyCache) get(size int) []byte {
	if v, ok := c.m.Load(size); ok {
		return v.([]byte)
	}
	v, _ := c.m.LoadOrStore(size, bytes.Repeat([]byte("b"), size))
	return v.([]byte)
}

func main() {
	addr := flag.String("addr", "127.0.0.1:18080", "address to listen on")
	defaultSize := flag.Int("size", 512, "default response body size in bytes")
	flag.Parse()

	var accepted, active atomic.Int64
	bodies := &bodyCache{}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Drain any request body (uploads) so the connection can be reused.
		_, _ = io.Copy(io.Discard, r.Body)

		if r.URL.Path == statsPath {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]int64{
				"accepted": accepted.Load(),
				"active":   active.Load(),
			})
			return
		}

		size := *defaultSize
		if s := r.URL.Query().Get("size"); s != "" {
			if v, err := strconv.Atoi(s); err == nil && v >= 0 && v <= maxSize {
				size = v
			}
		}
		body := bodies.get(size)

		h := w.Header()
		h["Content-Type"] = []string{"application/octet-stream"}
		h["Content-Length"] = []string{strconv.Itoa(len(body))}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	})

	srv := &http.Server{
		Addr:              *addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		ErrorLog:          log.New(io.Discard, "", 0),
		ConnState: func(_ net.Conn, state http.ConnState) {
			switch state {
			case http.StateNew:
				accepted.Add(1)
				active.Add(1)
			case http.StateClosed, http.StateHijacked:
				active.Add(-1)
			}
		},
	}
	log.Fatal(srv.ListenAndServe())
}
