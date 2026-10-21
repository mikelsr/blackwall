package main

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

// captureServer answers every request with a fixed response and records the
// raw bytes of the last request it read.
type captureServer struct {
	ln   net.Listener
	last chan []byte
}

func newCaptureServer(t *testing.T) *captureServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &captureServer{ln: ln, last: make(chan []byte, 16)}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(conn)
		}
	}()
	return s
}

func (s *captureServer) serve(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	r := bufio.NewReader(conn)
	for {
		var raw bytes.Buffer
		req, err := http.ReadRequest(bufio.NewReader(io.TeeReader(r, &raw)))
		if err != nil {
			return
		}
		// The tee reader may have read ahead into the next request; these
		// tests send one request at a time per connection, so it does not.
		_, _ = io.Copy(io.Discard, req.Body)
		s.last <- raw.Bytes()
		_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	}
}

func (s *captureServer) url() string { return "http://" + s.ln.Addr().String() }

// The server must see the same bytes from the raw client as from net/http.
func TestRawRequestMatchesNetHTTP(t *testing.T) {
	s := newCaptureServer(t)
	body := bytes.Repeat([]byte("u"), 3000)
	cases := []struct {
		name, method, path, cookie string
		body                       []byte
	}{
		{"get", http.MethodGet, "/allow/bench?size=1024", "", nil},
		{"cookie", http.MethodGet, "/bench/pass?size=1024", "techaro.lol-anubis-auth=abc.def", nil},
		{"upload", http.MethodPost, "/allow/upload?size=16", "", body},
		{"flood", http.MethodGet, "/bench/flood/317", "", nil},
	}
	client := newHTTPClient(1)
	raw, err := newRawClient(s.url())
	if err != nil {
		t.Fatal(err)
	}
	ok := check{status: http.StatusOK, bodyLen: 2}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ip := ipFor(123456)
			if err := do(context.Background(), client, c.method, s.url()+c.path, ip, c.cookie, c.body, ok); err != nil {
				t.Fatal(err)
			}
			want := <-s.last

			var tmpl *requestTemplate
			vals := [][]byte{[]byte(ip)}
			if c.name == "flood" {
				tmpl, err = newRequestTemplate(c.method, s.url()+"/bench/flood/"+fieldPath, fieldIP, c.cookie, c.body, fieldPath, fieldIP)
				vals = [][]byte{[]byte("317"), []byte(ip)}
			} else {
				tmpl, err = newRequestTemplate(c.method, s.url()+c.path, fieldIP, c.cookie, c.body, fieldIP)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := raw.do(context.Background(), tmpl, ok, vals...); err != nil {
				t.Fatal(err)
			}
			if got := <-s.last; !bytes.Equal(got, want) {
				t.Errorf("raw client sent\n%q\nnet/http sent\n%q", got, want)
			}
		})
	}
}

func TestAppendIP(t *testing.T) {
	for _, seq := range []uint64{0, 1, 255, 256, 1<<24 - 1, 1 << 24, 1<<22 + 7} {
		n := seq % (1 << 24)
		want := "11." + strconv.Itoa(int(n>>16)) + "." + strconv.Itoa(int(n>>8&0xff)) + "." + strconv.Itoa(int(n&0xff))
		if got := ipFor(seq); got != want {
			t.Errorf("ipFor(%d) = %q, want %q", seq, got, want)
		}
	}
	if got := len(ipFor(1<<24 - 1)); got != maxIPLen {
		t.Errorf("longest address is %d bytes, maxIPLen %d", got, maxIPLen)
	}
}

// Responses framed every way the servers might, and the checks do makes.
func TestRawResponses(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/length", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte("b"), 100_000))
	})
	mux.HandleFunc("/chunked", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		for range 5 {
			_, _ = w.Write(bytes.Repeat([]byte("c"), 3000))
			w.(http.Flusher).Flush()
		}
	})
	mux.HandleFunc("/deny", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "denied", http.StatusForbidden)
	})
	mux.HandleFunc("/close", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "close")
		_, _ = io.WriteString(w, "bye")
	})
	mux.HandleFunc("/empty", func(w http.ResponseWriter, r *http.Request) {})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	raw, err := newRawClient(srv.URL)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		path    string
		want    check
		wantErr string
	}{
		{"/length", check{status: 200, bodyLen: 100_000}, ""},
		{"/length", check{status: 200, bodyLen: 1024}, "body is 100000 bytes, want 1024"},
		{"/chunked", check{status: 200, gzip: true, bodyLen: 15000}, ""},
		{"/length", check{status: 200, gzip: true, bodyLen: -1}, "not a (gzip) challenge page"},
		{"/deny", check{status: 403, bodyLen: -1}, ""},
		{"/deny", check{status: 200, bodyLen: -1}, "status 403, want 200"},
		{"/close", check{status: 200, bodyLen: 3}, ""},
		{"/empty", check{status: 200, bodyLen: -1}, "empty body"},
	}
	for _, c := range cases {
		// Twice each, so the second reuses the connection the first left.
		for range 2 {
			tmpl, err := newRequestTemplate(http.MethodGet, srv.URL+c.path, fieldIP, "", nil, fieldIP)
			if err != nil {
				t.Fatal(err)
			}
			err = raw.do(context.Background(), tmpl, c.want, []byte(ipFor(1)))
			switch {
			case c.wantErr == "" && err != nil:
				t.Errorf("%s: %v", c.path, err)
			case c.wantErr != "" && (err == nil || !strings.Contains(err.Error(), c.wantErr)):
				t.Errorf("%s: error %v, want %q", c.path, err, c.wantErr)
			}
		}
	}
}

// Connections are reused while kept alive, and a reused connection the
// server closed while idle is replaced without an error.
func TestRawConnectionReuse(t *testing.T) {
	var accepted atomic.Int64
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			accepted.Add(1)
		}
	}
	srv.Start()
	t.Cleanup(srv.Close)
	raw, err := newRawClient(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	tmpl, err := newRequestTemplate(http.MethodGet, srv.URL+"/", fieldIP, "", nil, fieldIP)
	if err != nil {
		t.Fatal(err)
	}
	ok := check{status: 200, bodyLen: 2}
	for range 10 {
		if err := raw.do(context.Background(), tmpl, ok, []byte(ipFor(1))); err != nil {
			t.Fatal(err)
		}
	}
	if n := accepted.Load(); n != 1 {
		t.Fatalf("10 sequential requests opened %d connections, want 1", n)
	}

	srv.CloseClientConnections()
	if err := raw.do(context.Background(), tmpl, ok, []byte(ipFor(1))); err != nil {
		t.Fatalf("after the server closed the idle connection: %v", err)
	}
	if n := accepted.Load(); n != 2 {
		t.Fatalf("got %d connections, want 2", n)
	}
}
