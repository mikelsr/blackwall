package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"syscall"
	"time"
)

// rawClient sends the benchmark's simple requests (every scenario but the
// challenge solve) over plain keep-alive connections, without net/http.
//
// Under load the load generator shares the machine with the server and the
// backend, so its own CPU time limits how much load the rig can offer.
// net/http's client spends ~55 µs of CPU per request (plus ~24 µs in the
// kernel): it builds a request and a header map per call, and each connection
// runs a reader and a writer goroutine that every request is handed through.
// Here the worker that sends a request also reads its answer, the request is
// prebuilt bytes with a few fields filled in, and the response is parsed only
// as far as the checks need (bench/REPORT.md, "Validation").
//
// The server sees the same bytes as with net/http (requestTemplate) and the
// same connection pattern: idle connections are reused last-in, first-out,
// and a new one is opened only when all are busy, so the number of open
// connections follows the concurrency, as with net/http's pool.
type rawClient struct {
	addr string
	mu   sync.Mutex
	idle []*rawConn // a stack: the most recently used connection is on top
}

type rawConn struct {
	conn net.Conn
	r    *bufio.Reader
	iov  net.Buffers // the request's pieces, reused for every request
	vals []byte      // the request's fields, copied out of the caller's buffers
}

// Large enough for the response headers in one buffer and to read bodies in
// few system calls.
const rawReadBuffer = 32 << 10

// Same limits as newHTTPClient: 5 s to connect, 15 s per request.
const rawDialTimeout, rawRequestTimeout = 5 * time.Second, 15 * time.Second

func newRawClient(baseURL string) (*rawClient, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "http" {
		return nil, fmt.Errorf("%s: only http:// is supported", baseURL)
	}
	host := u.Host
	if u.Port() == "" {
		host = net.JoinHostPort(u.Hostname(), "80")
	}
	return &rawClient{addr: host}, nil
}

func (c *rawClient) get(ctx context.Context) (rc *rawConn, reused bool, err error) {
	c.mu.Lock()
	if n := len(c.idle); n > 0 {
		rc = c.idle[n-1]
		c.idle = c.idle[:n-1]
	}
	c.mu.Unlock()
	if rc != nil {
		return rc, true, nil
	}
	rc, err = c.dial(ctx)
	return rc, false, err
}

func (c *rawClient) dial(ctx context.Context) (*rawConn, error) {
	d := net.Dialer{Timeout: rawDialTimeout, KeepAlive: 30 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", c.addr)
	if err != nil {
		return nil, err
	}
	return &rawConn{conn: conn, r: bufio.NewReaderSize(conn, rawReadBuffer)}, nil
}

func (c *rawClient) put(rc *rawConn) {
	c.mu.Lock()
	c.idle = append(c.idle, rc)
	c.mu.Unlock()
}

// do sends t with vals in its fields and checks the response against want.
// Like net/http, it retries once on a new connection when a reused one turns
// out to be closed before any of the response arrived: the server closed it
// while idle and never saw the request.
func (c *rawClient) do(ctx context.Context, t *requestTemplate, want check, vals ...[]byte) error {
	if len(vals) != len(t.parts)-1 {
		return fmt.Errorf("request template has %d fields, got %d values", len(t.parts)-1, len(vals))
	}
	rc, reused, err := c.get(ctx)
	if err != nil {
		return err
	}
	keep, answered, err := rc.roundTrip(t, want, vals)
	if err != nil && reused && !answered {
		_ = rc.conn.Close()
		if rc, err = c.dial(ctx); err != nil {
			return err
		}
		keep, _, err = rc.roundTrip(t, want, vals)
	}
	if keep && err == nil {
		c.put(rc)
	} else {
		_ = rc.conn.Close()
	}
	return err
}

// roundTrip writes one request and reads its response. keep reports whether
// the connection can carry another request; answered, whether any of the
// response arrived.
func (rc *rawConn) roundTrip(t *requestTemplate, want check, vals [][]byte) (keep, answered bool, err error) {
	rc.vals = rc.vals[:0]
	for _, v := range vals {
		rc.vals = append(rc.vals, v...)
	}
	rc.iov = rc.iov[:0]
	off := 0
	for i, part := range t.parts {
		rc.iov = append(rc.iov, part)
		if i < len(vals) {
			rc.iov = append(rc.iov, rc.vals[off:off+len(vals[i])])
			off += len(vals[i])
		}
	}
	_ = rc.conn.SetDeadline(time.Now().Add(rawRequestTimeout))
	// WriteTo consumes iov; the copy keeps rc.iov's backing array for reuse.
	iov := rc.iov
	if _, err := iov.WriteTo(rc.conn); err != nil {
		return false, false, err
	}
	status, err := rc.r.ReadSlice('\n')
	if err != nil {
		return false, len(status) > 0 || !closedBeforeReply(err), err
	}
	keep, err = rc.readResponse(status, want)
	return keep, true, err
}

// closedBeforeReply reports whether err means the server closed the
// connection without answering.
func closedBeforeReply(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE)
}

var (
	headerContentLength    = []byte("Content-Length")
	headerTransferEncoding = []byte("Transfer-Encoding")
	headerContentEncoding  = []byte("Content-Encoding")
	headerConnection       = []byte("Connection")
)

// readResponse reads the rest of a response whose status line is status:
// the headers the checks and the framing need, then the body, discarded.
func (rc *rawConn) readResponse(status []byte, want check) (keep bool, err error) {
	// "HTTP/1.1 200 OK\r\n"
	if len(status) < 12 || !bytes.HasPrefix(status, []byte("HTTP/1.")) || status[8] != ' ' {
		return false, fmt.Errorf("malformed status line %q", status)
	}
	code, err := strconv.Atoi(string(status[9:12]))
	if err != nil {
		return false, fmt.Errorf("malformed status line %q", status)
	}
	keep = status[7] == '1' // HTTP/1.0 closes unless it says otherwise
	length := int64(-1)
	var chunked, gzipped bool
	for {
		line, err := rc.r.ReadSlice('\n')
		if err != nil {
			return false, fmt.Errorf("response headers: %w", err)
		}
		line = bytes.TrimRight(line, "\r\n")
		if len(line) == 0 {
			break
		}
		name, value, ok := bytes.Cut(line, []byte(":"))
		if !ok {
			return false, fmt.Errorf("malformed header %q", line)
		}
		value = bytes.TrimSpace(value)
		switch {
		case bytes.EqualFold(name, headerContentLength):
			if length, err = strconv.ParseInt(string(value), 10, 64); err != nil || length < 0 {
				return false, fmt.Errorf("malformed Content-Length %q", value)
			}
		case bytes.EqualFold(name, headerTransferEncoding):
			chunked = bytes.EqualFold(value, []byte("chunked"))
			if !chunked {
				return false, fmt.Errorf("unsupported Transfer-Encoding %q", value)
			}
		case bytes.EqualFold(name, headerContentEncoding):
			gzipped = bytes.EqualFold(value, []byte("gzip"))
		case bytes.EqualFold(name, headerConnection):
			if bytes.EqualFold(value, []byte("close")) {
				keep = false
			} else if bytes.EqualFold(value, []byte("keep-alive")) {
				keep = true
			}
		}
	}

	var n int64
	switch {
	case code == http.StatusNoContent || code == http.StatusNotModified || code < 200:
	case chunked:
		n, err = rc.discardChunked()
	case length >= 0:
		var d int
		d, err = rc.r.Discard(int(length))
		n = int64(d)
	default:
		// No length: the body ends when the server closes the connection.
		n, err = io.Copy(io.Discard, rc.r)
		keep = false
	}
	if err != nil {
		return false, fmt.Errorf("response body: %w", err)
	}

	// The same checks as do.
	switch {
	case code != want.status:
		err = fmt.Errorf("status %d, want %d", code, want.status)
	case want.gzip && !gzipped:
		err = errors.New("response is not a (gzip) challenge page")
	case want.bodyLen >= 0 && n != want.bodyLen:
		err = fmt.Errorf("body is %d bytes, want %d", n, want.bodyLen)
	case n == 0 && want.status == http.StatusOK && want.bodyLen != 0:
		err = errors.New("empty body")
	}
	return keep, err
}

// discardChunked reads a chunked body and returns its length.
func (rc *rawConn) discardChunked() (int64, error) {
	var n int64
	for {
		line, err := rc.r.ReadSlice('\n')
		if err != nil {
			return n, err
		}
		size, _, _ := bytes.Cut(bytes.TrimRight(line, "\r\n"), []byte(";"))
		chunk, err := strconv.ParseInt(string(bytes.TrimSpace(size)), 16, 64)
		if err != nil || chunk < 0 {
			return n, fmt.Errorf("malformed chunk size %q", line)
		}
		if chunk == 0 {
			break
		}
		if _, err := rc.r.Discard(int(chunk)); err != nil {
			return n, err
		}
		n += chunk
		if err := rc.expectCRLF(); err != nil {
			return n, err
		}
	}
	// Trailers, if any, up to the empty line.
	for {
		line, err := rc.r.ReadSlice('\n')
		if err != nil {
			return n, err
		}
		if len(bytes.TrimRight(line, "\r\n")) == 0 {
			return n, nil
		}
	}
}

func (rc *rawConn) expectCRLF() error {
	line, err := rc.r.ReadSlice('\n')
	if err != nil {
		return err
	}
	if !bytes.Equal(line, []byte("\r\n")) {
		return fmt.Errorf("chunk not followed by CRLF: %q", line)
	}
	return nil
}

// requestTemplate is one kind of request as bytes, split around its fields:
// the parts that change from request to request, such as the client address.
// fields[i] goes between parts[i] and parts[i+1].
type requestTemplate struct {
	parts [][]byte
}

// Placeholders for a template's fields. They are plain text so that net/http
// writes them unchanged, and appear nowhere else in a request.
const (
	fieldIP   = "b7lFIELDip"
	fieldPath = "b7lFIELDpath"
)

// newRequestTemplate builds the request newRequestWithBody would send and
// splits it around fields, placeholders that must appear in it in this
// order. net/http writes the request (Request.Write, as its client does over
// a connection without a proxy), so the server gets the same request line,
// headers and header order either way.
func newRequestTemplate(method, rawURL, ip, cookie string, body []byte, fields ...string) (*requestTemplate, error) {
	req, err := newRequestWithBody(context.Background(), method, rawURL, ip, cookie, body)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := req.Write(&buf); err != nil {
		return nil, err
	}
	rest := buf.Bytes()
	t := &requestTemplate{}
	for _, f := range fields {
		before, after, ok := bytes.Cut(rest, []byte(f))
		if !ok {
			return nil, fmt.Errorf("field %q not in the request (or out of order)", f)
		}
		t.parts = append(t.parts, before)
		rest = after
	}
	t.parts = append(t.parts, rest)
	return t, nil
}
