package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type Flavor string

const (
	FlavorBlackwall Flavor = "blackwall"
	FlavorAnubis    Flavor = "anubis"
)

const (
	passChallengePath = "/.within.website/x/cmd/anubis/api/pass-challenge"
	// Contains "Mozilla" so that the realistic policy's generic-browser rule
	// weighs it and the request ends up in the CHALLENGE threshold.
	benchUserAgent = "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0 b7l-bench/1.0"
)

func newHTTPClient(maxConns int) *http.Client {
	transport := &http.Transport{
		// Never go through HTTP(S)_PROXY, even if set in the environment.
		Proxy: nil,
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          maxConns * 2,
		MaxIdleConnsPerHost:   maxConns * 2,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		// We send Accept-Encoding ourselves so both servers compress the
		// challenge page, and only decompress when we need the body.
		DisableCompression: true,
		ForceAttemptHTTP2:  false,
	}
	return &http.Client{
		Transport: transport,
		Timeout:   15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// ipFor maps a sequence number to a stable, public-looking client address.
// 11.0.0.0/8 is not private, loopback, CGNAT or link-local, so neither proxy
// treats it specially.
func ipFor(seq uint64) string {
	var b [maxIPLen]byte
	return string(appendIP(b[:0], seq))
}

// maxIPLen is the longest address ipFor gives, "11.255.255.255".
const maxIPLen = 14

// appendIP appends ipFor(seq) to b.
func appendIP(b []byte, seq uint64) []byte {
	n := seq % (1 << 24)
	b = append(b, "11."...)
	b = strconv.AppendUint(b, (n>>16)&0xff, 10)
	b = append(b, '.')
	b = strconv.AppendUint(b, (n>>8)&0xff, 10)
	b = append(b, '.')
	return strconv.AppendUint(b, n&0xff, 10)
}

func newRequest(ctx context.Context, rawURL, ip, cookie string) (*http.Request, error) {
	return newRequestWithBody(ctx, http.MethodGet, rawURL, ip, cookie, nil)
}

func newRequestWithBody(ctx context.Context, method, rawURL, ip, cookie string, body []byte) (*http.Request, error) {
	var r io.Reader
	if body != nil {
		// bytes.Reader lets net/http set Content-Length and avoid chunking.
		r = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, r)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/octet-stream")
	}
	h := req.Header
	h.Set("User-Agent", benchUserAgent)
	h.Set("Accept", "text/html,application/xhtml+xml")
	// Anubis randomly rejects 1/64 challenge requests without gzip support.
	h.Set("Accept-Encoding", "gzip")
	h.Set("Accept-Language", "en")
	h.Set("X-Real-IP", ip)
	if cookie != "" {
		h.Set("Cookie", cookie)
	}
	return req, nil
}

// drain reads and discards the body so the connection can be reused.
func drain(resp *http.Response) (int64, error) {
	n, err := io.Copy(io.Discard, resp.Body)
	closeErr := resp.Body.Close()
	if err != nil {
		return n, err
	}
	return n, closeErr
}

func readBody(resp *http.Response) ([]byte, error) {
	defer func() { _ = resp.Body.Close() }()
	var r io.Reader = resp.Body
	if strings.EqualFold(resp.Header.Get("Content-Encoding"), "gzip") {
		gz, err := gzip.NewReader(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("gzip: %w", err)
		}
		defer func() { _ = gz.Close() }()
		r = gz
	}
	return io.ReadAll(r)
}

// cookieHeader turns the Set-Cookie headers of a response into a Cookie
// request header value, skipping cookies that are being cleared.
func cookieHeader(resp *http.Response) string {
	var parts []string
	for _, c := range resp.Cookies() {
		if c.Value == "" || c.MaxAge < 0 {
			continue
		}
		parts = append(parts, c.Name+"="+c.Value)
	}
	return strings.Join(parts, "; ")
}

type challengeInfo struct {
	ID         string
	Data       []byte // exact bytes fed to SHA-256 before the nonce
	Difficulty int
}

var (
	blackwallMarker = []byte("window.ANUBIS_CHALLENGE = ")
	anubisMarker    = []byte(`id="anubis_challenge"`)
	scriptEnd       = []byte("</script>")
)

func parseChallenge(flavor Flavor, body []byte) (challengeInfo, error) {
	switch flavor {
	case FlavorBlackwall:
		idx := bytes.Index(body, blackwallMarker)
		if idx < 0 {
			return challengeInfo{}, errors.New("blackwall challenge declaration not found in page")
		}
		var raw struct {
			ID         string          `json:"id"`
			RandomData json.RawMessage `json:"randomData"`
			Difficulty int             `json:"difficulty"`
		}
		// The decoder stops after the first JSON value, ignoring the trailing JS.
		if err := json.NewDecoder(bytes.NewReader(body[idx+len(blackwallMarker):])).Decode(&raw); err != nil {
			return challengeInfo{}, fmt.Errorf("decode blackwall challenge: %w", err)
		}
		data, err := decodeRandomData(raw.RandomData)
		if err != nil {
			return challengeInfo{}, err
		}
		if raw.ID == "" {
			return challengeInfo{}, errors.New("blackwall challenge is missing id")
		}
		return challengeInfo{ID: raw.ID, Data: data, Difficulty: raw.Difficulty}, nil

	case FlavorAnubis:
		idx := bytes.Index(body, anubisMarker)
		if idx < 0 {
			return challengeInfo{}, errors.New("anubis_challenge script not found in page")
		}
		rest := body[idx:]
		gt := bytes.IndexByte(rest, '>')
		end := bytes.Index(rest, scriptEnd)
		if gt < 0 || end < 0 || end < gt {
			return challengeInfo{}, errors.New("malformed anubis_challenge script")
		}
		// Payload shape: {"rules": {...}, "challenge": {...}}.
		var raw struct {
			Rules struct {
				Difficulty int `json:"difficulty"`
			} `json:"rules"`
			Challenge struct {
				ID         string `json:"id"`
				RandomData string `json:"randomData"`
				Difficulty int    `json:"difficulty"`
			} `json:"challenge"`
		}
		if err := json.Unmarshal(rest[gt+1:end], &raw); err != nil {
			return challengeInfo{}, fmt.Errorf("decode anubis challenge: %w", err)
		}
		c := raw.Challenge
		if c.ID == "" || c.RandomData == "" {
			return challengeInfo{}, errors.New("anubis challenge is missing id or randomData")
		}
		difficulty := c.Difficulty
		if difficulty == 0 {
			difficulty = raw.Rules.Difficulty
		}
		// Anubis hashes the hex string itself, not the decoded bytes.
		return challengeInfo{ID: c.ID, Data: []byte(c.RandomData), Difficulty: difficulty}, nil
	}
	return challengeInfo{}, fmt.Errorf("unknown flavor %q", flavor)
}

// decodeRandomData accepts serde's byte-array encoding ([1,2,3]) as well as a
// plain string, in case the serialization changes.
func decodeRandomData(raw json.RawMessage) ([]byte, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, errors.New("randomData missing")
	}
	if trimmed[0] == '"' {
		var s string
		if err := json.Unmarshal(trimmed, &s); err != nil {
			return nil, err
		}
		return []byte(s), nil
	}
	var ints []int
	if err := json.Unmarshal(trimmed, &ints); err != nil {
		return nil, fmt.Errorf("decode randomData: %w", err)
	}
	out := make([]byte, len(ints))
	for i, v := range ints {
		out[i] = byte(v)
	}
	return out, nil
}

func leadingZeroNibbles(sum *[sha256.Size]byte) int {
	n := 0
	for _, b := range sum {
		if b == 0 {
			n += 2
			continue
		}
		if b>>4 == 0 {
			n++
		}
		break
	}
	return n
}

// solve finds a nonce such that sha256(data || decimal(nonce)) has at least
// `difficulty` leading zero hex digits. This matches both implementations.
func solve(c challengeInfo) (uint64, string) {
	buf := make([]byte, 0, len(c.Data)+20)
	buf = append(buf, c.Data...)
	for nonce := uint64(0); ; nonce++ {
		msg := strconv.AppendUint(buf, nonce, 10)
		sum := sha256.Sum256(msg)
		if leadingZeroNibbles(&sum) >= c.Difficulty {
			return nonce, hex.EncodeToString(sum[:])
		}
	}
}

type solveResult struct {
	authCookie  string
	passLatency time.Duration
	pageBytes   int // the challenge page before compression
}

// solveFlow runs the full browser flow: get the challenge page, solve it and
// redeem it at pass-challenge, returning the auth cookie.
func solveFlow(ctx context.Context, client *http.Client, flavor Flavor, base, path, ip string) (solveResult, error) {
	req, err := newRequest(ctx, base+path, ip, "")
	if err != nil {
		return solveResult{}, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return solveResult{}, err
	}
	if resp.StatusCode != http.StatusOK {
		_, _ = drain(resp)
		return solveResult{}, fmt.Errorf("challenge page: status %d", resp.StatusCode)
	}
	cookies := cookieHeader(resp)
	body, err := readBody(resp)
	if err != nil {
		return solveResult{}, fmt.Errorf("challenge page: %w", err)
	}
	chall, err := parseChallenge(flavor, body)
	if err != nil {
		return solveResult{}, err
	}

	nonce, hash := solve(chall)

	q := url.Values{}
	q.Set("id", chall.ID)
	q.Set("response", hash)
	q.Set("nonce", strconv.FormatUint(nonce, 10))
	q.Set("redir", path)
	// Blackwall parses this as an integer, Anubis as a float.
	q.Set("elapsedTime", "1")

	req, err = newRequest(ctx, base+passChallengePath+"?"+q.Encode(), ip, cookies)
	if err != nil {
		return solveResult{}, err
	}
	start := time.Now()
	resp, err = client.Do(req)
	if err != nil {
		return solveResult{}, err
	}
	passLatency := time.Since(start)
	auth := cookieHeader(resp)
	if _, err := drain(resp); err != nil {
		return solveResult{}, err
	}
	if resp.StatusCode != http.StatusFound {
		return solveResult{}, fmt.Errorf("pass-challenge: status %d", resp.StatusCode)
	}
	if auth == "" {
		return solveResult{}, errors.New("pass-challenge: no auth cookie set")
	}
	return solveResult{authCookie: auth, passLatency: passLatency, pageBytes: len(body)}, nil
}
