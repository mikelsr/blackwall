package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// opFunc performs one unit of work. extra is an optional secondary latency
// (for example the pass-challenge request inside the solve flow).
type opFunc func(ctx context.Context, seq uint64) (extra time.Duration, err error)

type scenarioConfig struct {
	name    string
	flavor  Flavor
	target  string
	backend string
	tokens  int
	size    int // body size: response for direct/allow/pass, request for upload
	client  *http.Client
}

// sizedScenarios use the -size flag; the rest ignore it.
var sizedScenarios = map[string]bool{"direct": true, "allow": true, "pass": true, "upload": true}

var scenarioDescriptions = map[string]string{
	"direct": "GET straight to the backend (baseline, no proxy)",
	"allow":  "GET matching an ALLOW rule, proxied to the backend",
	"deny":   "GET matching a DENY rule (403)",
	"flood":  "GET matching a CHALLENGE rule without a cookie; never solved (bot flood)",
	"solve":  "full flow: challenge page + solve (difficulty 1) + pass-challenge",
	"pass":   "GET matching a CHALLENGE rule with a valid auth cookie, proxied",
	"upload": "POST with a request body matching an ALLOW rule, proxied",
	"conns":  "open N idle keep-alive connections, measure server memory per connection",
}

type check struct {
	status  int
	gzip    bool  // only the challenge page is gzip-encoded
	bodyLen int64 // exact expected body length, -1 to skip
}

// do issues a request and validates the response.
func do(ctx context.Context, client *http.Client, method, rawURL, ip, cookie string, body []byte, want check) error {
	req, err := newRequestWithBody(ctx, method, rawURL, ip, cookie, body)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	n, err := drain(resp)
	if err != nil {
		return err
	}
	if resp.StatusCode != want.status {
		return fmt.Errorf("status %d, want %d", resp.StatusCode, want.status)
	}
	if want.gzip && !strings.EqualFold(resp.Header.Get("Content-Encoding"), "gzip") {
		return errors.New("response is not a (gzip) challenge page")
	}
	if want.bodyLen >= 0 && n != want.bodyLen {
		return fmt.Errorf("body is %d bytes, want %d", n, want.bodyLen)
	}
	if n == 0 && want.status == http.StatusOK && want.bodyLen != 0 {
		return errors.New("empty body")
	}
	return nil
}

func simpleGet(ctx context.Context, client *http.Client, rawURL, ip, cookie string, want check) error {
	return do(ctx, client, http.MethodGet, rawURL, ip, cookie, nil, want)
}

// preparedScenario is the operation to benchmark and what its preflight
// request saw.
type preparedScenario struct {
	op opFunc
	// flood: the challenge page's size before compression.
	pageBytes int
}

// buildScenario validates the server configuration with a preflight request
// and returns the scenario to benchmark. Every scenario but solve sends its
// load through a rawClient; cfg.client mints cookies and fetches the flood's
// challenge page beforehand.
func buildScenario(ctx context.Context, cfg scenarioConfig) (preparedScenario, error) {
	if cfg.name == "solve" {
		op := func(ctx context.Context, seq uint64) (time.Duration, error) {
			res, err := solveFlow(ctx, cfg.client, cfg.flavor, strings.TrimRight(cfg.target, "/"), "/bench/solve", ipFor(seq))
			if err != nil {
				return 0, err
			}
			return res.passLatency, nil
		}
		_, err := op(ctx, 1<<23)
		return preparedScenario{op: op}, wrapPreflight(err)
	}
	prepared, err := buildRawScenario(ctx, cfg)
	if err != nil {
		return preparedScenario{}, wrapPreflight(err)
	}
	// The load runs on its own connections; don't leave the preparation's
	// open on the server.
	cfg.client.CloseIdleConnections()
	_, err = prepared.op(ctx, 0)
	return prepared, wrapPreflight(err)
}

// buildRawScenario prepares the scenarios that send prebuilt requests.
func buildRawScenario(ctx context.Context, cfg scenarioConfig) (preparedScenario, error) {
	base := strings.TrimRight(cfg.target, "/")
	if cfg.name == "direct" {
		base = strings.TrimRight(cfg.backend, "/")
	}
	raw, err := newRawClient(base)
	if err != nil {
		return preparedScenario{}, err
	}
	sizeQuery := "?size=" + strconv.Itoa(cfg.size)
	sized := check{status: http.StatusOK, bodyLen: int64(cfg.size)}

	// ipOp sends t, whose one field is the client address, from seq's address.
	ipOp := func(t *requestTemplate, want check) opFunc {
		return func(ctx context.Context, seq uint64) (time.Duration, error) {
			var ip [maxIPLen]byte
			return 0, raw.do(ctx, t, want, appendIP(ip[:0], seq))
		}
	}

	switch cfg.name {
	case "direct", "allow", "deny":
		path, want := "/bench/direct"+sizeQuery, sized
		switch cfg.name {
		case "allow":
			path = "/allow/bench" + sizeQuery
		case "deny":
			path, want = "/deny/bench", check{status: http.StatusForbidden, bodyLen: -1}
		}
		t, err := newRequestTemplate(http.MethodGet, base+path, fieldIP, "", nil, fieldIP)
		if err != nil {
			return preparedScenario{}, err
		}
		return preparedScenario{op: ipOp(t, want)}, nil

	case "upload":
		body := bytes.Repeat([]byte("u"), cfg.size)
		t, err := newRequestTemplate(http.MethodPost, base+"/allow/upload?size=16", fieldIP, "", body, fieldIP)
		if err != nil {
			return preparedScenario{}, err
		}
		// Small response so the request body dominates.
		return preparedScenario{op: ipOp(t, check{status: http.StatusOK, bodyLen: 16})}, nil

	case "flood":
		// Make sure the page really is a parseable challenge before blasting it.
		res, err := solveFlow(ctx, cfg.client, cfg.flavor, base, "/bench/flood", ipFor(1<<23))
		if err != nil {
			return preparedScenario{}, err
		}
		t, err := newRequestTemplate(http.MethodGet, base+"/bench/flood/"+fieldPath, fieldIP, "", nil, fieldPath, fieldIP)
		if err != nil {
			return preparedScenario{}, err
		}
		page := check{status: http.StatusOK, gzip: true, bodyLen: -1}
		op := func(ctx context.Context, seq uint64) (time.Duration, error) {
			// Every request comes from a different address, like a
			// distributed scraper, for one of 1024 paths.
			var path [4]byte
			var ip [maxIPLen]byte
			return 0, raw.do(ctx, t, page, strconv.AppendUint(path[:0], seq%1024, 10), appendIP(ip[:0], seq))
		}
		return preparedScenario{op: op, pageBytes: res.pageBytes}, nil

	case "pass":
		// One request per auth cookie, each from the address it was minted for.
		templates := make([]*requestTemplate, max(cfg.tokens, 1))
		for i := range templates {
			ip := ipFor(uint64(1<<22 + i))
			res, err := solveFlow(ctx, cfg.client, cfg.flavor, base, "/bench/pass", ip)
			if err != nil {
				return preparedScenario{}, fmt.Errorf("minting token %d: %w", i, err)
			}
			if templates[i], err = newRequestTemplate(http.MethodGet, base+"/bench/pass"+sizeQuery, ip, res.authCookie, nil); err != nil {
				return preparedScenario{}, err
			}
		}
		op := func(ctx context.Context, seq uint64) (time.Duration, error) {
			return 0, raw.do(ctx, templates[seq%uint64(len(templates))], sized)
		}
		return preparedScenario{op: op}, nil
	}
	return preparedScenario{}, fmt.Errorf("unknown scenario %q", cfg.name)
}

func wrapPreflight(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("preflight failed (check server config/policy): %w", err)
}
