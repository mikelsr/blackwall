package main

// The challenge page in a browser: visits to each server's challenge page in
// Chrome, from experiments/browser/run.sh, which runs on a workstation
// rather than the benchmark box, so its results sit apart from the others.

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type browserVisit struct {
	Server     string `json:"server"`
	Device     string `json:"device"`
	Difficulty int    `json:"difficulty"`
	Visit      string `json:"visit"`
	PaintMs    *int   `json:"paintMs"`
	SentMs     int    `json:"sentMs"`
	ReachedMs  int    `json:"reachedMs"`
	Files      []struct {
		Path  string `json:"path"`
		Bytes int    `json:"bytes"`
	} `json:"files"`
}

// fileKind sorts a file a visit downloaded by what it is for. Translations
// are their own kind: Anubis has them and Blackwall doesn't yet.
func fileKind(path string) (string, error) {
	switch {
	case path == "/" || strings.HasSuffix(path, "/pass-challenge"):
		return "page", nil
	case strings.Contains(path, "/locales/"):
		return "translation", nil
	case strings.HasSuffix(path, ".mjs"), strings.HasSuffix(path, ".js"), strings.HasSuffix(path, ".wasm"):
		return "script", nil
	case strings.HasSuffix(path, ".css"), strings.HasSuffix(path, ".woff2"):
		return "style", nil
	case strings.HasSuffix(path, ".webp"), strings.HasSuffix(path, ".png"), strings.HasSuffix(path, ".svg"):
		return "image", nil
	}
	return "", fmt.Errorf("no kind for %s", path)
}

// browserPage gives, per server, device, difficulty and kind of visit, every
// visit's times (the first paint only for visits that painted before
// leaving) and the median bytes and requests per kind of file.
func browserPage(dir string) (any, error) {
	path := filepath.Join(dir, "visits.jsonl")
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	type key struct {
		Server, Device, Visit string
		Difficulty            int
	}
	type cellOut struct {
		Server     string         `json:"server"`
		Device     string         `json:"device"`
		Difficulty int            `json:"difficulty"`
		Visit      string         `json:"visit"`
		PaintMs    []int          `json:"paintMs"`
		SentMs     []int          `json:"sentMs"`
		ReachedMs  []int          `json:"reachedMs"`
		Bytes      map[string]int `json:"bytes"`
		Requests   map[string]int `json:"requests"`
	}
	var order []key
	visits := map[key][]browserVisit{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var v browserVisit
		if err := json.Unmarshal(sc.Bytes(), &v); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		k := key{v.Server, v.Device, v.Visit, v.Difficulty}
		if _, seen := visits[k]; !seen {
			order = append(order, k)
		}
		visits[k] = append(visits[k], v)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}

	kinds := []string{"page", "script", "style", "image", "translation"}
	var out []cellOut
	for _, k := range order {
		// PaintMs stays a list when no visit painted, so it isn't null.
		c := cellOut{Server: k.Server, Device: k.Device, Difficulty: k.Difficulty, Visit: k.Visit,
			PaintMs: []int{}, Bytes: map[string]int{}, Requests: map[string]int{}}
		bytes, requests := map[string][]int{}, map[string][]int{}
		for _, v := range visits[k] {
			if v.PaintMs != nil {
				c.PaintMs = append(c.PaintMs, *v.PaintMs)
			}
			c.SentMs = append(c.SentMs, v.SentMs)
			c.ReachedMs = append(c.ReachedMs, v.ReachedMs)
			b, n := map[string]int{}, map[string]int{}
			for _, file := range v.Files {
				kind, err := fileKind(file.Path)
				if err != nil {
					return nil, err
				}
				b[kind] += file.Bytes
				n[kind]++
			}
			for _, kind := range kinds {
				bytes[kind] = append(bytes[kind], b[kind])
				requests[kind] = append(requests[kind], n[kind])
			}
		}
		for _, kind := range kinds {
			c.Bytes[kind] = median(bytes[kind])
			c.Requests[kind] = median(requests[kind])
		}
		out = append(out, c)
	}
	return out, nil
}
