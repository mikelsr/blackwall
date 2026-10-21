// Gzips each challenge page with compress/gzip at level 1, two ways: one
// writer reset per page (as Anubis's pool does) and a new writer per page (as
// Blackwall does). Prints the time per page and per input byte.
// Usage: go run . <page.html>... (pages from ../pages.sh).
package main

import (
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"time"
)

const iterations = 20000

func report(how, path string, n int, start time.Time) {
	per := float64(time.Since(start).Nanoseconds()) / iterations
	fmt.Printf("go %s %s %d B: %.1f µs per page, %.2f ns per byte\n", how, path, n, per/1000, per/float64(n))
}

func main() {
	for _, path := range os.Args[1:] {
		page, err := os.ReadFile(path)
		if err != nil {
			panic(err)
		}
		start := time.Now()
		for range iterations {
			gz, _ := gzip.NewWriterLevel(io.Discard, gzip.BestSpeed)
			_, _ = gz.Write(page)
			_ = gz.Close()
		}
		report("new", path, len(page), start)

		gz, _ := gzip.NewWriterLevel(io.Discard, gzip.BestSpeed)
		start = time.Now()
		for range iterations {
			gz.Reset(io.Discard)
			_, _ = gz.Write(page)
			_ = gz.Close()
		}
		report("reused", path, len(page), start)
	}
}
