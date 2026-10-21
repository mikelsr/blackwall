// Times the stock rules' user-agent regexes on the bench user agent with Go's
// regexp, once per rule. Anubis's HeaderMatchesChecker matches a single-valued,
// non-matching header twice, so its cost is twice the total printed here.
// Usage: go run . rules.json (from ../extract.py).
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"
)

const ua = "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0 b7l-bench/1.0"

const iterations = 20000

func main() {
	var rules []struct{ Rule, Kind, Pattern string }
	b, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	if err := json.Unmarshal(b, &rules); err != nil {
		panic(err)
	}
	var total time.Duration
	n := 0
	for _, r := range rules {
		if r.Kind != "ua" {
			continue
		}
		re := regexp.MustCompile(strings.TrimSpace(r.Pattern))
		start := time.Now()
		for range iterations {
			re.MatchString(ua)
		}
		per := time.Since(start) / iterations
		total += per
		n++
		fmt.Printf("%-40s %6.2f µs\n", r.Rule, float64(per.Nanoseconds())/1000)
	}
	fmt.Printf("all %d once: %.1f µs; twice, as Anubis: %.1f µs\n", n, float64(total.Nanoseconds())/1000, 2*float64(total.Nanoseconds())/1000)
}
