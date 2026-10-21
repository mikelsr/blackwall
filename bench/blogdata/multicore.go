package main

// Scaling with vCPUs: the reference cells on the server sizes a cloud VM
// would usually give either server (experiments/multicore.sh).

import (
	"fmt"
	"maps"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
)

// One run per layout, repeat and step: <layout>-<sweep|fixed>-<server>-<policy>-<scenario>-r<repeat>
// for the reference cells, <layout>-direct-r<repeat> for the rig alone and
// <layout>-idle-mem-r<repeat> for idle memory.
const multicoreRun = "multicore"

// The layouts in the order the graphs show them: the VM sizes, then 2core,
// two cores with their second threads idle, which separates cores from
// hyperthreads. A vCPU is one hardware thread.
var multicoreLayouts = []struct {
	Key     string `json:"key"`
	Threads int    `json:"threads"`
	Cores   int    `json:"cores"`
}{{"1vcpu", 1, 1}, {"2vcpu", 2, 1}, {"4vcpu", 4, 2}, {"2core", 2, 2}}

// The reference cells multicore.sh runs, matched by policy and scenario.
var multicoreCells = []cell{
	{"realistic", "allow", kib}, {"realistic", "pass", kib}, {"realistic", "flood", 0}, {"minimal", "allow", kib},
}

// The rig's own capacity varies by up to 13% between repeats (54–62k req/s),
// so a server that fails within 10% of it may have hit the rig's limit.
const rigMargin = 0.9

var (
	multicoreCellName = regexp.MustCompile(`^(\w+)-(sweep|fixed)-(\w+)-(\w+)-(\w+)-r(\d+)$`)
	multicoreRigName  = regexp.MustCompile(`^(\w+)-direct-r(\d+)$`)
	multicoreIdleName = regexp.MustCompile(`^(\w+)-idle-mem-r(\d+)$`)
)

// multicore gives, per layout: the rig's capacity alone, and per reference
// cell and server the max rate of each sweep repeat, CPU, latency and
// resident memory at the fixed rate (median of the repeats), and idle memory.
func multicore(dir string) (any, error) {
	type fixedOut struct {
		Rate float64  `json:"rate"`
		CPU  cpuSplit `json:"cpu"`
		P50  float64  `json:"p50"`
		P90  float64  `json:"p90"`
		P99  float64  `json:"p99"`
		P999 float64  `json:"p999"`
		RSS  float64  `json:"rssMb"`
	}
	type perLayout struct {
		Capacity []float64 `json:"capacity"`
		// In at least one repeat, the sweep's first failing rate was
		// within rigMargin of what the rig handles alone in the same
		// repeat, or above it: the rig, not the server, may have been the
		// limit.
		AtLeast bool     `json:"atLeast,omitempty"`
		Fixed   fixedOut `json:"fixed"`
	}
	type row struct {
		Policy    string               `json:"policy"`
		Scenario  string               `json:"scenario"`
		Blackwall map[string]perLayout `json:"blackwall"`
		Anubis    map[string]perLayout `json:"anubis"`
	}
	type cellKey struct{ server, policy, scenario, layout string }
	type layoutRepeat struct {
		layout string
		repeat int
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	rig := map[layoutRepeat]float64{}
	sweeps := map[cellKey]map[int][]record{}
	fixed := map[cellKey][]record{}
	idle := map[string]map[[2]string][]float64{} // layout, {policy, server}: MB per repeat
	for _, e := range entries {
		name := e.Name()
		if !e.IsDir() {
			continue
		}
		if m := multicoreIdleName.FindStringSubmatch(name); m != nil {
			rows, err := readIdleMem(filepath.Join(dir, name, "idle-mem.tsv"))
			if err != nil {
				return nil, err
			}
			totals := map[[2]string]float64{}
			for _, r := range rows {
				totals[[2]string{r.policy, r.server}] += r.mb
			}
			if idle[m[1]] == nil {
				idle[m[1]] = map[[2]string][]float64{}
			}
			for k, mb := range totals {
				idle[m[1]][k] = append(idle[m[1]][k], mb)
			}
			continue
		}
		recs, err := readRecords(filepath.Join(dir, name, "results.jsonl"))
		if err != nil {
			return nil, err
		}
		if m := multicoreRigName.FindStringSubmatch(name); m != nil {
			rep, _ := strconv.Atoi(m[2])
			rig[layoutRepeat{m[1], rep}] = maxRate(recs)
		} else if m := multicoreCellName.FindStringSubmatch(name); m != nil {
			k := cellKey{m[3], m[4], m[5], m[1]}
			if m[2] == "fixed" {
				fixed[k] = append(fixed[k], recs...)
			} else {
				if sweeps[k] == nil {
					sweeps[k] = map[int][]record{}
				}
				rep, _ := strconv.Atoi(m[6])
				sweeps[k][rep] = recs
			}
		}
	}
	if len(rig) == 0 || len(sweeps) == 0 {
		return nil, fmt.Errorf("no direct or sweep runs in %s", dir)
	}

	rigOut := map[string][]float64{}
	for _, l := range multicoreLayouts {
		for r := 1; ; r++ {
			v, ok := rig[layoutRepeat{l.Key, r}]
			if !ok {
				break
			}
			rigOut[l.Key] = append(rigOut[l.Key], v)
		}
	}

	var rows []row
	var sloMs float64
	for _, c := range multicoreCells {
		r := row{Policy: c.Policy, Scenario: c.Scenario, Blackwall: map[string]perLayout{}, Anubis: map[string]perLayout{}}
		for _, srv := range servers {
			for _, l := range multicoreLayouts {
				k := cellKey{srv, c.Policy, c.Scenario, l.Key}
				reps, recs := sweeps[k], fixed[k]
				if len(reps) == 0 || len(recs) == 0 {
					return nil, fmt.Errorf("%s %s %s %s: missing sweep or fixed-rate runs", l.Key, srv, c.Policy, c.Scenario)
				}
				var p perLayout
				for _, rep := range slices.Sorted(maps.Keys(reps)) {
					steps := reps[rep]
					p.Capacity = append(p.Capacity, maxRate(steps))
					rigMax, ok := rig[layoutRepeat{l.Key, rep}]
					if !ok {
						return nil, fmt.Errorf("%s r%d: no direct run", l.Key, rep)
					}
					p.AtLeast = p.AtLeast || firstFail(steps) > rigMargin*rigMax
				}
				m := medianRecord(recs, func(r record) float64 { return r.P99 })
				sloMs = m.SLOms
				rss := make([]float64, len(recs))
				for i, r := range recs {
					rss[i] = r.RSSPeak
				}
				p.Fixed = fixedOut{m.Rate, splitOf(recs), round(m.P50, 2), round(m.P90, 2), round(m.P99, 2), round(m.P999, 2), round(median(rss), 1)}
				if srv == "blackwall" {
					r.Blackwall[l.Key] = p
				} else {
					r.Anubis[l.Key] = p
				}
			}
		}
		rows = append(rows, r)
	}

	idleOut := map[string]map[string]map[string]float64{} // layout, policy, server: median MB
	for layout, byKey := range idle {
		idleOut[layout] = map[string]map[string]float64{}
		for k, mbs := range byKey {
			if idleOut[layout][k[0]] == nil {
				idleOut[layout][k[0]] = map[string]float64{}
			}
			idleOut[layout][k[0]][k[1]] = round(median(mbs), 1)
		}
	}
	return map[string]any{
		"layouts": multicoreLayouts, "rig": rigOut, "cells": rows, "idleMemory": idleOut,
		"sloMs": sloMs,
	}, nil
}

// firstFail is the lowest failing rate of one sweep, +Inf if every step
// passed.
func firstFail(steps []record) float64 {
	low := math.Inf(1)
	for _, r := range steps {
		if !r.Pass {
			low = min(low, r.Rate)
		}
	}
	return low
}
