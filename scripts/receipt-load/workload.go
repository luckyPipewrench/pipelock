// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

const (
	// blockEvery sets the deterministic share of requests that carry a
	// synthetic credential and must be blocked; the rest must be allowed.
	blockEvery = 20

	// workloadKeyParam is the query parameter that carries the per-request
	// workload key. A query value survives receipt target sanitation as long
	// as it is DLP-clean, which keeps the key readable in v1 and v2 receipts.
	workloadKeyParam = "wk"

	phaseWarmup  = 'w'
	phaseMeasure = 'm'
)

const fakeToken = "ghp_" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

// workload is the fixed, seed-derived request plan for one run. Every request
// has a unique non-secret key; all expectations (sink, receipts, response
// class) are derived from the plan rather than from observed counts.
type workload struct {
	seed        uint64
	warmup      int
	measured    int
	blockOffset int
}

func newWorkload(seed uint64, warmup, measured int) workload {
	return workload{seed: seed, warmup: warmup, measured: measured, blockOffset: int(seed % blockEvery)}
}

func (w workload) tag() string { return "s" + strconv.FormatUint(w.seed, 10) }

// total is the number of planned requests across both phases. Global slot
// numbers run warmup first, then measured.
func (w workload) total() int { return w.warmup + w.measured }

// slot maps a (phase, per-phase index) pair to a global slot number.
func (w workload) slot(phase byte, index int) int {
	if phase == phaseWarmup {
		return index
	}
	return w.warmup + index
}

// phaseOf reports the phase and per-phase index of a global slot.
func (w workload) phaseOf(slot int) (byte, int) {
	if slot < w.warmup {
		return phaseWarmup, slot
	}
	return phaseMeasure, slot - w.warmup
}

// blocked reports whether the request in a slot carries the synthetic
// credential and so must be blocked by Pipelock.
func (w workload) blocked(slot int) bool {
	_, index := w.phaseOf(slot)
	return (index+w.blockOffset)%blockEvery == 0
}

// key returns the unique workload key for a slot, for example s1-m000042.
func (w workload) key(slot int) string {
	phase, index := w.phaseOf(slot)
	return fmt.Sprintf("%s-%c%06d", w.tag(), phase, index)
}

// parseKey maps a key back to its slot. It fails for any key that does not
// belong to this plan, including keys from another seed or out-of-range
// indexes.
func (w workload) parseKey(key string) (int, bool) {
	rest, ok := strings.CutPrefix(key, w.tag()+"-")
	if !ok || len(rest) < 2 {
		return 0, false
	}
	phase := rest[0]
	if phase != phaseWarmup && phase != phaseMeasure {
		return 0, false
	}
	digits := rest[1:]
	for _, c := range digits {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	index, err := strconv.Atoi(digits)
	if err != nil || fmt.Sprintf("%06d", index) != digits {
		return 0, false
	}
	limit := w.measured
	if phase == phaseWarmup {
		limit = w.warmup
	}
	if index >= limit {
		return 0, false
	}
	return w.slot(phase, index), true
}

// pathAndQuery returns the path and query a request for a slot sends to the sink.
func (w workload) pathAndQuery(slot int) string {
	target := "/ok?" + workloadKeyParam + "=" + w.key(slot)
	if w.blocked(slot) {
		target += "&token=" + fakeToken
	}
	return target
}

// keyFromTarget extracts the workload key from a receipt or sink target. The
// second return value is false when the target carries no usable key, which
// includes a key that sanitation redacted away.
func keyFromTarget(target string) (string, bool) {
	u, err := url.Parse(target)
	if err != nil {
		return "", false
	}
	values := u.Query()[workloadKeyParam]
	if len(values) != 1 || values[0] == "" {
		return "", false
	}
	return values[0], true
}

// targetHost returns the host:port of a receipt target, or "" when the target
// is not a URL.
func targetHost(target string) string {
	u, err := url.Parse(target)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Host
}
