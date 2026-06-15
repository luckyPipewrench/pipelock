// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package playground

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
)

// runStats tracks per-run-nonce observation state.
type runStats struct {
	observedCount int
	totalCount    int
}

// Collector is a lab HTTP target that detects whether a planted synthetic
// canary secret arrives in incoming requests. The canary value is configured
// at startup and NEVER exposed through any public method or HTTP response.
//
// The witness/status endpoint is keyed by an opaque run nonce only, so the
// act of checking whether the canary arrived does not itself carry the
// canary value.
type Collector struct {
	canaryID    string
	canaryValue string // held internally; never returned to any caller

	mu               sync.Mutex
	runs             map[string]*runStats
	lastWitnessQuery string
}

// NewCollector creates a Collector preconfigured with a canary identifier
// and value. The value is held internally and never exposed.
func NewCollector(canaryID, canaryValue string) *Collector {
	return &Collector{
		canaryID:    canaryID,
		canaryValue: canaryValue,
		runs:        make(map[string]*runStats),
	}
}

// Handler returns the HTTP handler for the collector. Routes:
//   - /witness?run=<nonce> -- witness query (returns JSON, never carries canary)
//   - all other paths      -- ingestion endpoint (scans for canary)
func (c *Collector) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/witness", c.handleWitness)
	mux.HandleFunc("/", c.handleIngest)
	return mux
}

// ObservedCount returns how many requests for the given run nonce contained
// the canary value.
func (c *Collector) ObservedCount(nonce string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	if s, ok := c.runs[nonce]; ok {
		return s.observedCount
	}
	return 0
}

// TotalCount returns the total number of ingestion requests for the given
// run nonce (regardless of whether they contained the canary).
func (c *Collector) TotalCount(nonce string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	if s, ok := c.runs[nonce]; ok {
		return s.totalCount
	}
	return 0
}

// LastWitnessQueryRaw returns the raw query string of the most recent
// /witness request. Used in tests to verify the witness query never
// carries the canary value.
func (c *Collector) LastWitnessQueryRaw() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastWitnessQuery
}

// handleWitness serves the witness endpoint. It returns JSON with the run
// nonce, observed count, and total count. It MUST NOT read or require the
// canary value -- the query is keyed by run nonce only.
func (c *Collector) handleWitness(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	c.lastWitnessQuery = r.URL.RawQuery
	c.mu.Unlock()

	nonce := r.URL.Query().Get("run")

	type witnessResponse struct {
		Run           string `json:"run"`
		ObservedCount int    `json:"observed_count"`
		TotalCount    int    `json:"total_count"`
	}

	resp := witnessResponse{
		Run:           nonce,
		ObservedCount: c.ObservedCount(nonce),
		TotalCount:    c.TotalCount(nonce),
	}

	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	_ = enc.Encode(resp)
}

// handleIngest handles all non-witness requests. It scans the full request
// (URL query, headers, and body) for the canary value and records the
// result per run nonce.
func (c *Collector) handleIngest(w http.ResponseWriter, r *http.Request) {
	nonce := r.URL.Query().Get("run")

	observed := c.scanRequest(r)

	c.mu.Lock()
	s, ok := c.runs[nonce]
	if !ok {
		s = &runStats{}
		c.runs[nonce] = s
	}
	s.totalCount++
	if observed {
		s.observedCount++
	}
	c.mu.Unlock()

	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(w, "ingested run=%s observed=%t", nonce, observed)
}

// scanRequest checks whether the canary value appears anywhere in the
// request: URL query string, any header value, or the body. The body is
// read and then restored so downstream handlers (if any) can still read it.
func (c *Collector) scanRequest(r *http.Request) bool {
	target := c.canaryValue

	// Check URL (full raw query).
	if strings.Contains(r.URL.RawQuery, target) {
		return true
	}

	// Check all header values.
	for _, vals := range r.Header {
		for _, v := range vals {
			if strings.Contains(v, target) {
				return true
			}
		}
	}

	// Check body.
	if r.Body != nil {
		body, err := io.ReadAll(r.Body)
		if err == nil && strings.Contains(string(body), target) {
			// Restore the body for any downstream handler.
			r.Body = io.NopCloser(strings.NewReader(string(body)))
			return true
		}
		// Restore the body even when canary not found.
		r.Body = io.NopCloser(strings.NewReader(string(body)))
	}

	return false
}

// SafeTarget is a trivial HTTP target that returns a benign 200 response.
// Used for the "allowed request" beat of the demo.
type SafeTarget struct{}

// NewSafeTarget creates a new SafeTarget.
func NewSafeTarget() *SafeTarget {
	return &SafeTarget{}
}

// Handler returns the HTTP handler for the safe target.
func (s *SafeTarget) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = fmt.Fprintf(w, "ok")
	})
}
