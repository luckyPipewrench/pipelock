// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestPercentile(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		vals []time.Duration
		pct  int
		want time.Duration
	}{
		{name: "empty", vals: nil, pct: 95, want: 0},
		{name: "p50_rounds_up_nearest_rank", vals: []time.Duration{10, 20, 30, 40}, pct: 50, want: 20},
		{name: "p95_rounds_up_nearest_rank", vals: []time.Duration{10, 20, 30, 40}, pct: 95, want: 40},
		{name: "unsorted", vals: []time.Duration{50, 10, 40, 30, 20}, pct: 50, want: 30},
		{name: "p99", vals: []time.Duration{time.Second, 2 * time.Second, 3 * time.Second}, pct: 99, want: 3 * time.Second},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := percentile(tc.vals, tc.pct); got != tc.want {
				t.Fatalf("percentile(%v, %d) = %s, want %s", tc.vals, tc.pct, got, tc.want)
			}
		})
	}
}

func TestCategorizeStatus(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		status int
		want   string
	}{
		{name: "rate_limited", status: http.StatusTooManyRequests, want: categoryRateLimited},
		{name: "unauthorized", status: http.StatusUnauthorized, want: categoryAuth},
		{name: "forbidden", status: http.StatusForbidden, want: categoryAuth},
		{name: "server", status: http.StatusBadGateway, want: categoryServer},
		{name: "other", status: http.StatusNotFound, want: categoryOther},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := categorizeStatus(tc.status); got != tc.want {
				t.Fatalf("categorizeStatus(%d) = %q, want %q", tc.status, got, tc.want)
			}
		})
	}
}

func TestAggregateResults(t *testing.T) {
	t.Parallel()
	results := []userResult{
		{
			ID: 0,
			Steps: []stepResult{
				{Name: stepSession, Status: http.StatusOK, Latency: 10 * time.Millisecond},
				{Name: stepMessage, Status: http.StatusAccepted, Latency: 20 * time.Millisecond},
				{Name: stepBundle, Status: http.StatusOK, Latency: 30 * time.Millisecond},
			},
		},
		{
			ID: 1,
			Steps: []stepResult{
				{Name: stepSession, Status: http.StatusTooManyRequests, Latency: 40 * time.Millisecond, Failed: true, Category: categoryRateLimited},
			},
		},
		{
			ID: 2,
			Steps: []stepResult{
				{Name: stepSession, Status: http.StatusOK, Latency: 50 * time.Millisecond},
				{Name: stepMessage, Status: http.StatusForbidden, Latency: 60 * time.Millisecond, Failed: true, Category: categoryAuth},
			},
		},
		{
			ID: 3,
			Steps: []stepResult{
				{Name: stepSession, Status: 0, Latency: 70 * time.Millisecond, Failed: true, Category: categoryTimeout},
			},
		},
	}
	agg := aggregateResults(results, 3)
	if agg.Total != 4 || agg.Successes != 1 || agg.Failures != 3 || agg.MaxUsersInFlight != 3 {
		t.Fatalf("aggregate counts = total %d successes %d failures %d peak %d", agg.Total, agg.Successes, agg.Failures, agg.MaxUsersInFlight)
	}
	if agg.FailureCategories[categoryRateLimited] != 1 || agg.FailureCategories[categoryAuth] != 1 || agg.FailureCategories[categoryTimeout] != 1 {
		t.Fatalf("failure categories = %+v", agg.FailureCategories)
	}
	if got := agg.StepLatency[stepSession].P95; got != 70*time.Millisecond {
		t.Fatalf("session p95 = %s, want 70ms", got)
	}
	if got := agg.StepStatuses[stepSession]["200"]; got != 2 {
		t.Fatalf("session 200 count = %d, want 2", got)
	}
	if got := agg.StepStatuses[stepSession]["429"]; got != 1 {
		t.Fatalf("session 429 count = %d, want 1", got)
	}
	if got := agg.StepStatuses[stepSession]["error"]; got != 1 {
		t.Fatalf("session error count = %d, want 1", got)
	}
}

func TestInFlightTracker(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		actions []string
		want    int
	}{
		{name: "none", actions: nil, want: 0},
		{name: "serial", actions: []string{"start", "done", "start", "done"}, want: 1},
		{name: "peak_three", actions: []string{"start", "start", "start", "done", "start", "done", "done", "done"}, want: 3},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tracker := &inFlightTracker{}
			for _, action := range tc.actions {
				switch action {
				case "start":
					tracker.start()
				case "done":
					tracker.done()
				default:
					t.Fatalf("unknown action %q", action)
				}
			}
			if got := tracker.peakValue(); got != tc.want {
				t.Fatalf("peakValue() = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestRunLoadTestFakeBroker(t *testing.T) {
	t.Parallel()
	var sessionCalls atomic.Int32
	ts := newLocalTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case routeSession:
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			var req sessionRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			if req.Code != "demo-code" || req.TurnstileToken != "test-token" {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			call := sessionCalls.Add(1)
			if call%2 == 0 {
				http.Error(w, "rate limited", http.StatusTooManyRequests)
				return
			}
			writeTestJSON(t, w, http.StatusOK, map[string]string{
				"token":      fmt.Sprintf("token-%d", call),
				"session_id": fmt.Sprintf("sid-%d", call),
			})
		case routeMessage:
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			var req messageRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			if !strings.HasPrefix(req.Token, "token-") || req.Message != "hello" {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			writeTestJSON(t, w, http.StatusAccepted, map[string]string{"status": "accepted"})
		case routeBundle:
			if r.Method != http.MethodGet {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			if !strings.HasPrefix(r.URL.Query().Get("token"), "token-") {
				http.Error(w, "missing token", http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "bundle")
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	cfg := config{
		brokerURL:      ts.URL,
		code:           "demo-code",
		turnstileToken: "test-token",
		concurrency:    4,
		prompt:         "hello",
		timeout:        time.Second,
	}
	results, peak := runLoadTest(context.Background(), ts.Client(), cfg)
	agg := aggregateResults(results, peak)
	if agg.Total != 4 || agg.Successes != 2 || agg.Failures != 2 {
		t.Fatalf("counts = total %d successes %d failures %d", agg.Total, agg.Successes, agg.Failures)
	}
	if got := agg.FailureCategories[categoryRateLimited]; got != 2 {
		t.Fatalf("rate-limited failures = %d, want 2", got)
	}
	if got := agg.StepStatuses[stepSession]["429"]; got != 2 {
		t.Fatalf("session 429 count = %d, want 2", got)
	}
	if got := agg.StepStatuses[stepMessage]["202"]; got != 2 {
		t.Fatalf("message 202 count = %d, want 2", got)
	}
	if peak <= 0 || peak > 4 {
		t.Fatalf("peak in flight = %d, want 1..4", peak)
	}
}

func writeTestJSON(t *testing.T, w http.ResponseWriter, status int, v any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Fatalf("encode response: %v", err)
	}
}

func newLocalTestServer(t *testing.T, h http.Handler) *httptest.Server {
	t.Helper()
	lc := net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("httptest listener unavailable in this sandbox: %v", err)
	}
	ts := httptest.NewUnstartedServer(h)
	ts.Listener = ln
	ts.Start()
	return ts
}
