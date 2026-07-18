// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
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

func TestCategorizeError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want string
	}{
		{name: "deadline", err: context.DeadlineExceeded, want: categoryTimeout},
		{name: "net timeout", err: timeoutError{}, want: categoryTimeout},
		{name: "other", err: errors.New("connection refused"), want: categoryOther},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := categorizeError(tc.err); got != tc.want {
				t.Fatalf("categorizeError(%v) = %q, want %q", tc.err, got, tc.want)
			}
		})
	}
}

type timeoutError struct{}

func (timeoutError) Error() string {
	return "timeout"
}

func (timeoutError) Timeout() bool {
	return true
}

func (timeoutError) Temporary() bool {
	return true
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

func TestParseFlags(t *testing.T) {
	oldArgs := os.Args
	oldCommandLine := flag.CommandLine
	t.Cleanup(func() {
		os.Args = oldArgs
		flag.CommandLine = oldCommandLine
	})
	flag.CommandLine = flag.NewFlagSet("pipelock-playground-loadtest", flag.ContinueOnError)
	os.Args = []string{
		"pipelock-playground-loadtest",
		"--broker-url", "https://broker.example",
		"--code", "demo-code",
		"--turnstile-token", "test-token",
		"--concurrency", "3",
		"--ramp", "2s",
		"--prompt", "hello",
		"--timeout", "5s",
		"--json",
	}

	got := parseFlags()
	if got.brokerURL != "https://broker.example" ||
		got.code != "demo-code" ||
		got.turnstileToken != "test-token" ||
		got.concurrency != 3 ||
		got.ramp != 2*time.Second ||
		got.prompt != "hello" ||
		got.timeout != 5*time.Second ||
		!got.jsonOutput {
		t.Fatalf("parseFlags() = %#v, want parsed CLI values", got)
	}
}

func TestValidateConfigRejectsExcessiveConcurrency(t *testing.T) {
	t.Parallel()

	cfg := config{
		brokerURL:      "https://broker.example",
		code:           "demo-code",
		turnstileToken: "test-token",
		concurrency:    maxConcurrency + 1,
		prompt:         "hello",
		timeout:        time.Second,
	}
	if err := validateConfig(cfg); err == nil {
		t.Fatal("validateConfig accepted excessive concurrency")
	}
}

func TestValidateConfigRequiredFields(t *testing.T) {
	t.Parallel()

	valid := config{
		brokerURL:      "https://broker.example",
		code:           "demo-code",
		turnstileToken: "test-token",
		concurrency:    1,
		prompt:         "hello",
		timeout:        time.Second,
	}
	tests := []struct {
		name   string
		mutate func(*config)
		want   string
	}{
		{name: "broker url", mutate: func(cfg *config) { cfg.brokerURL = "://" }, want: "--broker-url"},
		{name: "broker host", mutate: func(cfg *config) { cfg.brokerURL = "https://" }, want: "--broker-url host"},
		{name: "code", mutate: func(cfg *config) { cfg.code = " " }, want: "--code"},
		{name: "turnstile", mutate: func(cfg *config) { cfg.turnstileToken = "" }, want: "--turnstile-token"},
		{name: "concurrency", mutate: func(cfg *config) { cfg.concurrency = 0 }, want: "--concurrency"},
		{name: "ramp", mutate: func(cfg *config) { cfg.ramp = -time.Second }, want: "--ramp"},
		{name: "prompt", mutate: func(cfg *config) { cfg.prompt = "" }, want: "--prompt"},
		{name: "timeout", mutate: func(cfg *config) { cfg.timeout = 0 }, want: "--timeout"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := valid
			tc.mutate(&cfg)
			err := validateConfig(cfg)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("validateConfig error = %v, want %q", err, tc.want)
			}
		})
	}
	if err := validateConfig(valid); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
}

func TestSameOriginClientBlocksCrossOriginRedirect(t *testing.T) {
	t.Parallel()

	client := sameOriginClient(&http.Client{}, "https://broker.example/base")
	sameReq, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://broker.example/next", nil)
	if err != nil {
		t.Fatalf("NewRequest same origin: %v", err)
	}
	if err := client.CheckRedirect(sameReq, nil); err != nil {
		t.Fatalf("same-origin redirect blocked: %v", err)
	}

	crossReq, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://other.example/next", nil)
	if err != nil {
		t.Fatalf("NewRequest cross origin: %v", err)
	}
	if err := client.CheckRedirect(crossReq, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("cross-origin redirect error = %v, want ErrUseLastResponse", err)
	}
}

func TestRunLoadTestCancellationDuringRampWaitsForStartedUsers(t *testing.T) {
	t.Parallel()

	started := make(chan struct{})
	release := make(chan struct{})
	var startOnce atomic.Bool
	var releaseOnce sync.Once
	releaseRequest := func() {
		releaseOnce.Do(func() {
			close(release)
		})
	}
	t.Cleanup(releaseRequest)
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		if startOnce.CompareAndSwap(false, true) {
			close(started)
		}
		<-release
		return &http.Response{
			StatusCode: http.StatusServiceUnavailable,
			Body:       io.NopCloser(strings.NewReader("stopped")),
			Header:     make(http.Header),
		}, nil
	})}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cfg := config{
		brokerURL:      "https://broker.example",
		code:           "demo-code",
		turnstileToken: "test-token",
		concurrency:    3,
		ramp:           300 * time.Millisecond,
		prompt:         "hello",
		timeout:        time.Second,
	}
	done := make(chan []userResult, 1)
	go func() {
		results, _ := runLoadTest(ctx, client, cfg)
		done <- results
	}()

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("first virtual user did not start")
	}
	cancel()
	select {
	case <-done:
		releaseRequest()
		t.Fatal("runLoadTest returned before started user finished")
	case <-time.After(50 * time.Millisecond):
	}
	releaseRequest()
	results := <-done
	if len(results) != cfg.concurrency {
		t.Fatalf("results len = %d, want %d", len(results), cfg.concurrency)
	}
	if len(results[0].Steps) != 1 || !results[0].Steps[0].Failed {
		t.Fatalf("first user result = %+v, want failed session step after release", results[0])
	}
}

func TestRunLoadTestPreCanceledZeroRampStartsNoUsers(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("{}")),
			Header:     make(http.Header),
		}, nil
	})}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cfg := config{
		brokerURL:   "https://broker.example",
		code:        "demo-code",
		concurrency: 3,
		ramp:        0,
		prompt:      "hello",
		timeout:     time.Second,
	}

	results, peak := runLoadTest(ctx, client, cfg)
	if len(results) != cfg.concurrency {
		t.Fatalf("results len = %d, want %d", len(results), cfg.concurrency)
	}
	if peak != 0 {
		t.Fatalf("peak in-flight = %d, want 0", peak)
	}
	if calls.Load() != 0 {
		t.Fatalf("HTTP calls after pre-canceled zero-ramp run = %d, want 0", calls.Load())
	}
	for _, result := range results {
		if len(result.Steps) != 0 {
			t.Fatalf("result %+v has steps, want no started users", result)
		}
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

func TestDoRequestKeepsTimeoutContextUntilBodyClose(t *testing.T) {
	t.Parallel()

	bodyAllowed := make(chan struct{})
	ts := newLocalTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		<-bodyAllowed
		_, _ = io.WriteString(w, "ok")
	}))
	defer ts.Close()

	cfg := config{
		brokerURL: ts.URL,
		timeout:   time.Second,
	}
	resp, step := doRequest(context.Background(), ts.Client(), cfg, http.MethodGet, "/", "", nil, "probe")
	if step.Failed {
		t.Fatalf("doRequest failed before body read: %+v", step)
	}
	close(bodyAllowed)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll after doRequest returned error: %v", err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if string(body) != "ok" {
		t.Fatalf("body = %q, want ok", body)
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

func TestPrintReportAndWriteJSON(t *testing.T) {
	t.Parallel()

	agg := aggregate{
		Total:             3,
		Successes:         1,
		Failures:          2,
		MaxUsersInFlight:  2,
		FailureCategories: newFailureCategories(),
		StepLatency: map[string]latencySummary{
			stepSession: {Count: 3, P50: time.Millisecond, P95: 2 * time.Millisecond, P99: 3 * time.Millisecond},
			stepMessage: {Count: 1, P50: 4 * time.Millisecond, P95: 4 * time.Millisecond, P99: 4 * time.Millisecond},
			stepBundle:  {},
		},
		StepStatuses: map[string]map[string]int{
			stepSession: {"200": 1, "429": 1, "error": 1},
			stepMessage: {"202": 1},
		},
		SessionCreateDist: sessionCreateDistribution{
			Count:   3,
			Min:     time.Millisecond,
			P50:     2 * time.Millisecond,
			P95:     3 * time.Millisecond,
			P99:     3 * time.Millisecond,
			Max:     3 * time.Millisecond,
			Buckets: map[string]int{"<=1s": 1, "<=5s": 1, "<=15s": 0, "<=30s": 0, ">30s": 1},
		},
	}
	agg.FailureCategories[categoryRateLimited] = 1
	agg.FailureCategories[categoryTimeout] = 1

	var report strings.Builder
	printReport(&report, agg)
	out := report.String()
	for _, want := range []string{
		"Pipelock playground broker load test",
		"total=3 successes=1 failures=2 max_in_flight=2",
		"rate_limited: 1",
		"session: 200=1 429=1 error=1",
		"buckets: <=1s=1 <=5s=1 <=15s=0 <=30s=0 >30s=1",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("report missing %q in:\n%s", want, out)
		}
	}

	var js strings.Builder
	if err := writeJSON(&js, agg); err != nil {
		t.Fatalf("writeJSON: %v", err)
	}
	var decoded aggregate
	if err := json.Unmarshal([]byte(js.String()), &decoded); err != nil {
		t.Fatalf("json output did not decode: %v", err)
	}
	if decoded.Total != agg.Total || decoded.SessionCreateDist.Buckets[">30s"] != 1 {
		t.Fatalf("decoded aggregate = %+v", decoded)
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
