// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// bodyDelay is how long the test origin holds a response body back after the
// headers have been sent. Any latency measured to the headers alone would be
// far below it.
const bodyDelay = 120 * time.Millisecond

func directParams(t *testing.T, plan workload, handler http.Handler) loadParams {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return loadParams{
		client:      &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 10 * time.Second},
		plan:        plan,
		sinkAddr:    strings.TrimPrefix(srv.URL, "http://"),
		concurrency: 4,
	}
}

func TestLatencyIsMeasuredToTheFullBody(t *testing.T) {
	plan := newWorkload(3, 0, 8)
	var headerLatency atomic.Int64
	params := directParams(t, plan, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "2")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush() // headers reach the client now
		select {                 // the body is what takes time
		case <-time.After(bodyDelay):
		case <-r.Context().Done():
			return
		}
		_, _ = w.Write([]byte(sinkBody))
	}))
	// Time to headers for the same server, measured the way the old harness
	// stopped its clock.
	before := time.Now()
	probe, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://"+params.sinkAddr+"/ok?wk=probe", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := params.client.Do(probe)
	if err != nil {
		t.Fatal(err)
	}
	headerLatency.Store(time.Since(before).Nanoseconds())
	_ = resp.Body.Close()
	if time.Duration(headerLatency.Load()) >= bodyDelay {
		t.Skipf("host too slow to separate header time (%s) from body delay", time.Duration(headerLatency.Load()))
	}

	res := runPhase(context.Background(), params, phaseMeasure, plan.measured)
	for i, out := range res.outcomes {
		if out.transportErr || out.bodyReadErr || out.bodyMismatch {
			// Blocked-class slots expect a 403; this origin always answers 200,
			// which is itself a class mismatch and is not what is under test.
			if !plan.blocked(plan.slot(phaseMeasure, i)) {
				t.Fatalf("request %d: %+v", i, out)
			}
			continue
		}
		if got := time.Duration(out.latencyNS); got < bodyDelay {
			t.Fatalf("request %d latency %s is shorter than the %s body delay: it was timed to headers", i, got, bodyDelay)
		}
	}
}

func TestBodyReadErrorsAreCounted(t *testing.T) {
	plan := newWorkload(3, 0, 6)
	params := directParams(t, plan, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Promise ten bytes, send three, then drop the connection.
		conn, buf, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		_, _ = buf.WriteString("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc")
		_ = buf.Flush()
		_ = conn.Close()
	}))
	res := runPhase(context.Background(), params, phaseMeasure, plan.measured)
	perf := summarizeMeasured(plan, res, time.Second, res.samples)
	if perf.BodyReadErrors != plan.measured || perf.Errors != 0 {
		t.Fatalf("body_read_errors=%d errors=%d, want %d and 0", perf.BodyReadErrors, perf.Errors, plan.measured)
	}
	if perf.Verdict != perfInvalid {
		t.Fatal("a run whose bodies failed to read must not be a valid measurement")
	}
	if perf.Latency.Samples != 0 {
		t.Fatalf("failed reads contributed %d latency samples", perf.Latency.Samples)
	}
}

func TestTransportErrorsAreCounted(t *testing.T) {
	plan := newWorkload(3, 0, 4)
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close() // nothing listens here now
	params := loadParams{client: &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 2 * time.Second}, plan: plan, sinkAddr: addr, concurrency: 2}
	res := runPhase(context.Background(), params, phaseMeasure, plan.measured)
	perf := summarizeMeasured(plan, res, time.Second, res.samples)
	if perf.Errors != plan.measured || perf.Verdict != perfInvalid {
		t.Fatalf("errors=%d verdict=%s", perf.Errors, perf.Verdict)
	}
}

func TestResponseClassIsChecked(t *testing.T) {
	plan := newWorkload(3, 0, 40)
	// A proxy that waves a credential through is a finding: every blocked-class
	// request answered 200 is a body mismatch, not a fast success.
	params := directParams(t, plan, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(sinkBody))
	}))
	res := runPhase(context.Background(), params, phaseMeasure, plan.measured)
	perf := summarizeMeasured(plan, res, time.Second, res.samples)
	if perf.Unexpected == 0 || perf.Verdict != perfInvalid {
		t.Fatalf("unexpected=%d verdict=%s, want blocked-class 200s flagged", perf.Unexpected, perf.Verdict)
	}
}

func TestWindowRates(t *testing.T) {
	ms := func(n int) int64 { return int64(time.Duration(n) * time.Millisecond) }
	done := []int64{ms(10), ms(20), ms(30), ms(110), ms(120), ms(210), ms(220), ms(230), ms(240), ms(250)}
	got := windowRates(done, 260*time.Millisecond, 100*time.Millisecond)
	if len(got) != 3 {
		t.Fatalf("windows = %d, want 3", len(got))
	}
	wantReq := []int{3, 2, 5}
	for i, w := range got {
		if w.Requests != wantReq[i] {
			t.Fatalf("window %d requests = %d, want %d", i, w.Requests, wantReq[i])
		}
	}
	if got[0].RequestsPerSecond != 30 || got[1].RequestsPerSecond != 20 {
		t.Fatalf("full-window rates = %v, %v, want 30 and 20", got[0].RequestsPerSecond, got[1].RequestsPerSecond)
	}
	if !got[2].Partial || math.Abs(got[2].Seconds-0.06) > 1e-9 || math.Abs(got[2].RequestsPerSecond-5/0.06) > 1e-6 {
		t.Fatalf("partial window = %+v", got[2])
	}
	summary := summarizeWindows(got, 100*time.Millisecond)
	if summary.FullWindows != 2 || summary.MinRPS != 20 || summary.MaxRPS != 30 || summary.MedianRPS != 25 {
		t.Fatalf("summary = %+v, want the partial window excluded", summary)
	}
}

func TestWindowRatesShortRunUsesPartialWindow(t *testing.T) {
	got := windowRates([]int64{int64(10 * time.Millisecond)}, 50*time.Millisecond, 5*time.Second)
	summary := summarizeWindows(got, 5*time.Second)
	if len(got) != 1 || !got[0].Partial || summary.FullWindows != 0 || summary.MedianRPS == 0 {
		t.Fatalf("got %+v summary %+v", got, summary)
	}
	if windowRates(nil, 0, time.Second) != nil {
		t.Fatal("an empty run should have no windows")
	}
}

func TestWarmupIsExcludedFromPerformance(t *testing.T) {
	plan := newWorkload(3, 5, 10)
	var hits atomic.Int64
	params := directParams(t, plan, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Query().Get("token") != "" {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("blocked: core DLP match: GitHub Token"))
			return
		}
		_, _ = w.Write([]byte(sinkBody))
	}))
	warm := runPhase(context.Background(), params, phaseWarmup, plan.warmup)
	measured := runPhase(context.Background(), params, phaseMeasure, plan.measured)
	if got := hits.Load(); got != int64(plan.total()) {
		t.Fatalf("origin saw %d requests, want %d", got, plan.total())
	}
	perf := summarizeMeasured(plan, measured, time.Second, measured.samples)
	if perf.Allowed+perf.Blocked != plan.measured || perf.Latency.Samples != plan.measured {
		t.Fatalf("performance covers %d requests with %d latency samples, want only the %d measured", perf.Allowed+perf.Blocked, perf.Latency.Samples, plan.measured)
	}
	if len(warm.outcomes) != plan.warmup {
		t.Fatalf("warmup outcomes = %d", len(warm.outcomes))
	}
	// Every request, warmup included, has a distinct key.
	seen := map[string]bool{}
	for slot := range plan.total() {
		if seen[plan.key(slot)] {
			t.Fatalf("duplicate key %s", plan.key(slot))
		}
		seen[plan.key(slot)] = true
	}
}

func TestWorkloadKeys(t *testing.T) {
	plan := newWorkload(7, 3, 50)
	blocked := 0
	for slot := range plan.total() {
		got, ok := plan.parseKey(plan.key(slot))
		if !ok || got != slot {
			t.Fatalf("slot %d round-tripped to %d (%v)", slot, got, ok)
		}
		if plan.blocked(slot) {
			blocked++
			if !strings.Contains(plan.pathAndQuery(slot), "token=") {
				t.Fatalf("slot %d is blocked but carries no credential", slot)
			}
		}
	}
	if blocked == 0 {
		t.Fatal("no blocked requests in plan")
	}
	for _, bad := range []string{"", "s7", "s7-", "s7-x000001", "s7-m1", "s7-m0000001", "s8-m000001", "s7-m000050", "s7-w000003", "s7-m00000a", "s7-m-00001"} {
		if _, ok := plan.parseKey(bad); ok {
			t.Fatalf("parseKey(%q) accepted a key outside the plan", bad)
		}
	}
}
