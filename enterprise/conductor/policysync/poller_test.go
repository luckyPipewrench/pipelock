//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package policysync

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
)

const (
	testBaseURL = "https://leader.example:8895"
	testETag1   = `"a1b2c3"`
	testETag2   = `"d4e5f6"`
)

// step scripts one stub response: status code, ETag header, and body. A nil
// body with readErr set makes the response body fail on Read.
type step struct {
	status  int
	etag    string
	body    []byte
	readErr bool
}

// errReader fails on Read to exercise the response-body read-error path.
type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("read failure") }

// stubDoer serves a scripted sequence of steps (one per request) and records
// the requests it received so tests can assert on headers (e.g. If-None-Match).
// The response is constructed inside Do - not pre-built and stored - so the
// bodyclose linter correctly attributes the close to the code under test (the
// poller defers resp.Body.Close()).
type stubDoer struct {
	mu    sync.Mutex
	steps []step
	err   error // non-nil => every Do returns this transport error
	reqs  []*http.Request
	i     int
}

func (s *stubDoer) Do(r *http.Request) (*http.Response, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reqs = append(s.reqs, r)
	if s.err != nil {
		return nil, s.err
	}
	idx := s.i
	s.i++
	if idx >= len(s.steps) {
		idx = len(s.steps) - 1
	}
	st := s.steps[idx]
	h := http.Header{}
	if st.etag != "" {
		h.Set("ETag", st.etag)
	}
	var body io.ReadCloser
	if st.readErr {
		body = io.NopCloser(errReader{})
	} else {
		body = io.NopCloser(strings.NewReader(string(st.body)))
	}
	return &http.Response{StatusCode: st.status, Header: h, Body: body, Request: r}, nil
}

func (s *stubDoer) reqCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.reqs)
}

func (s *stubDoer) inmAt(i int) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if i < 0 || i >= len(s.reqs) {
		return ""
	}
	return s.reqs[i].Header.Get("If-None-Match")
}

func (s *stubDoer) lastReq() *http.Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.reqs) == 0 {
		return nil
	}
	return s.reqs[len(s.reqs)-1]
}

type stubApplier struct {
	mu  sync.Mutex
	got []conductor.PolicyBundle
	err error
}

func (a *stubApplier) ApplyPolicyBundle(b conductor.PolicyBundle) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.got = append(a.got, b)
	return a.err
}

func (a *stubApplier) calls() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.got)
}

func mkBundleJSON(t *testing.T) []byte {
	t.Helper()
	raw, err := json.Marshal(conductor.PolicyBundle{BundleID: "b1", Version: 1})
	if err != nil {
		t.Fatalf("marshal bundle: %v", err)
	}
	return raw
}

func newTestPoller(t *testing.T, doer HTTPDoer, applier Applier) *Poller {
	t.Helper()
	p, err := NewPoller(PollerConfig{
		BaseURL:      testBaseURL,
		Client:       doer,
		Applier:      applier,
		PollInterval: time.Second,
	})
	if err != nil {
		t.Fatalf("NewPoller: %v", err)
	}
	return p
}

func TestNewPoller_Validation(t *testing.T) {
	okApplier := ApplierFunc(func(conductor.PolicyBundle) error { return nil })
	okDoer := &stubDoer{steps: []step{{status: http.StatusNoContent}}}
	tests := []struct {
		name    string
		cfg     PollerConfig
		wantErr error
	}{
		{name: "nil client", cfg: PollerConfig{BaseURL: testBaseURL, Applier: okApplier}, wantErr: ErrPollerRequired},
		{name: "nil applier", cfg: PollerConfig{BaseURL: testBaseURL, Client: okDoer}, wantErr: ErrPollerRequired},
		{name: "interval below floor", cfg: PollerConfig{BaseURL: testBaseURL, Client: okDoer, Applier: okApplier, PollInterval: time.Millisecond}},
		{name: "negative max response bytes", cfg: PollerConfig{BaseURL: testBaseURL, Client: okDoer, Applier: okApplier, MaxResponseBytes: -1}},
		{name: "non-https base url", cfg: PollerConfig{BaseURL: "http://leader.example:8895", Client: okDoer, Applier: okApplier}},
		{name: "base url with path", cfg: PollerConfig{BaseURL: "https://leader.example:8895/extra", Client: okDoer, Applier: okApplier}},
		{name: "base url with query", cfg: PollerConfig{BaseURL: "https://leader.example:8895?x=1", Client: okDoer, Applier: okApplier}},
		{name: "base url empty host", cfg: PollerConfig{BaseURL: "https://", Client: okDoer, Applier: okApplier}},
		{name: "base url unparseable", cfg: PollerConfig{BaseURL: "://bad", Client: okDoer, Applier: okApplier}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, err := NewPoller(tc.cfg)
			if err == nil {
				t.Fatalf("expected error, got nil poller=%v", p)
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("want errors.Is %v, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestNewPoller_DefaultsAndEndpoint(t *testing.T) {
	p, err := NewPoller(PollerConfig{
		BaseURL: testBaseURL,
		Client:  &stubDoer{},
		Applier: ApplierFunc(func(conductor.PolicyBundle) error { return nil }),
	})
	if err != nil {
		t.Fatalf("NewPoller: %v", err)
	}
	if p.pollInterval != defaultPollInterval {
		t.Errorf("pollInterval = %s, want %s", p.pollInterval, defaultPollInterval)
	}
	if p.maxResponseBytes != defaultResponseBytes {
		t.Errorf("maxResponseBytes = %d, want %d", p.maxResponseBytes, defaultResponseBytes)
	}
	if want := testBaseURL + LatestPolicyBundlePath; p.endpoint != want {
		t.Errorf("endpoint = %q, want %q", p.endpoint, want)
	}
}

func TestPollOnce_StatusHandling(t *testing.T) {
	tests := []struct {
		name        string
		status      int
		body        []byte
		applierErr  error
		wantErr     bool
		wantErrType error
		wantApplied int
	}{
		{name: "200 applies bundle", status: http.StatusOK, body: mkBundleJSON(t), wantApplied: 1},
		{name: "204 no bundle", status: http.StatusNoContent, wantApplied: 0},
		{name: "304 not modified", status: http.StatusNotModified, wantApplied: 0},
		{name: "500 server error", status: http.StatusInternalServerError, wantErr: true, wantErrType: ErrPollResponse, wantApplied: 0},
		{name: "403 forbidden", status: http.StatusForbidden, wantErr: true, wantErrType: ErrPollResponse, wantApplied: 0},
		{name: "200 invalid json", status: http.StatusOK, body: []byte("{not json"), wantErr: true, wantErrType: ErrPollResponse, wantApplied: 0},
		{name: "200 unknown field", status: http.StatusOK, body: []byte(`{"bundle_id":"b1","totally_unknown":true}`), wantErr: true, wantErrType: ErrPollResponse, wantApplied: 0},
		// A trailing JSON document is rejected BEFORE apply - a hostile leader
		// must not be able to smuggle a second payload past the strict decoder.
		{name: "200 trailing document", status: http.StatusOK, body: append(mkBundleJSON(t), []byte("\n{}")...), wantErr: true, wantErrType: ErrPollResponse, wantApplied: 0},
		{name: "200 applier rejects", status: http.StatusOK, body: mkBundleJSON(t), applierErr: errors.New("bad signature"), wantErr: true, wantApplied: 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			doer := &stubDoer{steps: []step{{status: tc.status, etag: testETag1, body: tc.body}}}
			applier := &stubApplier{err: tc.applierErr}
			p := newTestPoller(t, doer, applier)
			err := p.PollOnce(context.Background())
			if tc.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.wantErrType != nil && !errors.Is(err, tc.wantErrType) {
				t.Fatalf("want errors.Is %v, got %v", tc.wantErrType, err)
			}
			if got := applier.calls(); got != tc.wantApplied {
				t.Errorf("applier calls = %d, want %d", got, tc.wantApplied)
			}
		})
	}
}

func TestPollOnce_ETagAdvancesOnlyAfterSuccess(t *testing.T) {
	// First poll: 200 with ETag1 -> applied, ETag cached.
	// Second poll: must send If-None-Match: ETag1, and 304 skips apply.
	doer := &stubDoer{steps: []step{
		{status: http.StatusOK, etag: testETag1, body: mkBundleJSON(t)},
		{status: http.StatusNotModified, etag: testETag1},
	}}
	applier := &stubApplier{}
	p := newTestPoller(t, doer, applier)

	if err := p.PollOnce(context.Background()); err != nil {
		t.Fatalf("first poll: %v", err)
	}
	if got := doer.inmAt(0); got != "" {
		t.Errorf("first request should not send If-None-Match, got %q", got)
	}
	if err := p.PollOnce(context.Background()); err != nil {
		t.Fatalf("second poll: %v", err)
	}
	if got := doer.lastReq().Header.Get("If-None-Match"); got != testETag1 {
		t.Errorf("second request If-None-Match = %q, want %q", got, testETag1)
	}
	if applier.calls() != 1 {
		t.Errorf("applier should be called once (304 skips), got %d", applier.calls())
	}
}

func TestPollOnce_ETagNotAdvancedWhenApplierRejects(t *testing.T) {
	// Apply fails on the first poll -> ETag must NOT advance, so the second
	// poll re-fetches (no If-None-Match) instead of being masked by a 304.
	doer := &stubDoer{steps: []step{
		{status: http.StatusOK, etag: testETag1, body: mkBundleJSON(t)},
		{status: http.StatusOK, etag: testETag2, body: mkBundleJSON(t)},
	}}
	applier := &stubApplier{err: errors.New("reject")}
	p := newTestPoller(t, doer, applier)

	if err := p.PollOnce(context.Background()); err == nil {
		t.Fatal("first poll: expected apply error")
	}
	if err := p.PollOnce(context.Background()); err == nil {
		t.Fatal("second poll: expected apply error")
	}
	if got := doer.lastReq().Header.Get("If-None-Match"); got != "" {
		t.Errorf("after a rejected apply the poller must re-fetch without If-None-Match, got %q", got)
	}
	if applier.calls() != 2 {
		t.Errorf("applier should be retried, calls = %d, want 2", applier.calls())
	}
}

func TestPollOnce_BodyExceedsCap(t *testing.T) {
	doer := &stubDoer{steps: []step{{status: http.StatusOK, etag: testETag1, body: []byte(strings.Repeat("x", 64))}}}
	applier := &stubApplier{}
	p, err := NewPoller(PollerConfig{
		BaseURL:          testBaseURL,
		Client:           doer,
		Applier:          applier,
		PollInterval:     time.Second,
		MaxResponseBytes: 16,
	})
	if err != nil {
		t.Fatalf("NewPoller: %v", err)
	}
	if err := p.PollOnce(context.Background()); !errors.Is(err, ErrPollResponse) {
		t.Fatalf("want ErrPollResponse, got %v", err)
	}
	if applier.calls() != 0 {
		t.Errorf("oversized body must not be applied, calls = %d", applier.calls())
	}
}

func TestPollOnce_BodyReadError(t *testing.T) {
	doer := &stubDoer{steps: []step{{status: http.StatusOK, readErr: true}}}
	applier := &stubApplier{}
	p := newTestPoller(t, doer, applier)
	if err := p.PollOnce(context.Background()); err == nil {
		t.Fatal("expected body read error")
	}
	if applier.calls() != 0 {
		t.Errorf("read error must not apply, calls = %d", applier.calls())
	}
}

func TestPollOnce_TransportError(t *testing.T) {
	doer := &stubDoer{err: errors.New("dial tcp: connection refused")}
	applier := &stubApplier{}
	p := newTestPoller(t, doer, applier)
	if err := p.PollOnce(context.Background()); err == nil {
		t.Fatal("expected transport error")
	}
	if applier.calls() != 0 {
		t.Errorf("transport error must not apply, calls = %d", applier.calls())
	}
}

func TestPollOnce_RequestHeaders(t *testing.T) {
	doer := &stubDoer{steps: []step{{status: http.StatusNoContent}}}
	p := newTestPoller(t, doer, &stubApplier{})
	if err := p.PollOnce(context.Background()); err != nil {
		t.Fatalf("PollOnce: %v", err)
	}
	req := doer.lastReq()
	if req.Method != http.MethodGet {
		t.Errorf("method = %s, want GET", req.Method)
	}
	if got := req.Header.Get("Accept"); got != pollerAcceptedCT {
		t.Errorf("Accept = %q, want %q", got, pollerAcceptedCT)
	}
	if got := req.Header.Get("User-Agent"); got != pollerUserAgent {
		t.Errorf("User-Agent = %q, want %q", got, pollerUserAgent)
	}
	if !strings.HasSuffix(req.URL.Path, LatestPolicyBundlePath) {
		t.Errorf("path = %q, want suffix %q", req.URL.Path, LatestPolicyBundlePath)
	}
}

func TestRun_StopsOnContextCancel(t *testing.T) {
	doer := &stubDoer{steps: []step{{status: http.StatusNoContent}}}
	p := newTestPoller(t, doer, &stubApplier{})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- p.Run(ctx) }()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run returned %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop after cancel")
	}
}

func TestRun_LogsPollErrorAndContinues(t *testing.T) {
	// First poll fails (500); the poller logs and keeps looping. Exercises the
	// logPollError continue-branch inside Run.
	doer := &stubDoer{steps: []step{
		{status: http.StatusInternalServerError},
		{status: http.StatusNoContent},
	}}
	p, err := NewPoller(PollerConfig{
		BaseURL:      testBaseURL,
		Client:       doer,
		Applier:      &stubApplier{},
		PollInterval: time.Second,
		Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("NewPoller: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- p.Run(ctx) }()
	deadline := time.After(5 * time.Second)
	for doer.reqCount() < 1 {
		select {
		case <-deadline:
			t.Fatal("no poll occurred")
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop")
	}
}

func TestRun_NilPoller(t *testing.T) {
	var p *Poller
	if err := p.Run(context.Background()); !errors.Is(err, ErrPollerRequired) {
		t.Fatalf("nil Run = %v, want ErrPollerRequired", err)
	}
	if err := p.PollOnce(context.Background()); !errors.Is(err, ErrPollerRequired) {
		t.Fatalf("nil PollOnce = %v, want ErrPollerRequired", err)
	}
}

func TestLogPollError(t *testing.T) {
	var logs bytes.Buffer
	p := &Poller{logger: slog.New(slog.NewJSONHandler(&logs, nil))}
	p.logPollError(errors.New("boom"))
	got := logs.String()
	if !strings.Contains(got, "conductor_policy_bundle_poll_error") || !strings.Contains(got, "boom") {
		t.Fatalf("logs = %s, want poll error event", got)
	}
	// A nil logger must be a safe no-op.
	(&Poller{}).logPollError(errors.New("ignored"))
}
