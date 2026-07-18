// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type trackedBody struct {
	reader io.Reader
	closed atomic.Bool
	err    error
}

func (b *trackedBody) Read(p []byte) (int, error) {
	return b.reader.Read(p)
}

func (b *trackedBody) Close() error {
	b.closed.Store(true)
	return b.err
}

type failingReader struct {
	err error
}

func (r failingReader) Read([]byte) (int, error) {
	return 0, r.err
}

func validLoadConfig() config {
	return config{
		brokerURL:      "https://broker.example",
		code:           "demo-code",
		turnstileToken: "test-token",
		concurrency:    1,
		prompt:         "hello",
		timeout:        time.Second,
	}
}

func response(status int, body io.ReadCloser) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       body,
		Header:     make(http.Header),
	}
}

func TestValidateConfigRejectsMalformedEndpoints(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		url  string
		want string
	}{
		{name: "blank", url: " \t", want: "--broker-url is required"},
		{name: "unsupported scheme", url: "ftp://broker.example", want: "must use http or https"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := validLoadConfig()
			cfg.brokerURL = tc.url
			err := validateConfig(cfg)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("validateConfig() error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestCreateSessionRejectsUnsafeResponsesAndClosesBodies(t *testing.T) {
	t.Parallel()

	privateMarker := "visitor-private-response"
	tests := []struct {
		name         string
		status       int
		body         io.Reader
		wantCategory string
		wantError    string
	}{
		{
			name:         "authorization failure",
			status:       http.StatusForbidden,
			body:         strings.NewReader(privateMarker),
			wantCategory: categoryAuth,
		},
		{
			name:         "oversized response",
			status:       http.StatusOK,
			body:         io.LimitReader(strings.NewReader(strings.Repeat("x", maxResponseBytes+1)), maxResponseBytes+1),
			wantCategory: categoryOther,
			wantError:    "oversized or unreadable",
		},
		{
			name:         "unreadable response",
			status:       http.StatusOK,
			body:         failingReader{err: errors.New("read failed")},
			wantCategory: categoryOther,
			wantError:    "oversized or unreadable",
		},
		{
			name:         "malformed response",
			status:       http.StatusOK,
			body:         strings.NewReader("{"),
			wantCategory: categoryOther,
			wantError:    "decode session response",
		},
		{
			name:         "missing token",
			status:       http.StatusOK,
			body:         strings.NewReader(`{"token":""}`),
			wantCategory: categoryOther,
			wantError:    "missing token",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			body := &trackedBody{reader: tc.body}
			client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return response(tc.status, body), nil
			})}

			token, step := createSession(context.Background(), client, validLoadConfig())
			if token != "" || !step.Failed || step.Category != tc.wantCategory {
				t.Fatalf("createSession() = token %q, step %+v", token, step)
			}
			if tc.wantError != "" && !strings.Contains(step.ErrMessage, tc.wantError) {
				t.Fatalf("error = %q, want %q", step.ErrMessage, tc.wantError)
			}
			if strings.Contains(step.ErrMessage, privateMarker) {
				t.Fatalf("error exposed response content: %q", step.ErrMessage)
			}
			if !body.closed.Load() {
				t.Fatal("response body was not closed")
			}
		})
	}
}

func TestVirtualUserStopsAtFailedStepAndClosesBodies(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		failCall    int
		failStatus  int
		wantSteps   int
		wantFailure string
	}{
		{name: "message failure", failCall: 2, failStatus: http.StatusBadGateway, wantSteps: 2, wantFailure: categoryServer},
		{name: "bundle failure", failCall: 3, failStatus: http.StatusNotFound, wantSteps: 3, wantFailure: categoryOther},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var calls atomic.Int32
			var bodies []*trackedBody
			client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				call := int(calls.Add(1))
				status := http.StatusOK
				payload := "ok"
				if call == 1 {
					payload = `{"token":"session-token"}`
				}
				if call == tc.failCall {
					status = tc.failStatus
					payload = "private upstream detail"
				}
				body := &trackedBody{reader: strings.NewReader(payload)}
				bodies = append(bodies, body)
				return response(status, body), nil
			})}

			got := runVirtualUser(context.Background(), client, validLoadConfig(), 7)
			if got.ID != 7 || len(got.Steps) != tc.wantSteps {
				t.Fatalf("runVirtualUser() = %+v, want %d steps", got, tc.wantSteps)
			}
			last := got.Steps[len(got.Steps)-1]
			if !last.Failed || last.Category != tc.wantFailure {
				t.Fatalf("last step = %+v, want failed category %q", last, tc.wantFailure)
			}
			if int(calls.Load()) != tc.wantSteps {
				t.Fatalf("request count = %d, want %d", calls.Load(), tc.wantSteps)
			}
			for i, body := range bodies {
				if !body.closed.Load() {
					t.Fatalf("response body %d was not closed", i)
				}
			}
		})
	}
}

func TestRequestConstructionAndTransportFailuresAreContained(t *testing.T) {
	t.Parallel()

	cfg := validLoadConfig()
	cfg.brokerURL = "://bad"
	resp, step := doRequest(context.Background(), http.DefaultClient, cfg, http.MethodGet, "/", "", nil, "probe")
	if resp != nil {
		_ = resp.Body.Close()
	}
	if resp != nil || !step.Failed || step.Category != categoryOther {
		t.Fatalf("malformed base result = resp %v, step %+v", resp, step)
	}

	cfg = validLoadConfig()
	resp, step = doRequest(context.Background(), http.DefaultClient, cfg, "BAD\nMETHOD", "/", "", nil, "probe")
	if resp != nil {
		_ = resp.Body.Close()
	}
	if resp != nil || !step.Failed || step.Category != categoryOther {
		t.Fatalf("malformed method result = resp %v, step %+v", resp, step)
	}

	transportErr := errors.New("dial refused")
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, transportErr
	})}
	resp, step = doRequest(context.Background(), client, validLoadConfig(), http.MethodGet, "/", "", nil, "probe")
	if resp != nil {
		_ = resp.Body.Close()
	}
	if resp != nil || !step.Failed || step.Category != categoryOther || !strings.Contains(step.ErrMessage, transportErr.Error()) {
		t.Fatalf("transport failure result = resp %v, step %+v", resp, step)
	}

	resp, step = doJSON(context.Background(), client, validLoadConfig(), http.MethodPost, "/", "", make(chan int), "probe")
	if resp != nil {
		_ = resp.Body.Close()
	}
	if resp != nil || !step.Failed || step.Category != categoryOther || !strings.Contains(step.ErrMessage, "unsupported type") {
		t.Fatalf("marshal failure result = resp %v, step %+v", resp, step)
	}

	messageStep := postMessage(context.Background(), client, validLoadConfig(), "session-token")
	if !messageStep.Failed || messageStep.Category != categoryOther {
		t.Fatalf("message transport failure = %+v", messageStep)
	}
	bundleStep := getBundle(context.Background(), client, validLoadConfig(), "session-token")
	if !bundleStep.Failed || bundleStep.Category != categoryOther {
		t.Fatalf("bundle transport failure = %+v", bundleStep)
	}
}

func TestRequestCancellationAndCloseError(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		<-req.Context().Done()
		return nil, req.Context().Err()
	})}
	resp, step := doRequest(ctx, client, validLoadConfig(), http.MethodGet, "/", "", nil, "probe")
	if resp != nil {
		_ = resp.Body.Close()
	}
	if resp != nil || !step.Failed || step.Category != categoryOther {
		t.Fatalf("canceled request = resp %v, step %+v", resp, step)
	}

	closeErr := errors.New("close failed")
	body := &trackedBody{reader: strings.NewReader("ok"), err: closeErr}
	var canceled atomic.Bool
	wrapped := &cancelOnClose{ReadCloser: body, cancel: func() { canceled.Store(true) }}
	if err := wrapped.Close(); !errors.Is(err, closeErr) {
		t.Fatalf("Close() error = %v, want %v", err, closeErr)
	}
	if !body.closed.Load() || !canceled.Load() {
		t.Fatalf("Close() cleanup = body closed %v, context canceled %v", body.closed.Load(), canceled.Load())
	}
}

func TestAggregationAndDistributionEdgeCases(t *testing.T) {
	t.Parallel()

	results := []userResult{
		{ID: 1, Steps: []stepResult{{Name: stepSession, Failed: true}}},
		{ID: 2, Steps: []stepResult{{Name: stepSession, Status: http.StatusOK}}},
	}
	agg := aggregateResults(results, 1)
	if agg.Failures != 2 || agg.FailureCategories[categoryOther] != 2 {
		t.Fatalf("aggregate failures = %d, categories %+v", agg.Failures, agg.FailureCategories)
	}

	vals := []time.Duration{
		time.Second,
		5 * time.Second,
		15 * time.Second,
		30 * time.Second,
		31 * time.Second,
	}
	dist := summarizeSessionCreate(vals)
	for bucket, got := range dist.Buckets {
		if got != 1 {
			t.Fatalf("bucket %q = %d, want 1", bucket, got)
		}
	}
	if dist.Min != time.Second || dist.Max != 31*time.Second {
		t.Fatalf("distribution bounds = %s..%s", dist.Min, dist.Max)
	}
	if got := percentileSorted(vals, 0); got != time.Second {
		t.Fatalf("zero percentile = %s", got)
	}
	if got := percentileSorted(vals, 100); got != 31*time.Second {
		t.Fatalf("hundredth percentile = %s", got)
	}
}

func TestSameOriginClientHandlesNilClientAndMalformedBase(t *testing.T) {
	t.Parallel()

	client := sameOriginClient(nil, "https://broker.example")
	if client == nil || client == http.DefaultClient {
		t.Fatal("sameOriginClient did not return an isolated client copy")
	}
	original := &http.Client{}
	if got := sameOriginClient(original, "://bad"); got != original {
		t.Fatal("malformed base should leave the caller's client unchanged")
	}
}

func TestCommandJSONModeReportsConnectionFailure(t *testing.T) {
	originalArgs := os.Args
	originalFlags := flag.CommandLine
	originalStdout := os.Stdout
	t.Cleanup(func() {
		os.Args = originalArgs
		flag.CommandLine = originalFlags
		os.Stdout = originalStdout
	})

	output, err := os.CreateTemp(t.TempDir(), "loadtest-output-*.json")
	if err != nil {
		t.Fatalf("create output: %v", err)
	}
	t.Cleanup(func() { _ = output.Close() })
	os.Stdout = output
	flag.CommandLine = flag.NewFlagSet("pipelock-playground-loadtest", flag.ContinueOnError)
	flag.CommandLine.SetOutput(io.Discard)
	os.Args = []string{
		"pipelock-playground-loadtest",
		"--broker-url", "http://127.0.0.1:0",
		"--code", "demo-code",
		"--turnstile-token", "test-token",
		"--concurrency", "1",
		"--ramp", "0",
		"--prompt", "hello",
		"--timeout", "50ms",
		"--json",
	}

	main()
	if _, err := output.Seek(0, io.SeekStart); err != nil {
		t.Fatalf("seek output: %v", err)
	}
	var agg aggregate
	if err := json.NewDecoder(output).Decode(&agg); err != nil {
		t.Fatalf("decode command output: %v", err)
	}
	if agg.Total != 1 || agg.Successes != 0 || agg.Failures != 1 {
		t.Fatalf("command result = total %d successes %d failures %d", agg.Total, agg.Successes, agg.Failures)
	}
	if agg.FailureCategories[categoryOther]+agg.FailureCategories[categoryTimeout] != 1 {
		t.Fatalf("failure categories = %+v", agg.FailureCategories)
	}
}

func TestCommandTextModeCompletesSuccessfulWorkflow(t *testing.T) {
	server := newLocalTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case routeSession:
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"token":"session-token"}`)
		case routeMessage:
			w.WriteHeader(http.StatusAccepted)
		case routeBundle:
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, req)
		}
	}))
	defer server.Close()

	originalArgs := os.Args
	originalFlags := flag.CommandLine
	originalStdout := os.Stdout
	t.Cleanup(func() {
		os.Args = originalArgs
		flag.CommandLine = originalFlags
		os.Stdout = originalStdout
	})

	output, err := os.CreateTemp(t.TempDir(), "loadtest-report-*.txt")
	if err != nil {
		t.Fatalf("create output: %v", err)
	}
	t.Cleanup(func() { _ = output.Close() })
	os.Stdout = output
	flag.CommandLine = flag.NewFlagSet("pipelock-playground-loadtest", flag.ContinueOnError)
	flag.CommandLine.SetOutput(io.Discard)
	os.Args = []string{
		"pipelock-playground-loadtest",
		"--broker-url", server.URL,
		"--code", "demo-code",
		"--turnstile-token", "test-token",
		"--concurrency", "1",
		"--timeout", "1s",
	}

	main()
	if _, err := output.Seek(0, io.SeekStart); err != nil {
		t.Fatalf("seek output: %v", err)
	}
	raw, err := io.ReadAll(output)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	report := string(raw)
	if !strings.Contains(report, "total=1 successes=1 failures=0") {
		t.Fatalf("command report did not record success:\n%s", report)
	}
}
