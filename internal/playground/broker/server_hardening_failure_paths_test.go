// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package broker

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/playground/livechat"
)

type hardeningRoundTripper func(*http.Request) (*http.Response, error)

func (f hardeningRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

type hardeningErrorReader struct{}

func (hardeningErrorReader) Read([]byte) (int, error) {
	return 0, errors.New("forced read failure")
}

func TestHardeningBrokerRoutesRejectMalformedAndUnauthenticatedRequests(t *testing.T) {
	provider := &serverFakeProvider{}
	srv, err := NewServer(ServerConfig{
		Leases:       testLeaseManager(t, provider),
		Gate:         testBrokerGate(t),
		IPRate:       livechat.RateConfig{RefillPerSec: 100, Burst: 100},
		CodeRate:     livechat.RateConfig{RefillPerSec: 100, Burst: 100},
		ReapInterval: time.Hour,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(srv.Close)
	handler := srv.Handler()

	tests := []struct {
		name   string
		method string
		target string
		body   string
		status int
	}{
		{"health method", http.MethodPost, livechat.RouteHealth, "", http.StatusMethodNotAllowed},
		{"session preflight", http.MethodOptions, livechat.RouteSession, "", http.StatusNoContent},
		{"stream preflight", http.MethodOptions, livechat.RouteStream, "", http.StatusNoContent},
		{"stream missing token", http.MethodGet, livechat.RouteStream, "", http.StatusNotFound},
		{"message preflight", http.MethodOptions, livechat.RouteMessage, "", http.StatusNoContent},
		{"message malformed", http.MethodPost, livechat.RouteMessage, `{"token":`, http.StatusBadRequest},
		{"message unknown token", http.MethodPost, livechat.RouteMessage, `{"token":"unknown","message":"hello"}`, http.StatusNotFound},
		{"bundle preflight", http.MethodOptions, livechat.RouteBundle, "", http.StatusNoContent},
		{"bundle invalid os", http.MethodGet, livechat.RouteBundle + "?os=plan9", "", http.StatusBadRequest},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequestWithContext(t.Context(), tc.method, tc.target, strings.NewReader(tc.body))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != tc.status {
				t.Fatalf("status = %d, want %d; body=%s", rec.Code, tc.status, rec.Body.String())
			}
		})
	}
}

func TestHardeningBrokerUpstreamReadFailuresDoNotReturnArtifacts(t *testing.T) {
	t.Parallel()

	client := &http.Client{Transport: hardeningRoundTripper(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(hardeningErrorReader{}),
		}, nil
	})}
	srv := &Server{
		cfg:    ServerConfig{InternalPort: 8080},
		client: client,
	}
	lease := &Lease{Machine: &Machine{PrivateIP: "127.0.0.1"}}

	artifact, err := srv.fetchVMArtifact(context.Background(), lease, "token", "")
	if err == nil ||
		!strings.Contains(err.Error(), "read bundle body") {
		t.Fatalf("fetchVMArtifact error = %v", err)
	}
	if artifact.status != 0 || artifact.body != nil || artifact.contentType != "" || artifact.contentDisposition != "" {
		t.Fatalf("fetchVMArtifact returned partial artifact: %#v", artifact)
	}
	session, expiresAt, retryable, err := srv.attemptVMSession(
		context.Background(),
		"http://127.0.0.1:8080/api/live/session",
		[]byte(`{"code":"code"}`),
	)
	if err == nil || retryable || !strings.Contains(err.Error(), "read vm session response") {
		t.Fatalf("attemptVMSession retryable=%v error=%v", retryable, err)
	}
	if session != (vmSessionResponse{}) || !expiresAt.IsZero() {
		t.Fatalf("attemptVMSession returned partial state: session=%#v expires=%v", session, expiresAt)
	}
}

func TestHardeningBrokerHelpersFailClosedAndCleanState(t *testing.T) {
	t.Parallel()

	srv := &Server{
		cfg:            ServerConfig{InternalPort: 8080},
		tokens:         make(map[string]*tokenLease),
		bySess:         make(map[string]string),
		bundleInflight: make(map[string]int),
		bundleSealed:   make(map[string]bool),
		bundleFailed:   make(map[string]bool),
	}
	if _, err := srv.targetURL(nil, livechat.RouteMessage); err == nil {
		t.Fatal("targetURL accepted a nil lease")
	}
	srv.releaseToken(context.Background(), "missing")

	now := time.Now()
	srv.starts = []time.Time{now.Add(-2 * time.Minute), now}
	if got := srv.sessionStartsSince(now, time.Minute); got != 1 {
		t.Fatalf("sessionStartsSince = %d, want 1", got)
	}

	if release := srv.bundleLeave("missing"); release {
		t.Fatal("bundleLeave released an unsealed token")
	}

	rec := httptest.NewRecorder()
	status := &statusRecorder{ResponseWriter: rec}
	status.WriteHeader(http.StatusTeapot)
	if status.status != http.StatusTeapot || rec.Code != http.StatusTeapot {
		t.Fatalf("status recorder = %d/%d", status.status, rec.Code)
	}

	req := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodPost,
		livechat.RouteSession,
		bytes.NewBufferString(`{"code":"a"}{"code":"b"}`),
	)
	var decoded sessionRequest
	if err := decodeBrokerJSON(req, &decoded); err == nil {
		t.Fatal("decodeBrokerJSON accepted multiple objects")
	}
}
