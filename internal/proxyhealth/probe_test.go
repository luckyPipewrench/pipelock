// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxyhealth

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type brokenBody struct{}

func (brokenBody) Read([]byte) (int, error) { return 0, errors.New("read failure") }
func (brokenBody) Close() error             { return nil }

func TestGet(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			t.Errorf("path=%s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)
	resp, err := Get(t.Context(), server.Client(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp, err := Get(t.Context(), server.Client(), "http://[invalid"); err == nil {
		_ = resp.Body.Close()
		t.Fatal("invalid URL accepted")
	}
	ctx := t.Context()
	if resp, err := Get(ctx, server.Client(), "invalid://localhost"); err == nil {
		_ = resp.Body.Close()
		t.Fatal("unsupported scheme accepted")
	}
}

func TestReadFailure(t *testing.T) {
	t.Parallel()
	err := CheckLaunch(&http.Response{StatusCode: http.StatusOK, Body: brokenBody{}}, false)
	if err == nil || !strings.Contains(err.Error(), "read proxy health") {
		t.Fatalf("err=%v", err)
	}
}

func TestLaunchState(t *testing.T) {
	t.Parallel()
	const good = `{"status":"healthy","forward_proxy_enabled":true,"tls_interception_enabled":true,"kill_switch_active":false}`
	for _, tt := range []struct {
		name, body, want string
		require          bool
	}{
		{"healthy", good, "", true},
		{"forward off", strings.Replace(good, `"forward_proxy_enabled":true`, `"forward_proxy_enabled":false`, 1), "forward proxy", false},
		{"intercept off", strings.Replace(good, `"tls_interception_enabled":true`, `"tls_interception_enabled":false`, 1), "TLS interception", true},
		{"intercept optional", strings.Replace(good, `"tls_interception_enabled":true`, `"tls_interception_enabled":false`, 1), "", false},
		{"kill on", strings.Replace(good, `"kill_switch_active":false`, `"kill_switch_active":true`, 1), "kill switch", false},
		{"missing", `{}`, "incomplete", false},
		{"malformed", `{`, "invalid proxy health", false},
		{"invalid root", `[]`, "JSON object", false},
		{"bad status", strings.Replace(good, "healthy", "unhealthy", 1), "unhealthy", false},
		{"null flag", strings.Replace(good, `"kill_switch_active":false`, `"kill_switch_active":null`, 1), "incomplete", false},
		{"wrong flag type", strings.Replace(good, `"kill_switch_active":false`, `"kill_switch_active":"false"`, 1), "invalid proxy health", false},
		{"duplicate key", strings.Replace(good, `"forward_proxy_enabled":true`, `"forward_proxy_enabled":false,"forward_proxy_enabled":true`, 1), "duplicate health field", false},
		{"trailing data", good + `{}`, "trailing data", false},
		{"bad key syntax", `{"status":"healthy",x`, "invalid proxy health", false},
		{"bad value syntax", `{"status":x}`, "invalid proxy health", false},
		{"unclosed object", `{"status":"healthy"`, "invalid proxy health", false},
		{"too big", strings.Repeat("x", (64<<10)+1), "too large", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := CheckLaunch(&http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(tt.body))}, tt.require)
			if tt.want == "" && err != nil || tt.want != "" && (err == nil || !strings.Contains(err.Error(), tt.want)) {
				t.Fatalf("err=%v want=%q", err, tt.want)
			}
		})
	}
	if err := CheckLaunch(&http.Response{StatusCode: http.StatusServiceUnavailable, Body: io.NopCloser(strings.NewReader(good))}, false); err == nil {
		t.Fatal("non-OK health status accepted")
	}
}
