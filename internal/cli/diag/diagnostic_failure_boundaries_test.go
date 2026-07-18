// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package diag

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/proxy"
	"github.com/spf13/cobra"
)

func TestDiagnosticFetchResponsesFailClosed(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		handler http.HandlerFunc
		run     func(string) diagnoseResult
		want    string
	}{
		"allowed_malformed": {
			handler: func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "{") },
			run: func(url string) diagnoseResult {
				return checkFetchAllowed(url, "http://upstream.example", config.Defaults())
			},
			want: "decode error",
		},
		"allowed_blocked": {
			handler: func(w http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(w).Encode(proxy.FetchResponse{Blocked: true, BlockReason: "policy"})
			},
			run: func(url string) diagnoseResult {
				return checkFetchAllowed(url, "http://upstream.example", config.Defaults())
			},
			want: "got blocked",
		},
		"allowed_bad_status": {
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusBadGateway)
				_ = json.NewEncoder(w).Encode(proxy.FetchResponse{Content: "unexpected"})
			},
			run: func(url string) diagnoseResult {
				return checkFetchAllowed(url, "http://upstream.example", config.Defaults())
			},
			want: "expected 200",
		},
		"allowed_embedded_error": {
			handler: func(w http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(w).Encode(proxy.FetchResponse{Error: "upstream trust failure"})
			},
			run: func(url string) diagnoseResult {
				return checkFetchAllowed(url, "http://upstream.example", config.Defaults())
			},
			want: "fetch error",
		},
		"blocked_malformed": {
			handler: func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "not-json") },
			run: func(url string) diagnoseResult {
				return checkFetchBlocked(url, "http://upstream.example", config.Defaults())
			},
			want: "decode error",
		},
		"blocked_was_allowed": {
			handler: func(w http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(w).Encode(proxy.FetchResponse{Blocked: false})
			},
			run: func(url string) diagnoseResult {
				return checkFetchBlocked(url, "http://upstream.example", config.Defaults())
			},
			want: "request was allowed",
		},
		"blocked_wrong_layer": {
			handler: func(w http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(w).Encode(proxy.FetchResponse{Blocked: true, BlockReason: "rate limit"})
			},
			run: func(url string) diagnoseResult {
				return checkFetchBlocked(url, "http://upstream.example", config.Defaults())
			},
			want: "expected DLP scanner",
		},
		"hint_malformed": {
			handler: func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "[") },
			run: func(url string) diagnoseResult {
				cfg := config.Defaults()
				cfg.ExplainBlocks = diagBoolPtr(true)
				return checkFetchHint(url, "http://upstream.example", cfg)
			},
			want: "decode error",
		},
		"hint_was_allowed": {
			handler: func(w http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(w).Encode(proxy.FetchResponse{Blocked: false})
			},
			run: func(url string) diagnoseResult {
				cfg := config.Defaults()
				cfg.ExplainBlocks = diagBoolPtr(true)
				return checkFetchHint(url, "http://upstream.example", cfg)
			},
			want: "request was allowed",
		},
		"hint_empty": {
			handler: func(w http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(w).Encode(proxy.FetchResponse{Blocked: true})
			},
			run: func(url string) diagnoseResult {
				cfg := config.Defaults()
				cfg.ExplainBlocks = diagBoolPtr(true)
				return checkFetchHint(url, "http://upstream.example", cfg)
			},
			want: "non-empty hint",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			srv := httptest.NewServer(tc.handler)
			t.Cleanup(srv.Close)
			result := tc.run(srv.URL)
			if result.Status != statusFail || !strings.Contains(result.Detail, tc.want) {
				t.Fatalf("result = %#v, want fail containing %q", result, tc.want)
			}
		})
	}
}

func TestDiagnosticTransportFailuresDoNotBecomePasses(t *testing.T) {
	t.Parallel()

	unhealthy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(unhealthy.Close)
	health := checkHealth(unhealthy.URL, "", nil)
	if health.Status != statusFail || !strings.Contains(health.Detail, "503") {
		t.Fatalf("unhealthy endpoint result = %#v", health)
	}

	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Errorf("hijack failing diagnostic server: %v", err)
			return
		}
		_ = conn.Close()
	}))
	t.Cleanup(failing.Close)
	unreachable := failing.URL
	checks := []struct {
		name string
		run  func() diagnoseResult
		want string
	}{
		{"health", func() diagnoseResult { return checkHealth(unreachable, "", nil) }, "health request failed"},
		{"fetch_allowed", func() diagnoseResult {
			return checkFetchAllowed(unreachable, "http://upstream.example", nil)
		}, "fetch request failed"},
		{"fetch_blocked", func() diagnoseResult {
			return checkFetchBlocked(unreachable, "http://upstream.example", nil)
		}, "fetch request failed"},
		{"fetch_hint", func() diagnoseResult {
			cfg := config.Defaults()
			cfg.ExplainBlocks = diagBoolPtr(true)
			return checkFetchHint(unreachable, "http://upstream.example", cfg)
		}, "fetch request failed"},
		{"forward_allowed", func() diagnoseResult {
			return checkForwardAllowed(unreachable, "http://upstream.example:80", nil)
		}, "CONNECT failed"},
		{"forward_blocked", func() diagnoseResult {
			return checkForwardBlocked(unreachable, "", nil)
		}, "unexpected error"},
	}
	for _, tc := range checks {
		t.Run(tc.name, func(t *testing.T) {
			result := tc.run()
			if result.Status != statusFail || !strings.Contains(result.Detail, tc.want) {
				t.Fatalf("result = %#v, want fail containing %q", result, tc.want)
			}
		})
	}

	resp, err := diagnoseGet("http://[bad")
	if resp != nil {
		_ = resp.Body.Close()
	}
	if err == nil {
		t.Fatal("malformed diagnostic URL was accepted")
	}
	resp, err = verifyGet("http://[bad")
	if resp != nil {
		_ = resp.Body.Close()
	}
	if err == nil {
		t.Fatal("malformed verification URL was accepted")
	}
	if _, err := DirectTCPConnect("invalid-address"); err == nil {
		t.Fatal("invalid TCP address connected")
	}
	if _, err := DirectUDPConnect("invalid-address"); err == nil {
		t.Fatal("invalid UDP address connected")
	}
}

func TestConnectThroughProxyRejectsMalformedAndContradictoryResponses(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		response string
		want     string
	}{
		"malformed":          {"not http\r\n", "read response"},
		"explicit_rejection": {"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n", "407"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = ln.Close() })
			done := make(chan struct{})
			go func() {
				defer close(done)
				conn, acceptErr := ln.Accept()
				if acceptErr != nil {
					return
				}
				defer func() { _ = conn.Close() }()
				_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
				buf := make([]byte, 1024)
				_, _ = conn.Read(buf)
				_, _ = io.WriteString(conn, tc.response)
			}()

			_, err = connectThroughProxy("http://"+ln.Addr().String(), "api.vendor.example:443")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want substring %q", err, tc.want)
			}
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("proxy peer did not complete before deadline")
			}
		})
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	result := checkForwardBlocked(srv.URL, "", nil)
	if result.Status != statusFail || !strings.Contains(result.Detail, "it succeeded") {
		t.Fatalf("unexpected successful CONNECT did not fail closed: %#v", result)
	}
}

type rejectingWriter struct{}

func (rejectingWriter) Write([]byte) (int, error) {
	return 0, errors.New("output unavailable")
}

func diagBoolPtr(value bool) *bool {
	return &value
}

func TestDiagnosticOutputAndCancellationFailuresAreReturned(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cmd := &cobra.Command{}
	cmd.SetContext(ctx)
	cmd.SetOut(io.Discard)
	if err := runDiagnose(cmd, config.Defaults(), "cancelled", false, false); err == nil {
		t.Fatal("cancelled diagnostic run reported success")
	}

	jsonCmd := &cobra.Command{}
	jsonCmd.SetOut(rejectingWriter{})
	err := runDiagnoseSandbox(jsonCmd, true, false)
	if err == nil || !strings.Contains(err.Error(), "output unavailable") {
		t.Fatalf("sandbox JSON writer error = %v", err)
	}
}

func TestVerifyManifestTrustFailuresRemainFailures(t *testing.T) {
	t.Parallel()

	env := testScanEnv(t)
	dir := t.TempDir()
	emptyManifest := filepath.Join(dir, "empty.json")
	if err := os.WriteFile(emptyManifest, []byte(`{"version":1,"entries":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	env.Cfg.MCPBinaryIntegrity.ManifestPath = emptyManifest
	result := checkMCPBinaryIntegrity(env)
	if result.Status != verifyStatusFail || !strings.Contains(result.Detail, "no entries") {
		t.Fatalf("empty trust manifest result = %#v", result)
	}
}
