// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHealthcheckCmd(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		statusCode int
		wantErr    string
	}{
		{
			name:       "healthy",
			statusCode: http.StatusOK,
		},
		{
			name:       "unhealthy status",
			statusCode: http.StatusServiceUnavailable,
			wantErr:    "unhealthy: status 503",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/health" {
					t.Errorf("path = %q, want /health", r.URL.Path)
				}
				w.WriteHeader(tt.statusCode)
			}))
			t.Cleanup(server.Close)

			cmd := HealthcheckCmd()
			cmd.SilenceUsage = true
			cmd.SetArgs([]string{"--addr", strings.TrimPrefix(server.URL, "http://")})
			var out bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetErr(&out)

			err := cmd.Execute()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("healthcheck command: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("healthcheck command err = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestHealthcheckCmdReportsConnectionFailure(t *testing.T) {
	t.Parallel()

	listener, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve unavailable healthcheck address: %v", err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("close reserved healthcheck listener: %v", err)
	}

	cmd := HealthcheckCmd()
	cmd.SilenceUsage = true
	cmd.SetArgs([]string{"--addr", addr})
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)

	err = cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "health check failed") {
		t.Fatalf("healthcheck command err = %v, want connection failure", err)
	}
}
