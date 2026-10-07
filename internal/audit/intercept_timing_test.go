// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func readInterceptEntries(t *testing.T, path string) []map[string]any {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	var out []map[string]any
	for _, line := range bytes.Split(bytes.TrimSpace(data), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var entry map[string]any
		if err := json.Unmarshal(line, &entry); err != nil {
			t.Fatalf("invalid JSON %q: %v", line, err)
		}
		out = append(out, entry)
	}
	return out
}

func TestLogInterceptHTTP(t *testing.T) {
	ctx := LogContext{method: testMethodGet, url: "https://api.vendor.example/v1", clientIP: "10.0.0.5", requestID: "req-7"}
	tests := []struct {
		name         string
		timing       InterceptTiming
		wantUpstream any
		wantCanceled bool
	}{
		{
			name:         "reached upstream",
			timing:       InterceptTiming{StatusCode: 200, SizeBytes: 4096, Duration: 900 * time.Millisecond, Upstream: 700 * time.Millisecond, ReachedUpstream: true},
			wantUpstream: float64(700),
		},
		{
			name:         "blocked before upstream",
			timing:       InterceptTiming{StatusCode: 403, Duration: 5 * time.Millisecond},
			wantUpstream: nil,
		},
		{
			name:         "client gave up while waiting upstream",
			timing:       InterceptTiming{Duration: 20 * time.Second, Upstream: 19 * time.Second, ReachedUpstream: true, ClientCanceled: true},
			wantUpstream: float64(19000),
			wantCanceled: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "test.log")
			logger, err := New("json", "file", path, true, true)
			if err != nil {
				t.Fatal(err)
			}
			logger.LogInterceptHTTP(ctx, tt.timing)
			logger.Close()

			entries := readInterceptEntries(t, path)
			if len(entries) != 1 {
				t.Fatalf("entries = %d, want 1", len(entries))
			}
			e := entries[0]
			if e["event"] != string(EventInterceptHTTP) {
				t.Errorf("event = %v", e["event"])
			}
			if e["status_code"] != float64(tt.timing.StatusCode) {
				t.Errorf("status_code = %v", e["status_code"])
			}
			if e["size_bytes"] != float64(tt.timing.SizeBytes) {
				t.Errorf("size_bytes = %v", e["size_bytes"])
			}
			if e["duration_ms"] != float64(tt.timing.Duration.Milliseconds()) {
				t.Errorf("duration_ms = %v", e["duration_ms"])
			}
			if got, ok := e["upstream_ms"]; tt.wantUpstream == nil && ok {
				t.Errorf("upstream_ms present (%v) for a request that never reached upstream", got)
			} else if tt.wantUpstream != nil && got != tt.wantUpstream {
				t.Errorf("upstream_ms = %v, want %v", got, tt.wantUpstream)
			}
			if e["client_canceled"] != tt.wantCanceled {
				t.Errorf("client_canceled = %v, want %v", e["client_canceled"], tt.wantCanceled)
			}
		})
	}
}

func TestLogInterceptHTTP_FilteredWhenAllowedOff(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.log")
	logger, err := New("json", "file", path, false, true)
	if err != nil {
		t.Fatal(err)
	}
	logger.LogInterceptHTTP(LogContext{method: testMethodGet}, InterceptTiming{StatusCode: 200})
	logger.Close()
	if entries := readInterceptEntries(t, path); len(entries) != 0 {
		t.Fatalf("intercept_http logged with include_allowed=false: %v", entries)
	}
}
