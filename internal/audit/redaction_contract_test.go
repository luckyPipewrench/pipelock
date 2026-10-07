// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/emit"
)

func TestDropURLContentSegmentsRejectsInvalidDestinations(t *testing.T) {
	tests := []struct {
		raw  string
		want string
	}{
		{"data:payloadcanary", "[redacted-url]"},
		{"data:123", "[redacted-url]"},
		{"mailto:123", "[redacted-url]"},
		{"payloadcanary:123", "[redacted-url]"},
		{"payloadcanary://api.vendor.example", "[redacted-url]"},
		{"data://api.vendor.example", "[redacted-url]"},
		{"http:123", "[redacted-url]"},
		{"mailto:payloadcanary", "[redacted-url]"},
		{"javascript:payloadcanary", "[redacted-url]"},
		{"https:///payloadcanary", "[redacted-url]"},
		{"/payloadcanary", "[redacted-url]"},
		{"api.vendor.example:payloadcanary", "[redacted-url]"},
		{"api.vendor.example:65536", "[redacted-url]"},
		{"api.vendor.example:", "[redacted-url]"},
		{"api.vendor.example:0", "[redacted-url]"},
		{"api..vendor.example", "[redacted-url]"},
		{"-api.vendor.example", "[redacted-url]"},
		{"api-.vendor.example", "[redacted-url]"},
		{"api vendor.example", "[redacted-url]"},
		{"api%2fvendor.example", "[redacted-url]"},
		{"[invalid]:443", "[redacted-url]"},
		{"https://[invalid]:443", "[redacted-url]"},
		{"https://[fe80::1%25payloadcanary]", "[redacted-url]"},
		{"api_vendor.example", "[redacted-url]"},
		{"https://api.vendor.example/%zz", "[redacted-url]"},
		{"api.vendor.example:443", "api.vendor.example:443"},
		{"localhost:8080", "localhost:8080"},
		{"service:8080", "[redacted-url]"},
		{"//service:8080", "service:8080"},
		{"http://service:8080", "http://service:8080"},
		{"HTTPS://api.vendor.example", "https://api.vendor.example"},
		{"192.0.2.1:443", "192.0.2.1:443"},
		{"[2001:db8::1]:443", "[2001:db8::1]:443"},
		{"https://[2001:db8::1]:443", "https://[2001:db8::1]:443"},
		{"ws://api.vendor.example", "ws://api.vendor.example"},
		{"wss://api.vendor.example", "wss://api.vendor.example"},
		{"api.vendor.example.", "api.vendor.example."},
		{"https://user:payloadcanary@api.vendor.example", "https://api.vendor.example"},
		{"user:payloadcanary@api.vendor.example", "api.vendor.example"},
		{"//api.vendor.example", "api.vendor.example"},
		{"xn--bcher-kva.example", "xn--bcher-kva.example"},
		{"bücher.example", "bücher.example"},
		{strings.Repeat("a", 64) + ".example", "[redacted-url]"},
	}
	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			for _, keepPath := range []bool{false, true} {
				if got := dropURLContentSegments(tt.raw, keepPath); got != tt.want {
					t.Errorf("keepPath=%v: got %q, want %q", keepPath, got, tt.want)
				}
			}
		})
	}
}

func TestHTTPAuditDestinationsRedactedInBothOutputs(t *testing.T) {
	canary := strings.Join([]string{"payload", "canary"}, "")
	raw := "https://user:" + canary + "@api.vendor.example:443/" + canary + "?token=" + canary + "#" + canary
	const destination = "https://api.vendor.example:443"
	tests := []struct {
		name   string
		log    func(*Logger, string)
		fields []string
	}{
		{"intercept", func(l *Logger, value string) {
			l.LogInterceptHTTP(LogContext{method: testMethodGet, url: value, target: value}, InterceptTiming{StatusCode: 200})
		}, []string{"url", "target"}},
		{"forward", func(l *Logger, value string) {
			l.LogForwardHTTP(LogContext{method: testMethodGet, url: value, target: value}, 200, 10, time.Millisecond)
		}, []string{"url", "target"}},
		{"redirect", func(l *Logger, value string) {
			l.LogRedirect(value, value, testClientIP, testReqID, "", 1)
		}, []string{"original_url", "redirect_url"}},
		{"blocked destination", func(l *Logger, value string) {
			l.LogBlocked(LogContext{method: testMethodGet, url: value, target: value}, "ssrf", "destination blocked")
		}, []string{"url", "target"}},
	}
	for _, tt := range tests {
		for _, input := range []struct{ raw, want string }{
			{raw, destination},
			{"data:payloadcanary", "[redacted-url]"},
			{"data:123", "[redacted-url]"},
			{"payloadcanary://api.vendor.example", "[redacted-url]"},
			{"api.vendor.example:443/" + canary + "?token=" + canary, "api.vendor.example:443"},
		} {
			t.Run(tt.name+"/"+input.raw, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "audit.log")
				logger, err := New("json", "file", path, true, true)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(logger.Close)
				sink := &collectingSink{}
				emitter := emit.NewEmitter("test-instance", sink)
				t.Cleanup(func() { _ = emitter.Close() })
				logger.SetEmitter(emitter)
				tt.log(logger, input.raw)
				logger.Close()
				entries := readInterceptEntries(t, path)
				if len(entries) != 1 {
					t.Fatalf("local entries=%d, want 1", len(entries))
				}
				event := sink.onlyEvent(t)
				for _, fields := range []map[string]any{entries[0], event.Fields} {
					for _, field := range tt.fields {
						if fields[field] != input.want {
							t.Errorf("%s=%q, want %q", field, fields[field], input.want)
						}
					}
					for field, value := range fields {
						if s, ok := value.(string); ok && strings.Contains(s, "payloadcanary") {
							t.Errorf("payload reached %s: %q", field, s)
						}
					}
				}
			})
		}
	}
}

func TestAdaptiveAuditSanitizesBothOutputs(t *testing.T) {
	const dirty = "value\x1b[2J\x00"
	const clean = "value"
	tests := []struct {
		name   string
		log    func(*Logger, string, string)
		fields []string
	}{
		{"anomaly", func(l *Logger, ip, id string) {
			l.LogSessionAnomaly(dirty, dirty, dirty, ip, id, 1)
		}, []string{"session", "anomaly_type", "detail"}},
		{"escalation", func(l *Logger, ip, id string) {
			l.LogAdaptiveEscalation(dirty, dirty, dirty, ip, id, 1)
		}, []string{"session", "from", "to"}},
		{"upgrade", func(l *Logger, ip, id string) {
			l.LogAdaptiveUpgrade(dirty, dirty, dirty, dirty, dirty, ip, id)
		}, []string{"session", "escalation_level", "from_action", "to_action", "scanner"}},
	}
	for _, tt := range tests {
		for _, identifiers := range []string{dirty, ""} {
			t.Run(tt.name+"/"+identifiers, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "audit.log")
				logger, err := New("json", "file", path, true, true)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(logger.Close)
				sink := &collectingSink{}
				emitter := emit.NewEmitter("test-instance", sink)
				t.Cleanup(func() { _ = emitter.Close() })
				logger.SetEmitter(emitter)
				tt.log(logger, identifiers, identifiers)
				logger.Close()
				entries := readInterceptEntries(t, path)
				if len(entries) != 1 {
					t.Fatalf("local entries=%d, want 1", len(entries))
				}
				event := sink.onlyEvent(t)
				for _, field := range tt.fields {
					for _, fields := range []map[string]any{entries[0], event.Fields} {
						if fields[field] != clean {
							t.Errorf("%s=%q, want %q", field, fields[field], clean)
						}
					}
				}
				for _, field := range []string{"client_ip", "request_id"} {
					got, present := event.Fields[field]
					if identifiers == "" && present {
						t.Errorf("empty %s emitted", field)
					} else if identifiers != "" && got != clean {
						t.Errorf("%s=%q, want %q", field, got, clean)
					}
					want := clean
					if identifiers == "" {
						want = ""
					}
					if entries[0][field] != want {
						t.Errorf("local %s=%q, want %q", field, entries[0][field], want)
					}
				}
			})
		}
	}
}
