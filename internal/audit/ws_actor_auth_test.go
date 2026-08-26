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

	"github.com/luckyPipewrench/pipelock/internal/envelope"
)

// readSingleEntry returns the one JSON log line the logger wrote.
func readSingleEntry(t *testing.T, path string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("reading log: %v", err)
	}
	var entry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(data), &entry); err != nil {
		t.Fatalf("expected valid JSON: %v", err)
	}
	return entry
}

// TestWSEventsEmitTheGradeWithTheLabel closes the telemetry gap where the
// WebSocket close and scan events wrote the agent label directly instead of
// through the paired helper. The typed SIEM identity fields still failed closed
// because a missing grade reads as unknown, so this was never an identity
// bypass; the problem was that JSON, OTLP, and the local structured log
// serialize event fields generically, so those surfaces carried a bare agent
// name with nothing saying how it had been established.
func TestWSEventsEmitTheGradeWithTheLabel(t *testing.T) {
	cases := []struct {
		name  string
		emit  func(*Logger)
		want  string
		event string
	}{
		{
			name:  "close carries a bound grade",
			event: "ws_close",
			want:  string(envelope.ActorAuthBound),
			emit: func(l *Logger) {
				l.LogWSClose(WSCloseEvent{
					Target: "ws://api.vendor.example/stream", ClientIP: "10.0.0.5",
					RequestID: "req-1", Agent: "agent-a",
					AgentAuth: string(envelope.ActorAuthBound),
					Duration:  time.Second,
				})
			},
		},
		{
			name:  "close without a grade fails closed to unknown",
			event: "ws_close",
			want:  string(envelope.ActorAuthUnknown),
			emit: func(l *Logger) {
				l.LogWSClose(WSCloseEvent{
					Target: "ws://api.vendor.example/stream", ClientIP: "10.0.0.5",
					RequestID: "req-2", Agent: "agent-a", Duration: time.Second,
				})
			},
		},
		{
			name:  "scan carries a self-declared grade",
			event: "ws_scan",
			want:  string(envelope.ActorAuthSelfDeclared),
			emit: func(l *Logger) {
				l.LogWSScan(WSScanEvent{
					Target: "ws://api.vendor.example/stream", Direction: DirectionClientToServer,
					ClientIP: "10.0.0.5", RequestID: "req-3", Agent: "agent-a",
					AgentAuth: string(envelope.ActorAuthSelfDeclared),
					Action:    "warn", Scanner: "dlp", MatchCount: 1,
					PatternNames: []string{"pattern-a"},
				})
			},
		},
		{
			name:  "scan without a grade fails closed to unknown",
			event: "ws_scan",
			want:  string(envelope.ActorAuthUnknown),
			emit: func(l *Logger) {
				l.LogWSScan(WSScanEvent{
					Target: "ws://api.vendor.example/stream", Direction: DirectionClientToServer,
					ClientIP: "10.0.0.5", RequestID: "req-4", Agent: "agent-a",
					Action: "warn", Scanner: "dlp", MatchCount: 1,
					PatternNames: []string{"pattern-a"},
				})
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "test.log")
			logger, err := New("json", "file", path, true, true)
			if err != nil {
				t.Fatal(err)
			}
			tc.emit(logger)
			logger.Close()

			entry := readSingleEntry(t, path)
			if entry["event"] != tc.event {
				t.Fatalf("event = %v, want %s", entry["event"], tc.event)
			}
			if entry["agent"] != "agent-a" {
				t.Fatalf("agent = %v, want agent-a", entry["agent"])
			}
			if got := entry["agent_auth"]; got != tc.want {
				t.Fatalf("agent_auth = %v, want %q", got, tc.want)
			}
		})
	}
}
