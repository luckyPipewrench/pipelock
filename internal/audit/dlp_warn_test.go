// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/emit"
)

const (
	wantMode             = "warn"
	wantTransportFetch   = "fetch"
	wantTransportBody    = "body"
	wantPatternStagedKey = "staged-key"
	wantPatternStagedTok = "staged-token"
	wantSeverityHigh     = "high"
	wantSeverityMedium   = "medium"
)

func TestLogDLPWarn_EmitsCorrectFields(t *testing.T) {
	var buf bytes.Buffer
	logger, err := New("json", "custom", "", true, true)
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	logger.zl = logger.zl.Output(&buf)

	ctx, ctxErr := NewHTTPLogContext("GET", "https://example.com/api", "10.0.0.1", "req-42", "test-agent")
	if ctxErr != nil {
		t.Fatalf("NewHTTPLogContext: %v", ctxErr)
	}
	logger.LogDLPWarn(ctx, wantPatternStagedKey, wantSeverityHigh, wantTransportFetch)

	output := buf.String()
	if output == "" {
		t.Fatal("expected log output, got empty")
	}

	var entry map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(output)), &entry); err != nil {
		t.Fatalf("failed to parse log entry: %v\nraw: %s", err, output)
	}

	checks := map[string]string{
		"event":     string(EventDLPWarn),
		"mode":      wantMode,
		"pattern":   wantPatternStagedKey,
		"severity":  wantSeverityHigh,
		"transport": wantTransportFetch,
		"method":    "GET",
		"url":       "https://example.com/api",
		"client_ip": "10.0.0.1",
	}
	for key, want := range checks {
		got, ok := entry[key]
		if !ok {
			t.Errorf("missing field %q in log entry", key)
			continue
		}
		if gotStr, ok := got.(string); !ok || gotStr != want {
			t.Errorf("field %q: want %q, got %v", key, want, got)
		}
	}
}

func TestLogDLPWarn_EventTypeConstant(t *testing.T) {
	if EventDLPWarn != "dlp_warn" {
		t.Errorf("EventDLPWarn should be %q, got %q", "dlp_warn", EventDLPWarn)
	}
}

func TestLogDLPWarn_EmitterReceivesEvent(t *testing.T) {
	var buf bytes.Buffer
	logger, err := New("json", "custom", "", true, true)
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	logger.zl = logger.zl.Output(&buf)

	sink := &collectingSink{}
	emitter := emit.NewEmitter("test-dlp-warn", sink)
	logger.SetEmitter(emitter)
	t.Cleanup(func() { _ = emitter.Close() })

	ctx, ctxErr := NewHTTPLogContext("POST", "https://api.example.com/v1", "10.0.0.2", "req-99", "my-agent")
	if ctxErr != nil {
		t.Fatalf("NewHTTPLogContext: %v", ctxErr)
	}
	logger.LogDLPWarn(ctx, wantPatternStagedTok, wantSeverityMedium, wantTransportBody)

	_ = emitter.Close() // flush

	sink.mu.Lock()
	defer sink.mu.Unlock()

	if len(sink.events) == 0 {
		t.Fatal("emitter should have received an event")
	}
	ev := sink.events[0]
	if ev.Type != string(EventDLPWarn) {
		t.Errorf("emitted event type: want %q, got %q", EventDLPWarn, ev.Type)
	}
	if ev.Fields["mode"] != wantMode {
		t.Errorf("emitted mode: want %q, got %v", wantMode, ev.Fields["mode"])
	}
	if ev.Fields["pattern"] != wantPatternStagedTok {
		t.Errorf("emitted pattern: want %q, got %v", wantPatternStagedTok, ev.Fields["pattern"])
	}
	if ev.Fields["transport"] != wantTransportBody {
		t.Errorf("emitted transport: want %q, got %v", wantTransportBody, ev.Fields["transport"])
	}
}
