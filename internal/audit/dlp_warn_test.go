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
		"url":       "https://example.com/[redacted]",
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

func TestLogDLPWarn_RedactsContentBearingFields(t *testing.T) {
	var buf bytes.Buffer
	logger, err := New("json", "custom", "", true, true)
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}
	logger.zl = logger.zl.Output(&buf)

	sink := &collectingSink{}
	emitter := emit.NewEmitter("test-dlp-warn-redact", sink)
	logger.SetEmitter(emitter)
	t.Cleanup(func() { _ = emitter.Close() })

	const secret = "sk-live-" + "0123456789abcdef0123456789abcdef"
	rawURL := "https://api.vendor.example/v1/chat?api_key=" + secret
	logger.LogDLPWarn(LogContext{
		method:    "GET",
		url:       rawURL,
		target:    rawURL,
		resource:  secret,
		clientIP:  "10.0.0.3",
		requestID: "req-dlp-warn-redact",
		agent:     "test-agent",
	}, wantPatternStagedKey, wantSeverityHigh, wantTransportFetch)

	if err := emitter.Close(); err != nil {
		t.Fatalf("emitter.Close: %v", err)
	}
	output := buf.String()
	if output == "" {
		t.Fatal("expected log output, got empty")
	}
	if strings.Contains(output, secret) {
		t.Fatalf("DLP warn log leaked the matched credential: %s", output)
	}

	var entry map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(output)), &entry); err != nil {
		t.Fatalf("failed to parse log entry: %v\nraw: %s", err, output)
	}
	if entry["url"] != "https://api.vendor.example/[redacted]" {
		t.Errorf("log url = %v, want redacted scheme+host", entry["url"])
	}
	if entry["target"] != "https://api.vendor.example/[redacted]" {
		t.Errorf("log target = %v, want redacted scheme+host", entry["target"])
	}
	if entry["resource"] != "[redacted]" {
		t.Errorf("log resource = %v, want redacted marker", entry["resource"])
	}

	ev := sink.onlyEvent(t)
	if ev.Type != string(EventDLPWarn) {
		t.Fatalf("emitted event type = %q, want %q", ev.Type, EventDLPWarn)
	}
	if ev.Fields["url"] != "https://api.vendor.example/[redacted]" {
		t.Errorf("emitted url = %v, want redacted scheme+host", ev.Fields["url"])
	}
	if ev.Fields["target"] != "https://api.vendor.example/[redacted]" {
		t.Errorf("emitted target = %v, want redacted scheme+host", ev.Fields["target"])
	}
	if ev.Fields["resource"] != "[redacted]" {
		t.Errorf("emitted resource = %v, want redacted marker", ev.Fields["resource"])
	}
	rawEvent, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal emitted event: %v", err)
	}
	if strings.Contains(string(rawEvent), secret) {
		t.Fatalf("DLP warn emitted event leaked the matched credential: %s", rawEvent)
	}
}
