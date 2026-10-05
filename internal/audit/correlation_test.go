// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/emit"
	scannerpkg "github.com/luckyPipewrench/pipelock/internal/scanner"
)

const (
	testCorrHeader   = "X-Correlation-Id"
	testCorrValue    = "case-0042"
	testCorrValueAlt = "case-0099"
	testCorrReqID    = "req-77"
	testCorrURL      = "https://api.vendor.example/v1"
	testCorrClientIP = "192.0.2.10"
)

func corrTestScanner(t *testing.T) *scannerpkg.Scanner {
	t.Helper()
	cfg := config.Defaults()
	cfg.Internal = nil
	sc := scannerpkg.MustNew(cfg)
	t.Cleanup(sc.Close)
	return sc
}

func corrHeader(values ...string) http.Header {
	h := http.Header{}
	for _, v := range values {
		h.Add(testCorrHeader, v)
	}
	return h
}

func corrLogger(t *testing.T) (*Logger, *collectingSink, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	logger, err := NewWithStream("json", "stdout", "", true, true, &buf)
	if err != nil {
		t.Fatalf("NewWithStream: %v", err)
	}
	sink := &collectingSink{}
	emitter := emit.NewEmitter("test", sink)
	logger.SetEmitter(emitter)
	t.Cleanup(func() { _ = emitter.Close() })
	return logger, sink, &buf
}

func TestSanitizeCorrelationValue(t *testing.T) {
	t.Parallel()
	exact := strings.Repeat("a", CorrelationIDMaxBytes)
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{name: "simple", raw: testCorrValue, want: testCorrValue},
		{name: "internal space kept", raw: "case 42", want: "case 42"},
		{name: "surrounding space trimmed", raw: "  case-42\t", want: "case-42"},
		{name: "full printable range", raw: " !~azAZ09{}|\\\"'", want: "!~azAZ09{}|\\\"'"},
		{name: "exact cap", raw: exact, want: exact},
		{name: "one over cap", raw: exact + "b", want: ""},
		{name: "oversized", raw: strings.Repeat("x", 4096), want: ""},
		{name: "empty", raw: "", want: ""},
		{name: "spaces only", raw: "   ", want: ""},
		{name: "nul byte", raw: "case\x00-42", want: ""},
		{name: "newline", raw: "case\n-42", want: ""},
		{name: "carriage return", raw: "case\r-42", want: ""},
		{name: "internal tab", raw: "case\t-42", want: ""},
		{name: "escape", raw: "\x1b[2Jcase", want: ""},
		{name: "del", raw: "case\x7f", want: ""},
		{name: "non-ascii", raw: "case-é", want: ""},
		{name: "invalid utf8", raw: "case-\xff", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := sanitizeCorrelationValue(tt.raw); got != tt.want {
				t.Fatalf("sanitize(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

func TestCorrelationIDFromHeader(t *testing.T) {
	t.Parallel()
	sc := corrTestScanner(t)
	// Built at runtime so the source holds no credential literal.
	awsKey := "AKIA" + "IOSFODNN7EXAMPLE"
	ghToken := "ghp_" + strings.Repeat("a", 36)

	tests := []struct {
		name   string
		header http.Header
		hname  string
		sc     *scannerpkg.Scanner
		want   string
	}{
		{name: "present", header: corrHeader(testCorrValue), hname: testCorrHeader, sc: sc, want: testCorrValue},
		{name: "lookup is case-insensitive", header: corrHeader(testCorrValue), hname: "x-correlation-id", sc: sc, want: testCorrValue},
		{name: "feature off", header: corrHeader(testCorrValue), hname: "", sc: sc, want: ""},
		{name: "absent", header: http.Header{}, hname: testCorrHeader, sc: sc, want: ""},
		{name: "nil header", header: nil, hname: testCorrHeader, sc: sc, want: ""},
		{name: "repeated header is ambiguous", header: corrHeader(testCorrValue, testCorrValueAlt), hname: testCorrHeader, sc: sc, want: ""},
		{name: "no scanner fails closed", header: corrHeader(testCorrValue), hname: testCorrHeader, sc: nil, want: ""},
		{name: "oversized", header: corrHeader(strings.Repeat("z", CorrelationIDMaxBytes+1)), hname: testCorrHeader, sc: sc, want: ""},
		{name: "control char", header: corrHeader("case\x01"), hname: testCorrHeader, sc: sc, want: ""},
		{name: "aws key redacted", header: corrHeader(awsKey), hname: testCorrHeader, sc: sc, want: ""},
		{name: "github token redacted", header: corrHeader("run-" + ghToken), hname: testCorrHeader, sc: sc, want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := CorrelationIDFromHeader(context.Background(), tt.header, tt.hname, tt.sc)
			if got.String() != tt.want {
				t.Fatalf("CorrelationIDFromHeader = %q, want %q", got.String(), tt.want)
			}
			if got.IsZero() != (tt.want == "") {
				t.Fatalf("IsZero = %v, want %v", got.IsZero(), tt.want == "")
			}
		})
	}
}

// A proxy-held environment secret placed in the header must never reach a
// SIEM, even when it matches no built-in pattern.
func TestCorrelationIDFromHeader_EnvSecretOmitted(t *testing.T) {
	secret := strings.Join([]string{"Q7vP2mK9xR4nT8wB", "6cD3fG1hJ5sL0zA"}, "")
	t.Setenv("PIPELOCK_CORRELATION_TEST_SECRET", secret)
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = true
	cfg.DLP.Patterns = nil
	sc := scannerpkg.MustNew(cfg)
	defer sc.Close()

	if got := CorrelationIDFromHeader(context.Background(), corrHeader(secret), testCorrHeader, sc); !got.IsZero() {
		t.Fatalf("env secret accepted as correlation id: %q", got.String())
	}
	// Positive control: the same scanner accepts an ordinary tag.
	if got := CorrelationIDFromHeader(context.Background(), corrHeader(testCorrValue), testCorrHeader, sc); got.String() != testCorrValue {
		t.Fatalf("control tag = %q, want %q", got.String(), testCorrValue)
	}
}

func TestCorrelation_LogContextEventsCarryField(t *testing.T) {
	t.Parallel()
	logger, sink, buf := corrLogger(t)
	ctx, err := NewHTTPLogContext(http.MethodGet, testCorrURL, testCorrClientIP, testCorrReqID, testAgentName)
	if err != nil {
		t.Fatal(err)
	}
	ctx = ctx.WithCorrelation(CorrelationID{value: testCorrValue})

	logger.LogAllowed(ctx, http.StatusOK, 10, time.Millisecond)
	logger.LogBlocked(ctx, scannerpkg.ScannerDLP, "test block")
	logger.LogForwardHTTP(ctx, http.StatusOK, 10, time.Millisecond)
	logger.LogHeaderDLP(ctx, "X-Other", testActionWarn, []string{"p"}, nil)
	logger.LogBodyDLP(ctx, testActionWarn, 1, []string{"p"}, nil)
	logger.LogResponseScanExempt(ctx, "api.vendor.example")

	sink.mu.Lock()
	events := append([]emit.Event(nil), sink.events...)
	sink.mu.Unlock()
	if len(events) != 6 {
		t.Fatalf("got %d events, want 6", len(events))
	}
	for _, ev := range events {
		if ev.Fields[FieldCorrelationID] != testCorrValue {
			t.Errorf("%s: correlation_id = %v, want %q", ev.Type, ev.Fields[FieldCorrelationID], testCorrValue)
		}
		if ev.Fields["request_id"] != testCorrReqID {
			t.Errorf("%s: request_id = %v, want %q", ev.Type, ev.Fields["request_id"], testCorrReqID)
		}
	}
	// Scope: emitted events only, never the local audit log.
	if strings.Contains(buf.String(), testCorrValue) || strings.Contains(buf.String(), FieldCorrelationID) {
		t.Fatalf("local audit log carries the correlation tag:\n%s", buf.String())
	}
}

func TestCorrelation_ZeroLeavesFieldAbsent(t *testing.T) {
	t.Parallel()
	logger, sink, _ := corrLogger(t)
	ctx, err := NewHTTPLogContext(http.MethodGet, testCorrURL, testCorrClientIP, testCorrReqID, testAgentName)
	if err != nil {
		t.Fatal(err)
	}
	logger.WithCorrelation(CorrelationID{}).LogAllowed(ctx, http.StatusOK, 1, time.Millisecond)
	ev := sink.onlyEvent(t)
	if _, ok := ev.Fields[FieldCorrelationID]; ok {
		t.Fatalf("correlation_id present without a tag: %v", ev.Fields)
	}
}

// The sub-logger stamps events that are not built from a LogContext, such as
// WebSocket lifecycle events, and a LogContext tag wins when both are set.
func TestCorrelation_SubLogger(t *testing.T) {
	t.Parallel()
	logger, sink, buf := corrLogger(t)
	sub := logger.With("agent", testAgentName).WithCorrelation(CorrelationID{value: testCorrValue})

	sub.LogWSOpen("ws://ws.vendor.example/x", testCorrClientIP, testCorrReqID, testAgentName)
	sub.LogWSBlocked(WSBlockedEvent{Target: "ws://ws.vendor.example/x", Direction: "client", Scanner: "dlp", Reason: "r", ClientIP: testCorrClientIP, RequestID: testCorrReqID})
	sub.LogSessionAnomaly("sess", "kind", "detail", testCorrClientIP, testCorrReqID, 1)
	// With() after WithCorrelation keeps the tag.
	sub.With("k", "v").LogWSClose(WSCloseEvent{Target: "ws://ws.vendor.example/x", ClientIP: testCorrClientIP, RequestID: testCorrReqID})

	ctx, err := NewHTTPLogContext(http.MethodGet, testCorrURL, testCorrClientIP, testCorrReqID, testAgentName)
	if err != nil {
		t.Fatal(err)
	}
	sub.LogAllowed(ctx.WithCorrelation(CorrelationID{value: testCorrValueAlt}), http.StatusOK, 1, time.Millisecond)

	sink.mu.Lock()
	events := append([]emit.Event(nil), sink.events...)
	sink.mu.Unlock()
	if len(events) != 5 {
		t.Fatalf("got %d events, want 5", len(events))
	}
	for _, ev := range events[:4] {
		if ev.Fields[FieldCorrelationID] != testCorrValue {
			t.Errorf("%s: correlation_id = %v, want %q", ev.Type, ev.Fields[FieldCorrelationID], testCorrValue)
		}
	}
	if got := events[4].Fields[FieldCorrelationID]; got != testCorrValueAlt {
		t.Errorf("LogContext tag should win: got %v, want %q", got, testCorrValueAlt)
	}
	// The parent logger is unaffected.
	logger.LogWSOpen("ws://ws.vendor.example/y", testCorrClientIP, "req-other", testAgentName)
	last, _ := sink.lastEvent()
	if _, ok := last.Fields[FieldCorrelationID]; ok {
		t.Fatalf("parent logger leaked the sub-logger tag: %v", last.Fields)
	}
	if strings.Contains(buf.String(), testCorrValue) {
		t.Fatalf("local audit log carries the correlation tag:\n%s", buf.String())
	}
}

func TestCorrelation_SubLoggerDoesNotOwnFile(t *testing.T) {
	t.Parallel()
	var nilLogger *Logger
	if got := nilLogger.WithCorrelation(CorrelationID{value: testCorrValue}); got != nil {
		t.Fatal("nil logger WithCorrelation should return nil")
	}
	logger, _, _ := corrLogger(t)
	if logger.WithCorrelation(CorrelationID{}) != logger {
		t.Fatal("zero id should return the receiver unchanged")
	}
	sub := logger.WithCorrelation(CorrelationID{value: testCorrValue})
	if sub == logger || sub.fileHandle != nil || sub.filePath != "" || sub.fileCreated {
		t.Fatalf("sub-logger must be a distinct copy without file ownership: %+v", sub)
	}
	if !logger.correlation.IsZero() {
		t.Fatal("WithCorrelation mutated the parent")
	}
}

func TestCorrelation_FieldNameMatchesEmit(t *testing.T) {
	t.Parallel()
	// The documented wire name. audit.FieldCorrelationID is defined as the
	// emit constant, so this pins both.
	if got := FieldCorrelationID; got != "correlation_id" {
		t.Fatalf("FieldCorrelationID = %q, want correlation_id", got)
	}
}
