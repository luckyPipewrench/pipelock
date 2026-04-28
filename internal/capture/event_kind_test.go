// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package capture_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/capture"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

const (
	ekTestRequestID    = "req-event-kind"
	ekActionClassWrite = "write"
	ekDropOverflow     = "capture queue overflow"
)

// readCaptureSummary reads the first capture entry for the test session and
// returns the recorder.Entry (which carries EventKind) plus the parsed
// CaptureSummary (which carries ActionClass).
func readCaptureSummary(t *testing.T, dir string) (recorder.Entry, capture.CaptureSummary) {
	t.Helper()

	entries := readSessionEntries(t, dir, testSessionID)
	for _, e := range entries {
		if e.Type != capture.EntryTypeCapture {
			continue
		}
		detailJSON, err := json.Marshal(e.Detail)
		if err != nil {
			t.Fatalf("Marshal Detail: %v", err)
		}
		var s capture.CaptureSummary
		if err := json.Unmarshal(detailJSON, &s); err != nil {
			t.Fatalf("Unmarshal CaptureSummary: %v", err)
		}
		return e, s
	}
	t.Fatalf("no capture entries in %s/%s", dir, testSessionID)
	return recorder.Entry{}, capture.CaptureSummary{}
}

func newEventKindTestWriter(t *testing.T) (*capture.Writer, string) {
	t.Helper()
	dir := t.TempDir()
	w, err := capture.NewWriter(capture.WriterConfig{
		RecorderConfig: recorder.Config{
			Enabled:            true,
			Dir:                dir,
			CheckpointInterval: 1000,
		},
		QueueSize:    testQueueSize,
		BuildVersion: testVersion,
		BuildSHA:     testSHA,
	})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	return w, dir
}

// TestObserveURLVerdict_StampsEventKind asserts that URL pipeline observations
// stamp event_kind="url" on the recorder envelope and leave summary.ActionClass
// empty when the call site did not classify (the zero string is the
// unclassified signal so the unclassified-rate metric counts honestly).
func TestObserveURLVerdict_StampsEventKind(t *testing.T) {
	w, dir := newEventKindTestWriter(t)

	w.ObserveURLVerdict(context.Background(), &capture.URLVerdictRecord{
		Subsurface:      testSubsurface,
		Transport:       testTransport,
		SessionID:       testSessionID,
		RequestID:       ekTestRequestID,
		ConfigHash:      testConfigHash,
		Request:         capture.CaptureRequest{Method: "GET", URL: testURLVerdict},
		EffectiveAction: "allow",
		Outcome:         capture.OutcomeClean,
	})
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	entry, summary := readCaptureSummary(t, dir)
	if entry.EventKind != capture.SurfaceURL {
		t.Errorf("EventKind: got %q, want %q", entry.EventKind, capture.SurfaceURL)
	}
	if summary.ActionClass != "" {
		t.Errorf("summary.ActionClass: got %q, want empty (no classification supplied)",
			summary.ActionClass)
	}
}

// TestObserveResponseVerdict_StampsEventKind asserts response observations
// stamp event_kind="response".
func TestObserveResponseVerdict_StampsEventKind(t *testing.T) {
	w, dir := newEventKindTestWriter(t)

	w.ObserveResponseVerdict(context.Background(), &capture.ResponseVerdictRecord{
		Subsurface:      testSubsurface,
		Transport:       testTransport,
		SessionID:       testSessionID,
		RequestID:       ekTestRequestID,
		ConfigHash:      testConfigHash,
		Request:         capture.CaptureRequest{Method: "GET", URL: testURLVerdict},
		TransformKind:   capture.TransformReadability,
		WirePayload:     []byte("hello world"),
		EffectiveAction: "allow",
		Outcome:         capture.OutcomeClean,
	})
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	entry, summary := readCaptureSummary(t, dir)
	if entry.EventKind != capture.SurfaceResponse {
		t.Errorf("EventKind: got %q, want %q", entry.EventKind, capture.SurfaceResponse)
	}
	if summary.ActionClass != "" {
		t.Errorf("summary.ActionClass: got %q, want empty", summary.ActionClass)
	}
}

// TestObserveDLPVerdict_StampsEventKind asserts DLP observations stamp
// event_kind="dlp" and the explicit "write" classification reaches the wire.
func TestObserveDLPVerdict_StampsEventKind(t *testing.T) {
	w, dir := newEventKindTestWriter(t)

	w.ObserveDLPVerdict(context.Background(), &capture.DLPVerdictRecord{
		Subsurface:      testSubsurface,
		Transport:       testTransport,
		SessionID:       testSessionID,
		RequestID:       ekTestRequestID,
		ConfigHash:      testConfigHash,
		ActionClass:     ekActionClassWrite,
		Request:         capture.CaptureRequest{Method: "POST", URL: testURLVerdict},
		TransformKind:   capture.TransformJoinedFields,
		ScannerInput:    "field=value",
		EffectiveAction: "block",
		Outcome:         capture.OutcomeBlocked,
	})
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	entry, summary := readCaptureSummary(t, dir)
	if entry.EventKind != capture.SurfaceDLP {
		t.Errorf("EventKind: got %q, want %q", entry.EventKind, capture.SurfaceDLP)
	}
	if summary.ActionClass != ekActionClassWrite {
		t.Errorf("summary.ActionClass: got %q, want %q (explicit ActionClassWrite)",
			summary.ActionClass, ekActionClassWrite)
	}
}

// TestObserveCEEVerdict_StampsEventKind asserts CEE observations stamp
// event_kind="cee".
func TestObserveCEEVerdict_StampsEventKind(t *testing.T) {
	w, dir := newEventKindTestWriter(t)

	w.ObserveCEEVerdict(context.Background(), &capture.CEERecord{
		Subsurface:      testSubsurface,
		Transport:       testTransport,
		SessionID:       testSessionID,
		RequestID:       ekTestRequestID,
		ConfigHash:      testConfigHash,
		Request:         capture.CaptureRequest{Method: "POST", URL: testURLVerdict},
		TransformKind:   capture.TransformCEEWindow,
		ScannerInput:    "abc 123 xyz",
		EffectiveAction: "allow",
		Outcome:         capture.OutcomeClean,
	})
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	entry, _ := readCaptureSummary(t, dir)
	if entry.EventKind != capture.SurfaceCEE {
		t.Errorf("EventKind: got %q, want %q", entry.EventKind, capture.SurfaceCEE)
	}
}

// TestObserveToolPolicyVerdict_StampsEventKind asserts tool policy
// observations stamp event_kind="tool_policy".
func TestObserveToolPolicyVerdict_StampsEventKind(t *testing.T) {
	w, dir := newEventKindTestWriter(t)

	w.ObserveToolPolicyVerdict(context.Background(), &capture.ToolPolicyRecord{
		Subsurface: testSubsurface,
		Transport:  testTransport,
		SessionID:  testSessionID,
		RequestID:  ekTestRequestID,
		ConfigHash: testConfigHash,
		Request: capture.CaptureRequest{
			Method:    "POST",
			URL:       testURLVerdict,
			ToolName:  "fs.read",
			MCPMethod: "tools/call",
		},
		EffectiveAction: "allow",
		Outcome:         capture.OutcomeClean,
	})
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	entry, _ := readCaptureSummary(t, dir)
	if entry.EventKind != capture.SurfaceToolPolicy {
		t.Errorf("EventKind: got %q, want %q", entry.EventKind, capture.SurfaceToolPolicy)
	}
}

// TestObserveToolScanVerdict_StampsEventKind asserts tool scan observations
// stamp event_kind="tool_scan".
func TestObserveToolScanVerdict_StampsEventKind(t *testing.T) {
	w, dir := newEventKindTestWriter(t)

	w.ObserveToolScanVerdict(context.Background(), &capture.ToolScanRecord{
		Subsurface:      testSubsurface,
		Transport:       testTransport,
		SessionID:       testSessionID,
		RequestID:       ekTestRequestID,
		ConfigHash:      testConfigHash,
		Request:         capture.CaptureRequest{Method: "POST", URL: testURLVerdict, MCPMethod: "tools/list"},
		TransformKind:   capture.TransformToolsListDescription,
		ScannerInput:    "tool description",
		EffectiveAction: "allow",
		Outcome:         capture.OutcomeClean,
	})
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	entry, _ := readCaptureSummary(t, dir)
	if entry.EventKind != capture.SurfaceToolScan {
		t.Errorf("EventKind: got %q, want %q", entry.EventKind, capture.SurfaceToolScan)
	}
}

// TestWriteDropSentinel_StampsEventKind verifies the drop sentinel envelope
// carries event_kind="capture_drop" so consumers can route drop signals like
// any other classified event.
func TestWriteDropSentinel_StampsEventKind(t *testing.T) {
	dir := t.TempDir()
	sink := &testDropSink{}

	w, err := capture.NewWriter(capture.WriterConfig{
		RecorderConfig: recorder.Config{
			Enabled:            true,
			Dir:                dir,
			CheckpointInterval: 1000,
		},
		DropSink:     sink,
		QueueSize:    1,
		BuildVersion: testVersion,
		BuildSHA:     testSHA,
	})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	// Flood the writer until at least one drop sentinel is emitted.
	const floodCount = 500
	for range floodCount {
		w.ObserveURLVerdict(context.Background(), &capture.URLVerdictRecord{
			Subsurface:      testSubsurface,
			Transport:       testTransport,
			SessionID:       testSessionID,
			RequestID:       ekTestRequestID,
			ConfigHash:      testConfigHash,
			Request:         capture.CaptureRequest{Method: "GET", URL: testURLVerdict},
			EffectiveAction: "allow",
			Outcome:         capture.OutcomeClean,
		})
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	metaEntries := readSessionEntries(t, dir, "capture-meta")
	var found bool
	for _, e := range metaEntries {
		if e.Type != capture.EntryTypeCaptureDrop {
			continue
		}
		found = true
		if e.EventKind != capture.EntryTypeCaptureDrop {
			t.Errorf("EventKind: got %q, want %q", e.EventKind, capture.EntryTypeCaptureDrop)
		}
		if e.Summary != ekDropOverflow {
			t.Errorf("Summary: got %q, want %q", e.Summary, ekDropOverflow)
		}
	}
	if !found {
		t.Fatal("expected at least one capture_drop sentinel entry")
	}
}

// TestBuildSummary_ActionClassUnset exercises the URL Observe surface with no
// classification supplied. The empty string must round-trip to wire as an
// omitted action_class field so the unclassified-rate metric in a follow-up
// commit can count missing classifications honestly instead of reading every
// observation as "read".
func TestBuildSummary_ActionClassUnset(t *testing.T) {
	w, dir := newEventKindTestWriter(t)

	w.ObserveURLVerdict(context.Background(), &capture.URLVerdictRecord{
		Subsurface:      testSubsurface,
		Transport:       testTransport,
		SessionID:       testSessionID,
		RequestID:       ekTestRequestID,
		ConfigHash:      testConfigHash,
		Request:         capture.CaptureRequest{Method: "GET", URL: testURLVerdict},
		EffectiveAction: "allow",
		Outcome:         capture.OutcomeClean,
	})
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	_, summary := readCaptureSummary(t, dir)
	if summary.ActionClass != "" {
		t.Errorf("summary.ActionClass with no classification: got %q, want empty",
			summary.ActionClass)
	}
}

// TestBuildSummary_ActionClassPropagates_ExplicitWrite verifies that an
// explicit "write" classification on the verdict record reaches
// CaptureSummary.action_class on the wire.
func TestBuildSummary_ActionClassPropagates_ExplicitWrite(t *testing.T) {
	w, dir := newEventKindTestWriter(t)

	w.ObserveDLPVerdict(context.Background(), &capture.DLPVerdictRecord{
		Subsurface:      testSubsurface,
		Transport:       testTransport,
		SessionID:       testSessionID,
		RequestID:       ekTestRequestID,
		ConfigHash:      testConfigHash,
		ActionClass:     ekActionClassWrite,
		Request:         capture.CaptureRequest{Method: "POST", URL: testURLVerdict},
		TransformKind:   capture.TransformJoinedFields,
		ScannerInput:    "key=secret",
		EffectiveAction: "block",
		Outcome:         capture.OutcomeBlocked,
	})
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	_, summary := readCaptureSummary(t, dir)
	if summary.ActionClass != ekActionClassWrite {
		t.Errorf("summary.ActionClass with explicit write: got %q, want %q",
			summary.ActionClass, ekActionClassWrite)
	}
}
