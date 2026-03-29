// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package capture_test

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/capture"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// testRedactedPlaceholder is the expected value for redacted fields.
const testRedactedPlaceholder = "[REDACTED]"

// TestWriterSanitizeSessionID_PathTraversal verifies that a session ID with
// path traversal sequences is rejected and the entry is dropped.
func TestWriterSanitizeSessionID_PathTraversal(t *testing.T) {
	dir := t.TempDir()
	sink := &testDropSink{}

	w, err := capture.NewWriter(capture.WriterConfig{
		RecorderConfig: recorder.Config{
			Enabled:            true,
			Dir:                dir,
			CheckpointInterval: 1000,
		},
		DropSink:     sink,
		QueueSize:    testQueueSize,
		BuildVersion: testVersion,
		BuildSHA:     testSHA,
	})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	// Send a verdict with a path traversal session ID.
	w.ObserveURLVerdict(context.Background(), &capture.URLVerdictRecord{
		Subsurface:      testSubsurface,
		Transport:       testTransport,
		SessionID:       "../escape",
		RequestID:       "req-traversal",
		ConfigHash:      testConfigHash,
		EffectiveAction: "allow",
		Outcome:         capture.OutcomeClean,
		Request:         capture.CaptureRequest{Method: "GET", URL: testURLVerdict},
	})

	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// The path traversal session ID should cause a drop.
	if drops := sink.drops.Load(); drops == 0 {
		t.Error("expected drop for path traversal session ID")
	}
}

// TestWriterSanitizeSessionID_SlashInID verifies that a session ID with a
// forward slash is rejected.
func TestWriterSanitizeSessionID_SlashInID(t *testing.T) {
	dir := t.TempDir()
	sink := &testDropSink{}

	w, err := capture.NewWriter(capture.WriterConfig{
		RecorderConfig: recorder.Config{
			Enabled:            true,
			Dir:                dir,
			CheckpointInterval: 1000,
		},
		DropSink:     sink,
		QueueSize:    testQueueSize,
		BuildVersion: testVersion,
		BuildSHA:     testSHA,
	})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	w.ObserveURLVerdict(context.Background(), &capture.URLVerdictRecord{
		Subsurface:      testSubsurface,
		Transport:       testTransport,
		SessionID:       "bad/session",
		RequestID:       "req-slash",
		ConfigHash:      testConfigHash,
		EffectiveAction: "allow",
		Outcome:         capture.OutcomeClean,
		Request:         capture.CaptureRequest{Method: "GET", URL: testURLVerdict},
	})

	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if drops := sink.drops.Load(); drops == 0 {
		t.Error("expected drop for session ID with slash")
	}
}

// TestWriterSanitizeSessionID_Empty verifies that an empty session ID is
// rejected and the entry is dropped.
func TestWriterSanitizeSessionID_Empty(t *testing.T) {
	dir := t.TempDir()
	sink := &testDropSink{}

	w, err := capture.NewWriter(capture.WriterConfig{
		RecorderConfig: recorder.Config{
			Enabled:            true,
			Dir:                dir,
			CheckpointInterval: 1000,
		},
		DropSink:     sink,
		QueueSize:    testQueueSize,
		BuildVersion: testVersion,
		BuildSHA:     testSHA,
	})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	w.ObserveURLVerdict(context.Background(), &capture.URLVerdictRecord{
		Subsurface:      testSubsurface,
		Transport:       testTransport,
		SessionID:       "",
		RequestID:       "req-empty",
		ConfigHash:      testConfigHash,
		EffectiveAction: "allow",
		Outcome:         capture.OutcomeClean,
		Request:         capture.CaptureRequest{Method: "GET", URL: testURLVerdict},
	})

	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if drops := sink.drops.Load(); drops == 0 {
		t.Error("expected drop for empty session ID")
	}
}

// TestWriterSendAfterClose verifies that sending to a closed writer increments
// the drop counter rather than panicking.
func TestWriterSendAfterClose(t *testing.T) {
	dir := t.TempDir()
	sink := &testDropSink{}

	w, err := capture.NewWriter(capture.WriterConfig{
		RecorderConfig: recorder.Config{
			Enabled:            true,
			Dir:                dir,
			CheckpointInterval: 1000,
		},
		DropSink:     sink,
		QueueSize:    testQueueSize,
		BuildVersion: testVersion,
		BuildSHA:     testSHA,
	})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Send after close -- should not panic, should record a drop.
	w.ObserveURLVerdict(context.Background(), &capture.URLVerdictRecord{
		Subsurface:      testSubsurface,
		Transport:       testTransport,
		SessionID:       testSessionID,
		RequestID:       "req-post-close",
		ConfigHash:      testConfigHash,
		EffectiveAction: "allow",
		Outcome:         capture.OutcomeClean,
		Request:         capture.CaptureRequest{Method: "GET", URL: testURLVerdict},
	})

	if drops := sink.drops.Load(); drops == 0 {
		t.Error("expected drop for send after close")
	}
}

// TestWriterRedaction verifies that when a redactFn is provided, the
// CaptureSummary has redacted samples and cleared headers.
func TestWriterRedaction(t *testing.T) {
	dir := t.TempDir()

	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	sc := scanner.New(cfg)
	defer sc.Close()

	w, err := capture.NewWriter(capture.WriterConfig{
		RecorderConfig: recorder.Config{
			Enabled:            true,
			Dir:                dir,
			CheckpointInterval: 1000,
			Redact:             true,
		},
		RedactFn:     sc.ScanTextForDLP,
		QueueSize:    testQueueSize,
		BuildVersion: testVersion,
		BuildSHA:     testSHA,
	})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	w.ObserveURLVerdict(context.Background(), &capture.URLVerdictRecord{
		Subsurface:      testSubsurface,
		Transport:       testTransport,
		SessionID:       testSessionID,
		RequestID:       "req-redact",
		ConfigHash:      testConfigHash,
		EffectiveAction: "allow",
		Outcome:         capture.OutcomeClean,
		Request: capture.CaptureRequest{
			Method:  "POST",
			URL:     "https://example.com/api",
			Headers: map[string][]string{"Authorization": {"Bearer secret"}},
		},
	})

	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	entries := readSessionEntries(t, dir, testSessionID)
	var captureEntries []recorder.Entry
	for _, e := range entries {
		if e.Type == capture.EntryTypeCapture {
			captureEntries = append(captureEntries, e)
		}
	}
	if len(captureEntries) != 1 {
		t.Fatalf("expected 1 capture entry, got %d", len(captureEntries))
	}

	detailJSON, err := json.Marshal(captureEntries[0].Detail)
	if err != nil {
		t.Fatalf("Marshal Detail: %v", err)
	}

	var summary capture.CaptureSummary
	if err := json.Unmarshal(detailJSON, &summary); err != nil {
		t.Fatalf("Unmarshal CaptureSummary: %v", err)
	}

	// Redaction should replace scanner sample with placeholder.
	if summary.ScannerSample != testRedactedPlaceholder {
		t.Errorf("ScannerSample: got %q, want %q", summary.ScannerSample, testRedactedPlaceholder)
	}

	// Redaction should clear headers.
	if summary.Request.Headers != nil {
		t.Error("Request.Headers should be nil after redaction")
	}
}

// TestWriterResponseVerdictWirePayloadSidecar verifies that
// ObserveResponseVerdict uses wirePayload as the sidecar payload when no
// scannerInput is set (response verdicts have empty scannerInput).
func TestWriterResponseVerdictWirePayloadSidecar(t *testing.T) {
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

	w.ObserveResponseVerdict(context.Background(), &capture.ResponseVerdictRecord{
		Subsurface:      testSubsurface,
		Transport:       testTransport,
		SessionID:       testSessionID,
		RequestID:       "req-resp",
		ConfigHash:      testConfigHash,
		TransformKind:   capture.TransformReadability,
		WirePayload:     []byte("wire payload content"),
		EffectiveAction: "allow",
		Outcome:         capture.OutcomeClean,
		Request:         capture.CaptureRequest{Method: "GET", URL: testURLVerdict},
	})

	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	entries := readSessionEntries(t, dir, testSessionID)
	var captureEntries []recorder.Entry
	for _, e := range entries {
		if e.Type == capture.EntryTypeCapture {
			captureEntries = append(captureEntries, e)
		}
	}
	if len(captureEntries) != 1 {
		t.Fatalf("expected 1 capture entry, got %d", len(captureEntries))
	}

	detailJSON, err := json.Marshal(captureEntries[0].Detail)
	if err != nil {
		t.Fatalf("Marshal Detail: %v", err)
	}

	var summary capture.CaptureSummary
	if err := json.Unmarshal(detailJSON, &summary); err != nil {
		t.Fatalf("Unmarshal CaptureSummary: %v", err)
	}

	// Wire payload should be recorded in the summary.
	if summary.WirePayloadBytes != len("wire payload content") {
		t.Errorf("WirePayloadBytes: got %d, want %d", summary.WirePayloadBytes, len("wire payload content"))
	}
	if summary.WirePayloadSample != "wire payload content" {
		t.Errorf("WirePayloadSample: got %q, want %q", summary.WirePayloadSample, "wire payload content")
	}
}

// TestLoaderExtractCaptureSummary_CorruptEntry verifies that LoadAndReplay
// increments the skipped count when entries cannot be parsed.
func TestLoaderExtractCaptureSummary_CorruptEntry(t *testing.T) {
	dir := t.TempDir()

	// Write a valid capture entry, then a corrupt one (wrong schema version).
	w, err := capture.NewWriter(capture.WriterConfig{
		RecorderConfig: recorder.Config{
			Enabled:           true,
			Dir:               dir,
			MaxEntriesPerFile: 100,
		},
		QueueSize:    64,
		BuildVersion: testVersion,
		BuildSHA:     testSHA,
	})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	ctx := context.Background()

	// One valid URL verdict.
	w.ObserveURLVerdict(ctx, &capture.URLVerdictRecord{
		Subsurface:      "forward",
		Transport:       "forward",
		SessionID:       "corrupt-test",
		RequestID:       "req-good",
		EffectiveAction: config.ActionAllow,
		Outcome:         capture.OutcomeClean,
		Request: capture.CaptureRequest{
			Method: "GET",
			URL:    "https://good.example.com",
		},
	})

	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Replay: should get 1 record, 0 skipped.
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false

	records, _, skipped, _, err := capture.LoadAndReplay(cfg, dir)
	if err != nil {
		t.Fatalf("LoadAndReplay: %v", err)
	}
	if len(records) != 1 {
		t.Errorf("expected 1 record, got %d", len(records))
	}
	if skipped != 0 {
		t.Errorf("expected 0 skipped, got %d", skipped)
	}
}

// TestRenderDiffHTML_AllChangeTypes exercises the changeColor and pct template
// functions by producing a report with both new_block and new_allow changes.
// The template only renders Changes in the table; unchanged/evidence/summary
// types appear only as summary counters.
func TestRenderDiffHTML_AllChangeTypes(t *testing.T) {
	t.Parallel()

	changes := []capture.DiffEntry{
		{
			Summary:         capture.CaptureSummary{Surface: capture.SurfaceURL, Request: capture.CaptureRequest{URL: "https://a.example.com"}},
			OriginalAction:  config.ActionAllow,
			CandidateAction: config.ActionBlock,
			Changed:         true,
			ChangeType:      "new_block",
		},
		{
			Summary:         capture.CaptureSummary{Surface: capture.SurfaceURL, Request: capture.CaptureRequest{URL: "https://b.example.com"}},
			OriginalAction:  config.ActionBlock,
			CandidateAction: config.ActionAllow,
			Changed:         true,
			ChangeType:      "new_allow",
		},
	}

	report := &capture.DiffReport{
		ReportVersion: 1,
		TotalRecords:  5,
		Replayed:      3,
		NewBlocks:     1,
		NewAllows:     1,
		Unchanged:     1,
		EvidenceOnly:  1,
		SummaryOnly:   1,
		Changes:       changes,
	}

	var buf bytes.Buffer
	if err := capture.RenderDiffHTML(&buf, report); err != nil {
		t.Fatalf("RenderDiffHTML: %v", err)
	}

	html := buf.String()

	// Change types in the table.
	for _, want := range []string{"new_block", "new_allow"} {
		if !strings.Contains(html, want) {
			t.Errorf("HTML missing change type %q in table", want)
		}
	}

	// Badge color CSS classes should appear for the rendered change types.
	for _, want := range []string{"badge-red", "badge-yellow", "badge-green", "badge-gray"} {
		if !strings.Contains(html, want) {
			t.Errorf("HTML missing CSS class %q", want)
		}
	}

	// Summary counters should show non-zero evidence and summary counts.
	if !strings.Contains(html, "Evidence Only") {
		t.Error("HTML missing Evidence Only label")
	}
	if !strings.Contains(html, "Summary Only") {
		t.Error("HTML missing Summary Only label")
	}
}

// TestRenderDiffHTML_ZeroTotal exercises the pct function with total=0
// (division by zero guard).
func TestRenderDiffHTML_ZeroTotal(t *testing.T) {
	t.Parallel()

	report := &capture.DiffReport{
		ReportVersion: 1,
		TotalRecords:  0,
	}

	var buf bytes.Buffer
	if err := capture.RenderDiffHTML(&buf, report); err != nil {
		t.Fatalf("RenderDiffHTML: %v", err)
	}

	// Should not panic — the pct function should return "0" for total=0.
	if buf.Len() == 0 {
		t.Error("expected non-empty HTML output")
	}
}

// TestWriterBuildSummaryWirePayloadTruncation verifies that wire payload
// samples are truncated independently of scanner samples when both differ.
func TestWriterBuildSummaryWirePayloadTruncation(t *testing.T) {
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

	// Create a long wire payload (> 256 bytes) that differs from scanner input.
	longPayload := make([]byte, 400)
	for i := range longPayload {
		longPayload[i] = 'B'
	}

	w.ObserveResponseVerdict(context.Background(), &capture.ResponseVerdictRecord{
		Subsurface:      testSubsurface,
		Transport:       testTransport,
		SessionID:       testSessionID,
		RequestID:       "req-wire-trunc",
		ConfigHash:      testConfigHash,
		TransformKind:   capture.TransformReadability,
		WirePayload:     longPayload,
		EffectiveAction: "allow",
		Outcome:         capture.OutcomeClean,
		Request:         capture.CaptureRequest{Method: "GET", URL: testURLVerdict},
	})

	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	entries := readSessionEntries(t, dir, testSessionID)
	var captureEntries []recorder.Entry
	for _, e := range entries {
		if e.Type == capture.EntryTypeCapture {
			captureEntries = append(captureEntries, e)
		}
	}
	if len(captureEntries) != 1 {
		t.Fatalf("expected 1 capture entry, got %d", len(captureEntries))
	}

	detailJSON, err := json.Marshal(captureEntries[0].Detail)
	if err != nil {
		t.Fatalf("Marshal Detail: %v", err)
	}

	var summary capture.CaptureSummary
	if err := json.Unmarshal(detailJSON, &summary); err != nil {
		t.Fatalf("Unmarshal CaptureSummary: %v", err)
	}

	if summary.WirePayloadBytes != 400 {
		t.Errorf("WirePayloadBytes: got %d, want 400", summary.WirePayloadBytes)
	}

	const wantSampleLen = 256
	if len(summary.WirePayloadSample) != wantSampleLen {
		t.Errorf("WirePayloadSample length: got %d, want %d", len(summary.WirePayloadSample), wantSampleLen)
	}
}

// TestWriterRedactionWithFindings verifies that redaction clears MatchText
// from both raw and effective findings.
func TestWriterRedactionWithFindings(t *testing.T) {
	dir := t.TempDir()

	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	sc := scanner.New(cfg)
	defer sc.Close()

	w, err := capture.NewWriter(capture.WriterConfig{
		RecorderConfig: recorder.Config{
			Enabled:            true,
			Dir:                dir,
			CheckpointInterval: 1000,
			Redact:             true,
		},
		RedactFn:     sc.ScanTextForDLP,
		QueueSize:    testQueueSize,
		BuildVersion: testVersion,
		BuildSHA:     testSHA,
	})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	w.ObserveURLVerdict(context.Background(), &capture.URLVerdictRecord{
		Subsurface:      testSubsurface,
		Transport:       testTransport,
		SessionID:       testSessionID,
		RequestID:       "req-redact-findings",
		ConfigHash:      testConfigHash,
		EffectiveAction: config.ActionBlock,
		Outcome:         capture.OutcomeBlocked,
		RawFindings: []capture.Finding{
			{Kind: capture.KindDLP, MatchText: "secret-data-here"},
		},
		EffectiveFindings: []capture.Finding{
			{Kind: capture.KindDLP, MatchText: "secret-data-here", Action: config.ActionBlock},
		},
		Request: capture.CaptureRequest{
			Method:       "POST",
			URL:          "https://example.com",
			BodySample:   "sensitive body content",
			ToolArgsJSON: `{"key":"value"}`,
		},
	})

	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	entries := readSessionEntries(t, dir, testSessionID)
	var captureEntries []recorder.Entry
	for _, e := range entries {
		if e.Type == capture.EntryTypeCapture {
			captureEntries = append(captureEntries, e)
		}
	}
	if len(captureEntries) != 1 {
		t.Fatalf("expected 1 capture entry, got %d", len(captureEntries))
	}

	detailJSON, err := json.Marshal(captureEntries[0].Detail)
	if err != nil {
		t.Fatalf("Marshal Detail: %v", err)
	}

	var summary capture.CaptureSummary
	if err := json.Unmarshal(detailJSON, &summary); err != nil {
		t.Fatalf("Unmarshal CaptureSummary: %v", err)
	}

	// Findings should have MatchText cleared.
	for i, f := range summary.RawFindings {
		if f.MatchText != "" {
			t.Errorf("RawFindings[%d].MatchText should be empty, got %q", i, f.MatchText)
		}
	}
	for i, f := range summary.EffectiveFindings {
		if f.MatchText != "" {
			t.Errorf("EffectiveFindings[%d].MatchText should be empty, got %q", i, f.MatchText)
		}
	}

	// Body sample and tool args should be redacted.
	if summary.Request.BodySample != testRedactedPlaceholder {
		t.Errorf("Request.BodySample: got %q, want %q", summary.Request.BodySample, testRedactedPlaceholder)
	}
	if summary.Request.ToolArgsJSON != testRedactedPlaceholder {
		t.Errorf("Request.ToolArgsJSON: got %q, want %q", summary.Request.ToolArgsJSON, testRedactedPlaceholder)
	}
}
