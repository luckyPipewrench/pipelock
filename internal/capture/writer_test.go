// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package capture_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/nacl/box"

	"github.com/luckyPipewrench/pipelock/internal/capture"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

const (
	testSessionID   = "test-session-001"
	testTransport   = "fetch"
	testVersion     = "v2.0.0-test"
	testSHA         = "abcdef12"
	testConfigHash  = "confighash123"
	testSubsurface  = "forward"
	testQueueSize   = 128
	testAgent       = "test-agent"
	testProfile     = "default"
	testURLVerdict  = "https://example.com/api"
	testEffAction   = "block"
	testOutcome     = "blocked"
	testPatternName = "test_pattern"
	testSeverity    = "critical"
)

// testDropSink counts drop notifications via an atomic counter.
type testDropSink struct {
	drops atomic.Int64
}

func (s *testDropSink) RecordCaptureDrop() {
	s.drops.Add(1)
}

// newTestWriter creates a Writer with sensible test defaults.
func newTestWriter(t *testing.T, opts ...func(*capture.WriterConfig)) *capture.Writer {
	t.Helper()

	dir := t.TempDir()
	cfg := capture.WriterConfig{
		RecorderConfig: recorder.Config{
			Enabled:            true,
			Dir:                dir,
			CheckpointInterval: 1000,
		},
		QueueSize:    testQueueSize,
		BuildVersion: testVersion,
		BuildSHA:     testSHA,
	}

	for _, opt := range opts {
		opt(&cfg)
	}

	w, err := capture.NewWriter(cfg)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	return w
}

// readSessionEntries reads all evidence entries from the session subdirectory.
func readSessionEntries(t *testing.T, baseDir, sessionID string) []recorder.Entry {
	t.Helper()

	sessionDir := filepath.Join(baseDir, sessionID)
	dirEntries, err := os.ReadDir(sessionDir)
	if err != nil {
		t.Fatalf("ReadDir(%s): %v", sessionDir, err)
	}

	var all []recorder.Entry
	for _, de := range dirEntries {
		if de.IsDir() || filepath.Ext(de.Name()) != ".jsonl" {
			continue
		}
		entries, err := recorder.ReadEntries(filepath.Join(sessionDir, de.Name()))
		if err != nil {
			t.Fatalf("ReadEntries(%s): %v", de.Name(), err)
		}
		all = append(all, entries...)
	}

	return all
}

// TestWriterRecordsURLVerdict writes a URL verdict, closes the writer, then
// reads back from the session subdirectory and verifies CaptureSummary fields.
func TestWriterRecordsURLVerdict(t *testing.T) {
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

	// Verify Writer implements CaptureObserver at compile time.
	var obs capture.CaptureObserver = w

	obs.ObserveURLVerdict(context.Background(), &capture.URLVerdictRecord{
		Subsurface:  testSubsurface,
		Transport:   testTransport,
		SessionID:   testSessionID,
		RequestID:   "req-001",
		ConfigHash:  testConfigHash,
		Agent:       testAgent,
		Profile:     testProfile,
		Request:     capture.CaptureRequest{Method: "GET", URL: testURLVerdict},
		RawFindings: []capture.Finding{{Kind: capture.KindDLP, PatternName: testPatternName, Severity: testSeverity}},
		EffectiveFindings: []capture.Finding{
			{Kind: capture.KindDLP, PatternName: testPatternName, Action: testEffAction, Severity: testSeverity},
		},
		EffectiveAction: testEffAction,
		Outcome:         testOutcome,
	})

	if err := obs.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	entries := readSessionEntries(t, dir, testSessionID)

	// Filter to capture entries (skip checkpoints).
	var captureEntries []recorder.Entry
	for _, e := range entries {
		if e.Type == capture.EntryTypeCapture {
			captureEntries = append(captureEntries, e)
		}
	}

	if len(captureEntries) != 1 {
		t.Fatalf("expected 1 capture entry, got %d (total entries: %d)", len(captureEntries), len(entries))
	}

	ce := captureEntries[0]
	if ce.SessionID != testSessionID {
		t.Errorf("SessionID: got %q, want %q", ce.SessionID, testSessionID)
	}
	if ce.TraceID != "req-001" {
		t.Errorf("TraceID: got %q, want %q", ce.TraceID, "req-001")
	}
	if ce.Transport != testTransport {
		t.Errorf("Transport: got %q, want %q", ce.Transport, testTransport)
	}

	// Unmarshal the Detail back into a CaptureSummary.
	detailJSON, err := json.Marshal(ce.Detail)
	if err != nil {
		t.Fatalf("Marshal Detail: %v", err)
	}

	var summary capture.CaptureSummary
	if err := json.Unmarshal(detailJSON, &summary); err != nil {
		t.Fatalf("Unmarshal CaptureSummary: %v", err)
	}

	if summary.CaptureSchemaVersion != capture.CaptureSchemaV1 {
		t.Errorf("CaptureSchemaVersion: got %d, want %d", summary.CaptureSchemaVersion, capture.CaptureSchemaV1)
	}
	if summary.Surface != capture.SurfaceURL {
		t.Errorf("Surface: got %q, want %q", summary.Surface, capture.SurfaceURL)
	}
	if summary.Subsurface != testSubsurface {
		t.Errorf("Subsurface: got %q, want %q", summary.Subsurface, testSubsurface)
	}
	if summary.BuildVersion != testVersion {
		t.Errorf("BuildVersion: got %q, want %q", summary.BuildVersion, testVersion)
	}
	if summary.BuildSHA != testSHA {
		t.Errorf("BuildSHA: got %q, want %q", summary.BuildSHA, testSHA)
	}
	if summary.ConfigHash != testConfigHash {
		t.Errorf("ConfigHash: got %q, want %q", summary.ConfigHash, testConfigHash)
	}
	if summary.EffectiveAction != testEffAction {
		t.Errorf("EffectiveAction: got %q, want %q", summary.EffectiveAction, testEffAction)
	}
	if summary.Outcome != testOutcome {
		t.Errorf("Outcome: got %q, want %q", summary.Outcome, testOutcome)
	}
	if summary.Agent != testAgent {
		t.Errorf("Agent: got %q, want %q", summary.Agent, testAgent)
	}
	if summary.TransformKind != capture.TransformRaw {
		t.Errorf("TransformKind: got %q, want %q", summary.TransformKind, capture.TransformRaw)
	}
	if summary.Request.URL != testURLVerdict {
		t.Errorf("Request.URL: got %q, want %q", summary.Request.URL, testURLVerdict)
	}
	if len(summary.EffectiveFindings) != 1 {
		t.Fatalf("EffectiveFindings: got %d, want 1", len(summary.EffectiveFindings))
	}
	if summary.EffectiveFindings[0].Kind != capture.KindDLP {
		t.Errorf("EffectiveFindings[0].Kind: got %q, want %q", summary.EffectiveFindings[0].Kind, capture.KindDLP)
	}
	// URL is the scanner input for URL verdicts.
	if summary.ScannerSample != testURLVerdict {
		t.Errorf("ScannerSample: got %q, want %q", summary.ScannerSample, testURLVerdict)
	}
}

// TestWriterRecordsURLVerdictWithEscrow verifies that when an escrow public
// key is provided, the writer writes encrypted payload sidecar files.
func TestWriterRecordsURLVerdictWithEscrow(t *testing.T) {
	dir := t.TempDir()

	recipientPub, recipientPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	w, err := capture.NewWriter(capture.WriterConfig{
		RecorderConfig: recorder.Config{
			Enabled:            true,
			Dir:                dir,
			CheckpointInterval: 1000,
		},
		EscrowPublicKey: recipientPub,
		QueueSize:       testQueueSize,
		BuildVersion:    testVersion,
		BuildSHA:        testSHA,
	})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	w.ObserveURLVerdict(context.Background(), &capture.URLVerdictRecord{
		Subsurface:      testSubsurface,
		Transport:       testTransport,
		SessionID:       testSessionID,
		RequestID:       "req-escrow",
		ConfigHash:      testConfigHash,
		Request:         capture.CaptureRequest{Method: "GET", URL: testURLVerdict},
		EffectiveAction: "allow",
		Outcome:         capture.OutcomeClean,
	})

	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Read back entries.
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

	if summary.PayloadRef == "" {
		t.Fatal("PayloadRef should be set when escrow key is configured")
	}
	if !summary.PayloadComplete {
		t.Error("PayloadComplete should be true when sidecar succeeds")
	}
	if summary.PayloadSHA256 == "" {
		t.Error("PayloadSHA256 should be set when sidecar succeeds")
	}

	// Verify the sidecar file exists and can be decrypted.
	sidecarPath := filepath.Join(dir, testSessionID, summary.PayloadRef)
	ciphertext, err := os.ReadFile(filepath.Clean(sidecarPath))
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", sidecarPath, err)
	}

	plaintext, ok := box.OpenAnonymous(nil, ciphertext, recipientPub, recipientPriv)
	if !ok {
		t.Fatal("failed to decrypt payload sidecar")
	}

	if string(plaintext) != testURLVerdict {
		t.Errorf("decrypted payload: got %q, want %q", string(plaintext), testURLVerdict)
	}
}

// TestWriterDropSentinel floods a writer with a queue size of 1, then verifies
// that drop sentinel entries appear in the capture-meta subdirectory.
func TestWriterDropSentinel(t *testing.T) {
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

	// Flood the writer with many records. With queue size 1, most will drop.
	// Use enough to guarantee at least one drop sentinel interval is reached.
	const floodCount = 500
	for range floodCount {
		w.ObserveURLVerdict(context.Background(), &capture.URLVerdictRecord{
			Subsurface:      testSubsurface,
			Transport:       testTransport,
			SessionID:       testSessionID,
			RequestID:       "req-flood",
			ConfigHash:      testConfigHash,
			Request:         capture.CaptureRequest{Method: "GET", URL: testURLVerdict},
			EffectiveAction: "allow",
			Outcome:         capture.OutcomeClean,
		})
	}

	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Verify drops were recorded via the sink.
	drops := sink.drops.Load()
	if drops == 0 {
		t.Fatal("expected drops > 0 with queue size 1 and 500 sends")
	}
	t.Logf("total drops: %d out of %d sends", drops, floodCount)

	// Check for drop sentinel entries in the capture-meta subdirectory.
	metaEntries := readSessionEntries(t, dir, "capture-meta")

	var dropEntries []recorder.Entry
	for _, e := range metaEntries {
		if e.Type == capture.EntryTypeCaptureDrop {
			dropEntries = append(dropEntries, e)
		}
	}

	if len(dropEntries) == 0 {
		t.Fatal("expected at least one capture_drop sentinel in capture-meta")
	}

	// Verify the drop detail.
	detailJSON, err := json.Marshal(dropEntries[0].Detail)
	if err != nil {
		t.Fatalf("Marshal Detail: %v", err)
	}

	var dropDetail capture.CaptureDropDetail
	if err := json.Unmarshal(detailJSON, &dropDetail); err != nil {
		t.Fatalf("Unmarshal CaptureDropDetail: %v", err)
	}

	if dropDetail.Count == 0 {
		t.Error("drop sentinel Count should be > 0")
	}
	if dropDetail.Reason != "backpressure" {
		t.Errorf("drop sentinel Reason: got %q, want %q", dropDetail.Reason, "backpressure")
	}
}

// TestWriterCloseIdempotent verifies that calling Close multiple times does
// not panic or return spurious errors.
func TestWriterCloseIdempotent(t *testing.T) {
	w := newTestWriter(t)

	if err := w.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// TestWriterMultipleSessions verifies that entries for different sessions end
// up in separate subdirectories with independent hash chains.
func TestWriterMultipleSessions(t *testing.T) {
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

	const sessionA = "session-a"
	const sessionB = "session-b"

	w.ObserveURLVerdict(context.Background(), &capture.URLVerdictRecord{
		Subsurface: testSubsurface, Transport: testTransport,
		SessionID: sessionA, RequestID: "req-a",
		ConfigHash: testConfigHash, EffectiveAction: "allow",
		Outcome: capture.OutcomeClean,
		Request: capture.CaptureRequest{Method: "GET", URL: "https://a.example.com"},
	})
	w.ObserveURLVerdict(context.Background(), &capture.URLVerdictRecord{
		Subsurface: testSubsurface, Transport: testTransport,
		SessionID: sessionB, RequestID: "req-b",
		ConfigHash: testConfigHash, EffectiveAction: "allow",
		Outcome: capture.OutcomeClean,
		Request: capture.CaptureRequest{Method: "GET", URL: "https://b.example.com"},
	})

	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	aEntries := readSessionEntries(t, dir, sessionA)
	bEntries := readSessionEntries(t, dir, sessionB)

	if len(aEntries) == 0 {
		t.Error("expected entries for session-a")
	}
	if len(bEntries) == 0 {
		t.Error("expected entries for session-b")
	}

	// Both chains should start at genesis.
	if aEntries[0].PrevHash != recorder.GenesisHash {
		t.Errorf("session-a: first entry PrevHash = %q, want %q", aEntries[0].PrevHash, recorder.GenesisHash)
	}
	if bEntries[0].PrevHash != recorder.GenesisHash {
		t.Errorf("session-b: first entry PrevHash = %q, want %q", bEntries[0].PrevHash, recorder.GenesisHash)
	}
}

// TestWriterSignedCheckpoints verifies that when an Ed25519 key is provided,
// checkpoint entries in per-session recorders have valid signatures.
func TestWriterSignedCheckpoints(t *testing.T) {
	dir := t.TempDir()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	w, err := capture.NewWriter(capture.WriterConfig{
		RecorderConfig: recorder.Config{
			Enabled:            true,
			Dir:                dir,
			CheckpointInterval: 2, // Force frequent checkpoints.
			SignCheckpoints:    true,
		},
		PrivKey:      priv,
		QueueSize:    testQueueSize,
		BuildVersion: testVersion,
		BuildSHA:     testSHA,
	})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	// Write enough entries to trigger at least one checkpoint.
	for range 5 {
		w.ObserveURLVerdict(context.Background(), &capture.URLVerdictRecord{
			Subsurface: testSubsurface, Transport: testTransport,
			SessionID: testSessionID, RequestID: "req-cp",
			ConfigHash: testConfigHash, EffectiveAction: "allow",
			Outcome: capture.OutcomeClean,
			Request: capture.CaptureRequest{Method: "GET", URL: testURLVerdict},
		})
	}

	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	entries := readSessionEntries(t, dir, testSessionID)

	// Manually verify checkpoint signatures (same approach as recorder_test.go).
	// VerifyChain re-marshals Detail which can differ from the original struct
	// serialisation after a JSON round-trip through map[string]any, so we
	// verify signatures directly on the PrevHash field.
	var foundCheckpoint bool
	for _, e := range entries {
		if e.Type != "checkpoint" {
			continue
		}
		foundCheckpoint = true

		detailJSON, err := json.Marshal(e.Detail)
		if err != nil {
			t.Fatalf("marshal checkpoint detail: %v", err)
		}

		var cpDetail recorder.CheckpointDetail
		if err := json.Unmarshal(detailJSON, &cpDetail); err != nil {
			t.Fatalf("unmarshal checkpoint detail: %v", err)
		}

		if cpDetail.Signature == "" {
			t.Error("checkpoint should have a signature")
			continue
		}

		sig, err := hex.DecodeString(cpDetail.Signature)
		if err != nil {
			t.Fatalf("decode signature: %v", err)
		}

		if !ed25519.Verify(pub, []byte(e.PrevHash), sig) {
			t.Errorf("checkpoint signature verification failed at seq %d", e.Sequence)
		}
	}

	if !foundCheckpoint {
		t.Error("no checkpoint entry found in session evidence")
	}
}

// TestWriterBuildSummaryTruncation verifies that scanner and wire payload
// samples are truncated to maxScannerSample (256) bytes.
func TestWriterBuildSummaryTruncation(t *testing.T) {
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

	// Create a long scanner input that exceeds 256 bytes.
	longInput := make([]byte, 512)
	for i := range longInput {
		longInput[i] = 'A'
	}

	w.ObserveDLPVerdict(context.Background(), &capture.DLPVerdictRecord{
		Subsurface:      testSubsurface,
		Transport:       testTransport,
		SessionID:       testSessionID,
		RequestID:       "req-trunc",
		ConfigHash:      testConfigHash,
		TransformKind:   capture.TransformJoinedFields,
		ScannerInput:    string(longInput),
		EffectiveAction: "allow",
		Outcome:         capture.OutcomeClean,
		Request:         capture.CaptureRequest{Method: "POST", URL: "https://example.com"},
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

	if summary.ScannerBytes != 512 {
		t.Errorf("ScannerBytes: got %d, want 512", summary.ScannerBytes)
	}

	const wantSampleLen = 256
	if len(summary.ScannerSample) != wantSampleLen {
		t.Errorf("ScannerSample length: got %d, want %d", len(summary.ScannerSample), wantSampleLen)
	}
}

// TestWriterAllSurfaces exercises all six Observe methods to ensure each
// surface produces the correct entry type.
func TestWriterAllSurfaces(t *testing.T) {
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

	ctx := context.Background()
	base := func() (string, string, string) {
		return testSessionID, "req-all", testConfigHash
	}

	sid, rid, ch := base()
	w.ObserveURLVerdict(ctx, &capture.URLVerdictRecord{
		Subsurface: testSubsurface, Transport: testTransport,
		SessionID: sid, RequestID: rid, ConfigHash: ch,
		EffectiveAction: "allow", Outcome: capture.OutcomeClean,
		Request: capture.CaptureRequest{Method: "GET", URL: testURLVerdict},
	})

	w.ObserveResponseVerdict(ctx, &capture.ResponseVerdictRecord{
		Subsurface: testSubsurface, Transport: testTransport,
		SessionID: sid, RequestID: rid, ConfigHash: ch,
		TransformKind:   capture.TransformReadability,
		WirePayload:     []byte("response body"),
		EffectiveAction: "allow", Outcome: capture.OutcomeClean,
		Request: capture.CaptureRequest{Method: "GET", URL: testURLVerdict},
	})

	w.ObserveDLPVerdict(ctx, &capture.DLPVerdictRecord{
		Subsurface: testSubsurface, Transport: testTransport,
		SessionID: sid, RequestID: rid, ConfigHash: ch,
		TransformKind: capture.TransformRaw, ScannerInput: "dlp-input",
		EffectiveAction: "allow", Outcome: capture.OutcomeClean,
		Request: capture.CaptureRequest{Method: "POST", URL: testURLVerdict},
	})

	w.ObserveCEEVerdict(ctx, &capture.CEERecord{
		Subsurface: testSubsurface, Transport: testTransport,
		SessionID: sid, RequestID: rid, ConfigHash: ch,
		TransformKind: capture.TransformCEEWindow, ScannerInput: "cee-input",
		EffectiveAction: "allow", Outcome: capture.OutcomeClean,
		Request: capture.CaptureRequest{Method: "GET", URL: testURLVerdict},
	})

	w.ObserveToolPolicyVerdict(ctx, &capture.ToolPolicyRecord{
		Subsurface: "mcp_stdio", Transport: "mcp-stdio",
		SessionID: sid, RequestID: rid, ConfigHash: ch,
		EffectiveAction: "allow", Outcome: capture.OutcomeClean,
		Request: capture.CaptureRequest{ToolName: "exec", MCPMethod: "tools/call"},
	})

	w.ObserveToolScanVerdict(ctx, &capture.ToolScanRecord{
		Subsurface: "mcp_stdio", Transport: "mcp-stdio",
		SessionID: sid, RequestID: rid, ConfigHash: ch,
		TransformKind:   capture.TransformToolsListDescription,
		ScannerInput:    "tool description text",
		EffectiveAction: "allow", Outcome: capture.OutcomeClean,
		Request: capture.CaptureRequest{MCPMethod: "tools/list"},
	})

	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	entries := readSessionEntries(t, dir, testSessionID)
	var captureCount int
	for _, e := range entries {
		if e.Type == capture.EntryTypeCapture {
			captureCount++
		}
	}

	const wantSurfaces = 6
	if captureCount != wantSurfaces {
		t.Errorf("expected %d capture entries (one per surface), got %d", wantSurfaces, captureCount)
	}
}

// TestWriterNewWriterDisabledRecorder verifies that when the recorder config
// has Enabled=false, the writer still creates successfully (meta recorder is nop).
func TestWriterNewWriterDisabledRecorder(t *testing.T) {
	dir := t.TempDir()
	w, err := capture.NewWriter(capture.WriterConfig{
		RecorderConfig: recorder.Config{
			Enabled: false,
			Dir:     dir,
		},
		QueueSize:    testQueueSize,
		BuildVersion: testVersion,
		BuildSHA:     testSHA,
	})
	if err != nil {
		t.Fatalf("NewWriter with disabled recorder: %v", err)
	}

	// Should accept records without error (they go to nop recorder).
	w.ObserveURLVerdict(context.Background(), &capture.URLVerdictRecord{
		Subsurface: testSubsurface, Transport: testTransport,
		SessionID: testSessionID, RequestID: "req-nop",
		ConfigHash: testConfigHash, EffectiveAction: "allow",
		Outcome: capture.OutcomeClean,
		Request: capture.CaptureRequest{Method: "GET", URL: testURLVerdict},
	})

	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}
