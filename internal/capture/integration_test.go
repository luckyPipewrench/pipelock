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
)

// roundTripSessionID is the session ID used across the integration test.
const roundTripSessionID = "round-trip"

// roundTripBuildVersion and roundTripBuildSHA are stub build metadata values.
const (
	roundTripBuildVersion = "test"
	roundTripBuildSHA     = "test"
)

// TestCaptureReplayRoundTrip exercises the full capture → replay → diff →
// render pipeline end-to-end. Two URL verdicts are captured for the same
// session: one originally allowed (api.example.com) and one originally
// blocked (evil.example.com). The candidate config adds both domains to its
// blocklist, so the replay produces one new_block and one unchanged record.
func TestCaptureReplayRoundTrip(t *testing.T) {
	captureDir := t.TempDir()

	// --- Phase 1: Capture ---
	w, err := capture.NewWriter(capture.WriterConfig{
		RecorderConfig: recorder.Config{
			Enabled:           true,
			Dir:               captureDir,
			MaxEntriesPerFile: 100,
		},
		QueueSize:    64,
		BuildVersion: roundTripBuildVersion,
		BuildSHA:     roundTripBuildSHA,
	})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	ctx := context.Background()

	// Record 1: api.example.com was allowed originally.
	w.ObserveURLVerdict(ctx, &capture.URLVerdictRecord{
		Subsurface:      "forward",
		Transport:       "forward",
		SessionID:       roundTripSessionID,
		RequestID:       "req-1",
		EffectiveAction: config.ActionAllow,
		Outcome:         capture.OutcomeClean,
		Request: capture.CaptureRequest{
			Method: "GET",
			URL:    "https://api.example.com/safe",
		},
	})

	// Record 2: evil.example.com was blocked originally.
	w.ObserveURLVerdict(ctx, &capture.URLVerdictRecord{
		Subsurface:      "forward",
		Transport:       "forward",
		SessionID:       roundTripSessionID,
		RequestID:       "req-2",
		EffectiveAction: config.ActionBlock,
		Outcome:         capture.OutcomeBlocked,
		RawFindings: []capture.Finding{
			{Kind: capture.KindDLP, Action: config.ActionBlock, PatternName: "test_pattern"},
		},
		EffectiveFindings: []capture.Finding{
			{Kind: capture.KindDLP, Action: config.ActionBlock, PatternName: "test_pattern"},
		},
		Request: capture.CaptureRequest{
			Method: "GET",
			URL:    "https://evil.example.com/exfil",
		},
	})

	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// --- Phase 2: LoadAndReplay ---
	candidateCfg := config.Defaults()
	candidateCfg.Internal = nil      // disable SSRF checks (no DNS in tests)
	candidateCfg.DLP.ScanEnv = false // no env leak scanning
	// Candidate blocks both domains — api.example.com was previously allowed,
	// so it becomes a new_block. evil.example.com was already blocked, so it
	// remains unchanged.
	candidateCfg.FetchProxy.Monitoring.Blocklist = []string{
		"api.example.com",
		"evil.example.com",
	}

	records, dropped, originalHash, err := capture.LoadAndReplay(candidateCfg, captureDir)
	if err != nil {
		t.Fatalf("LoadAndReplay: %v", err)
	}

	if len(records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(records))
	}
	if dropped != 0 {
		t.Fatalf("expected dropped=0, got %d", dropped)
	}

	// --- Phase 3: ComputeDiff ---
	diff := capture.ComputeDiff(records, dropped, originalHash, "sha256:v2")

	if diff.TotalRecords != 2 {
		t.Errorf("TotalRecords: got %d, want 2", diff.TotalRecords)
	}
	if diff.NewBlocks != 1 {
		t.Errorf("NewBlocks: got %d, want 1 (api.example.com: allow→block)", diff.NewBlocks)
	}
	if diff.Unchanged != 1 {
		t.Errorf("Unchanged: got %d, want 1 (evil.example.com: block→block)", diff.Unchanged)
	}
	if diff.Dropped != 0 {
		t.Errorf("Dropped: got %d, want 0", diff.Dropped)
	}
	if diff.ReportVersion == 0 {
		t.Error("ReportVersion should be non-zero")
	}

	// --- Phase 4: RenderDiffHTML ---
	var htmlBuf bytes.Buffer
	if err := capture.RenderDiffHTML(&htmlBuf, diff); err != nil {
		t.Fatalf("RenderDiffHTML: %v", err)
	}

	htmlOut := htmlBuf.String()
	if !strings.Contains(htmlOut, "new_block") {
		t.Error("HTML output should contain 'new_block' change type")
	}

	// --- Phase 5: RenderDiffJSON ---
	var jsonBuf bytes.Buffer
	if err := capture.RenderDiffJSON(&jsonBuf, diff); err != nil {
		t.Fatalf("RenderDiffJSON: %v", err)
	}

	var parsed capture.DiffReport
	if err := json.Unmarshal(jsonBuf.Bytes(), &parsed); err != nil {
		t.Fatalf("json.Unmarshal DiffReport: %v", err)
	}

	if parsed.ReportVersion == 0 {
		t.Error("JSON DiffReport.ReportVersion should be non-zero")
	}
	if parsed.TotalRecords != 2 {
		t.Errorf("JSON TotalRecords: got %d, want 2", parsed.TotalRecords)
	}
}
