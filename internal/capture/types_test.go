// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package capture_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/capture"
)

// fakeAWSKey builds a fake AWS access key ID at runtime to avoid G101 (gosec
// hardcoded credentials false positive).
func fakeAWSKey() string { return "AKIA" + "IOSFODNN7EXAMPLE" }

// TestCaptureSummary_JSONRoundTrip verifies that CaptureSummary survives a
// JSON marshal/unmarshal cycle with all field types, including *int BatchIndex.
func TestCaptureSummary_JSONRoundTrip(t *testing.T) {
	batchIdx := 3
	summary := capture.CaptureSummary{
		CaptureSchemaVersion: capture.CaptureSchemaV1,
		Surface:              capture.SurfaceURL,
		Subsurface:           "forward",
		BatchIndex:           &batchIdx,
		ConfigHash:           "abc123",
		BuildVersion:         "v2.0.0",
		BuildSHA:             "deadbeef",
		Agent:                "test-agent",
		Profile:              "default",
		PayloadRef:           "raw/0001",
		PayloadSHA256:        "sha256hex",
		PayloadBytes:         1024,
		PayloadComplete:      true,
		TransformKind:        capture.TransformReadability,
		WirePayloadBytes:     512,
		WirePayloadSample:    "sample text",
		ScannerBytes:         256,
		ScannerSample:        "scanned text",
		Request: capture.CaptureRequest{
			Method:       "GET",
			URL:          "https://example.com/path",
			Headers:      map[string][]string{"Content-Type": {"application/json"}},
			BodySample:   "{}",
			ToolName:     "bash",
			ToolArgsJSON: `{"cmd":"ls"}`,
			MCPMethod:    "tools/call",
		},
		RawFindings: []capture.Finding{
			{
				Kind:         capture.KindDLP,
				Action:       "block",
				Severity:     "critical",
				PatternName:  "aws_key",
				Encoded:      "base64",
				MatchText:    fakeAWSKey(),
				ToolSequence: []string{"tool_a", "tool_b"},
			},
		},
		EffectiveFindings: []capture.Finding{
			{
				Kind:        capture.KindInjection,
				Action:      "block",
				Severity:    "critical",
				PatternName: "jailbreak_dan",
				MatchText:   "DAN mode",
			},
		},
		EffectiveAction: "block",
		Outcome:         capture.OutcomeBlocked,
	}

	data, err := json.Marshal(summary)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got capture.CaptureSummary
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if got.CaptureSchemaVersion != summary.CaptureSchemaVersion {
		t.Errorf("CaptureSchemaVersion: got %d, want %d", got.CaptureSchemaVersion, summary.CaptureSchemaVersion)
	}
	if got.Surface != summary.Surface {
		t.Errorf("Surface: got %q, want %q", got.Surface, summary.Surface)
	}
	if got.BatchIndex == nil {
		t.Fatal("BatchIndex: got nil, want non-nil")
	}
	if *got.BatchIndex != *summary.BatchIndex {
		t.Errorf("BatchIndex: got %d, want %d", *got.BatchIndex, *summary.BatchIndex)
	}
	if got.PayloadComplete != summary.PayloadComplete {
		t.Errorf("PayloadComplete: got %v, want %v", got.PayloadComplete, summary.PayloadComplete)
	}
	if len(got.RawFindings) != 1 {
		t.Fatalf("RawFindings: got %d, want 1", len(got.RawFindings))
	}
	if got.RawFindings[0].Kind != capture.KindDLP {
		t.Errorf("RawFindings[0].Kind: got %q, want %q", got.RawFindings[0].Kind, capture.KindDLP)
	}
	if len(got.RawFindings[0].ToolSequence) != 2 {
		t.Errorf("RawFindings[0].ToolSequence: got len %d, want 2", len(got.RawFindings[0].ToolSequence))
	}
	if got.Request.ToolArgsJSON != summary.Request.ToolArgsJSON {
		t.Errorf("Request.ToolArgsJSON: got %q, want %q", got.Request.ToolArgsJSON, summary.Request.ToolArgsJSON)
	}
	if got.Outcome != capture.OutcomeBlocked {
		t.Errorf("Outcome: got %q, want %q", got.Outcome, capture.OutcomeBlocked)
	}
}

// TestCaptureSummary_BatchIndexOmittedWhenNil verifies that a nil BatchIndex is
// omitted from JSON entirely (not marshalled as null), so that replays can
// distinguish "not a batch" from "batch element 0".
func TestCaptureSummary_BatchIndexOmittedWhenNil(t *testing.T) {
	summary := capture.CaptureSummary{
		CaptureSchemaVersion: capture.CaptureSchemaV1,
		Surface:              capture.SurfaceDLP,
		Outcome:              capture.OutcomeClean,
	}

	data, err := json.Marshal(summary)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal to map: %v", err)
	}

	if _, present := raw["batch_index"]; present {
		t.Error("batch_index should be absent from JSON when nil, but was present")
	}
}

// TestFindingKindConstants verifies that all Finding kind constants have
// distinct values. A collision would mean two detector types map to the same
// label in the evidence log and replay diff output.
func TestFindingKindConstants_AllDistinct(t *testing.T) {
	const (
		kindDLP            = capture.KindDLP
		kindAddressProtect = capture.KindAddressProtection
		kindInjection      = capture.KindInjection
		kindCEE            = capture.KindCEE
		kindChain          = capture.KindChainDetection
		kindSession        = capture.KindSessionBinding
		kindToolPoison     = capture.KindToolPoison
		kindToolDrift      = capture.KindToolDrift
		kindToolPolicy     = capture.KindToolPolicy
		kindRedirect       = capture.KindRedirect
	)

	kinds := []string{
		kindDLP,
		kindAddressProtect,
		kindInjection,
		kindCEE,
		kindChain,
		kindSession,
		kindToolPoison,
		kindToolDrift,
		kindToolPolicy,
		kindRedirect,
	}

	seen := make(map[string]bool, len(kinds))
	for _, k := range kinds {
		if seen[k] {
			t.Errorf("duplicate Finding kind constant value: %q", k)
		}
		seen[k] = true
	}
}

// TestNopObserver_ImplementsInterface verifies at compile time that NopObserver
// satisfies the CaptureObserver interface, and verifies that all methods
// return without panicking.
func TestNopObserver_ImplementsInterface(t *testing.T) {
	var obs capture.CaptureObserver = capture.NopObserver{}

	ctx := context.Background()

	// None of these should panic.
	obs.ObserveURLVerdict(ctx, &capture.URLVerdictRecord{})
	obs.ObserveResponseVerdict(ctx, &capture.ResponseVerdictRecord{})
	obs.ObserveDLPVerdict(ctx, &capture.DLPVerdictRecord{})
	obs.ObserveCEEVerdict(ctx, &capture.CEERecord{})
	obs.ObserveToolPolicyVerdict(ctx, &capture.ToolPolicyRecord{})
	obs.ObserveToolScanVerdict(ctx, &capture.ToolScanRecord{})

	if err := obs.Close(); err != nil {
		t.Errorf("NopObserver.Close() returned unexpected error: %v", err)
	}
}
