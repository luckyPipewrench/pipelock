// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package capture

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// testOrigHash and testCandHash are fixed short hashes used across render tests.
const (
	testOrigHash = "aabbccddeeff0011"
	testCandHash = "1100ffeeddeeccbb"
)

// newTestDiffReport builds a minimal DiffReport with one new_block change.
func newTestDiffReport() *DiffReport {
	entry := DiffEntry{
		Summary: CaptureSummary{
			Surface:    SurfaceURL,
			Subsurface: "forward",
			Request: CaptureRequest{
				Method: "GET",
				URL:    "https://example.com/api",
			},
			EffectiveAction: "allow",
		},
		OriginalAction:  "allow",
		CandidateAction: "block",
		Changed:         true,
		ChangeType:      changeTypeNewBlock,
	}
	return &DiffReport{
		ReportVersion:       reportVersion,
		OriginalConfigHash:  testOrigHash,
		CandidateConfigHash: testCandHash,
		TotalRecords:        1,
		Replayed:            1,
		NewBlocks:           1,
		Changes:             []DiffEntry{entry},
		AllRecords:          []DiffEntry{entry},
	}
}

func TestRenderDiffHTML(t *testing.T) {
	t.Parallel()

	d := newTestDiffReport()
	var buf bytes.Buffer
	if err := RenderDiffHTML(&buf, d); err != nil {
		t.Fatalf("RenderDiffHTML: %v", err)
	}
	got := buf.String()

	if !strings.Contains(got, testOrigHash) {
		t.Errorf("HTML missing original config hash %q", testOrigHash)
	}
	if !strings.Contains(got, testCandHash) {
		t.Errorf("HTML missing candidate config hash %q", testCandHash)
	}
	if !strings.Contains(got, changeTypeNewBlock) {
		t.Errorf("HTML missing change type %q", changeTypeNewBlock)
	}
	if !strings.Contains(got, "Policy Replay Diff Report") {
		t.Error("HTML missing report title")
	}
}

func TestRenderDiffJSON(t *testing.T) {
	t.Parallel()

	d := newTestDiffReport()
	var buf bytes.Buffer
	if err := RenderDiffJSON(&buf, d); err != nil {
		t.Fatalf("RenderDiffJSON: %v", err)
	}

	var got DiffReport
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal JSON output: %v", err)
	}
	if got.ReportVersion != reportVersion {
		t.Errorf("ReportVersion: got %d, want %d", got.ReportVersion, reportVersion)
	}
	if got.OriginalConfigHash != testOrigHash {
		t.Errorf("OriginalConfigHash: got %q, want %q", got.OriginalConfigHash, testOrigHash)
	}
	if got.NewBlocks != d.NewBlocks {
		t.Errorf("NewBlocks: got %d, want %d", got.NewBlocks, d.NewBlocks)
	}
}
