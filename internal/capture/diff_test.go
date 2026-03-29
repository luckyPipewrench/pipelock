// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package capture

import (
	"testing"
)

// Test hash constants to avoid goconst lint triggers for repeated string values.
const (
	testOriginalHash  = "sha256:original"
	testCandidateHash = "sha256:candidate"
)

func TestComputeDiff(t *testing.T) {
	records := []ReplayedRecord{
		// Changed: original allow → candidate block  → new_block
		{
			Summary: CaptureSummary{Surface: SurfaceURL, EffectiveAction: "allow"},
			Result:  ReplayResult{OriginalAction: "allow", CandidateAction: "block", Changed: true},
		},
		// Unchanged
		{
			Summary: CaptureSummary{Surface: SurfaceURL, EffectiveAction: "allow"},
			Result:  ReplayResult{OriginalAction: "allow", CandidateAction: "allow", Changed: false},
		},
		// Changed: original block → candidate allow → new_allow
		{
			Summary: CaptureSummary{Surface: SurfaceURL, EffectiveAction: "block"},
			Result:  ReplayResult{OriginalAction: "block", CandidateAction: "allow", Changed: true},
		},
		// Evidence-only (CEE surface)
		{
			Summary: CaptureSummary{Surface: SurfaceCEE, EffectiveAction: "block"},
			Result:  ReplayResult{EvidenceOnly: true},
		},
		// Summary-only (response surface, no scanner input stored)
		{
			Summary: CaptureSummary{Surface: SurfaceResponse, EffectiveAction: "allow"},
			Result:  ReplayResult{SummaryOnly: true},
		},
	}

	diff := ComputeDiff(records, 7, 0, testOriginalHash, testCandidateHash)

	if diff.TotalRecords != 5 {
		t.Errorf("TotalRecords: got %d, want 5", diff.TotalRecords)
	}
	if diff.Replayed != 3 {
		t.Errorf("Replayed: got %d, want 3", diff.Replayed)
	}
	if diff.NewBlocks != 1 {
		t.Errorf("NewBlocks: got %d, want 1", diff.NewBlocks)
	}
	if diff.NewAllows != 1 {
		t.Errorf("NewAllows: got %d, want 1", diff.NewAllows)
	}
	if diff.Unchanged != 1 {
		t.Errorf("Unchanged: got %d, want 1", diff.Unchanged)
	}
	if diff.EvidenceOnly != 1 {
		t.Errorf("EvidenceOnly: got %d, want 1", diff.EvidenceOnly)
	}
	if diff.SummaryOnly != 1 {
		t.Errorf("SummaryOnly: got %d, want 1", diff.SummaryOnly)
	}
	if diff.Dropped != 7 {
		t.Errorf("Dropped: got %d, want 7", diff.Dropped)
	}
	if len(diff.Changes) != 2 {
		t.Errorf("len(Changes): got %d, want 2", len(diff.Changes))
	}
	if diff.ReportVersion != reportVersion {
		t.Errorf("ReportVersion: got %d, want %d", diff.ReportVersion, reportVersion)
	}
	if diff.OriginalConfigHash != testOriginalHash {
		t.Errorf("OriginalConfigHash: got %q, want %q", diff.OriginalConfigHash, testOriginalHash)
	}
	if diff.CandidateConfigHash != testCandidateHash {
		t.Errorf("CandidateConfigHash: got %q, want %q", diff.CandidateConfigHash, testCandidateHash)
	}
	if len(diff.AllRecords) != 5 {
		t.Errorf("len(AllRecords): got %d, want 5", len(diff.AllRecords))
	}

	// Verify change types in Changes slice.
	changeTypes := map[string]int{}
	for _, c := range diff.Changes {
		changeTypes[c.ChangeType]++
	}
	if changeTypes[changeTypeNewBlock] != 1 {
		t.Errorf("Changes new_block count: got %d, want 1", changeTypes[changeTypeNewBlock])
	}
	if changeTypes[changeTypeNewAllow] != 1 {
		t.Errorf("Changes new_allow count: got %d, want 1", changeTypes[changeTypeNewAllow])
	}
}

func TestComputeDiff_Empty(t *testing.T) {
	diff := ComputeDiff(nil, 0, 0, testOriginalHash, testCandidateHash)

	if diff.TotalRecords != 0 {
		t.Errorf("TotalRecords: got %d, want 0", diff.TotalRecords)
	}
	if diff.Replayed != 0 {
		t.Errorf("Replayed: got %d, want 0", diff.Replayed)
	}
	if diff.Changes != nil {
		t.Errorf("Changes: got non-nil, want nil")
	}
	if diff.Dropped != 0 {
		t.Errorf("Dropped: got %d, want 0", diff.Dropped)
	}
}

func TestComputeDiff_AllUnchanged(t *testing.T) {
	records := []ReplayedRecord{
		{
			Summary: CaptureSummary{Surface: SurfaceURL, EffectiveAction: "allow"},
			Result:  ReplayResult{OriginalAction: "allow", CandidateAction: "allow", Changed: false},
		},
		{
			Summary: CaptureSummary{Surface: SurfaceDLP, EffectiveAction: "block"},
			Result:  ReplayResult{OriginalAction: "block", CandidateAction: "block", Changed: false},
		},
	}

	diff := ComputeDiff(records, 0, 0, testOriginalHash, testCandidateHash)

	if diff.TotalRecords != 2 {
		t.Errorf("TotalRecords: got %d, want 2", diff.TotalRecords)
	}
	if diff.Replayed != 2 {
		t.Errorf("Replayed: got %d, want 2", diff.Replayed)
	}
	if diff.Unchanged != 2 {
		t.Errorf("Unchanged: got %d, want 2", diff.Unchanged)
	}
	if diff.NewBlocks != 0 {
		t.Errorf("NewBlocks: got %d, want 0", diff.NewBlocks)
	}
	if diff.NewAllows != 0 {
		t.Errorf("NewAllows: got %d, want 0", diff.NewAllows)
	}
	if diff.Changes != nil {
		t.Errorf("Changes: got non-nil, want nil")
	}
}

func TestComputeDiff_AllEvidenceOnly(t *testing.T) {
	records := []ReplayedRecord{
		{
			Summary: CaptureSummary{Surface: SurfaceCEE, EffectiveAction: "block"},
			Result:  ReplayResult{OriginalAction: "block", EvidenceOnly: true},
		},
		{
			Summary: CaptureSummary{Surface: SurfaceToolScan, EffectiveAction: "allow"},
			Result:  ReplayResult{OriginalAction: "allow", EvidenceOnly: true},
		},
	}

	diff := ComputeDiff(records, 3, 0, testOriginalHash, testCandidateHash)

	if diff.TotalRecords != 2 {
		t.Errorf("TotalRecords: got %d, want 2", diff.TotalRecords)
	}
	if diff.Replayed != 0 {
		t.Errorf("Replayed: got %d, want 0", diff.Replayed)
	}
	if diff.EvidenceOnly != 2 {
		t.Errorf("EvidenceOnly: got %d, want 2", diff.EvidenceOnly)
	}
	if diff.Dropped != 3 {
		t.Errorf("Dropped: got %d, want 3", diff.Dropped)
	}
	if diff.Changes != nil {
		t.Errorf("Changes: got non-nil, want nil")
	}
}

func TestComputeDiff_FailClosedTreatedAsBlock(t *testing.T) {
	// fail_closed as candidate action should be classified as new_block when
	// original was not a blocking action.
	records := []ReplayedRecord{
		{
			Summary: CaptureSummary{Surface: SurfaceURL, EffectiveAction: "allow"},
			Result:  ReplayResult{OriginalAction: "allow", CandidateAction: "fail_closed", Changed: true},
		},
	}

	diff := ComputeDiff(records, 0, 0, testOriginalHash, testCandidateHash)

	if diff.NewBlocks != 1 {
		t.Errorf("NewBlocks: got %d, want 1 (fail_closed should count as block)", diff.NewBlocks)
	}
	if diff.NewAllows != 0 {
		t.Errorf("NewAllows: got %d, want 0", diff.NewAllows)
	}
}

func TestIsBlockAction(t *testing.T) {
	tests := []struct {
		action string
		want   bool
	}{
		{"block", true},
		{"fail_closed", true},
		{"allow", false},
		{"warn", false},
		{"strip", false},
		{"redirect", false},
		{"", false},
	}

	for _, tc := range tests {
		got := isBlockAction(tc.action)
		if got != tc.want {
			t.Errorf("isBlockAction(%q) = %v, want %v", tc.action, got, tc.want)
		}
	}
}
