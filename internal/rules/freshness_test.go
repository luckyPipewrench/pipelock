// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCheckFreshness_V1BundleAlwaysOK(t *testing.T) {
	t.Parallel()

	b := &Bundle{FormatVersion: 1, Name: "test-bundle"}
	state := &FreshnessState{HighestSeen: make(map[string]uint64)}
	result := CheckFreshness(b, state, time.Date(2026, 4, 5, 0, 0, 0, 0, time.UTC), false)
	if !result.OK {
		t.Errorf("v1 bundle should always pass freshness check, got: %s", result.Message)
	}
}

func TestCheckFreshness_RollbackRejected(t *testing.T) {
	t.Parallel()

	state := &FreshnessState{
		HighestSeen: map[string]uint64{
			"standard:test-bundle": 10,
		},
	}
	b := &Bundle{
		FormatVersion:    2,
		Name:             "test-bundle",
		Tier:             TierStandard,
		MonotonicVersion: 5, // lower than 10
		PublishedAt:      "2026-04-01T00:00:00Z",
		ExpiresAt:        "2026-06-01T00:00:00Z",
		KeyID:            "test-key",
	}

	result := CheckFreshness(b, state, time.Date(2026, 4, 5, 0, 0, 0, 0, time.UTC), false)
	if result.OK {
		t.Fatal("expected rollback rejection, got OK")
	}
	if !result.Rollback {
		t.Error("expected Rollback=true")
	}
}

func TestCheckFreshness_RollbackAllowed_SameVersion(t *testing.T) {
	t.Parallel()

	state := &FreshnessState{
		HighestSeen: map[string]uint64{
			"standard:test-bundle": 10,
		},
	}
	b := &Bundle{
		FormatVersion:    2,
		Name:             "test-bundle",
		Tier:             TierStandard,
		MonotonicVersion: 10, // equal to highest seen
		PublishedAt:      "2026-04-01T00:00:00Z",
		ExpiresAt:        "2026-06-01T00:00:00Z",
		KeyID:            "test-key",
	}

	result := CheckFreshness(b, state, time.Date(2026, 4, 5, 0, 0, 0, 0, time.UTC), false)
	if !result.OK {
		t.Errorf("same version should be accepted, got: %s", result.Message)
	}
}

func TestCheckFreshness_NewerVersionAccepted(t *testing.T) {
	t.Parallel()

	state := &FreshnessState{
		HighestSeen: map[string]uint64{
			"standard:test-bundle": 10,
		},
	}
	b := &Bundle{
		FormatVersion:    2,
		Name:             "test-bundle",
		Tier:             TierStandard,
		MonotonicVersion: 15,
		PublishedAt:      "2026-04-01T00:00:00Z",
		ExpiresAt:        "2026-06-01T00:00:00Z",
		KeyID:            "test-key",
	}

	result := CheckFreshness(b, state, time.Date(2026, 4, 5, 0, 0, 0, 0, time.UTC), false)
	if !result.OK {
		t.Errorf("newer version should be accepted, got: %s", result.Message)
	}
}

func TestCheckFreshness_ExpiredRejected(t *testing.T) {
	t.Parallel()

	state := &FreshnessState{HighestSeen: make(map[string]uint64)}
	b := &Bundle{
		FormatVersion:    2,
		Name:             "test-bundle",
		Tier:             TierCommunity,
		MonotonicVersion: 1,
		PublishedAt:      "2026-01-01T00:00:00Z",
		ExpiresAt:        "2026-02-01T00:00:00Z", // in the past
		KeyID:            "test-key",
	}

	now := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	result := CheckFreshness(b, state, now, false)
	if result.OK {
		t.Fatal("expected expiry rejection, got OK")
	}
	if !result.Expired {
		t.Error("expected Expired=true")
	}
}

func TestCheckFreshness_ExpiredAllowedWithStaleFlag(t *testing.T) {
	t.Parallel()

	state := &FreshnessState{HighestSeen: make(map[string]uint64)}
	b := &Bundle{
		FormatVersion:    2,
		Name:             "test-bundle",
		Tier:             TierCommunity,
		MonotonicVersion: 1,
		PublishedAt:      "2026-01-01T00:00:00Z",
		ExpiresAt:        "2026-02-01T00:00:00Z",
		KeyID:            "test-key",
	}

	now := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	result := CheckFreshness(b, state, now, true) // allowStale=true
	if !result.OK {
		t.Errorf("expected stale bundle to be accepted with allowStale, got: %s", result.Message)
	}
	if !result.Expired {
		t.Error("expected Expired=true even with allowStale")
	}
}

func TestCheckFreshness_DifferentTiersIndependent(t *testing.T) {
	t.Parallel()

	state := &FreshnessState{
		HighestSeen: map[string]uint64{
			"standard:standard-rules": 50,
		},
	}
	b := &Bundle{
		FormatVersion:    2,
		Name:             "community-rules",
		Tier:             TierCommunity,
		MonotonicVersion: 1, // v1 for community, even though standard is v50
		PublishedAt:      "2026-04-01T00:00:00Z",
		ExpiresAt:        "2026-06-01T00:00:00Z",
		KeyID:            "test-key",
	}

	result := CheckFreshness(b, state, time.Date(2026, 4, 5, 0, 0, 0, 0, time.UTC), false)
	if !result.OK {
		t.Errorf("different tier should have independent version tracking, got: %s", result.Message)
	}
}

func TestCheckFreshness_SameTierDifferentBundlesIndependent(t *testing.T) {
	t.Parallel()

	state := &FreshnessState{
		HighestSeen: map[string]uint64{
			"community:financial-dlp": 50,
		},
	}
	b := &Bundle{
		FormatVersion:    2,
		Name:             "healthcare-phi",
		Tier:             TierCommunity,
		MonotonicVersion: 1,
		PublishedAt:      "2026-04-01T00:00:00Z",
		ExpiresAt:        "2026-06-01T00:00:00Z",
		KeyID:            "test-key",
	}

	result := CheckFreshness(b, state, time.Date(2026, 4, 5, 0, 0, 0, 0, time.UTC), false)
	if !result.OK {
		t.Errorf("different bundle in same tier should not be blocked: %s", result.Message)
	}
}

func TestRecordVersion(t *testing.T) {
	t.Parallel()

	state := &FreshnessState{HighestSeen: make(map[string]uint64)}
	key := "standard:test-bundle"

	RecordVersion(state, TierStandard, "test-bundle", 5)
	if state.HighestSeen[key] != 5 {
		t.Errorf("expected 5, got %d", state.HighestSeen[key])
	}

	RecordVersion(state, TierStandard, "test-bundle", 10)
	if state.HighestSeen[key] != 10 {
		t.Errorf("expected 10, got %d", state.HighestSeen[key])
	}

	// Lower version should NOT update.
	RecordVersion(state, TierStandard, "test-bundle", 3)
	if state.HighestSeen[key] != 10 {
		t.Errorf("expected 10 (should not decrease), got %d", state.HighestSeen[key])
	}

	// Different name in same tier should be independent.
	RecordVersion(state, TierStandard, "other-bundle", 2)
	otherKey := "standard:other-bundle"
	if state.HighestSeen[otherKey] != 2 {
		t.Errorf("expected 2 for other-bundle, got %d", state.HighestSeen[otherKey])
	}
	if state.HighestSeen[key] != 10 {
		t.Errorf("recording other-bundle should not affect test-bundle: expected 10, got %d", state.HighestSeen[key])
	}
}

func TestFreshnessState_LoadSave(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	// Save state with tier:name keys.
	state := &FreshnessState{
		HighestSeen: map[string]uint64{
			"standard:pipelock-standard": 42,
			"community:financial-dlp":    7,
		},
	}
	if err := SaveFreshnessState(dir, state); err != nil {
		t.Fatalf("SaveFreshnessState: %v", err)
	}

	// Verify file exists.
	path := filepath.Join(dir, freshnessFilename)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("freshness file not created: %v", err)
	}

	// Load and verify.
	loaded, err := LoadFreshnessState(dir)
	if err != nil {
		t.Fatalf("LoadFreshnessState: %v", err)
	}
	if loaded.HighestSeen["standard:pipelock-standard"] != 42 {
		t.Errorf("standard:pipelock-standard: expected 42, got %d", loaded.HighestSeen["standard:pipelock-standard"])
	}
	if loaded.HighestSeen["community:financial-dlp"] != 7 {
		t.Errorf("community:financial-dlp: expected 7, got %d", loaded.HighestSeen["community:financial-dlp"])
	}
}

func TestFreshnessState_LoadMissing(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	state, err := LoadFreshnessState(dir)
	if err != nil {
		t.Fatalf("LoadFreshnessState on missing file: %v", err)
	}
	if state.HighestSeen == nil {
		t.Error("expected initialized HighestSeen map")
	}
}

func TestFreshnessState_LoadCorrupt_FailsClosed(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, freshnessFilename)

	// Write corrupt JSON.
	if err := os.WriteFile(path, []byte("{invalid json"), 0o600); err != nil {
		t.Fatalf("writing corrupt file: %v", err)
	}

	_, err := LoadFreshnessState(dir)
	if err == nil {
		t.Fatal("expected error for corrupt freshness state, got nil")
	}
}

func TestFreshnessState_LoadUnreadable_FailsClosed(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, freshnessFilename)

	// Write valid JSON but make it unreadable.
	if err := os.WriteFile(path, []byte(`{"highest_seen":{}}`), 0o600); err != nil {
		t.Fatalf("writing file: %v", err)
	}
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })

	_, err := LoadFreshnessState(dir)
	if err == nil {
		t.Fatal("expected error for unreadable freshness state, got nil")
	}
}

func TestCheckTierKeyBinding_V1SkipsCheck(t *testing.T) {
	t.Parallel()

	b := &Bundle{FormatVersion: 1}
	if err := CheckTierKeyBinding(b, "any-fp", nil); err != nil {
		t.Errorf("v1 bundle should skip tier-key check: %v", err)
	}
}

func TestCheckTierKeyBinding_KeyIDMismatch(t *testing.T) {
	t.Parallel()

	b := &Bundle{
		FormatVersion: 2,
		KeyID:         "sha256:declared-key",
		Tier:          TierStandard,
	}
	err := CheckTierKeyBinding(b, "sha256:actual-signer", nil)
	if err == nil {
		t.Fatal("expected error for key_id mismatch")
	}
}

func TestCheckTierKeyBinding_TierMismatch(t *testing.T) {
	t.Parallel()

	b := &Bundle{
		FormatVersion: 2,
		KeyID:         "sha256:community-key",
		Tier:          TierStandard,
	}
	keyMapping := map[string]string{
		TierStandard: "sha256:standard-key",
	}
	err := CheckTierKeyBinding(b, "sha256:community-key", keyMapping)
	if err == nil {
		t.Fatal("expected error: community key should not sign standard bundle")
	}
}

func TestCheckTierKeyBinding_CorrectBinding(t *testing.T) {
	t.Parallel()

	b := &Bundle{
		FormatVersion: 2,
		KeyID:         "sha256:standard-key",
		Tier:          TierStandard,
	}
	keyMapping := map[string]string{
		TierStandard: "sha256:standard-key",
	}
	if err := CheckTierKeyBinding(b, "sha256:standard-key", keyMapping); err != nil {
		t.Errorf("correct binding should pass: %v", err)
	}
}

func TestCheckTierKeyBinding_UnmappedTierPasses(t *testing.T) {
	t.Parallel()

	b := &Bundle{
		FormatVersion: 2,
		KeyID:         "sha256:pro-key",
		Tier:          TierPro,
	}
	// No mapping for pro tier.
	keyMapping := map[string]string{
		TierStandard: "sha256:standard-key",
	}
	if err := CheckTierKeyBinding(b, "sha256:pro-key", keyMapping); err != nil {
		t.Errorf("unmapped tier should pass: %v", err)
	}
}
