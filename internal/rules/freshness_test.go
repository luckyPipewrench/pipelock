// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
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

func TestFreshnessState_PrimaryOnlyBackfillsSecondaryAndContext(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	state := &FreshnessState{HighestSeen: map[string]uint64{"community:test-bundle": 17}}
	if err := writeFreshnessStateFile(filepath.Join(dir, freshnessFilename), dir, state); err != nil {
		t.Fatalf("write primary freshness state: %v", err)
	}

	loaded, err := LoadFreshnessState(dir)
	if err != nil {
		t.Fatalf("LoadFreshnessState: %v", err)
	}
	if got := loaded.HighestSeen["community:test-bundle"]; got != 17 {
		t.Fatalf("loaded floor = %d, want 17", got)
	}
	if _, err := os.Stat(freshnessSecondaryPath(dir)); err != nil {
		t.Fatalf("secondary freshness state not backfilled: %v", err)
	}
	if found, err := readFreshnessContext(dir); err != nil || !found {
		t.Fatalf("freshness context after primary-only load = (%v, %v), want (true, nil)", found, err)
	}
}

func TestFreshnessState_SecondaryOnlyRestoresPrimaryAndContext(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	state := &FreshnessState{HighestSeen: map[string]uint64{"standard:pipelock-standard": 23}}
	if err := writeFreshnessStateFile(freshnessSecondaryPath(dir), dir, state); err != nil {
		t.Fatalf("write secondary freshness state: %v", err)
	}

	loaded, err := LoadFreshnessState(dir)
	if err != nil {
		t.Fatalf("LoadFreshnessState: %v", err)
	}
	if got := loaded.HighestSeen["standard:pipelock-standard"]; got != 23 {
		t.Fatalf("loaded floor = %d, want 23", got)
	}
	if _, err := os.Stat(filepath.Join(dir, freshnessFilename)); err != nil {
		t.Fatalf("primary freshness state not restored: %v", err)
	}
	if found, err := readFreshnessContext(dir); err != nil || !found {
		t.Fatalf("freshness context after secondary-only load = (%v, %v), want (true, nil)", found, err)
	}
}

func TestFreshnessState_MismatchedCopiesFailClosed(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := writeFreshnessStateFile(filepath.Join(dir, freshnessFilename), dir, &FreshnessState{
		HighestSeen: map[string]uint64{"community:test-bundle": 10},
	}); err != nil {
		t.Fatalf("write primary freshness state: %v", err)
	}
	if err := writeFreshnessStateFile(freshnessSecondaryPath(dir), dir, &FreshnessState{
		HighestSeen: map[string]uint64{"community:test-bundle": 11},
	}); err != nil {
		t.Fatalf("write secondary freshness state: %v", err)
	}

	_, err := LoadFreshnessState(dir)
	if err == nil || !strings.Contains(err.Error(), "freshness state mismatch") {
		t.Fatalf("LoadFreshnessState mismatch error = %v, want mismatch", err)
	}
}

func TestFreshnessState_ContextAndDigestMismatchFailClosed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
		want string
	}{
		{
			name: "context mismatch",
			body: `{"highest_seen":{"community:test-bundle":10},"context":"wrong-context"}`,
			want: "context mismatch",
		},
		{
			name: "digest mismatch",
			body: `{"highest_seen":{"community:test-bundle":10},"digest":"wrong-digest"}`,
			want: "digest mismatch",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, freshnessFilename), []byte(tc.body), 0o600); err != nil {
				t.Fatalf("write freshness state: %v", err)
			}

			_, err := LoadFreshnessState(dir)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("LoadFreshnessState error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestFreshnessState_ContextFileErrorsFailClosed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
		want string
	}{
		{name: "invalid json", body: "{not json", want: "parse freshness context"},
		{name: "wrong context", body: `{"context":"wrong-context"}`, want: "freshness context mismatch"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			if err := os.MkdirAll(filepath.Dir(freshnessContextPath(dir)), 0o750); err != nil {
				t.Fatalf("mkdir context dir: %v", err)
			}
			if err := os.WriteFile(freshnessContextPath(dir), []byte(tc.body), 0o600); err != nil {
				t.Fatalf("write context: %v", err)
			}

			_, err := LoadFreshnessState(dir)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("LoadFreshnessState error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestResetFreshnessStateFromInstalledBundlesNoV2WritesEmptyState(t *testing.T) {
	t.Parallel()

	dir := filepath.Join(t.TempDir(), "rules")
	if err := ResetFreshnessStateFromInstalledBundles(dir); err != nil {
		t.Fatalf("ResetFreshnessStateFromInstalledBundles: %v", err)
	}
	loaded, err := LoadFreshnessState(dir)
	if err != nil {
		t.Fatalf("LoadFreshnessState: %v", err)
	}
	if len(loaded.HighestSeen) != 0 {
		t.Fatalf("HighestSeen = %#v, want empty", loaded.HighestSeen)
	}
}

func TestFreshnessState_DeleteAllWithInstalledV2ContextFailsClosed(t *testing.T) {
	dir := t.TempDir()
	bundleDir := filepath.Join(dir, "test-bundle")
	if err := os.MkdirAll(bundleDir, 0o750); err != nil {
		t.Fatalf("mkdir bundle dir: %v", err)
	}
	writeUnsignedBundle(t, bundleDir, testBundleV2("test-bundle", TierCommunity, 10, []Rule{testDLPRule("one", confidenceHigh, StatusStable)}))

	state := &FreshnessState{HighestSeen: map[string]uint64{"community:test-bundle": 10}}
	if err := SaveFreshnessState(dir, state); err != nil {
		t.Fatalf("SaveFreshnessState: %v", err)
	}
	if err := os.Remove(filepath.Join(dir, freshnessFilename)); err != nil {
		t.Fatalf("remove primary freshness: %v", err)
	}
	if err := os.Remove(freshnessSecondaryPath(dir)); err != nil {
		t.Fatalf("remove secondary freshness: %v", err)
	}

	if _, err := LoadFreshnessState(dir); err == nil || !strings.Contains(err.Error(), "freshness state missing") {
		t.Fatalf("LoadFreshnessState after delete-all error = %v, want missing freshness state", err)
	}

	if err := ResetFreshnessStateFromInstalledBundles(dir); err != nil {
		t.Fatalf("ResetFreshnessStateFromInstalledBundles: %v", err)
	}
	loaded, err := LoadFreshnessState(dir)
	if err != nil {
		t.Fatalf("LoadFreshnessState after reset: %v", err)
	}
	if got := loaded.HighestSeen["community:test-bundle"]; got != 10 {
		t.Fatalf("reset floor = %d, want 10", got)
	}
	rolledBack := testBundleV2("test-bundle", TierCommunity, 4, nil)
	if result := CheckFreshness(rolledBack, loaded, time.Now().UTC(), false); result.OK || !result.Rollback {
		t.Fatalf("rolled-back bundle after reset = %+v, want rollback rejection", result)
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

func TestFreshnessState_RejectsDuplicateAndOversizedState(t *testing.T) {
	for _, tt := range []struct {
		name string
		body []byte
	}{
		{name: "duplicate floor", body: []byte(`{"highest_seen":{},"highest_seen":{"community:test":99}}`)},
		{name: "oversized", body: bytes.Repeat([]byte("x"), maxFreshnessStateBytes+1)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, freshnessFilename), tt.body, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadFreshnessState(dir); err == nil {
				t.Fatal("LoadFreshnessState accepted hostile state")
			}
		})
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
