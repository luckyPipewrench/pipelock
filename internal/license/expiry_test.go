// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package license

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestExpiryStatusThresholdBands(t *testing.T) {
	now := time.Date(2026, 5, 23, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name          string
		expiresIn     time.Duration
		wantActive    bool
		wantThreshold int
		wantSeverity  string
	}{
		{"outside warning window", 31 * expiryDay, false, 0, ""},
		{"thirty days", 30 * expiryDay, true, 30, ExpirySeverityInfo},
		{"fourteen days", 14 * expiryDay, true, 14, ExpirySeverityWarn},
		{"seven days", 7 * expiryDay, true, 7, ExpirySeverityWarn},
		{"one day", expiryDay, true, 1, ExpirySeverityError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status := ExpiryStatus(License{
				ID:        "lic_test",
				ExpiresAt: now.Add(tt.expiresIn).Unix(),
			}, now)
			if status.Active != tt.wantActive {
				t.Fatalf("Active = %v, want %v; status=%+v", status.Active, tt.wantActive, status)
			}
			if status.ThresholdDays != tt.wantThreshold {
				t.Errorf("ThresholdDays = %d, want %d", status.ThresholdDays, tt.wantThreshold)
			}
			if status.Severity != tt.wantSeverity {
				t.Errorf("Severity = %q, want %q", status.Severity, tt.wantSeverity)
			}
		})
	}
}

func TestExpiryStatusNoWarningForPerpetualOrExpired(t *testing.T) {
	now := time.Date(2026, 5, 23, 12, 0, 0, 0, time.UTC)
	for _, lic := range []License{
		{ID: "lic_perpetual"},
		{ID: "lic_expired", ExpiresAt: now.Add(-time.Hour).Unix()},
	} {
		status := ExpiryStatus(lic, now)
		if status.Active {
			t.Fatalf("ExpiryStatus(%s).Active = true, want false", lic.ID)
		}
	}
}

func TestShouldEmitExpiryWarningIdempotentPerBand(t *testing.T) {
	current := ExpiryWarning{Active: true, LicenseID: "lic_test", ThresholdDays: 14}
	if !ShouldEmitExpiryWarning(current, ExpiryWarningState{}) {
		t.Fatal("first warning should emit")
	}
	if ShouldEmitExpiryWarning(current, ExpiryWarningState{LicenseID: "lic_test", ThresholdDays: 14}) {
		t.Fatal("same license and threshold should not emit twice")
	}
	if !ShouldEmitExpiryWarning(current, ExpiryWarningState{LicenseID: "lic_test", ThresholdDays: 30}) {
		t.Fatal("threshold change should emit")
	}
	if !ShouldEmitExpiryWarning(current, ExpiryWarningState{LicenseID: "lic_other", ThresholdDays: 14}) {
		t.Fatal("license change should emit")
	}
}

func TestExpiryWarningStateRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "license-expiry.json")
	want := NewExpiryWarningState(ExpiryWarning{
		Active:        true,
		LicenseID:     "lic_state",
		ThresholdDays: 7,
	}, time.Date(2026, 5, 23, 12, 0, 0, 0, time.UTC))
	if err := SaveExpiryWarningState(path, want); err != nil {
		t.Fatalf("SaveExpiryWarningState: %v", err)
	}
	got, err := LoadExpiryWarningState(path)
	if err != nil {
		t.Fatalf("LoadExpiryWarningState: %v", err)
	}
	if got.LicenseID != want.LicenseID || got.ThresholdDays != want.ThresholdDays || !got.LastEmittedUTC.Equal(want.LastEmittedUTC) {
		t.Fatalf("state mismatch: got %+v want %+v", got, want)
	}
}

func TestExpiryWarningStateErrorsAndNoopPaths(t *testing.T) {
	if _, err := LoadExpiryWarningState(""); err != nil {
		t.Fatalf("empty load path should be a no-op: %v", err)
	}
	if err := SaveExpiryWarningState("", ExpiryWarningState{}); err != nil {
		t.Fatalf("empty save path should be a no-op: %v", err)
	}
	if _, err := LoadExpiryWarningState(filepath.Join(t.TempDir(), "missing.json")); err != nil {
		t.Fatalf("missing state should be empty without error: %v", err)
	}

	dir := t.TempDir()
	badJSON := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(badJSON, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadExpiryWarningState(badJSON); err == nil {
		t.Fatal("expected parse error")
	}

	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := SaveExpiryWarningState(filepath.Join(blocker, "state.json"), ExpiryWarningState{})
	if err == nil {
		t.Fatal("expected directory creation error")
	}
}

func TestExpirySeverityDefault(t *testing.T) {
	if got := expirySeverity(99); got != "" {
		t.Fatalf("expirySeverity(99) = %q, want empty", got)
	}
	if ShouldEmitExpiryWarning(ExpiryWarning{}, ExpiryWarningState{}) {
		t.Fatal("inactive warning should not emit")
	}
}
