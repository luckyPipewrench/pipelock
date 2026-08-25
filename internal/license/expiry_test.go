// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package license

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestExpiryStatusLifetimeAwareBands(t *testing.T) {
	now := time.Date(2026, 5, 23, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name          string
		lifetime      time.Duration
		remaining     time.Duration
		wantActive    bool
		wantBand      string
		wantThreshold int
		wantSeverity  string
	}{
		{"30 day trial at issuance", 30 * expiryDay, 30 * expiryDay, false, "", 0, ""},
		{"30 day trial early", 30 * expiryDay, 15 * expiryDay, true, "early", 15, ExpirySeverityInfo},
		{"30 day trial mid", 30 * expiryDay, 7 * expiryDay, true, "mid", 8, ExpirySeverityWarn},
		{"30 day trial late", 30 * expiryDay, 3 * expiryDay, true, "late", 4, ExpirySeverityWarn},
		{"30 day trial final", 30 * expiryDay, expiryDay, true, "final", 1, ExpirySeverityError},
		{"45 day paid token at issuance", 45 * expiryDay, 45 * expiryDay, false, "", 0, ""},
		{"45 day paid token early", 45 * expiryDay, 22 * expiryDay, true, "early", 23, ExpirySeverityInfo},
		{"45 day paid token mid", 45 * expiryDay, 11 * expiryDay, true, "mid", 12, ExpirySeverityWarn},
		{"45 day paid token late", 45 * expiryDay, 5 * expiryDay, true, "late", 6, ExpirySeverityWarn},
		{"45 day paid token final", 45 * expiryDay, expiryDay, true, "final", 1, ExpirySeverityError},
		{"60 day evaluation at issuance", 60 * expiryDay, 60 * expiryDay, false, "", 0, ""},
		{"60 day evaluation early", 60 * expiryDay, 30 * expiryDay, true, "early", 30, ExpirySeverityInfo},
		{"60 day evaluation mid", 60 * expiryDay, 14 * expiryDay, true, "mid", 14, ExpirySeverityWarn},
		{"60 day evaluation late", 60 * expiryDay, 7 * expiryDay, true, "late", 7, ExpirySeverityWarn},
		{"60 day evaluation final", 60 * expiryDay, expiryDay, true, "final", 1, ExpirySeverityError},
		{"long lived license at issuance", 365 * expiryDay, 365 * expiryDay, false, "", 0, ""},
		{"long lived license early", 365 * expiryDay, 30 * expiryDay, true, "early", 30, ExpirySeverityInfo},
		{"long lived license mid", 365 * expiryDay, 14 * expiryDay, true, "mid", 14, ExpirySeverityWarn},
		{"long lived license late", 365 * expiryDay, 7 * expiryDay, true, "late", 7, ExpirySeverityWarn},
		{"long lived license final", 365 * expiryDay, expiryDay, true, "final", 1, ExpirySeverityError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expiresAt := now.Add(tt.remaining)
			status := ExpiryStatus(License{
				ID:        "lic_test",
				IssuedAt:  expiresAt.Add(-tt.lifetime).Unix(),
				ExpiresAt: expiresAt.Unix(),
			}, now)
			if status.Active != tt.wantActive {
				t.Fatalf("Active = %v, want %v; status=%+v", status.Active, tt.wantActive, status)
			}
			if status.Band != tt.wantBand {
				t.Errorf("Band = %q, want %q", status.Band, tt.wantBand)
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

func TestExpiryStatusUsesLegacyBandsForUnusableIssuedAt(t *testing.T) {
	now := time.Date(2026, 5, 23, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name     string
		issuedAt int64
		expires  int64
	}{
		{"missing", 0, now.Add(30 * expiryDay).Unix()},
		{"future", now.Add(expiryDay).Unix(), now.Add(30 * expiryDay).Unix()},
		{"after expiry", now.Add(31 * expiryDay).Unix(), now.Add(30 * expiryDay).Unix()},
		{"equal expiry", now.Add(30 * expiryDay).Unix(), now.Add(30 * expiryDay).Unix()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status := ExpiryStatus(License{ID: "lic_bad_iat", IssuedAt: tt.issuedAt, ExpiresAt: tt.expires}, now)
			if !status.Active || status.Band != "early" || status.ThresholdDays != 30 || status.Severity != ExpirySeverityInfo {
				t.Fatalf("status = %+v, want legacy 30-day info band", status)
			}
		})
	}
}

func TestLegacyExpiryBand(t *testing.T) {
	tests := []struct {
		name          string
		days          int
		wantBand      string
		wantThreshold int
	}{
		{"final", 1, "final", 1},
		{"late", 2, "late", 7},
		{"mid", 8, "mid", 14},
		{"early", 15, "early", 30},
		{"outside", 31, "", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			band, threshold := legacyExpiryBand(tt.days)
			if tt.wantBand == "" {
				if band != nil || threshold != 0 {
					t.Fatalf("legacyExpiryBand(%d) = %v, %d; want nil, 0", tt.days, band, threshold)
				}
				return
			}
			if band == nil || band.name != tt.wantBand || threshold != tt.wantThreshold {
				t.Fatalf("legacyExpiryBand(%d) = %v, %d; want %s, %d", tt.days, band, threshold, tt.wantBand, tt.wantThreshold)
			}
		})
	}
}

func TestExpiryStatusNoWarningForPerpetualOrExpired(t *testing.T) {
	now := time.Date(2026, 5, 23, 12, 0, 0, 0, time.UTC)
	for _, lic := range []License{
		{ID: "lic_perpetual"},
		{ID: "lic_expired", IssuedAt: now.Add(-30 * expiryDay).Unix(), ExpiresAt: now.Add(-time.Hour).Unix()},
	} {
		status := ExpiryStatus(lic, now)
		if status.Active {
			t.Fatalf("ExpiryStatus(%s).Active = true, want false", lic.ID)
		}
		if status.DaysRemaining != 0 && lic.ExpiresAt > 0 {
			t.Fatalf("ExpiryStatus(%s).DaysRemaining = %d, want 0", lic.ID, status.DaysRemaining)
		}
	}
}

func TestExpiryStatusSkipsDuplicateShortLifetimeBands(t *testing.T) {
	now := time.Date(2026, 5, 23, 12, 0, 0, 0, time.UTC)
	status := ExpiryStatus(License{
		ID:        "lic_short",
		IssuedAt:  now.Add(-18 * time.Hour).Unix(),
		ExpiresAt: now.Add(6 * time.Hour).Unix(),
	}, now)
	if !status.Active || status.Band != "final" || status.ThresholdDays != 1 || status.Severity != ExpirySeverityError {
		t.Fatalf("status = %+v, want final band after duplicate short-lived bands are skipped", status)
	}
	if ShouldEmitExpiryWarning(status, NewExpiryWarningState(status, now)) {
		t.Fatal("the same final band should not re-emit after a successful run")
	}
}

func TestExpiryWarningMessage(t *testing.T) {
	expiresAt := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		name string
		tier string
		want string
	}{
		{
			name: "trial",
			tier: trialTier,
			want: "trial ends in 7 day(s) on 2026-06-01; Pro features stop at expiry. Subscribe at https://pipelab.org/pricing/",
		},
		{
			name: "enterprise evaluation",
			tier: enterpriseEvalTier,
			want: "Enterprise evaluation ends in 7 day(s) on 2026-06-01; licensed runtime surfaces stop at expiry. See https://pipelab.org/pricing/",
		},
		{
			name: "subscription",
			tier: "pro",
			want: "license expires in 7 day(s) on 2026-06-01; check billing or token delivery",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			warning := ExpiryWarning{Active: true, Tier: tt.tier, DaysRemaining: 7, ExpiresAt: expiresAt}
			if got := warning.Message(); got != tt.want {
				t.Fatalf("Message() = %q, want %q", got, tt.want)
			}
		})
	}

	if got := (ExpiryWarning{}).Message(); got != "" {
		t.Fatalf("inactive Message() = %q, want empty", got)
	}
}

func TestShouldEmitExpiryWarningIdempotentPerBand(t *testing.T) {
	current := ExpiryWarning{Active: true, LicenseID: "lic_test", Band: "mid", ThresholdDays: 8}
	if !ShouldEmitExpiryWarning(current, ExpiryWarningState{}) {
		t.Fatal("first warning should emit")
	}
	if ShouldEmitExpiryWarning(current, ExpiryWarningState{LicenseID: "lic_test", Band: "mid", ThresholdDays: 8}) {
		t.Fatal("same license and band should not emit twice")
	}
	if !ShouldEmitExpiryWarning(current, ExpiryWarningState{LicenseID: "lic_test", Band: "early", ThresholdDays: 15}) {
		t.Fatal("a skipped intermediate band must not suppress the current band")
	}
	if !ShouldEmitExpiryWarning(current, ExpiryWarningState{LicenseID: "lic_test", Band: "early", ThresholdDays: 8}) {
		t.Fatal("a state from a different named band must not suppress the current band when their threshold days match")
	}
	if !ShouldEmitExpiryWarning(current, ExpiryWarningState{LicenseID: "lic_other", Band: "mid", ThresholdDays: 8}) {
		t.Fatal("license change should emit")
	}
	if ShouldEmitExpiryWarning(ExpiryWarning{}, ExpiryWarningState{}) {
		t.Fatal("inactive warning should not emit")
	}
}

func TestShouldEmitExpiryWarningSupportsLegacyState(t *testing.T) {
	current := ExpiryWarning{Active: true, LicenseID: "lic_test", Band: "early", ThresholdDays: 15}
	if !ShouldEmitExpiryWarning(current, ExpiryWarningState{LicenseID: "lic_test", ThresholdDays: 30}) {
		t.Fatal("legacy state with a different absolute band must not suppress the new lifetime-aware band")
	}
	if ShouldEmitExpiryWarning(current, ExpiryWarningState{LicenseID: "lic_test", ThresholdDays: 15}) {
		t.Fatal("legacy state with the same threshold should continue suppressing a duplicate warning")
	}
}

func TestExpiryWarningStateRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "license-expiry.json")
	want := NewExpiryWarningState(ExpiryWarning{
		Active:        true,
		LicenseID:     "lic_state",
		Band:          "late",
		ThresholdDays: 4,
	}, time.Date(2026, 5, 23, 12, 0, 0, 0, time.UTC))
	if err := SaveExpiryWarningState(path, want); err != nil {
		t.Fatalf("SaveExpiryWarningState: %v", err)
	}
	got, err := LoadExpiryWarningState(path)
	if err != nil {
		t.Fatalf("LoadExpiryWarningState: %v", err)
	}
	if got.LicenseID != want.LicenseID || got.Band != want.Band || got.ThresholdDays != want.ThresholdDays || !got.LastEmittedUTC.Equal(want.LastEmittedUTC) {
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
	if _, err := LoadExpiryWarningState(dir); err == nil {
		t.Fatal("expected unreadable state error for directory path")
	}

	legacy := filepath.Join(dir, "legacy.json")
	if err := os.WriteFile(legacy, []byte(`{"license_id":"lic_legacy","threshold_days":30,"last_emitted_utc":"2026-05-23T12:00:00Z"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	state, err := LoadExpiryWarningState(legacy)
	if err != nil {
		t.Fatalf("LoadExpiryWarningState legacy: %v", err)
	}
	if state.Band != "" || state.ThresholdDays != 30 || !strings.EqualFold(state.LicenseID, "lic_legacy") {
		t.Fatalf("legacy state = %+v, want older schema preserved", state)
	}

	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	err = SaveExpiryWarningState(filepath.Join(blocker, "state.json"), ExpiryWarningState{})
	if err == nil {
		t.Fatal("expected directory creation error")
	}
	if err := SaveExpiryWarningState(dir, ExpiryWarningState{}); err == nil {
		t.Fatal("expected write error for directory state path")
	}
}
