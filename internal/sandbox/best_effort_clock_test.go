// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"strings"
	"testing"
	"time"
)

// TestValidateBestEffortOverrideUsesCurrentClock checks the exported entry
// point evaluates expiry against the real clock. Every timestamp is derived
// from time.Now so the test never ages into a different result.
func TestValidateBestEffortOverrideUsesCurrentClock(t *testing.T) {
	const reason = "container user namespaces are disabled"
	future := time.Now().Add(2 * time.Hour).UTC().Truncate(time.Second)

	tests := []struct {
		name    string
		reason  string
		expiry  string
		wantErr string
		// wantAt, when set, is the exact expiry the call must return.
		wantAt time.Time
		// wantIn, when set, is a duration the expiry must be measured from now.
		wantIn time.Duration
	}{
		{name: "duration measured from now", reason: reason, expiry: "45m", wantIn: 45 * time.Minute},
		{name: "future timestamp", reason: reason, expiry: future.Format(time.RFC3339), wantAt: future},
		{name: "timestamp just past", reason: reason, expiry: time.Now().Add(-time.Minute).UTC().Format(time.RFC3339), wantErr: "expired"},
		{name: "negative duration", reason: reason, expiry: "-1m", wantErr: "expired"},
		{name: "blank reason", reason: "   ", expiry: "45m", wantErr: "requires a reason"},
		{name: "blank expiry", reason: reason, expiry: " ", wantErr: "requires an expiry"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := time.Now()
			got, err := ValidateBestEffortOverride(tt.reason, tt.expiry)
			after := time.Now()
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("ValidateBestEffortOverride() = %v, %v; want error containing %q", got, err, tt.wantErr)
				}
				if !got.IsZero() {
					t.Fatalf("ValidateBestEffortOverride() returned expiry %v alongside an error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ValidateBestEffortOverride() = %v, want nil", err)
			}
			if !tt.wantAt.IsZero() && !got.Equal(tt.wantAt) {
				t.Fatalf("expiry = %v, want %v", got, tt.wantAt)
			}
			if tt.wantIn != 0 && (got.Before(before.Add(tt.wantIn)) || got.After(after.Add(tt.wantIn))) {
				t.Fatalf("expiry = %s, want between %s and %s", got.Format(time.RFC3339Nano), before.Add(tt.wantIn).Format(time.RFC3339Nano), after.Add(tt.wantIn).Format(time.RFC3339Nano))
			}
		})
	}
}
