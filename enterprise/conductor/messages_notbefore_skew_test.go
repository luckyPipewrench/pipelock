//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package conductor

import (
	"errors"
	"testing"
	"time"
)

// TestWithinValidity_NotBeforeClockSkew proves the not_before check tolerates a
// bounded operator/validator clock skew (the cross-machine bug reproduced on
// prod 2026-06-22 where an operator clock slightly ahead of the conductor made
// every kill/rollback "not yet valid"), while keeping expiry strict.
func TestWithinValidity_NotBeforeClockSkew(t *testing.T) {
	now := time.Now().UTC()
	expires := now.Add(time.Hour)

	tests := []struct {
		name      string
		notBefore time.Time
		expires   time.Time
		wantErr   error
	}{
		{"not_before equal to now", now, expires, nil},
		{"not_before in the past", now.Add(-time.Minute), expires, nil},
		{"not_before within skew (operator slightly ahead)", now.Add(30 * time.Second), expires, nil},
		{"not_before at skew boundary", now.Add(MessageNotBeforeSkew), expires, nil},
		{"not_before beyond skew", now.Add(MessageNotBeforeSkew + 5*time.Second), expires, ErrNotYetValid},
		{"expired stays strict (no skew on expiry)", now.Add(-time.Hour), now.Add(-time.Second), ErrExpired},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := withinValidity(now, tc.notBefore, tc.expires)
			switch {
			case tc.wantErr == nil && err != nil:
				t.Fatalf("want nil, got %v", err)
			case tc.wantErr != nil && !errors.Is(err, tc.wantErr):
				t.Fatalf("want %v, got %v", tc.wantErr, err)
			}
		})
	}
}
