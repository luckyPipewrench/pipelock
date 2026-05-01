// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package envelope

import (
	"errors"
	"fmt"
	"testing"
)

func TestVerificationFailureCodeOf(t *testing.T) {
	t.Parallel()

	base := errors.New("signature wording changed")
	err := fmt.Errorf("wrapped: %w", &VerificationError{
		Code: VerificationFailureSignature,
		Err:  base,
	})

	code, ok := VerificationFailureCodeOf(err)
	if !ok {
		t.Fatal("expected verification failure code")
	}
	if code != VerificationFailureSignature {
		t.Fatalf("code = %q, want %q", code, VerificationFailureSignature)
	}
	if !errors.Is(err, base) {
		t.Fatal("verification error should unwrap to original error")
	}
}

func TestVerificationErrorNil(t *testing.T) {
	t.Parallel()

	var err *VerificationError
	if got := err.Error(); got != string(VerificationFailureFailed) {
		t.Fatalf("nil Error() = %q", got)
	}
	if unwrapped := err.Unwrap(); unwrapped != nil {
		t.Fatalf("nil Unwrap() = %v, want nil", unwrapped)
	}
	if code, ok := VerificationFailureCodeOf(errors.New("plain")); ok || code != "" {
		t.Fatalf("plain error code = (%q, %v), want empty false", code, ok)
	}
}
