// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package redact

import (
	"errors"
	"strings"
	"testing"
)

func TestBlockError_ErrorMessage(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		err        *BlockError
		wantSubstr []string
	}{
		{
			name: "with detail",
			err:  &BlockError{Reason: ReasonOverflow, Detail: "10k cap"},
			wantSubstr: []string{
				"redact: blocked",
				string(ReasonOverflow),
				"10k cap",
			},
		},
		{
			name:       "reason only",
			err:        &BlockError{Reason: ReasonBodyUnparseable},
			wantSubstr: []string{"redact: blocked", string(ReasonBodyUnparseable)},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			msg := tc.err.Error()
			for _, want := range tc.wantSubstr {
				if !strings.Contains(msg, want) {
					t.Errorf("message %q missing %q", msg, want)
				}
			}
		})
	}
}

func TestBlockError_NilSafe(t *testing.T) {
	t.Parallel()
	var e *BlockError
	if got := e.Error(); got != "" {
		t.Fatalf("nil error should produce empty string, got %q", got)
	}
	if e.Is(&BlockError{Reason: ReasonBodyTooLarge}) {
		t.Fatal("nil Is should return false")
	}
}

func TestBlockError_IsByReason(t *testing.T) {
	t.Parallel()
	err := newBlock(ReasonOverflow, 100, "")
	if !errors.Is(err, &BlockError{Reason: ReasonOverflow}) {
		t.Fatal("errors.Is should match on same reason")
	}
	if errors.Is(err, &BlockError{Reason: ReasonBodyTooLarge}) {
		t.Fatal("errors.Is should not match on different reason")
	}
	// Empty-reason target matches any BlockError (sentinel).
	if !errors.Is(err, &BlockError{}) {
		t.Fatal("empty-reason target should match any BlockError")
	}
	// Non-BlockError target does not match.
	if errors.Is(err, errors.New("unrelated")) {
		t.Fatal("errors.Is should not match non-BlockError target")
	}
}

func TestBlockError_ExposesMatchesBeforeBlock(t *testing.T) {
	t.Parallel()
	err := newBlock(ReasonOverflow, 42, "")
	var be *BlockError
	if !errors.As(err, &be) {
		t.Fatal("errors.As failed")
	}
	if be.MatchesBeforeBlock != 42 {
		t.Fatalf("MatchesBeforeBlock = %d, want 42", be.MatchesBeforeBlock)
	}
}
