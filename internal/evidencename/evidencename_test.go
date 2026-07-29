// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package evidencename

import (
	"errors"
	"testing"
)

// The recorder and the contract verifier both decide session membership from
// this one function, so its grammar is security-relevant: a shard attributed to
// the wrong session becomes another chain's head. These cases pin the shapes
// that distinguish membership, especially the ones prefix matching gets wrong.
func TestParse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		input       string
		wantSession string
		wantSeq     uint64
		wantOK      bool
	}{
		{"plain", "evidence-proxy-42.jsonl", "proxy", 42, true},
		// The case prefix matching gets wrong: for session "s" this satisfies
		// "evidence-s-" but belongs to "s-evil", and it sorts above the tail.
		{"session_with_dash", "evidence-s-evil-999.jsonl", "s-evil", 999, true},
		{"session_with_digits", "evidence-s-1-999.jsonl", "s-1", 999, true},
		{"session_with_dot", "evidence-s.v1-999.jsonl", "s.v1", 999, true},
		{"session_ending_dash", "evidence-s--1.jsonl", "s-", 1, true},
		{"unicode_session", "evidence-π-3.jsonl", "π", 3, true},
		{"zero_seq", "evidence-proxy-0.jsonl", "proxy", 0, true},
		{"leading_zero_seq", "evidence-proxy-007.jsonl", "proxy", 7, true},
		// Above MaxInt64. Parsing this as a signed int made it collapse to 0 and
		// sort before a single-digit shard.
		{"max_uint64_seq", "evidence-proxy-18446744073709551615.jsonl", "proxy", 18446744073709551615, true},
		{"nonnumeric_seq_is_zero", "evidence-s-abc.jsonl", "s", 0, true},
		// Overflows uint64. Reaches the same zero fallback as a non-numeric
		// segment, but by ErrRange rather than ErrSyntax, so it is a distinct
		// path worth pinning.
		{"overflows_uint64", "evidence-proxy-99999999999999999999.jsonl", "proxy", 0, true},
		{"missing_evidence_prefix", "proxy-1.jsonl", "", 0, false},
		{"wrong_suffix", "evidence-proxy-1.txt", "", 0, false},
		{"no_dash_after_prefix", "evidence-proxy.jsonl", "", 0, false},
		{"bare_prefix", "evidence-.jsonl", "", 0, false},
		{"full_path", "/tmp/evidence/evidence-proxy-7.jsonl", "proxy", 7, true},
		{"empty", "", "", 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			session, seq, ok := Parse(tt.input)
			if ok != tt.wantOK || session != tt.wantSession || seq != tt.wantSeq {
				t.Fatalf("Parse(%q) = (%q, %d, %v), want (%q, %d, %v)",
					tt.input, session, seq, ok, tt.wantSession, tt.wantSeq, tt.wantOK)
			}
			if got := SeqStart(tt.input); got != tt.wantSeq {
				t.Fatalf("SeqStart(%q) = %d, want %d", tt.input, got, tt.wantSeq)
			}
		})
	}
}

// Every consumer of the shard-directory contract applies this same rule, so the
// rule itself needs to be right: two distinct names for one sequence are
// refused, and everything else passes.
func TestCheckNoDuplicateSeqStart(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		names   []string
		wantErr bool
	}{
		{"empty", nil, false},
		{"single", []string{"evidence-proxy-1.jsonl"}, false},
		{"distinct", []string{"evidence-proxy-1.jsonl", "evidence-proxy-2.jsonl"}, false},
		// Leading zeros make two distinct names parse to one sequence.
		{"leading_zero_twin", []string{"evidence-proxy-7.jsonl", "evidence-proxy-007.jsonl"}, true},
		// Both non-numeric segments collapse to zero.
		{"nonnumeric_collision", []string{"evidence-proxy-abc.jsonl", "evidence-proxy-xyz.jsonl"}, true},
		// The identical name repeated is not an ambiguity, just a duplicate entry.
		{"same_name_twice", []string{"evidence-proxy-1.jsonl", "evidence-proxy-1.jsonl"}, false},
		// Different sessions sharing a sequence are different chains, not an
		// ambiguity; a sequence-only comparison would wrongly refuse this.
		{"different_sessions", []string{"evidence-a-1.jsonl", "evidence-b-1.jsonl"}, false},
		{"full_paths", []string{"/x/evidence-proxy-1.jsonl", "/y/evidence-proxy-2.jsonl"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := CheckNoDuplicateSeqStart(tt.names)
			if tt.wantErr && err == nil {
				t.Fatalf("CheckNoDuplicateSeqStart(%v) = nil, want an ambiguity error", tt.names)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("CheckNoDuplicateSeqStart(%v) = %v, want nil", tt.names, err)
			}
			if tt.wantErr && !errors.Is(err, ErrAmbiguousSeqStart) {
				t.Fatalf("error %v does not wrap ErrAmbiguousSeqStart", err)
			}
		})
	}
}
