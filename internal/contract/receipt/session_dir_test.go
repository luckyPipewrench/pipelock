// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

// For session "s", the file evidence-s-evil-999.jsonl satisfies an
// "evidence-s-" prefix but belongs to session "s-evil". Prefix matching folded
// another session's receipts into this chain.
//
// Neutralization: restore prefix matching in
// ExtractEvidenceReceiptsFromSessionDir and this fails, because the foreign
// file is read and its parse error surfaces.
func TestExtractEvidenceReceiptsFromSessionDir_IgnoresForeignSessionSharingPrefix(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	// Deliberately unparseable content. If session filtering is correct this
	// file is never opened; if it regresses to prefix matching, reading it
	// fails and the error names the foreign shard.
	foreign := filepath.Join(dir, "evidence-s-evil-999.jsonl")
	if err := os.WriteFile(foreign, []byte("{ not valid receipt json\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	got, err := ExtractEvidenceReceiptsFromSessionDir(dir, "s")
	if err != nil {
		t.Fatalf("ExtractEvidenceReceiptsFromSessionDir: %v (foreign session shard must be ignored)", err)
	}
	if len(got) != 0 {
		t.Fatalf("returned %d receipts, want 0", len(got))
	}
}

// Both parseEvidenceName and recorder.ParseEvidenceFilename now delegate to
// evidencename.Parse, so this is a contract pin rather than a drift detector:
// it fails if either side stops delegating and reintroduces its own grammar.
// Session membership decided two different ways is a cross-session chain
// contamination, so the equivalence is worth asserting even once the
// duplication is gone.
func TestParseEvidenceName_MatchesRecorderSemantics(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		input       string
		wantSession string
		wantSeq     uint64
		wantOK      bool
	}{
		{"plain", "evidence-proxy-42.jsonl", "proxy", 42, true},
		{"session_with_dash", "evidence-s-evil-999.jsonl", "s-evil", 999, true},
		{"session_with_digits", "evidence-s-1-999.jsonl", "s-1", 999, true},
		{"session_with_dot", "evidence-s.v1-999.jsonl", "s.v1", 999, true},
		{"zero_seq", "evidence-proxy-0.jsonl", "proxy", 0, true},
		{"leading_zero_seq", "evidence-proxy-007.jsonl", "proxy", 7, true},
		{"max_uint64_seq", "evidence-proxy-18446744073709551615.jsonl", "proxy", 18446744073709551615, true},
		{"nonnumeric_seq_is_zero", "evidence-s-abc.jsonl", "s", 0, true},
		{"session_ending_dash", "evidence-s--1.jsonl", "s-", 1, true},
		{"unicode_session", "evidence-\u03c0-3.jsonl", "\u03c0", 3, true},
		{"missing_evidence_prefix", "proxy-1.jsonl", "", 0, false},
		{"wrong_suffix", "evidence-proxy-1.txt", "", 0, false},
		{"no_dash_after_prefix", "evidence-proxy.jsonl", "", 0, false},
		{"full_path", "/tmp/evidence/evidence-proxy-7.jsonl", "proxy", 7, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			session, seq, ok := parseEvidenceName(tt.input)
			if ok != tt.wantOK || session != tt.wantSession || seq != tt.wantSeq {
				t.Fatalf("parseEvidenceName(%q) = (%q, %d, %v), want (%q, %d, %v)",
					tt.input, session, seq, ok, tt.wantSession, tt.wantSeq, tt.wantOK)
			}
			recSession, recSeq, recOK := recorder.ParseEvidenceFilename(tt.input)
			if recOK != ok || recSession != session || recSeq != seq {
				t.Fatalf("recorder.ParseEvidenceFilename(%q) = (%q, %d, %v), parseEvidenceName = (%q, %d, %v)",
					tt.input, recSession, recSeq, recOK, session, seq, ok)
			}
		})
	}
}
