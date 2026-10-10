package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

// The legacy fallback must read the descriptor the snapshot checks. A pathname
// swapped to a valid receipt file during that read must not supply receipts,
// whether or not the final check later notices the swap.
func TestReadChainFileInputLegacyReadsTheCheckedDescriptor(t *testing.T) {
	fix := newCompletenessFixture(t)
	replacement := writeCompletenessJSONL(t, []receipt.Receipt{
		fix.intent("run-legacy", "a1"),
		fix.outcome("run-legacy", "a1"),
	})
	// Empty input is the case that reaches the legacy fallback.
	path := filepath.Join(t.TempDir(), "evidence.jsonl")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("write evidence: %v", err)
	}
	aside := path + ".orig"

	called := false
	previous := legacyChainExtraction
	t.Cleanup(func() { legacyChainExtraction = previous })
	legacyChainExtraction = func(extract func() ([]receipt.Receipt, error)) ([]receipt.Receipt, error) {
		called = true
		if err := os.Rename(path, aside); err != nil {
			t.Fatalf("move original aside: %v", err)
		}
		if err := os.Rename(replacement, path); err != nil {
			t.Fatalf("swap in replacement: %v", err)
		}
		actions, err := extract()
		if err := os.Rename(path, replacement); err != nil {
			t.Fatalf("move replacement back: %v", err)
		}
		if err := os.Rename(aside, path); err != nil {
			t.Fatalf("restore original: %v", err)
		}
		if len(actions) > 0 {
			t.Errorf("legacy extraction read %d receipts from the swapped-in pathname", len(actions))
		}
		return actions, err
	}

	actions, _, err := readChainFileInput(filepath.Base(path), path, chainTrust{})
	if !called {
		t.Fatalf("input did not reach the legacy extraction: actions=%d err=%v", len(actions), err)
	}
	if len(actions) > 0 {
		t.Fatalf("returned %d receipts for an empty evidence file", len(actions))
	}
	if err != nil && !errors.Is(err, recorder.ErrEvidenceChanged) {
		t.Fatalf("swap around the read: got %v, want nil or ErrEvidenceChanged", err)
	}
}
