// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyBaseRestoredMetadataIsUnavailable(t *testing.T) {
	fired := false
	report := verifyBaseWithWalkHook(t, false, func(t *testing.T, _, path string, _ int) {
		if fired {
			return
		}
		fired = true
		before, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(filepath.Clean(path))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, before.ModTime(), before.ModTime()); err != nil {
			t.Fatal(err)
		}
	})
	if !fired || report.Healthy() || !report.EvidenceChangedDuringVerification() {
		t.Fatalf("consumed shard rewrite accepted: %+v", report)
	}
}

func TestVerifyBaseFutureParseFailureIsUnavailable(t *testing.T) {
	const future = "evidence-proxy.run.f7b327337534352a514bd0a256b1d1c0-0.jsonl"
	fired := false
	report := verifyBaseWithWalkHook(t, false, func(t *testing.T, dir, path string, _ int) {
		if fired || filepath.Base(path) == future {
			return
		}
		fired = true
		target := filepath.Join(dir, future)
		if _, err := os.Stat(target); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, []byte("{malformed}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	})
	if !fired || report.Healthy() || !report.EvidenceChangedDuringVerification() {
		t.Fatalf("changed future input became corruption: %+v", report)
	}
}

// A duplicate sequence start is a corrupt_chain finding, as it was before the
// inventory fingerprint existed; the fingerprint must not turn it into a
// listing failure that hides which session is ambiguous.
func TestVerifyBaseDuplicateSeqStartIsFinding(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	for _, name := range []string{"evidence-proxy-0.jsonl", "evidence-proxy-00.jsonl"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	report, err := VerifyBase(dir, "proxy", BaseVerifyOptions{})
	if err != nil {
		t.Fatalf("VerifyBase returned %v, want a corrupt_chain finding", err)
	}
	found := false
	for _, f := range report.Findings {
		found = found || (f.Kind == FindingCorruptChain && strings.Contains(f.Detail, "sequence"))
	}
	if !found || report.Healthy() {
		t.Fatalf("findings=%+v, want a corrupt_chain naming the ambiguous sequence", report.Findings)
	}
}
