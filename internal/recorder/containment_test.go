// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"os"
	"path/filepath"
	"testing"
)

// TestResolveEvidenceRunRefusesEscapingID pins the containment property rather
// than one implementation of it. Two mechanisms currently enforce it: the run-ID
// cleaner rejects a dot-dot path, and a resolved ID must match a discovered
// descendant run. Either alone contains an escape today, so this asserts the
// outcome so a later change to the matching logic cannot open the escape while
// the cleaner is the only thing left holding it shut.
func TestResolveEvidenceRunRefusesEscapingID(t *testing.T) {
	t.Parallel()
	escaping := []string{
		"..",
		"../..",
		filepath.Join("..", "..", "etc"),
		filepath.Join("..", "sibling-root"),
	}
	for _, runID := range escaping {
		t.Run(runID, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			writeDiscoveryShard(t, root, "evidence-proxy-0.jsonl")
			// Give the escape a real target so a resolved path would succeed if
			// containment failed, making the assertion meaningful rather than a
			// missing-directory artifact.
			writeDiscoveryShard(t, filepath.Join(filepath.Dir(root), "sibling-root"), "evidence-proxy-0.jsonl")
			if _, err := ResolveEvidenceRun(root, runID); err == nil {
				t.Fatalf("ResolveEvidenceRun(%q) resolved outside the evidence root, want refusal", runID)
			}
		})
	}
}

// TestDiscoverEvidenceRunsFailsClosedOnUnreadableDir proves an unreadable
// directory surfaces an error instead of being skipped. Skipping would make
// missing evidence indistinguishable from absent evidence, which is a fail-open
// on evidence completeness. One live recorder directory is owned by a separate
// service account, so this state is real rather than theoretical.
func TestDiscoverEvidenceRunsFailsClosedOnUnreadableDir(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permissions")
	}
	root := t.TempDir()
	writeDiscoveryShard(t, root, "evidence-proxy-0.jsonl")
	blocked := filepath.Join(root, "unreadable")
	writeDiscoveryShard(t, blocked, "evidence-proxy-1.jsonl")
	if err := os.Chmod(blocked, 0o000); err != nil {
		t.Skipf("chmod unavailable: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(blocked, 0o750) })

	if _, err := DiscoverEvidenceRuns(root); err == nil {
		t.Fatal("DiscoverEvidenceRuns() succeeded over an unreadable directory, want a surfaced error so missing evidence cannot look absent")
	}
}
