// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestLocalPathIdentity_InconclusiveWalkExplainsItself proves a block caused by
// the fail-closed hard-link rule names the real cause, and that a genuine
// hard-link match does not claim the walk was inconclusive.
func TestLocalPathIdentity_InconclusiveWalkExplainsItself(t *testing.T) {
	newFixture := func(t *testing.T) (f localPathFixture, value string) {
		f = newLocalPathFixture(t)
		f.write(t, filepath.Join(f.ws, "a.txt"))
		hardLink(t, filepath.Join(f.ws, "a.txt"), filepath.Join(f.ws, "b.txt"))
		return f, filepath.Join(f.ws, "b.txt")
	}
	verdict := func(f localPathFixture, value string) Verdict {
		return checkPath(f.policy(true), testReadTool, "path", value)
	}
	notesText := func(v Verdict) string { return strings.Join(v.Notes, "\n") }

	t.Run("unlistable directory", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root reads any directory")
		}
		f, value := newFixture(t)
		f.write(t, filepath.Join(f.home, ".ssh", "sub", "f"))
		if v := verdict(f, value); len(v.Notes) != 0 {
			t.Fatalf("control: readable tree produced notes: %+v", v)
		}
		chmodForTest(t, filepath.Join(f.home, ".ssh", "sub"), 0o000)
		v := verdict(f, value)
		if !slices.Contains(v.Rules, testKeyReadRule) {
			t.Fatalf("rule must stay matched: %+v", v)
		}
		got := notesText(v)
		for _, want := range []string{"ruled out as a hard link", filepath.Join(f.home, ".ssh"), hardLinkCauseUnlistable, "stat -c %h"} {
			if !strings.Contains(got, want) {
				t.Fatalf("notes %q missing %q", got, want)
			}
		}
	})

	t.Run("walk bound reached", func(t *testing.T) {
		f, value := newFixture(t)
		f.write(t, filepath.Join(f.home, ".ssh", "known_hosts"))
		f.write(t, filepath.Join(f.home, ".ssh", "config"))
		old := localPathMaxDirEntries
		t.Cleanup(func() { localPathMaxDirEntries = old })
		localPathMaxDirEntries = 1
		v := verdict(f, value)
		if !slices.Contains(v.Rules, testKeyReadRule) || !strings.Contains(notesText(v), hardLinkCauseBound) {
			t.Fatalf("bound case must match with the bound named: %+v", v)
		}
	})

	t.Run("real hard link match carries no note", func(t *testing.T) {
		f := newLocalPathFixture(t)
		key := filepath.Join(f.home, ".ssh", "id_ed25519")
		f.write(t, key)
		hardLink(t, key, filepath.Join(f.ws, "notes.txt"))
		v := verdict(f, filepath.Join(f.ws, "notes.txt"))
		if !slices.Contains(v.Rules, testKeyReadRule) {
			t.Fatalf("real hard link not matched: %+v", v)
		}
		// Other protected directories on the same device (system log or spool
		// trees a runner cannot list) may honestly add their own notes; the
		// directory that holds the real link was walked and must not.
		sshDir := filepath.Join(f.home, ".ssh")
		for _, note := range v.Notes {
			if strings.Contains(note, "protected directory "+sshDir+" ") {
				t.Fatalf("a known hard link must not claim an inconclusive walk of its directory: %q", note)
			}
		}
	})
}
