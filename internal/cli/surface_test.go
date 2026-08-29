// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"slices"
	"strings"
	"testing"
)

// These two helpers are what the capability manifest enumerates the operator
// surface from, so the completeness check is only as good as they are. A
// helper that silently returned nothing would make that check pass while
// covering nothing, which is the exact failure the manifest exists to prevent.

func TestRegisteredTopLevelCommandNames(t *testing.T) {
	names := RegisteredTopLevelCommandNames()
	if len(names) == 0 {
		t.Fatal("no top-level commands enumerated; the manifest completeness check would be vacuous")
	}
	if !slices.IsSorted(names) {
		t.Fatalf("names are not sorted, so callers cannot rely on the order: %v", names)
	}

	// A few commands that must exist for the enumeration to be believable.
	for _, want := range []string{"check", "evidence", "explain", "mcp", "run"} {
		if !slices.Contains(names, want) {
			t.Errorf("%q missing from the enumerated surface: %v", want, names)
		}
	}

	for _, name := range names {
		if strings.TrimSpace(name) != name || name == "" {
			t.Errorf("enumerated command name %q is empty or padded", name)
		}
		if strings.Contains(name, " ") {
			t.Errorf("top-level name %q contains a space, so it is a path rather than a name", name)
		}
	}
}

func TestRegisteredCommandPaths(t *testing.T) {
	paths := RegisteredCommandPaths()
	if len(paths) == 0 {
		t.Fatal("no command paths enumerated")
	}
	if len(paths) < len(RegisteredTopLevelCommandNames()) {
		t.Fatalf("paths (%d) fewer than top-level names (%d); nested walk did not run",
			len(paths), len(RegisteredTopLevelCommandNames()))
	}

	// A nested path proves the walk descends rather than listing only the roots.
	nested := false
	for _, p := range paths {
		// "pipelock run" already contains a space, so requiring three words is
		// what actually proves the walk descended past the first level.
		if len(strings.Fields(p)) >= 3 {
			nested = true
			break
		}
	}
	if !nested {
		t.Fatalf("no nested command path found, so the walk did not descend: %v", paths)
	}

	for _, p := range paths {
		if strings.TrimSpace(p) != p || p == "" {
			t.Errorf("enumerated path %q is empty or padded", p)
		}
	}
}
