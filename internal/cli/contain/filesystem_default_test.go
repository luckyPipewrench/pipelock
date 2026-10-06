// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestApplyFreshFilesystemDefault(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	fresh, err := applyFreshFilesystemDefault(env, []byte("mode: balanced\nmetrics_listen: 127.0.0.1:9091\n"))
	if err != nil {
		t.Fatal(err)
	}
	const wantFresh = "mode: balanced\nmetrics_listen: 127.0.0.1:9091\ncontainment:\n  filesystem:\n    mode: enforce\n"
	if string(fresh) != wantFresh {
		t.Fatalf("fresh config = %q", fresh)
	}

	explicit := []byte("containment:\n  filesystem:\n    mode: off\n")
	kept, err := applyFreshFilesystemDefault(env, explicit)
	if err != nil {
		t.Fatal(err)
	}
	if string(kept) != string(explicit) {
		t.Fatalf("explicit off was rewritten: %q", kept)
	}

	nullMode := []byte("containment:\n  filesystem:\n    mode:\n")
	keptNull, err := applyFreshFilesystemDefault(env, nullMode)
	if err != nil {
		t.Fatal(err)
	}
	if string(keptNull) != string(nullMode) {
		t.Fatalf("null mode was rewritten: %q", keptNull)
	}

	dst := managedPipelockConfigPath(env)
	if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, []byte("mode: balanced\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	existing := []byte("mode: strict\n")
	unchanged, err := applyFreshFilesystemDefault(env, existing)
	if err != nil {
		t.Fatal(err)
	}
	if string(unchanged) != string(existing) {
		t.Fatalf("existing install was rewritten: %q", unchanged)
	}

	env.stat = func(string) (os.FileInfo, error) { return nil, errors.New("stat denied") }
	if _, err := applyFreshFilesystemDefault(env, existing); err == nil || !strings.Contains(err.Error(), "stat managed config") {
		t.Fatalf("stat failure = %v", err)
	}
}
