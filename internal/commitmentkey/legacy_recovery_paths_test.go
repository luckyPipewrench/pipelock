// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package commitmentkey

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestRestoreLegacyUnverifiedRefusesEveryUnusableSource covers the refusal paths
// of the recovery escape hatch.
//
// This is the one path that accepts a keyring without a verified content check,
// so it is the path most worth pinning. Each case below is a way the hatch could
// widen from "recover a keyring written before the check existed" into "accept
// anything", which would return the product to the defect this change closed.
func TestRestoreLegacyUnverifiedRefusesEveryUnusableSource(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(t *testing.T, source string)
		want    string
		wantIs  error
	}{
		{
			// Matched by class, not by message: the operating system chooses the
			// wording, so a text match fails on a platform without any product
			// regression behind it.
			name:    "source does not exist",
			prepare: func(*testing.T, string) {},
			wantIs:  fs.ErrNotExist,
		},
		{
			name: "source is not JSON",
			prepare: func(t *testing.T, source string) {
				if err := os.WriteFile(source, []byte("not json at all"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			want: "decode",
		},
		{
			name: "source is structurally invalid",
			prepare: func(t *testing.T, source string) {
				keyring := &Keyring{Format: FormatV1, Purpose: Purpose}
				writeRawKeyring(t, source, keyring)
			},
			want: "commitment keyring",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			source := filepath.Join(dir, "legacy.json")
			tt.prepare(t, source)

			_, err := RestoreLegacyUnverified(source, filepath.Join(dir, "restored.json"))
			if err == nil {
				t.Fatal("legacy recovery accepted an unusable source; the escape hatch must stay narrow")
			}
			if tt.wantIs != nil && !errors.Is(err, tt.wantIs) {
				t.Errorf("error = %v, want it to wrap %v", err, tt.wantIs)
			}
			if tt.want != "" && !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %q, want it to mention %q", err.Error(), tt.want)
			}
		})
	}
}

// TestRestoreLegacyUnverifiedWillNotOverwrite pins that recovery creates a
// keyring and never replaces one. An operator reaching for this flag is already
// in an incident; silently overwriting the keyring still on disk would destroy
// the material they might yet recover.
func TestRestoreLegacyUnverifiedWillNotOverwrite(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "legacy.json")
	destination := filepath.Join(dir, "restored.json")

	keyring, err := Initialize(source, time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	keyring.Format = FormatV1
	keyring.ContentCheck = ""
	writeRawKeyring(t, source, keyring)

	if _, err := Initialize(destination, time.Unix(1_700_000_001, 0)); err != nil {
		t.Fatalf("Initialize destination: %v", err)
	}
	before, err := os.ReadFile(filepath.Clean(destination))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := RestoreLegacyUnverified(source, destination); err == nil {
		t.Fatal("legacy recovery overwrote an existing keyring")
	}

	after, err := os.ReadFile(filepath.Clean(destination))
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Error("the existing keyring changed during a refused recovery")
	}
}

// TestRestoreLegacyUnverifiedRefusesAnUnwritableDestination covers the parent
// directory failure, so a recovery that cannot land reports the failure rather
// than returning a keyring that was never written.
func TestRestoreLegacyUnverifiedRefusesAnUnwritableDestination(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "legacy.json")

	keyring, err := Initialize(source, time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	keyring.Format = FormatV1
	keyring.ContentCheck = ""
	writeRawKeyring(t, source, keyring)

	// A regular file standing where the parent directory must be.
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := RestoreLegacyUnverified(source, filepath.Join(blocker, "nested", "restored.json")); err == nil {
		t.Fatal("legacy recovery reported success with nowhere to write the keyring")
	} else if errors.Is(err, ErrInvalidKeyring) {
		t.Errorf("error = %v, want a write failure rather than an invalid-keyring verdict", err)
	}
}
