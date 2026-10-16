// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package workspacediff

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSignRejectsMalformedInputs(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("capsule"))
	goodDigest := hex.EncodeToString(sum[:])
	sts := []Statement{{Root: "/workspace"}}
	tests := []struct {
		name    string
		sts     []Statement
		capsule string
		want    string // empty means success expected
	}{
		{name: "valid inputs sign", sts: sts, capsule: goodDigest},
		{name: "digest-length non-hex capsule", sts: sts, capsule: strings.Repeat("z", sha256.Size*2), want: "not valid hex"},
		{name: "no statements", sts: nil, capsule: goodDigest, want: "at least one workspace statement"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signed, err := Sign(tt.sts, tt.capsule, priv)
			if tt.want == "" {
				if err != nil {
					t.Fatalf("Sign: %v", err)
				}
				if signed.Signature == "" {
					t.Fatal("Sign returned an empty signature")
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Sign error = %v, want %q", err, tt.want)
			}
			if signed.Signature != "" {
				t.Fatalf("Sign returned a signature alongside error %v", err)
			}
		})
	}
}

func TestWriteJSONFailsClosedOnUnwritableDestination(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("capsule"))
	signed, err := Sign([]Statement{{Root: "/workspace"}}, hex.EncodeToString(sum[:]), priv)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name  string
		setup func(t *testing.T) string
		want  string // empty means success expected
	}{
		{name: "writable directory succeeds", setup: func(t *testing.T) string { return t.TempDir() }},
		{name: "destination occupied by a directory", setup: func(t *testing.T) string {
			dir := t.TempDir()
			blocker := filepath.Join(dir, "workspace-change-statement.json")
			if err := os.MkdirAll(filepath.Join(blocker, "child"), 0o750); err != nil {
				t.Fatal(err)
			}
			return dir
		}, want: "rename into place"},
		{name: "read-only output directory", setup: func(t *testing.T) string {
			if runtime.GOOS == "windows" || os.Geteuid() == 0 {
				t.Skip("directory write permission is not enforced here")
			}
			dir := filepath.Join(t.TempDir(), "ro")
			if err := os.Mkdir(dir, 0o500); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(dir, 0o700) }) //nolint:gosec // restore so TempDir cleanup can remove it
			return dir
		}, want: "create temp file"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := tt.setup(t)
			path, err := WriteJSON(dir, signed)
			if tt.want == "" {
				if err != nil {
					t.Fatalf("WriteJSON: %v", err)
				}
				if _, statErr := os.Stat(path); statErr != nil {
					t.Fatalf("written statement missing: %v", statErr)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("WriteJSON error = %v, want %q", err, tt.want)
			}
			if path != "" {
				t.Fatalf("WriteJSON returned path %q alongside error", path)
			}
			leftovers, globErr := filepath.Glob(filepath.Join(dir, ".workspace-change-statement-*.tmp"))
			if globErr != nil {
				t.Fatal(globErr)
			}
			if len(leftovers) != 0 {
				t.Fatalf("temp files left behind after failure: %v", leftovers)
			}
		})
	}
}
