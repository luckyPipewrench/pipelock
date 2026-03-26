// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package plsentry

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadFileSecrets(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		content  string
		wantLen  int
		wantErr  bool
		wantVals []string
	}{
		{
			name:     "valid secrets",
			content:  "mysecret12345678\nanothersecret999\n",
			wantLen:  2,
			wantVals: []string{"mysecret12345678", "anothersecret999"},
		},
		{
			name:    "skips short lines",
			content: "short\nmysecret12345678\nab\n",
			wantLen: 1,
		},
		{
			name:    "skips comments",
			content: "# this is a comment\nmysecret12345678\n",
			wantLen: 1,
		},
		{
			name:    "skips blank lines",
			content: "\n\n\nmysecret12345678\n\n",
			wantLen: 1,
		},
		{
			name:    "trims whitespace",
			content: "  mysecret12345678  \n",
			wantLen: 1,
		},
		{
			name:    "empty file",
			content: "",
			wantLen: 0,
		},
		{
			name:    "only comments and blanks",
			content: "# comment\n\n# another\n",
			wantLen: 0,
		},
		{
			name:    "exactly 8 chars included",
			content: "12345678\n",
			wantLen: 1,
		},
		{
			name:    "7 chars excluded",
			content: "1234567\n",
			wantLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			path := filepath.Join(dir, "secrets.txt")
			if err := os.WriteFile(path, []byte(tt.content), 0o600); err != nil {
				t.Fatalf("write test file: %v", err)
			}

			secrets, err := loadFileSecrets(path)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(secrets) != tt.wantLen {
				t.Errorf("got %d secrets, want %d", len(secrets), tt.wantLen)
			}
			for i, want := range tt.wantVals {
				if i < len(secrets) && secrets[i] != want {
					t.Errorf("secrets[%d] = %q, want %q", i, secrets[i], want)
				}
			}
		})
	}
}

func TestLoadFileSecrets_NonExistentFile(t *testing.T) {
	t.Parallel()

	_, err := loadFileSecrets(filepath.Join(t.TempDir(), "nonexistent.txt"))
	if err == nil {
		t.Fatal("expected error for nonexistent file, got nil")
	}
}
