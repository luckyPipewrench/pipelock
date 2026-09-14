// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package posturebinding

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestReleaseAssuranceUnreadableProofWarningDescribesKnownAndUnknownOwnership(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not report POSIX proof ownership")
	}

	knownPath := filepath.Join(t.TempDir(), "proof.json")
	if err := os.WriteFile(knownPath, []byte("proof"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	tests := []struct {
		name string
		path string
		want []string
	}{
		{
			name: "inspectable proof",
			path: knownPath,
			want: []string{"owner ", "group "},
		},
		{
			name: "uninspectable path",
			path: filepath.Join(t.TempDir(), "missing", "proof.json"),
			want: []string{"owner/group could not be inspected"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			warning := unreadableProofWarning(Result{
				Path:  tt.path,
				Cause: errors.New("permission denied"),
			})
			for _, want := range tt.want {
				if !strings.Contains(warning, want) {
					t.Fatalf("warning = %q, want %q", warning, want)
				}
			}
			if !strings.Contains(warning, "permission denied") {
				t.Fatalf("warning = %q, want underlying read failure", warning)
			}
		})
	}
}
