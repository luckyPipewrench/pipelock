// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestDiscoverEvidenceRuns(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		setup   func(t *testing.T, root string)
		wantIDs []string
		wantErr string
	}{
		{
			name: "legacy flat directory",
			setup: func(t *testing.T, root string) {
				t.Helper()
				writeDiscoveryShard(t, root)
			},
			wantIDs: []string{""},
		},
		{
			name: "nested runs remain separate",
			setup: func(t *testing.T, root string) {
				t.Helper()
				writeDiscoveryShard(t, filepath.Join(root, "recorder-a", "run-a"))
				writeDiscoveryShard(t, filepath.Join(root, "recorder-b", "run-b"))
			},
			wantIDs: []string{"recorder-a/run-a", "recorder-b/run-b"},
		},
		{
			name: "unexpected deeply nested run is found",
			setup: func(t *testing.T, root string) {
				t.Helper()
				writeDiscoveryShard(t, filepath.Join(root, "unexpected", "deep", "run"))
			},
			wantIDs: []string{"unexpected/deep/run"},
		},
		{
			name: "symlink is refused",
			setup: func(t *testing.T, root string) {
				t.Helper()
				target := t.TempDir()
				writeDiscoveryShard(t, target)
				if err := os.Symlink(target, filepath.Join(root, "other-run")); err != nil {
					t.Skipf("symlink unavailable: %v", err)
				}
			},
			wantErr: "refuse symlink",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			tt.setup(t, root)
			runs, err := DiscoverEvidenceRuns(root)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("DiscoverEvidenceRuns() error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("DiscoverEvidenceRuns(): %v", err)
			}
			gotIDs := make([]string, 0, len(runs))
			for _, run := range runs {
				gotIDs = append(gotIDs, run.ID)
			}
			if !reflect.DeepEqual(gotIDs, tt.wantIDs) {
				t.Fatalf("run IDs = %q, want %q", gotIDs, tt.wantIDs)
			}
		})
	}
}

func TestResolveEvidenceRun(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeDiscoveryShard(t, root)
	writeDiscoveryShard(t, filepath.Join(root, "recorder-a", "run-a"))

	if _, err := ResolveEvidenceRun(root, ""); err == nil || !strings.Contains(err.Error(), "multiple evidence runs") {
		t.Fatalf("ResolveEvidenceRun without selector error = %v, want ambiguity", err)
	}
	run, err := ResolveEvidenceRun(root, "recorder-a/run-a")
	if err != nil {
		t.Fatalf("ResolveEvidenceRun selected run: %v", err)
	}
	if run.ID != "recorder-a/run-a" {
		t.Fatalf("selected run ID = %q", run.ID)
	}
	if _, err := ResolveEvidenceRun(root, "../escape"); err == nil {
		t.Fatal("ResolveEvidenceRun accepted an escaping selector")
	}
}

// discoveryShardName is the evidence filename every discovery test writes. The
// tests care about which directory holds a shard, never what it is called.
const discoveryShardName = "evidence-proxy-0.jsonl"

func writeDiscoveryShard(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("MkdirAll(%q): %v", dir, err)
	}
	if err := os.WriteFile(filepath.Join(dir, discoveryShardName), []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(%q): %v", discoveryShardName, err)
	}
}
