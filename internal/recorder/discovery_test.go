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

func TestDiscoverEvidenceLocations(t *testing.T) {
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
			name: "nested locations remain separate",
			setup: func(t *testing.T, root string) {
				t.Helper()
				writeDiscoveryShard(t, filepath.Join(root, "recorder-a", "run-a"))
				writeDiscoveryShard(t, filepath.Join(root, "recorder-b", "run-b"))
			},
			wantIDs: []string{"recorder-a/run-a", "recorder-b/run-b"},
		},
		{
			name: "unexpected deeply nested location is found",
			setup: func(t *testing.T, root string) {
				t.Helper()
				writeDiscoveryShard(t, filepath.Join(root, "unexpected", "deep", "run"))
			},
			wantIDs: []string{"unexpected/deep/run"},
		},
		{
			name: "nested location below evidence location is found",
			setup: func(t *testing.T, root string) {
				t.Helper()
				writeDiscoveryShard(t, root)
				writeDiscoveryShard(t, filepath.Join(root, "nested"))
			},
			wantIDs: []string{"", "nested"},
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
			locations, err := DiscoverEvidenceLocations(root)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("DiscoverEvidenceLocations() error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("DiscoverEvidenceLocations(): %v", err)
			}
			gotIDs := make([]string, 0, len(locations))
			for _, location := range locations {
				gotIDs = append(gotIDs, location.ID)
			}
			if !reflect.DeepEqual(gotIDs, tt.wantIDs) {
				t.Fatalf("location IDs = %q, want %q", gotIDs, tt.wantIDs)
			}
		})
	}
}

func TestResolveEvidenceLocation(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeDiscoveryShard(t, root)
	writeDiscoveryShard(t, filepath.Join(root, "recorder-a", "run-a"))

	if _, err := ResolveEvidenceLocation(root, ""); err == nil || !strings.Contains(err.Error(), "multiple evidence locations") {
		t.Fatalf("ResolveEvidenceLocation without selector error = %v, want ambiguity", err)
	}
	location, err := ResolveEvidenceLocation(root, "recorder-a/run-a")
	if err != nil {
		t.Fatalf("ResolveEvidenceLocation selected location: %v", err)
	}
	if location.ID != "recorder-a/run-a" {
		t.Fatalf("selected location ID = %q", location.ID)
	}
	if _, err := ResolveEvidenceLocation(root, "../escape"); err == nil {
		t.Fatal("ResolveEvidenceLocation accepted an escaping selector")
	}
	if _, err := ResolveEvidenceLocation(root, "missing/run"); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("ResolveEvidenceLocation missing selector error = %v", err)
	}
	if _, err := ResolveEvidenceLocation(root, filepath.Join(string(filepath.Separator), "absolute")); err == nil {
		t.Fatal("ResolveEvidenceLocation accepted an absolute selector")
	}
	rootLocation, err := ResolveEvidenceLocation(root, ".")
	if err != nil {
		t.Fatalf("ResolveEvidenceLocation root selector: %v", err)
	}
	if rootLocation.ID != "" || rootLocation.Dir != root {
		t.Fatalf("root location = %+v, want dir %q with empty ID", rootLocation, root)
	}
}

func TestResolveEvidenceLocationNormalizesRelativeRoot(t *testing.T) {
	t.Parallel()
	absRoot := t.TempDir()
	writeDiscoveryShard(t, absRoot)
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	relRoot, err := filepath.Rel(cwd, absRoot)
	if err != nil {
		t.Fatalf("filepath.Rel: %v", err)
	}
	location, err := ResolveEvidenceLocation(relRoot, "")
	if err != nil {
		t.Fatalf("ResolveEvidenceLocation relative root: %v", err)
	}
	if location.Root != absRoot || location.Dir != absRoot {
		t.Fatalf("relative location = %+v, want absolute root %q", location, absRoot)
	}
}

func TestDiscoverEvidenceLocationsRejectsRootSymlink(t *testing.T) {
	t.Parallel()
	target := t.TempDir()
	writeDiscoveryShard(t, target)
	root := filepath.Join(t.TempDir(), "evidence-link")
	if err := os.Symlink(target, root); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := DiscoverEvidenceLocations(root); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("DiscoverEvidenceLocations root symlink error = %v", err)
	}
}

func TestDiscoverEvidenceLocationsRejectsSymlinkedRootAncestor(t *testing.T) {
	t.Parallel()
	target := t.TempDir()
	writeDiscoveryShard(t, filepath.Join(target, "run"))
	link := filepath.Join(t.TempDir(), "evidence-link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	root := filepath.Join(link, "run")
	if _, err := DiscoverEvidenceLocations(root); err == nil || !strings.Contains(err.Error(), "symlink") || !strings.Contains(err.Error(), link) {
		t.Fatalf("DiscoverEvidenceLocations symlinked ancestor error = %v, want rejection at %q", err, link)
	}
}

func TestDiscoverEvidenceLocationsRejectsRootSwapAfterOpen(t *testing.T) {
	t.Parallel()
	parent := t.TempDir()
	root := filepath.Join(parent, "evidence")
	replacement := filepath.Join(parent, "replacement")
	moved := filepath.Join(parent, "moved")
	writeDiscoveryShard(t, root)
	writeDiscoveryShard(t, replacement)

	locations, err := discoverEvidenceLocations(root, func() {
		if renameErr := os.Rename(root, moved); renameErr != nil {
			t.Fatalf("move opened evidence root: %v", renameErr)
		}
		if renameErr := os.Rename(replacement, root); renameErr != nil {
			t.Fatalf("swap evidence root: %v", renameErr)
		}
	})
	if err == nil || !strings.Contains(err.Error(), "changed while opening") {
		t.Fatalf("discover after root swap = %+v, %v; want fail-closed identity error", locations, err)
	}
}

func TestDiscoverEvidenceLocationsRejectsMissingAndNonDirectoryRoots(t *testing.T) {
	t.Parallel()
	if _, err := DiscoverEvidenceLocations(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("DiscoverEvidenceLocations accepted a missing root")
	}
	path := filepath.Join(t.TempDir(), "evidence-file")
	if err := os.WriteFile(path, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := DiscoverEvidenceLocations(path); err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("DiscoverEvidenceLocations non-directory error = %v", err)
	}
}

func TestEvidenceRawSidecarRecognition(t *testing.T) {
	t.Parallel()
	if !isEvidenceRawSidecar("evidence-proxy-0.raw.enc") {
		t.Fatal("valid raw sidecar was not recognized")
	}
	for _, name := range []string{"evidence-proxy-0.jsonl", "unrelated.raw.enc", "evidence-proxy.raw.enc"} {
		if isEvidenceRawSidecar(name) {
			t.Fatalf("isEvidenceRawSidecar(%q) = true, want false", name)
		}
	}
}

func TestDiscoverEvidenceLocationsFindsRawSidecarOnly(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "evidence-proxy-0.raw.enc"), []byte("encrypted"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	locations, err := DiscoverEvidenceLocations(root)
	if err != nil {
		t.Fatalf("DiscoverEvidenceLocations: %v", err)
	}
	if len(locations) != 1 || locations[0].ID != "" {
		t.Fatalf("locations = %+v, want one root location", locations)
	}
}

func TestResolveEvidenceLocationEmptyDirectory(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	location, err := ResolveEvidenceLocation(root, "")
	if err != nil {
		t.Fatalf("ResolveEvidenceLocation empty directory: %v", err)
	}
	if location.Root != root || location.Dir != root || location.ID != "" {
		t.Fatalf("empty directory location = %+v, want root %q", location, root)
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
