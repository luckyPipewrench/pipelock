// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package recorder

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestDriveRelativeEvidenceRootUsesDriveWorkingDirectory(t *testing.T) {
	base := physicalTempDir(t)
	volume := filepath.VolumeName(base)
	if len(volume) != 2 || volume[1] != ':' {
		t.Skipf("test requires a drive-letter temp directory: %q", base)
	}
	realEv := filepath.Join(base, "real", "ev")
	if err := os.MkdirAll(realEv, 0o750); err != nil {
		t.Fatal(err)
	}
	t.Chdir(base)
	plain := volume + `real\ev`
	if err := refuseSymlinkInWalkedRootPath(plain); err != nil {
		t.Fatalf("drive-relative positive control %q: %v", plain, err)
	}
	if _, err := DiscoverEvidenceLocations(plain); err != nil {
		t.Fatalf("drive-relative discovery %q: %v", plain, err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(realEv, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := refuseSymlinkInWalkedRootPath(volume + `link\..\real\ev`); !errors.Is(err, ErrEvidenceRefused) {
		t.Fatalf("drive-relative symlink walk = %v, want refusal", err)
	}
}
