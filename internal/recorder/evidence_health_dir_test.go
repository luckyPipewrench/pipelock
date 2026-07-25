// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeHealthShard(t *testing.T, dir, name string, age time.Duration) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	if age > 0 {
		old := time.Now().Add(-age)
		if err := os.Chtimes(path, old, old); err != nil {
			t.Fatalf("chtimes %s: %v", name, err)
		}
	}
}

// TestEvidenceDirectoryHealthForDirThresholds covers the counts an operator and
// the doctor both act on. The near/over flags decide whether a deployment is
// warned before receipts break or only after, so an off-by-one here is the
// difference between an early warning and a surprise outage.
func TestEvidenceDirectoryHealthForDirThresholds(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		files    int
		wantNear bool
		wantOver bool
	}{
		{name: "below warning", files: 3},
		{name: "at warning", files: EvidenceFileWarningThreshold, wantNear: true},
		{name: "over cap", files: MaxEvidenceReadDirectoryEntries + 1, wantNear: true, wantOver: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			for i := range tc.files {
				writeHealthShard(t, dir, fmt.Sprintf("evidence-proxy-%d.jsonl", i), 0)
			}
			health, err := EvidenceDirectoryHealthForDir(dir, 0)
			if err != nil {
				t.Fatalf("EvidenceDirectoryHealthForDir: %v", err)
			}
			if health.TotalEvidenceFiles != tc.files {
				t.Fatalf("TotalEvidenceFiles = %d, want %d", health.TotalEvidenceFiles, tc.files)
			}
			if health.MaxSessionFiles != tc.files || health.MaxSessionID != "proxy" {
				t.Fatalf("session counts = %d/%q, want %d/proxy", health.MaxSessionFiles, health.MaxSessionID, tc.files)
			}
			if health.NearSessionFileLimit != tc.wantNear || health.OverSessionFileLimit != tc.wantOver {
				t.Fatalf("near=%v over=%v, want near=%v over=%v",
					health.NearSessionFileLimit, health.OverSessionFileLimit, tc.wantNear, tc.wantOver)
			}
			if health.WarningThreshold != EvidenceFileWarningThreshold || health.MaxFilesPerSession != MaxEvidenceReadDirectoryEntries {
				t.Fatalf("thresholds not reported: %+v", health)
			}
		})
	}
}

// TestEvidenceDirectoryHealthForDirRetentionEligibility checks which files the
// expirer is actually allowed to remove. JSONL shards are the chain spine and
// must never be counted as eligible, or the health report would imply retention
// can bound growth when it cannot.
func TestEvidenceDirectoryHealthForDirRetentionEligibility(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeHealthShard(t, dir, "evidence-proxy-0.jsonl", 48*time.Hour) // old chain shard
	writeHealthShard(t, dir, "evidence-proxy-1.jsonl", 0)            // fresh chain shard
	writeHealthShard(t, dir, "evidence-proxy-0.raw.enc", 48*time.Hour)
	writeHealthShard(t, dir, "evidence-proxy-1.raw.enc", 0)

	t.Run("retention disabled reports nothing eligible", func(t *testing.T) {
		health, err := EvidenceDirectoryHealthForDir(dir, 0)
		if err != nil {
			t.Fatalf("health: %v", err)
		}
		if health.RetentionEnabled {
			t.Fatal("RetentionEnabled true with retentionDays=0")
		}
		if health.RetentionEligibleFiles != 0 {
			t.Fatalf("RetentionEligibleFiles = %d, want 0 when retention is off", health.RetentionEligibleFiles)
		}
	})

	t.Run("only aged sidecars are eligible", func(t *testing.T) {
		health, err := EvidenceDirectoryHealthForDir(dir, 1)
		if err != nil {
			t.Fatalf("health: %v", err)
		}
		if !health.RetentionEnabled || health.RetentionDays != 1 {
			t.Fatalf("retention not reported: %+v", health)
		}
		if health.RetentionEligibleFiles != 1 {
			t.Fatalf("RetentionEligibleFiles = %d, want 1 (the aged sidecar only; JSONL shards are never eligible)",
				health.RetentionEligibleFiles)
		}
	})
}

// TestEvidenceDirectoryHealthForDirUnreadable confirms the health probe reports
// failure rather than an empty-but-successful result. A zeroed health struct
// would render as "0 of 256 files" and read as healthy while the probe is blind.
func TestEvidenceDirectoryHealthForDirUnreadable(t *testing.T) {
	t.Parallel()

	if _, err := EvidenceDirectoryHealthForDir(filepath.Join(t.TempDir(), "missing"), 1); err == nil {
		t.Fatal("missing directory reported success")
	}
}

// TestRemoveExpiredEvidenceFileFailsClosed covers the guards on the delete
// path. Every one of them exists so a file is retained when the expirer cannot
// prove it is safe to remove. Retaining evidence is recoverable; deleting the
// wrong file is not.
func TestRemoveExpiredEvidenceFileFailsClosed(t *testing.T) {
	t.Parallel()

	cutoff := time.Now().Add(-24 * time.Hour)

	t.Run("missing file is not an error", func(t *testing.T) {
		t.Parallel()
		removed, err := removeExpiredEvidenceFile(filepath.Join(t.TempDir(), "gone.jsonl"), cutoff)
		if err != nil || removed {
			t.Fatalf("removed=%v err=%v, want false/nil for an already-absent file", removed, err)
		}
	})

	t.Run("file newer than cutoff is retained", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		writeHealthShard(t, dir, "evidence-proxy-0.raw.enc", 0) // fresh
		path := filepath.Join(dir, "evidence-proxy-0.raw.enc")
		removed, err := removeExpiredEvidenceFile(path, cutoff)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if removed {
			t.Fatal("a file newer than the cutoff was deleted")
		}
		if _, statErr := os.Stat(path); statErr != nil {
			t.Fatalf("file should still exist: %v", statErr)
		}
	})

	t.Run("symlink is refused", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		target := filepath.Join(dir, "real.raw.enc")
		writeHealthShard(t, dir, "real.raw.enc", 48*time.Hour)
		link := filepath.Join(dir, "evidence-proxy-0.raw.enc")
		if err := os.Symlink(target, link); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		removed, err := removeExpiredEvidenceFile(link, cutoff)
		if removed {
			t.Fatal("expiry followed a symlink; a planted link could redirect deletion")
		}
		if err == nil {
			t.Fatal("symlinked evidence path should be reported, not silently skipped")
		}
		if _, statErr := os.Lstat(target); statErr != nil {
			t.Fatalf("symlink target was deleted: %v", statErr)
		}
	})

	t.Run("aged regular file is removed", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		writeHealthShard(t, dir, "evidence-proxy-0.raw.enc", 48*time.Hour)
		path := filepath.Join(dir, "evidence-proxy-0.raw.enc")
		removed, err := removeExpiredEvidenceFile(path, cutoff)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !removed {
			t.Fatal("an aged sidecar past the cutoff should be removed")
		}
		if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
			t.Fatalf("file still present after removal: %v", statErr)
		}
	})
}

// TestExpireOldFilesContinuesPastUnremovableEntry guards availability of the
// retention pass. Returning on the first failure let one planted symlink or one
// unreadable sidecar stop pruning for every remaining file, leaving a directory
// that silently stopped retaining correctly and could only be fixed by hand.
func TestExpireOldFilesContinuesPastUnremovableEntry(t *testing.T) {
	t.Parallel()

	if os.Geteuid() == 0 {
		t.Skip("root can open a mode-0000 file, so the unremovable case cannot be staged")
	}
	dir := t.TempDir()
	// An aged but unreadable sidecar, sorted before a removable one, so a
	// fail-fast loop would never reach the second file.
	writeHealthShard(t, dir, "evidence-proxy-0.raw.enc", 48*time.Hour)
	blocked := filepath.Join(dir, "evidence-proxy-0.raw.enc")
	if err := os.Chmod(blocked, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(blocked, 0o600) })
	writeHealthShard(t, dir, "evidence-proxy-1.raw.enc", 48*time.Hour)

	r, err := New(Config{Enabled: true, Dir: dir, RetentionDays: 1}, nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = r.Close() }()

	removed, err := r.ExpireOldFiles()
	if err == nil {
		t.Fatal("the unremovable entry should still be reported")
	}
	if removed != 1 {
		t.Fatalf("removed = %d, want 1: the pass must expire what it can despite one failure", removed)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "evidence-proxy-1.raw.enc")); !os.IsNotExist(statErr) {
		t.Fatalf("the removable sidecar past the failure was not expired: %v", statErr)
	}
}
