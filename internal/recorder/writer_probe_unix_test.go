// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build unix && !aix

package recorder

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEvidenceWriterGone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evidence.jsonl")
	writer, err := os.OpenFile(filepath.Clean(path), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = writer.Close() })
	if err := lockEvidenceFileForWrite(writer); err != nil {
		t.Fatal(err)
	}
	busy, err := EvidenceWriterGone(path)
	if err != nil || busy {
		t.Fatalf("live writer: gone=%v, err=%v; want false, nil", busy, err)
	}
	if err := unlockEvidenceFile(writer); err != nil {
		t.Fatal(err)
	}
	gone, err := EvidenceWriterGone(path)
	if err != nil || !gone {
		t.Fatalf("released writer: gone=%v, err=%v; want true, nil", gone, err)
	}
	if _, err := EvidenceWriterGone(filepath.Join(t.TempDir(), "missing")); err == nil || !strings.Contains(err.Error(), "opening evidence file for writer probe") {
		t.Fatalf("missing file: err=%v; want probe-open error", err)
	}
}

// TestEvidenceRunWriterGoneAcrossRotation covers the run-lifetime lock that
// closes the rotation gap: a shard lock is released while the next shard is
// opened, so only this lock can answer whether a run has really exited.
func TestEvidenceRunWriterGoneAcrossRotation(t *testing.T) {
	dir := t.TempDir()
	const session = "proxy.run.abc"

	// A run with no lock file at all must fail closed, because an absent lock
	// cannot prove the writer exited.
	gone, err := EvidenceRunWriterGone(dir, session)
	if err == nil || gone {
		t.Fatalf("absent lock: gone=%v, err=%v; want false and an error", gone, err)
	}

	held, err := acquireRunPresence(dir, session)
	if err != nil {
		t.Fatalf("acquireRunPresence: %v", err)
	}
	info, statErr := os.Stat(filepath.Join(dir, "writer-"+session+".lock"))
	if statErr != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("lock file mode: %v %v", info, statErr)
	}
	if gone, err := EvidenceRunWriterGone(dir, session); err != nil || gone {
		t.Fatalf("live run: gone=%v, err=%v; want false, nil", gone, err)
	}

	if err := unlockEvidenceFile(held); err != nil {
		t.Fatal(err)
	}
	if err := held.Close(); err != nil {
		t.Fatal(err)
	}
	if gone, err := EvidenceRunWriterGone(dir, session); err != nil || !gone {
		t.Fatalf("exited run: gone=%v, err=%v; want true, nil", gone, err)
	}
}
