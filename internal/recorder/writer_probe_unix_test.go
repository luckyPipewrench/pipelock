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
	writer, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
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
