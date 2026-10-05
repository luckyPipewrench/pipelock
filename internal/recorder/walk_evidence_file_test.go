// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

const walkEvidenceFixture = "../../sdk/conformance/testdata/run-chains/valid/evidence-proxy.run.03b13ee13e01e7f770480f62ea42f1fe-0.jsonl"

func copyWalkFixture(t *testing.T) (string, []byte) {
	t.Helper()
	data, err := os.ReadFile(walkEvidenceFixture)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), filepath.Base(walkEvidenceFixture))
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, data
}

// TestWalkEvidenceFileRawBytesAndEntries pins that the secured walk delivers
// the same entries as WalkEntries and reports exactly the file's bytes.
func TestWalkEvidenceFileRawBytesAndEntries(t *testing.T) {
	t.Parallel()
	path, data := copyWalkFixture(t)
	var want []Entry
	if err := WalkEntries(path, func(e Entry) error { want = append(want, e); return nil }); err != nil {
		t.Fatal(err)
	}
	var raw bytes.Buffer
	var got []Entry
	info, err := WalkEvidenceFile(path, &raw, func(e Entry) error { got = append(got, e); return nil })
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw.Bytes(), data) {
		t.Fatalf("raw bytes differ from the file: %d vs %d bytes", raw.Len(), len(data))
	}
	if info.Size() != int64(len(data)) {
		t.Fatalf("info size %d, want %d", info.Size(), len(data))
	}
	if len(got) != len(want) || len(got) == 0 {
		t.Fatalf("entries %d, WalkEntries %d", len(got), len(want))
	}
	for i := range got {
		if got[i].Hash != want[i].Hash {
			t.Fatalf("entry %d hash %s, want %s", i, got[i].Hash, want[i].Hash)
		}
	}
	// A nil raw writer is allowed.
	if _, err := WalkEvidenceFile(path, nil, func(Entry) error { return nil }); err != nil {
		t.Fatal(err)
	}
}

func TestWalkEvidenceFileRefusesSymlinkAndNonRegular(t *testing.T) {
	t.Parallel()
	path, _ := copyWalkFixture(t)
	link := filepath.Join(t.TempDir(), filepath.Base(path))
	if err := os.Symlink(path, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	// Positive control: the target itself reads.
	if _, err := WalkEvidenceFile(path, nil, func(Entry) error { return nil }); err != nil {
		t.Fatal(err)
	}
	called := false
	if _, err := WalkEvidenceFile(link, nil, func(Entry) error { called = true; return nil }); !errors.Is(err, ErrEvidenceRefused) {
		t.Fatalf("symlink: err = %v, want ErrEvidenceRefused", err)
	}
	if called {
		t.Fatal("symlink: entries were delivered before the refusal")
	}
	if _, err := WalkEvidenceFile(t.TempDir(), nil, func(Entry) error { return nil }); !errors.Is(err, ErrEvidenceRefused) {
		t.Fatalf("directory: err = %v, want ErrEvidenceRefused", err)
	}
}

func TestWalkEvidenceFilePropagatesConsumerAndParseErrors(t *testing.T) {
	t.Parallel()
	path, data := copyWalkFixture(t)
	stop := errors.New("stop")
	if _, err := WalkEvidenceFile(path, nil, func(Entry) error { return stop }); !errors.Is(err, stop) {
		t.Fatalf("consumer error: %v", err)
	}
	bad := append(append([]byte(nil), data...), []byte("{not json}\n")...)
	if err := os.WriteFile(path, bad, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := WalkEvidenceFile(path, nil, func(Entry) error { return nil }); err == nil {
		t.Fatal("malformed trailing line accepted")
	}
	if _, err := WalkEvidenceFile(filepath.Join(t.TempDir(), "missing.jsonl"), nil, func(Entry) error { return nil }); err == nil {
		t.Fatal("missing file accepted")
	}
}
