// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

func TestStartupIncompleteRefreshStability(t *testing.T) {
	prepared, r, _, previous := startupPreparedWindow(t, false)
	paths, err := filepath.Glob(filepath.Join(r.Dir(), "evidence-"+previous.Shards[0].SessionID+"-*.jsonl"))
	if err != nil || len(paths) == 0 {
		t.Fatalf("segments: %v %v", paths, err)
	}
	path := paths[len(paths)-1]
	if err = startupAppendFile(path, `{"v":`); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(path, 0o640); err != nil { // #nosec G302 -- deliberate metadata mutation in an isolated test directory.
		t.Fatal(err)
	}
	fired := false
	prepared.previous.ceremony.afterPublicationRefresh = func() {
		fired = true
		if err := startupAppendFile(path, "xyz"); err != nil {
			t.Fatal(err)
		}
	}
	err = prepared.Activate(testConfigHash)
	if !fired {
		t.Fatal("refresh seam not reached")
	}
	if !errors.Is(err, recorder.ErrEvidenceChanged) {
		t.Fatalf("unstable prefix admitted: %v", err)
	}
	for _, shard := range previous.Shards {
		if _, e := os.Stat(filepath.Join(r.Dir(), ChainLinkFileName(shard.SessionID))); !os.IsNotExist(e) {
			t.Fatalf("seal published for stale observation: %v", e)
		}
	}
	open, _ := prepared.Opening()
	n, _ := ReceiptGroupFileName(open.GroupID, "transition")
	if _, e := os.Stat(filepath.Join(r.Dir(), n)); !os.IsNotExist(e) {
		t.Fatalf("transition published for stale observation: %v", e)
	}
}

func TestStartupPublicationDirectoryPinPopulated(t *testing.T) {
	prepared, r, _, previous := startupPreparedWindow(t, true)
	c := prepared.previous.ceremony
	run := c.proofs[previous.Shards[0].SessionID].session.claim.run
	path := filepath.Join(r.Dir(), "ael", run, "recorders")
	// The pin comes from Prepare's real loader/publication path. Replacing its
	// directory with a symlink must refuse even when it exposes identical bytes.
	moved := filepath.Join(t.TempDir(), "recorders")
	if err := os.Rename(path, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(moved, path); err != nil {
		t.Fatal(err)
	}
	if err := c.checkIdentity(); !errors.Is(err, recorder.ErrEvidenceChanged) {
		t.Fatalf("real publication directory pin absent or ineffective: %v", err)
	}
}
