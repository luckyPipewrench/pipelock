// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

// A session whose evidence cannot be read reaches no verdict. It is reported
// as unavailable, never as a broken chain.
func TestSessionVerificationReportsUnreadableEvidenceAsUnavailable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission denial does not apply to root")
	}
	dir := parityFixture(t)
	const session = "proxy.run.03b13ee13e01e7f770480f62ea42f1fe"
	shards, err := filepath.Glob(filepath.Join(dir, "evidence-"+session+"-*.jsonl"))
	if err != nil || len(shards) == 0 {
		t.Fatalf("fixture shards: %v %v", shards, err)
	}
	shard := shards[0]
	if err := os.Chmod(shard, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(shard, 0o600) })
	if _, err := os.ReadFile(filepath.Clean(shard)); err == nil {
		t.Skip("process can read mode-0 files")
	}
	location := recorder.EvidenceLocation{Root: dir, Dir: dir}
	var out bytes.Buffer
	err = verifyChainFromResolvedSessionDirDetailed(&out, location, session, []string{parityKey(t)}, verifyReceiptOptions{})
	if err == nil {
		t.Fatal("unreadable evidence verified")
	}
	if !strings.Contains(out.String(), "CHAIN UNAVAILABLE") || strings.Contains(out.String(), "CHAIN BROKEN") {
		t.Fatalf("output = %q, want CHAIN UNAVAILABLE", out.String())
	}
}

// The same verdict without depending on file permissions: evidence that
// changes while it is read reaches no verdict either.
func TestSessionVerificationReportsChangedEvidenceAsUnavailable(t *testing.T) {
	dir := parityFixture(t)
	const session = "proxy.run.03b13ee13e01e7f770480f62ea42f1fe"
	shards, err := filepath.Glob(filepath.Join(dir, "evidence-"+session+"-*.jsonl"))
	if err != nil || len(shards) == 0 {
		t.Fatalf("fixture shards: %v %v", shards, err)
	}
	restore := afterSessionEvidenceRead
	afterSessionEvidenceRead = func() {
		f, err := os.OpenFile(filepath.Clean(shards[0]), os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = f.Close() }()
		if _, err := f.WriteString("\n"); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { afterSessionEvidenceRead = restore })
	location := recorder.EvidenceLocation{Root: dir, Dir: dir}
	var out bytes.Buffer
	err = verifyChainFromResolvedSessionDirDetailed(&out, location, session, []string{parityKey(t)}, verifyReceiptOptions{})
	if err == nil {
		t.Fatal("evidence that changed during the read verified")
	}
	if !strings.Contains(out.String(), "CHAIN UNAVAILABLE") || strings.Contains(out.String(), "CHAIN BROKEN") {
		t.Fatalf("output = %q, want CHAIN UNAVAILABLE", out.String())
	}
}

// A symlink where a shard belongs is tampering, refused by the no-follow
// open: it stays a broken chain, never "no verdict".
func TestSessionVerificationReportsSymlinkedShardAsBroken(t *testing.T) {
	dir := parityFixture(t)
	const session = "proxy.run.03b13ee13e01e7f770480f62ea42f1fe"
	shards, err := filepath.Glob(filepath.Join(dir, "evidence-"+session+"-*.jsonl"))
	if err != nil || len(shards) == 0 {
		t.Fatalf("fixture shards: %v %v", shards, err)
	}
	moved := filepath.Join(t.TempDir(), "elsewhere.jsonl")
	if err := os.Rename(shards[0], moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(moved, shards[0]); err != nil {
		t.Fatal(err)
	}
	location := recorder.EvidenceLocation{Root: dir, Dir: dir}
	var out bytes.Buffer
	if err := verifyChainFromResolvedSessionDirDetailed(&out, location, session, []string{parityKey(t)}, verifyReceiptOptions{}); err == nil {
		t.Fatal("a symlinked shard verified")
	}
	if !strings.Contains(out.String(), "CHAIN BROKEN") || strings.Contains(out.String(), "CHAIN UNAVAILABLE") {
		t.Fatalf("output = %q, want CHAIN BROKEN", out.String())
	}
}
