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
