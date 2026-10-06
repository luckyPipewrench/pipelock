// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"path/filepath"
	"strings"
	"testing"

	anchorpkg "github.com/luckyPipewrench/pipelock/internal/anchor"
	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

// writeRunChainAnchor anchors the first run chain of the real per-run evidence
// fixture and returns the bundle and local log the verifier needs.
func writeRunChainAnchor(t *testing.T, evidenceDir, key string) (bundlePath, logPath string) {
	t.Helper()
	receipts, err := receipt.ExtractReceiptsFromSessionDir(evidenceDir, parityRun1)
	if err != nil || len(receipts) == 0 {
		t.Fatalf("read run chain %s: %d receipts, err %v", parityRun1, len(receipts), err)
	}
	checkpoint, err := anchorpkg.BuildCheckpoint(parityRun1, receipts, []string{key})
	if err != nil {
		t.Fatalf("BuildCheckpoint: %v", err)
	}
	dir := t.TempDir()
	logPath = filepath.Join(dir, "anchor.jsonl")
	proof, err := anchorpkg.LocalLog{Path: logPath, LogID: "verifier-test-log"}.Submit(checkpoint)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	bundlePath = filepath.Join(dir, "anchor-bundle.json")
	if err := anchorpkg.WriteBundle(bundlePath, anchorpkg.NewBundle(checkpoint, proof)); err != nil {
		t.Fatalf("WriteBundle: %v", err)
	}
	return bundlePath, logPath
}

// An anchor of one per-run chain verifies against its evidence directory
// without --session: the bundle names the chain, so the flag's default of
// "proxy" no longer has to match a directory that holds only proxy.run.<id>
// chains. An explicit --session still wins.
func TestIndependent_DirDefaultsToTheSessionTheBundleAnchored(t *testing.T) {
	t.Setenv("PIPELOCK_ANCHOR_TEST_NOW", "2026-06-28T14:00:00Z")
	key := readRunChainFixture(t, "signer-key.hex")
	evidence := filepath.Join(runChainFixtures, "valid")
	bundle, logPath := writeRunChainAnchor(t, evidence, key)
	base := []string{"independent", evidence, "--dir", "--bundle", bundle, "--key", key, "--local-log", logPath, "--log-id", "verifier-test-log"}

	stdout, stderr, code := runRoot(t, base...)
	if code != cliutil.ExitOK || !strings.Contains(stdout, "INDEPENDENT VERIFY OK") {
		t.Fatalf("default session: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}

	// The anchored run, named explicitly, verifies the same way.
	stdout, stderr, code = runRoot(t, append(append([]string{}, base...), "--session", parityRun1)...)
	if code != cliutil.ExitOK || !strings.Contains(stdout, "INDEPENDENT VERIFY OK") {
		t.Fatalf("explicit anchored session: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}

	// An explicit session is the operator's choice and is not overridden: the
	// bare base holds no chain of its own here, so it must not verify.
	stdout, stderr, code = runRoot(t, append(append([]string{}, base...), "--session", "proxy")...)
	if code == cliutil.ExitOK || strings.Contains(stdout, "INDEPENDENT VERIFY OK") {
		t.Fatalf("explicit --session proxy verified an anchor of a run chain: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}

	// Another run's chain does not satisfy this run's anchor.
	stdout, stderr, code = runRoot(t, append(append([]string{}, base...), "--session", parityRun2)...)
	if code == cliutil.ExitOK || strings.Contains(stdout, "INDEPENDENT VERIFY OK") {
		t.Fatalf("a different run's chain verified this run's anchor: code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestIndependentSession_Selection(t *testing.T) {
	t.Parallel()
	named := anchorpkg.Bundle{Checkpoint: anchorpkg.Checkpoint{SessionID: parityRun1}}
	for _, tc := range []struct {
		name   string
		opts   independentOptions
		bundle anchorpkg.Bundle
		want   string
	}{
		{"directory, flag unset: the bundle's session", independentOptions{asDir: true, sessionID: "proxy"}, named, parityRun1},
		{"directory, flag set: the flag", independentOptions{asDir: true, sessionID: "proxy", sessionExplicit: true}, named, "proxy"},
		{"single file: the flag", independentOptions{sessionID: "proxy"}, named, "proxy"},
		{"bundle of a single file: the flag", independentOptions{asDir: true, sessionID: "proxy"}, anchorpkg.Bundle{Checkpoint: anchorpkg.Checkpoint{SessionID: "file"}}, "proxy"},
		{"bundle without a session: the flag", independentOptions{asDir: true, sessionID: "proxy"}, anchorpkg.Bundle{}, "proxy"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := independentSession(tc.opts, tc.bundle); got != tc.want {
				t.Fatalf("independentSession = %q, want %q", got, tc.want)
			}
		})
	}
}
