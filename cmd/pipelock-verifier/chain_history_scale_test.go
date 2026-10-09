// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
)

func TestStandaloneChainFilePastArtifactBudget(t *testing.T) {
	// This signed conformance chain was produced by pipelock run. Permitted
	// blank lines expand its representation without changing signed records.
	const name = "evidence-proxy.run.03b13ee13e01e7f770480f62ea42f1fe-0.jsonl"
	raw, err := os.ReadFile(filepath.Join(runChainFixtures, "valid", name))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, append(raw, bytes.Repeat([]byte("\n"), int(maxVerifierInputBytes))...), 0o600); err != nil {
		t.Fatal(err)
	}
	key := readRunChainFixture(t, "signer-key.hex")
	stdout, stderr, code := runRoot(t, "chain", path, "--key", key, "--json")
	if code != cliutil.ExitOK || !strings.Contains(stdout, `"valid": true`) {
		t.Fatalf("valid large producer evidence: exit=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	// A byte-heavy forged chain must still fail its recorder/signature checks.
	bad := bytes.Replace(raw, []byte(`"summary":"`), []byte(`"summary":"changed `), 1)
	if bytes.Equal(raw, bad) {
		t.Fatal("positive control has no summary to change")
	}
	if err := os.WriteFile(path, append(bad, bytes.Repeat([]byte("\n"), int(maxVerifierInputBytes))...), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, code = runRoot(t, "chain", path, "--key", key, "--json")
	if code != cliutil.ExitGeneral || strings.Contains(stdout, `"valid": true`) {
		t.Fatalf("invalid large producer evidence: exit=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
}
