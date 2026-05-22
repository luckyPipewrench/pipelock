// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

// writeSignedReceiptFile signs an ActionRecord and writes the receipt JSON
// under dir/receipt.json. Returns the path. (The public-key hex is recovered
// inside receipt.VerifyWithKey via the receipt's embedded signer_key field
// when --key is not passed, so the test helper doesn't need to return it.)
func writeSignedReceiptFile(t *testing.T, dir string, ar receipt.ActionRecord) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	r, err := receipt.Sign(ar, priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	data, err := receipt.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	path := filepath.Join(dir, "receipt.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write receipt: %v", err)
	}
	return path
}

// writePolicyFile writes a YAML pipelock config under dir/policy.yaml. The
// blocklist lets each test set fetch_proxy.monitoring.blocklist. Mode is
// always "balanced" today; if a future test needs strict/audit, add a
// separate helper.
func writePolicyFile(t *testing.T, dir string, blocklist []string) string {
	t.Helper()
	var sb strings.Builder
	sb.WriteString("mode: balanced\n")
	sb.WriteString("fetch_proxy:\n")
	sb.WriteString("  monitoring:\n")
	sb.WriteString("    entropy_threshold: 4.5\n")
	sb.WriteString("    subdomain_entropy_threshold: 4.0\n")
	sb.WriteString("    max_url_length: 8192\n")
	if len(blocklist) > 0 {
		sb.WriteString("    blocklist:\n")
		for _, d := range blocklist {
			sb.WriteString("      - " + d + "\n")
		}
	} else {
		sb.WriteString("    blocklist: []\n")
	}
	sb.WriteString("internal: []\n")
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte(sb.String()), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	return path
}

// runReplayCommand invokes the replay subcommand exactly like the binary
// does. Returns the report (from JSON output), stdout text, and the exit
// code embedded in the returned error. stderr is intentionally not returned
// because no test currently asserts on it; if a future test needs stderr,
// add a sibling helper instead of changing this signature.
func runReplayCommand(t *testing.T, args ...string) (replayReport, string, int) {
	t.Helper()
	root := newRootCmd()
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs(append([]string{"replay"}, args...))

	err := root.Execute()
	exitCode := 0
	if err != nil {
		exitCode = exitCodeFor(err)
	}

	var report replayReport
	if stdout.Len() > 0 {
		// JSON output is one object per replay invocation; ignore parse
		// errors when the test asked for human-readable output.
		_ = json.Unmarshal(stdout.Bytes(), &report)
	}
	return report, stdout.String(), exitCode
}

func TestReplay_StableVerdict(t *testing.T) {
	dir := t.TempDir()
	ar := receipt.ActionRecord{
		Version:       receipt.ActionRecordVersion,
		ActionID:      receipt.NewActionID(),
		ActionType:    receipt.ActionRead,
		Timestamp:     time.Now(),
		Target:        "https://allowed.example/",
		Verdict:       "allow",
		Transport:     "https",
		ChainPrevHash: receipt.GenesisHash,
		ChainSeq:      0,
		PolicyHash:    "policy-fixture",
	}
	receiptPath := writeSignedReceiptFile(t, dir, ar)
	policyPath := writePolicyFile(t, dir, nil)

	report, _, exitCode := runReplayCommand(t,
		"--policy", policyPath,
		"--json",
		receiptPath,
	)

	if !report.ReceiptValid {
		t.Errorf("receipt should be valid, got error %q", report.Error)
	}
	if report.OriginalVerdict != "allow" {
		t.Errorf("original verdict: got %q, want allow", report.OriginalVerdict)
	}
	if report.ReplayVerdict != "allow" {
		t.Errorf("replay verdict: got %q, want allow", report.ReplayVerdict)
	}
	if report.VerdictChanged {
		t.Errorf("verdicts should agree, got changed=true")
	}
	if exitCode != 0 {
		t.Errorf("exit code: got %d, want 0", exitCode)
	}
}

func TestReplay_VerdictChanged_PolicyTightened(t *testing.T) {
	dir := t.TempDir()
	ar := receipt.ActionRecord{
		Version:       receipt.ActionRecordVersion,
		ActionID:      receipt.NewActionID(),
		ActionType:    receipt.ActionRead,
		Timestamp:     time.Now(),
		Target:        "https://now-blocked.example/path",
		Verdict:       "allow", // originally allowed
		Transport:     "https",
		ChainPrevHash: receipt.GenesisHash,
		ChainSeq:      0,
		PolicyHash:    "policy-fixture",
	}
	receiptPath := writeSignedReceiptFile(t, dir, ar)
	// New policy blocks the domain that was previously allowed.
	policyPath := writePolicyFile(t, dir, []string{"now-blocked.example"})

	report, _, exitCode := runReplayCommand(t,
		"--policy", policyPath,
		"--json",
		receiptPath,
	)

	if !report.ReceiptValid {
		t.Fatalf("receipt should be valid, got %q", report.Error)
	}
	if report.OriginalVerdict != "allow" {
		t.Errorf("original verdict: got %q want allow", report.OriginalVerdict)
	}
	if report.ReplayVerdict != "block" {
		t.Errorf("replay verdict: got %q want block", report.ReplayVerdict)
	}
	if !report.VerdictChanged {
		t.Error("VerdictChanged should be true")
	}
	if exitCode != cliutil.ExitGeneral {
		t.Errorf("exit code: got %d want %d (ExitGeneral)", exitCode, cliutil.ExitGeneral)
	}
}

func TestReplay_VerdictChanged_PolicyLoosened(t *testing.T) {
	dir := t.TempDir()
	ar := receipt.ActionRecord{
		Version:       receipt.ActionRecordVersion,
		ActionID:      receipt.NewActionID(),
		ActionType:    receipt.ActionRead,
		Timestamp:     time.Now(),
		Target:        "https://once-blocked.example/path",
		Verdict:       "block", // originally blocked
		Transport:     "https",
		ChainPrevHash: receipt.GenesisHash,
		ChainSeq:      0,
		PolicyHash:    "policy-fixture",
	}
	receiptPath := writeSignedReceiptFile(t, dir, ar)
	// New policy has empty blocklist — would now allow.
	policyPath := writePolicyFile(t, dir, nil)

	report, _, exitCode := runReplayCommand(t,
		"--policy", policyPath,
		"--json",
		receiptPath,
	)

	if !report.ReceiptValid {
		t.Fatalf("receipt should be valid, got %q", report.Error)
	}
	if report.ReplayVerdict != "allow" {
		t.Errorf("replay verdict: got %q want allow", report.ReplayVerdict)
	}
	if !report.VerdictChanged {
		t.Error("VerdictChanged should be true (block -> allow)")
	}
	if exitCode != cliutil.ExitGeneral {
		t.Errorf("exit code: got %d want %d", exitCode, cliutil.ExitGeneral)
	}
}

func TestReplay_MalformedReceipt(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "receipt.json")
	if err := os.WriteFile(bad, []byte(`{not valid json`), 0o600); err != nil {
		t.Fatalf("write bad receipt: %v", err)
	}
	policyPath := writePolicyFile(t, dir, nil)

	report, _, exitCode := runReplayCommand(t,
		"--policy", policyPath,
		"--json",
		bad,
	)

	if report.ReceiptValid {
		t.Error("malformed receipt should be invalid")
	}
	if report.Error == "" {
		t.Error("expected error message for malformed receipt")
	}
	if exitCode != cliutil.ExitConfig {
		t.Errorf("exit code: got %d want %d (ExitConfig)", exitCode, cliutil.ExitConfig)
	}
}

func TestReplay_MissingPolicy(t *testing.T) {
	dir := t.TempDir()
	ar := receipt.ActionRecord{
		Version:       receipt.ActionRecordVersion,
		ActionID:      receipt.NewActionID(),
		ActionType:    receipt.ActionRead,
		Timestamp:     time.Now(),
		Target:        "https://example.com/",
		Verdict:       "allow",
		Transport:     "https",
		ChainPrevHash: receipt.GenesisHash,
		ChainSeq:      0,
		PolicyHash:    "policy-fixture",
	}
	receiptPath := writeSignedReceiptFile(t, dir, ar)

	_, _, exitCode := runReplayCommand(t, "--json", receiptPath)

	if exitCode != exitUsage {
		t.Errorf("exit code: got %d want %d (exitUsage)", exitCode, exitUsage)
	}
}

func TestReplay_BadKeyMismatch(t *testing.T) {
	dir := t.TempDir()
	ar := receipt.ActionRecord{
		Version:       receipt.ActionRecordVersion,
		ActionID:      receipt.NewActionID(),
		ActionType:    receipt.ActionRead,
		Timestamp:     time.Now(),
		Target:        "https://example.com/",
		Verdict:       "allow",
		Transport:     "https",
		ChainPrevHash: receipt.GenesisHash,
		ChainSeq:      0,
		PolicyHash:    "policy-fixture",
	}
	receiptPath := writeSignedReceiptFile(t, dir, ar)
	policyPath := writePolicyFile(t, dir, nil)

	// Pass a different key — the verifier should reject.
	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherKeyHex := hex.EncodeToString(otherPub)

	report, _, exitCode := runReplayCommand(t,
		"--policy", policyPath,
		"--key", otherKeyHex,
		"--json",
		receiptPath,
	)

	if report.ReceiptValid {
		t.Error("receipt signed by another key should not validate against the supplied --key")
	}
	if exitCode != cliutil.ExitConfig {
		t.Errorf("exit code: got %d want %d", exitCode, cliutil.ExitConfig)
	}
}

func TestReplay_HumanReadableOutput(t *testing.T) {
	dir := t.TempDir()
	ar := receipt.ActionRecord{
		Version:       receipt.ActionRecordVersion,
		ActionID:      receipt.NewActionID(),
		ActionType:    receipt.ActionRead,
		Timestamp:     time.Now(),
		Target:        "https://allowed.example/",
		Verdict:       "allow",
		Transport:     "https",
		ChainPrevHash: receipt.GenesisHash,
		ChainSeq:      0,
		PolicyHash:    "policy-fixture",
	}
	receiptPath := writeSignedReceiptFile(t, dir, ar)
	policyPath := writePolicyFile(t, dir, nil)

	_, stdout, exitCode := runReplayCommand(t,
		"--policy", policyPath,
		receiptPath,
	)

	if exitCode != 0 {
		t.Errorf("exit code: got %d want 0", exitCode)
	}
	mustContain := []string{"receipt:", "policy:", "receipt_valid: true", "original:", "replay:", "verdict:"}
	for _, want := range mustContain {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout missing %q\n%s", want, stdout)
		}
	}
}

func TestVerdictsAgree(t *testing.T) {
	tests := []struct {
		name     string
		original string
		replay   string
		want     bool
	}{
		{"exact match allow", "allow", "allow", true},
		{"exact match block", "block", "block", true},
		{"warn maps to allow", "warn", "allow", true},
		{"strip maps to allow", "strip", "allow", true},
		{"redirect maps to allow", "redirect", "allow", true},
		{"ask maps to allow", "ask", "allow", true},
		{"forward maps to allow", "forward", "allow", true},
		{"block vs allow disagree", "block", "allow", false},
		{"allow vs block disagree", "allow", "block", false},
		{"warn vs block disagree", "warn", "block", false},
		{"case-insensitive", "BLOCK", "block", true},
		{"trim whitespace", "  allow  ", "allow", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := verdictsAgree(tt.original, tt.replay)
			if got != tt.want {
				t.Errorf("verdictsAgree(%q,%q)=%v want %v", tt.original, tt.replay, got, tt.want)
			}
		})
	}
}

// Ensure errors.Is is wired up by exiting with the right code on context
// failures.
func TestReplay_ReadReceiptError(t *testing.T) {
	dir := t.TempDir()
	policyPath := writePolicyFile(t, dir, nil)
	_, _, exitCode := runReplayCommand(t,
		"--policy", policyPath,
		"--json",
		filepath.Join(dir, "does-not-exist.json"),
	)
	if exitCode != cliutil.ExitConfig {
		t.Errorf("exit code: got %d want %d", exitCode, cliutil.ExitConfig)
	}
}

// Sentinel to ensure errors package compiles unused for tests above.
var _ = errors.New
