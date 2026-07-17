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
// under dir/receipt.json. Returns the path.
func writeSignedReceiptFile(t *testing.T, dir string, ar receipt.ActionRecord) string {
	t.Helper()
	path, _ := writeSignedReceiptFileWithKey(t, dir, ar)
	return path
}

func writeSignedReceiptFileWithKey(t *testing.T, dir string, ar receipt.ActionRecord) (string, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
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
	return path, hex.EncodeToString(pub)
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
	receiptPath, signerKey := writeSignedReceiptFileWithKey(t, dir, ar)
	policyPath := writePolicyFile(t, dir, nil)

	report, _, exitCode := runReplayCommand(t,
		"--policy", policyPath,
		"--key", signerKey,
		"--json",
		receiptPath,
	)

	if !report.ReceiptValid {
		t.Errorf("receipt should be valid, got error %q", report.Error)
	}
	if !report.StructuralValid {
		t.Error("trusted replay should report structural_valid=true")
	}
	if !report.VerificationAccepted {
		t.Error("trusted replay should report verification_accepted=true")
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
	if !report.SignaturesVerified {
		t.Error("trusted replay should report signatures_verified=true")
	}
	if report.Unpinned {
		t.Error("trusted replay should not report unpinned=true")
	}
	if exitCode != 0 {
		t.Errorf("exit code: got %d, want 0", exitCode)
	}
}

func TestReplay_ForgedSelfConsistentReceiptFailsClosedWithoutPinnedKey(t *testing.T) {
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

	for _, tc := range []struct {
		name string
		args []string
	}{
		{
			name: "omitted_allow_unpinned",
			args: []string{"--policy", policyPath, "--json", receiptPath},
		},
		{
			name: "explicit_allow_unpinned_false",
			args: []string{"--policy", policyPath, "--allow-unpinned=false", "--json", receiptPath},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			report, _, exitCode := runReplayCommand(t, tc.args...)

			if report.ReceiptValid {
				t.Error("self-consistent receipt should not be accepted without --key or --allow-unpinned")
			}
			if !report.StructuralValid {
				t.Error("self-consistent receipt should report structural_valid=true")
			}
			if report.VerificationAccepted {
				t.Error("self-consistent receipt should not be accepted without --allow-unpinned")
			}
			if !report.Unpinned {
				t.Error("self-consistent no-key replay should report unpinned=true")
			}
			if report.SignaturesVerified {
				t.Error("self-consistent no-key replay should not report signatures_verified=true")
			}
			if len(report.Warnings) == 0 || !strings.Contains(report.Warnings[0], "UNPINNED") {
				t.Fatalf("self-consistent no-key replay should report JSON warning, got %#v", report.Warnings)
			}
			for _, want := range []string{"pass --key for provenance", "--allow-unpinned for structural-only verification"} {
				if !strings.Contains(report.Error, want) {
					t.Errorf("error missing %q: %q", want, report.Error)
				}
			}
			if exitCode != cliutil.ExitGeneral {
				t.Errorf("exit code: got %d, want %d", exitCode, cliutil.ExitGeneral)
			}
		})
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
		"--allow-unpinned",
		"--json",
		receiptPath,
	)

	if report.ReceiptValid {
		t.Fatalf("structural-only replay should not report receipt_valid=true: %#v", report)
	}
	if !report.StructuralValid || !report.VerificationAccepted {
		t.Fatalf("structural-only replay should be accepted but not trusted: %#v", report)
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
	if !report.Unpinned {
		t.Error("structural-only replay should report unpinned=true")
	}
	if report.SignaturesVerified {
		t.Error("structural-only replay should not report signatures_verified=true")
	}
	if len(report.Warnings) == 0 || !strings.Contains(report.Warnings[0], "UNPINNED") {
		t.Fatalf("structural-only replay should report JSON warning, got %#v", report.Warnings)
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
	// New policy has empty blocklist - would now allow.
	policyPath := writePolicyFile(t, dir, nil)

	report, _, exitCode := runReplayCommand(t,
		"--policy", policyPath,
		"--allow-unpinned",
		"--json",
		receiptPath,
	)

	if report.ReceiptValid {
		t.Fatalf("structural-only replay should not report receipt_valid=true: %#v", report)
	}
	if !report.StructuralValid || !report.VerificationAccepted {
		t.Fatalf("structural-only replay should be accepted but not trusted: %#v", report)
	}
	if report.ReplayVerdict != "allow" {
		t.Errorf("replay verdict: got %q want allow", report.ReplayVerdict)
	}
	if !report.VerdictChanged {
		t.Error("VerdictChanged should be true (block -> allow)")
	}
	if !report.Unpinned {
		t.Error("structural-only replay should report unpinned=true")
	}
	if len(report.Warnings) == 0 || !strings.Contains(report.Warnings[0], "UNPINNED") {
		t.Fatalf("structural-only replay should report JSON warning, got %#v", report.Warnings)
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

	// Pass a different key - the verifier should reject.
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
	if !report.StructuralValid {
		t.Error("receipt signed by another key should still report structural_valid=true when internally self-consistent")
	}
	if report.VerificationAccepted {
		t.Error("receipt signed by another key should not be accepted")
	}
	if exitCode != cliutil.ExitGeneral {
		t.Errorf("exit code: got %d want %d", exitCode, cliutil.ExitGeneral)
	}
}

func TestReplay_AllowUnpinnedDoesNotWeakenPinnedVerification(t *testing.T) {
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
	receiptPath, signerKey := writeSignedReceiptFileWithKey(t, dir, ar)
	policyPath := writePolicyFile(t, dir, nil)
	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherKeyHex := hex.EncodeToString(otherPub)

	report, _, exitCode := runReplayCommand(t,
		"--policy", policyPath,
		"--key", otherKeyHex,
		"--allow-unpinned",
		"--json",
		receiptPath,
	)
	if report.ReceiptValid {
		t.Fatal("--allow-unpinned must not accept a receipt signed by a different pinned key")
	}
	if !report.StructuralValid {
		t.Fatal("wrong pinned key should still report structural_valid=true for internally self-consistent receipt")
	}
	if report.VerificationAccepted {
		t.Fatal("wrong pinned key should not report verification_accepted=true")
	}
	if report.Unpinned {
		t.Fatal("--allow-unpinned with --key should stay on the pinned path, not report unpinned")
	}
	if report.SignaturesVerified {
		t.Fatal("mismatched pinned key should not report signatures_verified=true")
	}
	if exitCode != cliutil.ExitGeneral {
		t.Fatalf("exit code with wrong pinned key: got %d want %d", exitCode, cliutil.ExitGeneral)
	}

	report, _, exitCode = runReplayCommand(t,
		"--policy", policyPath,
		"--key", signerKey,
		"--allow-unpinned",
		"--json",
		receiptPath,
	)
	if !report.ReceiptValid || !report.StructuralValid || !report.VerificationAccepted || !report.SignaturesVerified || report.Unpinned {
		t.Fatalf("correct pinned key with --allow-unpinned should remain trusted: %#v", report)
	}
	if len(report.Warnings) != 0 {
		t.Fatalf("trusted replay should not report unpinned warnings: %#v", report.Warnings)
	}
	if exitCode != 0 {
		t.Fatalf("exit code with correct pinned key: got %d want 0", exitCode)
	}
}

func TestReplay_EmptyKeyFlagStillFailsClosed(t *testing.T) {
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

	for _, tc := range []struct {
		name string
		args []string
	}{
		{
			name: "empty_key",
			args: []string{"--policy", policyPath, "--key", "", "--json", receiptPath},
		},
		{
			name: "empty_key_with_allow_unpinned",
			args: []string{"--policy", policyPath, "--key", "", "--allow-unpinned", "--json", receiptPath},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			report, _, exitCode := runReplayCommand(t, tc.args...)
			if report.ReceiptValid || report.StructuralValid || report.VerificationAccepted {
				t.Fatalf(`%v report = %#v, want no trusted or structural acceptance`, tc.args, report)
			}
			if report.Unpinned || report.SignaturesVerified {
				t.Fatalf(`%v report = %#v, want config failure before unpinned/trusted states`, tc.args, report)
			}
			if !strings.Contains(report.Error, "--key was provided but empty") {
				t.Fatalf("%v error = %q, want empty --key config error", tc.args, report.Error)
			}
			if exitCode != cliutil.ExitConfig {
				t.Fatalf("%v exit code: got %d want %d", tc.args, exitCode, cliutil.ExitConfig)
			}
		})
	}
}

func TestReplay_EmptyKeyFileFailsClosedEvenWhenUnpinnedAllowed(t *testing.T) {
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
	emptyKeyPath := filepath.Join(dir, "empty.pub")
	if err := os.WriteFile(emptyKeyPath, nil, 0o600); err != nil {
		t.Fatalf("write empty key file: %v", err)
	}

	report, _, exitCode := runReplayCommand(t,
		"--policy", policyPath,
		"--key", emptyKeyPath,
		"--allow-unpinned",
		"--json",
		receiptPath,
	)

	if report.ReceiptValid || report.StructuralValid || report.VerificationAccepted {
		t.Fatalf("empty key file report = %#v, want no trusted or structural acceptance", report)
	}
	if report.Unpinned || report.SignaturesVerified {
		t.Fatalf("empty key file report = %#v, want config failure before unpinned/trusted states", report)
	}
	if !strings.Contains(report.Error, "resolve signer key:") || !strings.Contains(report.Error, "public key") {
		t.Fatalf("error = %q, want public-key resolution failure", report.Error)
	}
	if exitCode != cliutil.ExitConfig {
		t.Fatalf("exit code: got %d want %d", exitCode, cliutil.ExitConfig)
	}
}

func TestReplay_MalformedEmbeddedSignerFailsClosedEvenWhenUnpinnedAllowed(t *testing.T) {
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
	data, err := os.ReadFile(filepath.Clean(receiptPath))
	if err != nil {
		t.Fatalf("read receipt: %v", err)
	}
	r, err := receipt.Unmarshal(data)
	if err != nil {
		t.Fatalf("unmarshal receipt: %v", err)
	}
	r.SignerKey = ""
	data, err = receipt.Marshal(r)
	if err != nil {
		t.Fatalf("marshal receipt: %v", err)
	}
	if err := os.WriteFile(receiptPath, data, 0o600); err != nil {
		t.Fatalf("write malformed receipt: %v", err)
	}
	policyPath := writePolicyFile(t, dir, nil)

	for _, tc := range []struct {
		name string
		args []string
	}{
		{
			name: "no_key",
			args: []string{"--policy", policyPath, "--json", receiptPath},
		},
		{
			name: "allow_unpinned",
			args: []string{"--policy", policyPath, "--allow-unpinned", "--json", receiptPath},
		},
		{
			name: "pinned_key",
			args: []string{"--policy", policyPath, "--key", strings.Repeat("0", 64), "--json", receiptPath},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			report, _, exitCode := runReplayCommand(t, tc.args...)
			if report.ReceiptValid {
				t.Fatalf("%v accepted receipt with empty signer_key: %#v", tc.args, report)
			}
			if report.Unpinned || report.SignaturesVerified || report.StructuralValid || report.VerificationAccepted {
				t.Fatalf("%v report = %#v, want invalid before unpinned/trusted states", tc.args, report)
			}
			if tc.name == "pinned_key" && len(report.Details) == 0 {
				t.Fatalf("%v report = %#v, want structural verification detail", tc.args, report)
			}
			if !strings.Contains(report.Error, "receipt has no signer_key") {
				t.Fatalf("%v error = %q, want signer_key failure", tc.args, report.Error)
			}
			if exitCode != cliutil.ExitGeneral {
				t.Fatalf("%v exit code: got %d want %d", tc.args, exitCode, cliutil.ExitGeneral)
			}
		})
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
		"--allow-unpinned",
		receiptPath,
	)

	if exitCode != 0 {
		t.Errorf("exit code: got %d want 0", exitCode)
	}
	mustContain := []string{
		"receipt:",
		"policy:",
		"receipt_valid: false",
		"structural_valid: true",
		"verification_accepted: true",
		"signatures_verified: false",
		"unpinned:      true",
		"receipt_valid=false",
		"untrusted embedded signer_key",
		"provenance not verified",
		"original:",
		"replay:",
		"verdict:",
	}
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
