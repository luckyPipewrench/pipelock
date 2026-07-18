// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package learn

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/contract"
	contractreceipt "github.com/luckyPipewrench/pipelock/internal/contract/receipt"
	contractstore "github.com/luckyPipewrench/pipelock/internal/contract/store"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

func TestRatifyRejectsMalformedAndIncompleteCandidates(t *testing.T) {
	t.Run("unknown envelope field", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "candidate.yaml")
		raw := []byte("body: {}\nsignature: ed25519:bad\nunexpected: true\n")
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatalf("write malformed candidate: %v", err)
		}

		err := runRatify(learnTestCommand(""), ratifyFlags{
			candidatePath: path,
			deterministic: true,
		})
		if err == nil || !strings.Contains(err.Error(), "decode candidate envelope") {
			t.Fatalf("runRatify err = %v, want strict decode failure", err)
		}
	})

	t.Run("empty rules", func(t *testing.T) {
		dir := t.TempDir()
		env := signedCandidateForFailureTest(t, testRatifyContract())
		env.Body.Rules = nil
		env.Body.FieldDataClasses = nil
		path := writeRawCandidateEnvelope(t, dir, env)

		err := runRatify(learnTestCommand(""), ratifyFlags{
			candidatePath: path,
			deterministic: true,
		})
		if !errors.Is(err, ErrInvalidCandidate) || !strings.Contains(err.Error(), "no rules") {
			t.Fatalf("runRatify err = %v, want empty-rules rejection", err)
		}
	})

	t.Run("invalid interactive decision", func(t *testing.T) {
		dir := t.TempDir()
		path := writeCandidateEnvelope(t, dir, testRatifyContract())
		out := filepath.Join(dir, "ratified.yaml")

		err := runRatify(learnTestCommand("approve\n"), ratifyFlags{
			candidatePath: path,
			outPath:       out,
			interactive:   true,
			deterministic: true,
		})
		if err == nil || !strings.Contains(err.Error(), "invalid decision") {
			t.Fatalf("runRatify err = %v, want invalid-decision rejection", err)
		}
		assertPathAbsent(t, out)
	})

	t.Run("all rules rejected", func(t *testing.T) {
		dir := t.TempDir()
		path := writeCandidateEnvelope(t, dir, testRatifyContract())
		out := filepath.Join(dir, "ratified.yaml")

		err := runRatify(learnTestCommand("r\nreject\n"), ratifyFlags{
			candidatePath: path,
			outPath:       out,
			interactive:   true,
			deterministic: true,
		})
		if err == nil || !strings.Contains(err.Error(), "all rules rejected") {
			t.Fatalf("runRatify err = %v, want empty-ratification rejection", err)
		}
		assertPathAbsent(t, out)
	})
}

func TestRatifyReceiptFailurePreservesCandidate(t *testing.T) {
	dir := t.TempDir()
	candidate := writeCandidateEnvelope(t, dir, testRatifyContract())
	before := mustReadTestFile(t, candidate)
	receiptPath := unwritableReceiptPath(t)

	err := runRatify(learnTestCommand("e\nc\n"), ratifyFlags{
		candidatePath: candidate,
		outPath:       candidate,
		receiptOut:    receiptPath,
		interactive:   true,
		deterministic: true,
	})
	if err == nil || !strings.Contains(err.Error(), "open lifecycle receipts") {
		t.Fatalf("runRatify err = %v, want receipt open failure", err)
	}
	assertFileBytes(t, candidate, before)
	assertNoStagingFiles(t, dir, filepath.Base(candidate))
}

func TestRatifyMissingSigningKeysDoesNotPublishCandidate(t *testing.T) {
	t.Run("compile key", func(t *testing.T) {
		dir := t.TempDir()
		candidate := writeCandidateEnvelope(t, dir, testRatifyContract())
		out := filepath.Join(dir, "ratified.yaml")

		err := runRatify(learnTestCommand(""), ratifyFlags{
			candidatePath:   candidate,
			outPath:         out,
			receiptOut:      filepath.Join(dir, "receipts.jsonl"),
			keystore:        filepath.Join(dir, "keys"),
			compileKeyAgent: "missing-compile",
			receiptKey:      "missing-receipt",
		})
		if err == nil || !strings.Contains(err.Error(), "missing-compile") {
			t.Fatalf("runRatify err = %v, want missing compile key", err)
		}
		assertPathAbsent(t, out)
		assertPathAbsent(t, filepath.Join(dir, "receipts.jsonl"))
	})

	t.Run("receipt key after compile key loads", func(t *testing.T) {
		dir := t.TempDir()
		candidate := writeCandidateEnvelope(t, dir, testRatifyContract())
		out := filepath.Join(dir, "ratified.yaml")
		keystoreDir := filepath.Join(dir, "keys")
		if _, err := signing.NewKeystore(keystoreDir).GenerateAgent("compile-signer"); err != nil {
			t.Fatalf("generate compile signer: %v", err)
		}

		err := runRatify(learnTestCommand(""), ratifyFlags{
			candidatePath: candidate,
			outPath:       out,
			receiptOut:    filepath.Join(dir, "receipts.jsonl"),
			keystore:      keystoreDir,
			receiptKey:    "missing-receipt",
		})
		if err == nil || !strings.Contains(err.Error(), "missing-receipt") {
			t.Fatalf("runRatify err = %v, want missing receipt key", err)
		}
		assertPathAbsent(t, out)
		assertPathAbsent(t, filepath.Join(dir, "receipts.jsonl"))
	})
}

func TestForgetRejectsInvalidRequestsWithoutMutation(t *testing.T) {
	tests := []struct {
		name    string
		ruleID  string
		reason  string
		prepare func(t *testing.T, env *contract.ContractEnvelope)
		want    string
	}{
		{name: "blank rule", ruleID: " \t", reason: "ticket", want: "--rule-id is required"},
		{name: "blank reason", ruleID: "r-enforce", reason: "\n", want: "--reason is required"},
		{name: "missing rule", ruleID: "r-missing", reason: "ticket", want: "r-missing"},
		{
			name:   "empty contract hash",
			ruleID: "r-enforce",
			reason: "ticket",
			prepare: func(_ *testing.T, env *contract.ContractEnvelope) {
				env.Body.ContractHash = ""
			},
			want: "contract_hash is empty",
		},
		{
			name:   "last rule",
			ruleID: "r-enforce",
			reason: "ticket",
			prepare: func(_ *testing.T, env *contract.ContractEnvelope) {
				env.Body.Rules = env.Body.Rules[:1]
				env.Body.FieldDataClasses = map[string]string{"/rules/0": "internal"}
			},
			want: "no rules",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			env := signedCandidateForFailureTest(t, testRatifyContract())
			if tt.prepare != nil {
				tt.prepare(t, &env)
			}
			candidate := writeRawCandidateEnvelope(t, dir, env)
			before := mustReadTestFile(t, candidate)
			out := filepath.Join(dir, "forgotten.yaml")

			err := runForget(learnTestCommand(""), forgetFlags{
				candidatePath: candidate,
				ruleID:        tt.ruleID,
				reason:        tt.reason,
				outPath:       out,
				deterministic: true,
			})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("runForget err = %v, want substring %q", err, tt.want)
			}
			assertFileBytes(t, candidate, before)
			assertPathAbsent(t, out)
		})
	}
}

func TestForgetMissingSigningKeysDoesNotPublishArtifacts(t *testing.T) {
	t.Run("compile key", func(t *testing.T) {
		dir := t.TempDir()
		candidate := writeCandidateEnvelope(t, dir, testRatifyContract())
		out := filepath.Join(dir, "forgotten.yaml")

		err := runForget(learnTestCommand(""), forgetFlags{
			candidatePath:   candidate,
			ruleID:          "r-enforce",
			reason:          "ticket-42",
			outPath:         out,
			keystore:        filepath.Join(dir, "keys"),
			compileKeyAgent: "missing-compile",
			activationKey:   "missing-activation",
		})
		if err == nil || !strings.Contains(err.Error(), "missing-compile") {
			t.Fatalf("runForget err = %v, want missing compile key", err)
		}
		assertPathAbsent(t, out)
		assertPathAbsent(t, filepath.Join(dir, "tombstones"))
	})

	t.Run("activation key after compile key loads", func(t *testing.T) {
		dir := t.TempDir()
		candidate := writeCandidateEnvelope(t, dir, testRatifyContract())
		out := filepath.Join(dir, "forgotten.yaml")
		keystoreDir := filepath.Join(dir, "keys")
		if _, err := signing.NewKeystore(keystoreDir).GenerateAgent("compile-signer"); err != nil {
			t.Fatalf("generate compile signer: %v", err)
		}

		err := runForget(learnTestCommand(""), forgetFlags{
			candidatePath: candidate,
			ruleID:        "r-enforce",
			reason:        "ticket-42",
			outPath:       out,
			keystore:      keystoreDir,
			activationKey: "missing-activation",
		})
		if err == nil || !strings.Contains(err.Error(), "missing-activation") {
			t.Fatalf("runForget err = %v, want missing activation key", err)
		}
		assertPathAbsent(t, out)
		assertPathAbsent(t, filepath.Join(dir, "tombstones"))
	})
}

func TestForgetReceiptFailureDoesNotPublishReducedCandidate(t *testing.T) {
	dir := t.TempDir()
	candidate := writeCandidateEnvelope(t, dir, testRatifyContract())
	before := mustReadTestFile(t, candidate)
	receiptPath := unwritableReceiptPath(t)

	err := runForget(learnTestCommand(""), forgetFlags{
		candidatePath: candidate,
		ruleID:        "r-enforce",
		reason:        "ticket-42",
		outPath:       candidate,
		tombstoneDir:  filepath.Join(dir, "tombstones"),
		receiptOut:    receiptPath,
		deterministic: true,
	})
	if err == nil || !strings.Contains(err.Error(), "open lifecycle receipts") {
		t.Fatalf("runForget err = %v, want receipt open failure", err)
	}
	assertFileBytes(t, candidate, before)
	assertNoStagingFiles(t, dir, filepath.Base(candidate))
}

func TestLifecycleTrustFailuresDoNotCreateActiveState(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*lifecycleFlags)
		want   string
	}{
		{
			name: "wrong roster fingerprint",
			mutate: func(flags *lifecycleFlags) {
				flags.rosterRootFingerprint = strings.Repeat("0", 64)
			},
			want: "fingerprint",
		},
		{
			name: "production missing second authority",
			mutate: func(flags *lifecycleFlags) {
				flags.production = true
			},
			want: "--dual-control-from",
		},
		{
			name: "missing second key",
			mutate: func(flags *lifecycleFlags) {
				flags.dualControlFrom = "not-in-keystore"
			},
			want: "not-in-keystore",
		},
		{
			name: "wrong purpose activation key",
			mutate: func(flags *lifecycleFlags) {
				flags.activationKey = "compile-primary"
			},
			want: "activation signer",
		},
		{
			name: "wrong purpose receipt key",
			mutate: func(flags *lifecycleFlags) {
				flags.receiptKey = "activation-primary"
			},
			want: "receipt signer",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture := newLifecycleTestFixture(t)
			hash := fixture.putContract(t, "agent-a")
			flags := fixture.promoteFlags(hash, "agent-a", filepath.Join(fixture.root, "receipts.jsonl"))
			tt.mutate(&flags)

			err := runPromote(lifecycleTestCmd(nil, nil), flags)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("runPromote err = %v, want substring %q", err, tt.want)
			}
			assertPathAbsent(t, filepath.Join(fixture.storeDir, "active.json"))
			assertPathAbsent(t, flags.receiptOut)
		})
	}
}

func TestPromoteDefaultsReceiptPathInsideStore(t *testing.T) {
	fixture := newLifecycleTestFixture(t)
	hash := fixture.putContract(t, "agent-a")
	flags := fixture.promoteFlags(hash, "agent-a", "")

	if err := runPromote(lifecycleTestCmd(nil, nil), flags); err != nil {
		t.Fatalf("runPromote: %v", err)
	}
	receipts := readLifecycleReceipts(t, filepath.Join(fixture.storeDir, defaultLifecycleReceiptOut))
	if len(receipts) != 2 {
		t.Fatalf("receipt count = %d, want 2", len(receipts))
	}
}

func TestPromoteFilesystemPreflightFailuresDoNotWriteReceipts(t *testing.T) {
	t.Run("relative store", func(t *testing.T) {
		err := runPromote(lifecycleTestCmd(nil, nil), lifecycleFlags{
			storeDir: "relative-store",
		})
		if err == nil || !strings.Contains(err.Error(), "absolute") {
			t.Fatalf("runPromote err = %v, want absolute store rejection", err)
		}
	})

	t.Run("manifest index is not a directory", func(t *testing.T) {
		fixture := newLifecycleTestFixture(t)
		hash := fixture.putContract(t, "agent-a")
		receiptOut := filepath.Join(fixture.root, "receipts.jsonl")
		if err := os.WriteFile(filepath.Join(fixture.storeDir, "manifests"), []byte("not a directory"), 0o600); err != nil {
			t.Fatalf("write malformed manifest index: %v", err)
		}

		err := runPromote(lifecycleTestCmd(nil, nil), fixture.promoteFlags(hash, "agent-a", receiptOut))
		if err == nil || !strings.Contains(err.Error(), "accepted manifests") {
			t.Fatalf("runPromote err = %v, want manifest index failure", err)
		}
		assertPathAbsent(t, receiptOut)
		assertPathAbsent(t, filepath.Join(fixture.storeDir, "active.json"))
	})

	t.Run("relative receipt output", func(t *testing.T) {
		fixture := newLifecycleTestFixture(t)
		hash := fixture.putContract(t, "agent-a")
		flags := fixture.promoteFlags(hash, "agent-a", "relative-receipts.jsonl")

		err := runPromote(lifecycleTestCmd(nil, nil), flags)
		if err == nil || !strings.Contains(err.Error(), "absolute") {
			t.Fatalf("runPromote err = %v, want absolute receipt rejection", err)
		}
		assertPathAbsent(t, filepath.Join(fixture.storeDir, "active.json"))
	})
}

func TestPromoteHonorsOptionalDualControlOutsideProduction(t *testing.T) {
	fixture := newLifecycleTestFixture(t)
	hash := fixture.putContract(t, "agent-a")
	flags := fixture.promoteFlags(hash, "agent-a", filepath.Join(fixture.root, "receipts.jsonl"))
	flags.dualControlFrom = "activation-secondary"

	if err := runPromote(lifecycleTestCmd(nil, nil), flags); err != nil {
		t.Fatalf("runPromote: %v", err)
	}
	latest := fixture.latestAccepted(t)
	if len(latest.Envelope.Signatures) != 2 {
		t.Fatalf("manifest signatures = %d, want 2", len(latest.Envelope.Signatures))
	}
}

func TestPromoteSwapFailureEmitsRejectedTerminalReceipt(t *testing.T) {
	fixture := newLifecycleTestFixture(t)
	hash := fixture.putContract(t, "agent-a")
	activePath := filepath.Join(fixture.storeDir, "active.json")
	if err := os.Mkdir(activePath, 0o750); err != nil {
		t.Fatalf("mkdir active path: %v", err)
	}
	receiptOut := filepath.Join(fixture.root, "promote-receipts.jsonl")

	err := runPromote(lifecycleTestCmd(nil, nil), fixture.promoteFlags(hash, "agent-a", receiptOut))
	if err == nil {
		t.Fatal("runPromote unexpectedly accepted an unwritable active path")
	}
	assertRejectedTerminalReceipt(t, receiptOut, contractreceipt.PayloadContractPromoteCommitted)
	if _, hasLatest, latestErr := latestAccepted(contractstore.New(fixture.storeDir), contractstore.Options{
		Roster: fixture.roster,
		Now:    lifecycleTestNow,
	}); latestErr != nil {
		t.Fatalf("latestAccepted after rejected promote: %v", latestErr)
	} else if hasLatest {
		t.Fatal("rejected promote entered accepted history")
	}
}

func TestRollbackSwapFailureKeepsPreviousAcceptedManifest(t *testing.T) {
	fixture := newLifecycleTestFixture(t)
	firstHash := fixture.putContract(t, "agent-a")
	secondHash := fixture.putContract(t, "agent-b")
	if err := runPromote(lifecycleTestCmd(nil, nil), fixture.promoteFlags(firstHash, "agent-a", filepath.Join(fixture.root, "first.jsonl"))); err != nil {
		t.Fatalf("first promote: %v", err)
	}
	target := fixture.latestAccepted(t)
	if err := runPromote(lifecycleTestCmd(nil, nil), fixture.promoteFlags(secondHash, "agent-b", filepath.Join(fixture.root, "second.jsonl"))); err != nil {
		t.Fatalf("second promote: %v", err)
	}
	current := fixture.latestAccepted(t)
	activePath := filepath.Join(fixture.storeDir, "active.json")
	if err := os.Remove(activePath); err != nil {
		t.Fatalf("remove active manifest: %v", err)
	}
	if err := os.Mkdir(activePath, 0o750); err != nil {
		t.Fatalf("mkdir active path: %v", err)
	}
	receiptOut := filepath.Join(fixture.root, "rollback.jsonl")
	flags := fixture.promoteFlags("", "", receiptOut)
	flags.rollbackTarget = target.ManifestHash

	err := runRollback(lifecycleTestCmd(nil, nil), flags)
	if err == nil {
		t.Fatal("runRollback unexpectedly accepted an unwritable active path")
	}
	assertRejectedTerminalReceipt(t, receiptOut, contractreceipt.PayloadContractRollbackCommitted)
	latest := fixture.latestAccepted(t)
	if latest.ManifestHash != current.ManifestHash || latest.Envelope.Body.Generation != current.Envelope.Body.Generation {
		t.Fatalf("accepted state changed after rejected rollback: got %s generation %d, want %s generation %d",
			latest.ManifestHash, latest.Envelope.Body.Generation, current.ManifestHash, current.Envelope.Body.Generation)
	}
}

func TestReviewStrictDecodeAndWriteFailure(t *testing.T) {
	dir := t.TempDir()
	candidate := writeCandidateEnvelope(t, dir, testRatifyContract())

	t.Run("stdout", func(t *testing.T) {
		var stdout bytes.Buffer
		cmd := lifecycleTestCmd(&stdout, nil)
		if err := runReview(cmd, candidate, ""); err != nil {
			t.Fatalf("runReview: %v", err)
		}
		if !strings.Contains(stdout.String(), "r-enforce") {
			t.Fatalf("review output missing rule id:\n%s", stdout.String())
		}
	})

	t.Run("output is directory", func(t *testing.T) {
		dest := filepath.Join(dir, "review-target")
		if err := os.Mkdir(dest, 0o750); err != nil {
			t.Fatalf("mkdir review target: %v", err)
		}
		err := runReview(lifecycleTestCmd(nil, nil), candidate, dest)
		if err == nil || !strings.Contains(err.Error(), "regular file") {
			t.Fatalf("runReview err = %v, want directory rejection", err)
		}
	})

	t.Run("unknown body field", func(t *testing.T) {
		raw := mustReadTestFile(t, candidate)
		var decoded map[string]any
		if err := json.Unmarshal(mustCandidateJSON(t, raw), &decoded); err != nil {
			t.Fatalf("decode candidate JSON: %v", err)
		}
		body := decoded["body"].(map[string]any)
		body["unexpected"] = true
		badPath := filepath.Join(dir, "bad-candidate.yaml")
		if err := os.WriteFile(badPath, mustJSON(t, decoded), 0o600); err != nil {
			t.Fatalf("write malformed candidate: %v", err)
		}
		err := runReview(lifecycleTestCmd(nil, nil), badPath, "")
		if err == nil || !strings.Contains(err.Error(), "decode candidate") {
			t.Fatalf("runReview err = %v, want strict decode failure", err)
		}
	})
}

func signedCandidateForFailureTest(t *testing.T, body contract.Contract) contract.ContractEnvelope {
	t.Helper()
	path := writeCandidateEnvelope(t, t.TempDir(), body)
	_, env, err := loadCandidateEnvelope(path)
	if err != nil {
		t.Fatalf("load signed candidate: %v", err)
	}
	return env
}

func writeRawCandidateEnvelope(t *testing.T, dir string, env contract.ContractEnvelope) string {
	t.Helper()
	path := filepath.Join(dir, "candidate.yaml")
	if err := writeContractEnvelopeYAML(path, env); err != nil {
		t.Fatalf("write candidate envelope: %v", err)
	}
	return path
}

func learnTestCommand(input string) *cobra.Command {
	cmd, _ := learnTestCmd(input)
	return cmd
}

func assertRejectedTerminalReceipt(t *testing.T, path string, kind contractreceipt.PayloadKind) {
	t.Helper()
	receipts := readLifecycleReceipts(t, path)
	if len(receipts) != 2 {
		t.Fatalf("receipt count = %d, want intent and terminal receipt", len(receipts))
	}
	if receipts[1].PayloadKind != kind {
		t.Fatalf("terminal payload kind = %q, want %q", receipts[1].PayloadKind, kind)
	}
	var payload struct {
		ValidationOutcome string `json:"validation_outcome"`
		RejectReason      string `json:"reject_reason"`
	}
	if err := json.Unmarshal(receipts[1].Payload, &payload); err != nil {
		t.Fatalf("decode terminal payload: %v", err)
	}
	if payload.ValidationOutcome != lifecycleOutcomeRejected || payload.RejectReason == "" {
		t.Fatalf("terminal payload = %+v, want rejected outcome with reason", payload)
	}
}

func unwritableReceiptPath(t *testing.T) string {
	t.Helper()
	const path = "/proc/self/status"
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		t.Skipf("kernel status file unavailable: %v", err)
	}
	return path
}

func assertNoStagingFiles(t *testing.T, dir, base string) {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, "."+base+".*.tmp"))
	if err != nil {
		t.Fatalf("glob staging files: %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("staging files remain after failure: %v", matches)
	}
}

func assertFileBytes(t *testing.T, path string, want []byte) {
	t.Helper()
	got := mustReadTestFile(t, path)
	if !bytes.Equal(got, want) {
		t.Fatalf("%s changed after rejected operation", path)
	}
}

func assertPathAbsent(t *testing.T, path string) {
	t.Helper()
	_, err := os.Lstat(path)
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("path %s exists or returned unexpected error: %v", path, err)
	}
}

func mustReadTestFile(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Clean(path)) // #nosec G304 -- test path is rooted in t.TempDir.
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return raw
}

func mustCandidateJSON(t *testing.T, raw []byte) []byte {
	t.Helper()
	var env contract.ContractEnvelope
	if err := contract.DecodeStrictYAML(raw, &env); err != nil {
		t.Fatalf("decode candidate YAML: %v", err)
	}
	out, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal candidate JSON: %v", err)
	}
	return out
}
