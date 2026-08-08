// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	contractreceipt "github.com/luckyPipewrench/pipelock/internal/contract/receipt"
)

// evidenceTipHash returns the ReceiptHash of the fixture's final receipt, which
// is what trusted external context would pin as the expected head.
func evidenceTipHash(t *testing.T, fix *evidenceFixture) string {
	t.Helper()
	h, err := contractreceipt.ReceiptHash(fix.receipts[len(fix.receipts)-1])
	if err != nil {
		t.Fatalf("hash chain tip: %v", err)
	}
	return h
}

// writeTruncatedEvidence writes the fixture's chain with the last receipt
// dropped, which is the omission every other check is blind to.
func writeTruncatedEvidence(t *testing.T, fix *evidenceFixture, path string) {
	t.Helper()
	full := fix.receipts
	fix.receipts = full[:len(full)-1]
	fix.writeEvidenceJSONL(t, path)
	fix.receipts = full
}

// TestChain_CompletenessNotProvenWithoutExpectedHead pins the reporting change.
// A chain verified without an expected head is still VALID, because every check
// but the head binding is satisfied by any prefix. Leaving that unsaid lets a
// reader take "CHAIN VALID" as "nothing is missing", so the verdict has to say
// which of the two it means.
func TestChain_CompletenessNotProvenWithoutExpectedHead(t *testing.T) {
	t.Parallel()
	fix := newEvidenceFixture(t, 3)
	evidence := filepath.Join(t.TempDir(), "evidence.jsonl")
	fix.writeEvidenceJSONL(t, evidence)

	stdout, stderr, code := runRoot(t, "chain", "--key", fix.keyHex, evidence)
	if code != cliutil.ExitOK {
		t.Fatalf("chain should verify, stdout=%q stderr=%q", stdout, stderr)
	}
	if !strings.Contains(stdout, "completeness: not proven") {
		t.Fatalf("stdout = %q, want completeness reported as not proven", stdout)
	}
	if !strings.Contains(stdout, "--expect-head") {
		t.Fatalf("stdout = %q, want the remediation flag named", stdout)
	}
}

// TestChain_ExpectedHeadReportsVerified covers the other half: supplying the
// real head both passes and says so.
func TestChain_ExpectedHeadReportsVerified(t *testing.T) {
	t.Parallel()
	fix := newEvidenceFixture(t, 3)
	evidence := filepath.Join(t.TempDir(), "evidence.jsonl")
	fix.writeEvidenceJSONL(t, evidence)

	stdout, stderr, code := runRoot(t, "chain", "--key", fix.keyHex, "--expect-head", evidenceTipHash(t, fix), evidence)
	if code != cliutil.ExitOK {
		t.Fatalf("chain with its own head should verify, stdout=%q stderr=%q", stdout, stderr)
	}
	if !strings.Contains(stdout, "completeness: head verified") {
		t.Fatalf("stdout = %q, want completeness reported as head verified", stdout)
	}
}

// TestChain_ExpectedHeadCatchesTruncation is the reason the flag exists. The
// truncated chain passes every per-receipt check, so without a pinned head the
// CLI reports it valid; with one it is rejected.
func TestChain_ExpectedHeadCatchesTruncation(t *testing.T) {
	t.Parallel()
	fix := newEvidenceFixture(t, 3)
	evidence := filepath.Join(t.TempDir(), "truncated.jsonl")
	writeTruncatedEvidence(t, fix, evidence)
	tip := evidenceTipHash(t, fix)

	stdout, _, code := runRoot(t, "chain", "--key", fix.keyHex, evidence)
	if code != cliutil.ExitOK {
		t.Fatalf("a truncated chain still passes structurally; got exit %d stdout=%q", code, stdout)
	}
	if !strings.Contains(stdout, "completeness: not proven") {
		t.Fatalf("stdout = %q, want the truncated chain flagged as completeness-unproven", stdout)
	}

	_, stderr, code := runRoot(t, "chain", "--key", fix.keyHex, "--expect-head", tip, evidence)
	if code == cliutil.ExitOK {
		t.Fatalf("truncated chain verified against the full-chain head, stderr=%q", stderr)
	}
	if !strings.Contains(stderr, "truncated") {
		t.Fatalf("stderr = %q, want the rejection to name truncation", stderr)
	}
}

// TestChain_ExpectedHeadJSONField keeps the machine-readable verdict honest for
// a consumer that never reads the human output.
func TestChain_ExpectedHeadJSONField(t *testing.T) {
	t.Parallel()
	fix := newEvidenceFixture(t, 2)
	evidence := filepath.Join(t.TempDir(), "evidence.jsonl")
	fix.writeEvidenceJSONL(t, evidence)

	unpinned, _, code := runRoot(t, "chain", "--key", fix.keyHex, "--json", evidence)
	if code != cliutil.ExitOK {
		t.Fatalf("json chain should verify: %s", unpinned)
	}
	var unpinnedReport struct {
		HeadVerified *bool `json:"head_verified"`
	}
	if err := json.Unmarshal([]byte(unpinned), &unpinnedReport); err != nil {
		t.Fatalf("decode json verdict: %v", err)
	}
	if unpinnedReport.HeadVerified == nil || *unpinnedReport.HeadVerified {
		t.Fatalf("json = %q, want head_verified false with no expected head", unpinned)
	}

	pinned, _, code := runRoot(t, "chain", "--key", fix.keyHex, "--expect-head", evidenceTipHash(t, fix), "--json", evidence)
	if code != cliutil.ExitOK {
		t.Fatalf("json chain with head should verify: %s", pinned)
	}
	var pinnedReport struct {
		HeadVerified *bool `json:"head_verified"`
	}
	if err := json.Unmarshal([]byte(pinned), &pinnedReport); err != nil {
		t.Fatalf("decode json verdict: %v", err)
	}
	if pinnedReport.HeadVerified == nil || !*pinnedReport.HeadVerified {
		t.Fatalf("json = %q, want head_verified true", pinned)
	}
}

// TestReceipt_ExpectedHeadBindsASingleReceipt covers the single-receipt half of
// the shared expect-head option. There is no omission to detect in one receipt,
// so this binds identity: the file has to be the receipt the caller expected.
// The option reaches this command through the shared evidenceBindingOptions, and
// an option that is plumbed but unread is an inert security knob, so a mismatch
// must be rejected rather than passed over.
func TestReceipt_ExpectedHeadBindsASingleReceipt(t *testing.T) {
	t.Parallel()
	fix := newEvidenceFixture(t, 1)
	path := filepath.Join(t.TempDir(), "receipt.json")
	data, marshalErr := json.Marshal(fix.receipts[0])
	if marshalErr != nil {
		t.Fatalf("marshal receipt: %v", marshalErr)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write receipt: %v", err)
	}
	tip := evidenceTipHash(t, fix)

	stdout, stderr, code := runRoot(t, "receipt", "--key", fix.keyHex, "--expect-head", tip, path)
	if code != cliutil.ExitOK {
		t.Fatalf("receipt with its own hash should verify, stdout=%q stderr=%q", stdout, stderr)
	}

	_, stderr, code = runRoot(t, "receipt", "--key", fix.keyHex, "--expect-head", strings.Repeat("0", 64), path)
	if code == cliutil.ExitOK {
		t.Fatalf("receipt verified against a head hash it does not have, stderr=%q", stderr)
	}
	if !strings.Contains(stderr, "does not match expected head") {
		t.Fatalf("stderr = %q, want the expected-head mismatch named", stderr)
	}
}

// TestReceipt_UnpinnedStillAppliesTheExpectBindings covers the path a pinned
// test cannot reach. The receipt command verifies an unpinned receipt on its own
// branch, which returned before the binding checks were reached, so every
// Expect* flag was accepted and never compared when --key was omitted: the
// command exited 0 with no error and no warning. An operator who pinned an
// expectation and got silence had no way to tell the check never ran, which is
// worse than the flag not existing.
//
// These bindings read the receipt's own declared fields, so none of them needs a
// trusted key. Provenance is a separate question and the unpinned banner already
// reports it.
func TestReceipt_UnpinnedStillAppliesTheExpectBindings(t *testing.T) {
	t.Parallel()
	fix := newEvidenceFixture(t, 1)
	path := filepath.Join(t.TempDir(), "receipt.json")
	data, marshalErr := json.Marshal(fix.receipts[0])
	if marshalErr != nil {
		t.Fatalf("marshal receipt: %v", marshalErr)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write receipt: %v", err)
	}

	for _, tc := range []struct {
		name   string
		flag   string
		value  string
		wantIn string
	}{
		{"expect_head", "--expect-head", strings.Repeat("0", 64), "does not match expected head"},
		{"expect_signer_id", "--expect-signer-id", "not-the-signer", "signer_key_id"},
		{"expect_contract", "--expect-contract", "sha256:not-the-contract", "contract_hash"},
		{"expect_payload_kind", "--expect-payload-kind", "not_a_payload_kind", "payload_kind"},
		{"expect_manifest", "--expect-manifest", "sha256:not-the-manifest", "active_manifest_hash"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, stderr, code := runRoot(t, "receipt", "--allow-unpinned", tc.flag, tc.value, path)
			if code == cliutil.ExitOK {
				t.Fatalf("%s mismatch accepted on the unpinned path, stderr=%q", tc.flag, stderr)
			}
			if !strings.Contains(stderr, tc.wantIn) {
				t.Fatalf("stderr = %q, want it to name %s", stderr, tc.wantIn)
			}
		})
	}

	// The matching case must still pass, or the bindings would be refusing
	// legitimate input rather than catching a mismatch.
	stdout, stderr, code := runRoot(t, "receipt", "--allow-unpinned", "--expect-head", evidenceTipHash(t, fix), path)
	if code != cliutil.ExitOK {
		t.Fatalf("matching unpinned expected head rejected, stdout=%q stderr=%q", stdout, stderr)
	}
}
