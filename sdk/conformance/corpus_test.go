// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package conformance_test

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

// The corpus under testdata/corpus is a VENDORED copy of the receipt-verifier
// conformance corpus maintained in the agent-egress-bench repository at
// receipts/v0/conformance. The same corpus is run against the TypeScript, Rust,
// and Python reference verifiers by the cross-language gate (corpus-gate.sh);
// this Go-native test is the fourth language in that gate and runs in the
// standard `test` CI job. check-corpus-drift.sh guards the vendored copy against
// drift from the agent-egress-bench master.
//
// The corpus's reject_reason values are a published, closed enum. This test
// checks the security-meaningful accept/reject verdict (not the reason string)
// because the reference verifiers emit prose errors, not enum codes.
const corpusDir = "testdata/corpus"

// Policy fixtures: the reference verifiers (Go/TS/Rust/Python) deliberately do
// not implement these verifier-policy checks yet, so all four UNANIMOUSLY
// accept them. They are not a cross-language differential — they are a tracked
// coverage gap (max_age expiry; control-byte/header-injection rejection). The
// gate documents them; this test pins the current behavior so that adding the
// policy later is a deliberate, test-visible change.
var corpusPolicyFixtures = map[string]string{
	"m03-expired-timestamp":          "max_age expiry policy not implemented by reference verifiers",
	"m12-header-injection-null-byte": "control-byte rejection policy not implemented by reference verifiers",
}

type corpusExpect struct {
	FixtureID    string `json:"fixture_id"`
	Category     string `json:"category"`
	InputFormat  string `json:"input_format"`
	Verdict      string `json:"verdict"`
	RejectReason string `json:"reject_reason"`
}

// corpusKeyHex returns the pinned conformance test public key.
func corpusKeyHex(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(filepath.Join(corpusDir, "test-key.json")))
	if err != nil {
		t.Fatalf("read corpus test-key.json: %v", err)
	}
	var info map[string]string
	if err := json.Unmarshal(data, &info); err != nil {
		t.Fatalf("unmarshal corpus test-key.json: %v", err)
	}
	key := info["public_key_hex"]
	if _, err := hex.DecodeString(key); err != nil || len(key) != 64 {
		t.Fatalf("corpus public_key_hex is not a 32-byte hex string: %q", key)
	}
	return key
}

// goVerdict returns "accept" or "reject" for a single-receipt fixture, matching
// the verify path the production CLI uses (receipt.Unmarshal then VerifyWithKey
// against the pinned key).
func goVerdict(data []byte, keyHex string) string {
	r, err := receipt.Unmarshal(data)
	if err != nil {
		return "reject"
	}
	if err := receipt.VerifyWithKey(r, keyHex); err != nil {
		return "reject"
	}
	return "accept"
}

// TestCorpus_SingleReceipts runs the Go verifier over every single-receipt
// fixture in the vendored corpus and asserts the accept/reject verdict matches
// the corpus's .expect.json. Chain (.jsonl) fixtures are intentionally excluded
// (the corpus encodes chains as bare receipts, while the receipt readers expect
// flight-recorder entries; chain parity is tracked separately).
func TestCorpus_SingleReceipts(t *testing.T) {
	t.Parallel()
	keyHex := corpusKeyHex(t)

	var checked int
	for _, category := range []string{"golden", "malicious", "edge"} {
		dir := filepath.Join(corpusDir, category)
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read corpus dir %s: %v", dir, err)
		}
		for _, e := range entries {
			name := e.Name()
			if !strings.HasSuffix(name, ".json") || strings.HasSuffix(name, ".expect.json") {
				continue
			}
			base := strings.TrimSuffix(name, ".json")
			t.Run(category+"/"+base, func(t *testing.T) {
				t.Parallel()
				expect := readCorpusExpect(t, filepath.Join(dir, base+".expect.json"))
				if expect.InputFormat == "chain" {
					t.Skipf("chain fixture excluded from single-receipt gate")
				}
				data, err := os.ReadFile(filepath.Clean(filepath.Join(dir, name)))
				if err != nil {
					t.Fatalf("read fixture: %v", err)
				}
				got := goVerdict(data, keyHex)

				if reason, isPolicy := corpusPolicyFixtures[base]; isPolicy {
					// Reference verifiers unanimously accept policy fixtures.
					// Pin that so adding the policy is a deliberate change.
					if got != "accept" {
						t.Errorf("policy fixture %s: got %q, want current-behavior \"accept\" (%s)", base, got, reason)
					}
					return
				}
				if got != expect.Verdict {
					t.Errorf("fixture %s: got %q, want %q (reject_reason=%q)", base, got, expect.Verdict, expect.RejectReason)
				}
			})
			checked++
		}
	}
	if checked == 0 {
		t.Fatal("no single-receipt fixtures found; corpus vendoring is broken")
	}
}

// TestCorpus_DuplicateKeyRejected asserts the duplicate-key fixture is rejected
// specifically by the duplicate-key scanner (errors.Is ErrDuplicateKey), not by
// some incidental downstream check. This is the regression that proves the
// parser-differential smuggling vector is closed on the Go verify path.
func TestCorpus_DuplicateKeyRejected(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile(filepath.Clean(filepath.Join(corpusDir, "malicious", "m13-duplicate-key-verdict.json")))
	if err != nil {
		t.Fatalf("read m13 fixture: %v", err)
	}
	_, err = receipt.Unmarshal(data)
	if err == nil {
		t.Fatal("Unmarshal accepted a receipt with a duplicate key")
	}
	if !errors.Is(err, receipt.ErrDuplicateKey) {
		t.Errorf("error = %v, want errors.Is ErrDuplicateKey", err)
	}
}

func readCorpusExpect(t *testing.T, path string) corpusExpect {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("read expect %s: %v", path, err)
	}
	var exp corpusExpect
	if err := json.Unmarshal(data, &exp); err != nil {
		t.Fatalf("unmarshal expect %s: %v", path, err)
	}
	return exp
}
