// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package conformance_test

// TestFrozenV1ReceiptFixtures is the forward-compatibility regression guard for
// Pipelock's two frozen v1 receipt formats:
//
//   - ActionReceipt v1 (receipt.ReceiptVersion = 1, internal/receipt/receipt.go:17)
//     verified by receipt.VerifyWithKey (internal/receipt/receipt.go:66)
//   - AARP v0.1 assurance envelope (aarp.Profile = "aarp/v0.1", internal/aarp/doc.go:50)
//     verified by aarp.Verify (internal/aarp/verify.go:67)
//
// The test does two things for each frozen fixture:
//
//  1. Drift guard — computes the SHA-256 of the fixture bytes and compares against a
//     pinned constant. If a frozen fixture is mutated the test fails immediately with
//     a "frozen fixture drift" message before any verification runs.
//
//  2. Forward-compat check — feeds the unchanged bytes through the CURRENT verifier and
//     asserts acceptance. A future refactor that accidentally breaks v1 parsing is caught
//     here on every CI run.
//
// The frozen files live at sdk/conformance/testdata/frozen/v1/ and must never be edited.
// Their hashes are pinned below. Versioning policy: docs/receipts/versioning.md.

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/aarp"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

const (
	// frozenV1Dir is the directory holding the immutable v1 fixture files.
	frozenV1Dir = "testdata/frozen/v1"

	// Pinned SHA-256 hashes for each frozen file (drift guard). These were computed
	// by running sha256sum over the files in testdata/frozen/v1/ at the time of freezing.
	frozenHashActionSingle = "c7475b5cca93c10dc97892335034e8f9a2cb935e473c9c1c84d803b7d8ff5b75"
	frozenHashActionChain  = "f17357e9e3ed6ce7926ae4579c184404bbe7f92444e89465c1af323730d4b8e2"
	frozenHashAARPEnvelope = "1c873a078f0ba4b3a75a87c6f3dd423fcb0b52939a1aac9c9e785082ed11a46e"
)

// frozenFixture holds one frozen fixture's name, expected hash, and a verify
// function that returns an error if the CURRENT verifier rejects the bytes.
type frozenFixture struct {
	name   string
	hash   string
	verify func(data []byte) error
}

// aarpFrozenVerifyOptions returns the trust options for the frozen AARP fixture.
// The fixture was generated against seedSigner (pipelock-aarp-corpus-signer-key-v1),
// the same deterministic seed used in aarp_corpus_gen_test.go, so we derive it here
// from that same seed rather than embedding a raw key literal.
func aarpFrozenVerifyOptions() aarp.VerifyOptions {
	signerPub, _ := keyFromSeed(seedSigner) // seedSigner declared in aarp_corpus_gen_test.go
	issuerPub, _ := keyFromSeed(seedIssuer) // seedIssuer declared in aarp_corpus_gen_test.go
	return corpusVerifyOptions(signerPub, issuerPub)
}

func TestFrozenV1ReceiptFixtures(t *testing.T) {
	t.Parallel()

	actionSingleFile := filepath.Join(frozenV1Dir, "action-receipt-v1-single.json")
	actionChainFile := filepath.Join(frozenV1Dir, "action-receipt-v1-chain.jsonl")
	aarpEnvelopeFile := filepath.Join(frozenV1Dir, "aarp-v0.1-envelope.aarp.json")

	aarpOpts := aarpFrozenVerifyOptions()

	fixtures := []frozenFixture{
		{
			name: "action-receipt-v1-single",
			hash: frozenHashActionSingle,
			verify: func(data []byte) error {
				r, err := receipt.Unmarshal(data)
				if err != nil {
					return fmt.Errorf("Unmarshal: %w", err)
				}
				// Pass empty key: VerifyWithKey uses the embedded signer_key field.
				if err := receipt.VerifyWithKey(r, ""); err != nil {
					return fmt.Errorf("VerifyWithKey: %w", err)
				}
				return nil
			},
		},
		{
			name: "action-receipt-v1-chain",
			hash: frozenHashActionChain,
			verify: func(data []byte) error {
				// The chain file is JSONL: one flight-recorder entry per line. The
				// receipt lives under the "detail" key (see valid-chain.jsonl format).
				sc := bufio.NewScanner(bytes.NewReader(data))
				var receipts []receipt.Receipt
				var n int
				for sc.Scan() {
					line := bytes.TrimSpace(sc.Bytes())
					if len(line) == 0 {
						continue
					}
					var wrapper struct {
						Detail json.RawMessage `json:"detail"`
					}
					if err := json.Unmarshal(line, &wrapper); err != nil {
						return fmt.Errorf("line %d: unmarshal chain wrapper: %w", n+1, err)
					}
					// json.RawMessage("null") is non-nil, so a literal `detail: null`
					// must be caught here, not slip through to the verifier.
					if len(bytes.TrimSpace(wrapper.Detail)) == 0 || string(bytes.TrimSpace(wrapper.Detail)) == "null" {
						return fmt.Errorf("line %d: missing detail field", n+1)
					}
					r, err := receipt.Unmarshal(wrapper.Detail)
					if err != nil {
						return fmt.Errorf("line %d: Unmarshal: %w", n+1, err)
					}
					// Pass empty key: VerifyWithKey uses the embedded signer_key field.
					if err := receipt.VerifyWithKey(r, ""); err != nil {
						return fmt.Errorf("line %d: VerifyWithKey: %w", n+1, err)
					}
					receipts = append(receipts, r)
					n++
				}
				if err := sc.Err(); err != nil {
					return fmt.Errorf("scan chain file: %w", err)
				}
				if n == 0 {
					return fmt.Errorf("chain file had no entries")
				}
				result := receipt.VerifyChain(receipts, "")
				if !result.Valid {
					return fmt.Errorf("VerifyChain: %s", result.Error)
				}
				if result.ReceiptCount != uint64(n) {
					return fmt.Errorf("VerifyChain receipt_count = %d, want %d", result.ReceiptCount, n)
				}
				return nil
			},
		},
		{
			name: "aarp-v0.1-envelope",
			hash: frozenHashAARPEnvelope,
			verify: func(data []byte) error {
				env, err := aarp.Unmarshal(data)
				if err != nil {
					return fmt.Errorf("Unmarshal: %w", err)
				}
				ap, err := aarp.Verify(env, aarpOpts)
				if err != nil {
					return fmt.Errorf("Verify: %w", err)
				}
				if !ap.AssertionSigned {
					return fmt.Errorf("expected AssertionSigned=true, got false (verified claims: %v)", ap.VerifiedClaims)
				}
				return nil
			},
		},
	}

	files := map[string]string{
		"action-receipt-v1-single": actionSingleFile,
		"action-receipt-v1-chain":  actionChainFile,
		"aarp-v0.1-envelope":       aarpEnvelopeFile,
	}

	for _, fx := range fixtures {
		fx := fx // capture
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()

			path := files[fx.name]
			data, err := os.ReadFile(filepath.Clean(path))
			if err != nil {
				t.Fatalf("read frozen fixture %s: %v", path, err)
			}

			// Drift guard: the hash of a frozen file must never change.
			sum := sha256.Sum256(data)
			got := hex.EncodeToString(sum[:])
			if got != fx.hash {
				t.Fatalf("frozen fixture drift for %s:\n  want sha256 %s\n   got sha256 %s\n"+
					"Frozen files must never be edited; see sdk/conformance/testdata/frozen/v1/README.md",
					path, fx.hash, got)
			}

			// Forward-compat check: the CURRENT verifier must accept the bytes.
			if err := fx.verify(data); err != nil {
				t.Errorf("current verifier rejected frozen v1 fixture %s (forward-compat failure): %v", path, err)
			}
		})
	}
}
