// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package conformance_test

// Fleet Receipt Report v1 frozen conformance fixtures.
//
// This file generates and verifies frozen Fleet Receipt Report v1 fixtures.
// The valid fixture is a DSSE-wrapped in-toto Statement v1 with a fleet-receipt/v1
// predicate, signed with a committed deterministic test key. Negative fixtures
// cover every L1 tampering class the verifier must reject.
//
// The fixtures are generated deterministically from committed key material and
// static timestamps. No wall-clock dates. Regenerate with:
//
//	go test ./sdk/conformance/ -run TestGenerateFleetReceiptCorpus -update-fleet-receipt
//
// The conformance test runs without any license or enterprise build tag because
// verification is Free-tier (internal/fleetreceipt).

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/fleetreceipt"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

var updateFleetReceipt = flag.Bool("update-fleet-receipt", false, "regenerate the fleet receipt corpus fixtures")

const (
	fleetReceiptFixtureDir = "testdata/fleet-receipt-v1"

	// Deterministic seed for fleet receipt test keys.
	seedFleetReportSigner = "pipelock-fleet-receipt-corpus-signer-v1"
	seedFleetReportWrong  = "pipelock-fleet-receipt-corpus-wrong-key-v1"

	fleetReportSignerKeyID = "fleet-report-test-signer"

	// Static fixture timestamps (never time.Now).
	fleetReportGeneratedAt = "2026-06-01T00:00:00Z"
	fleetReportWindowStart = "2026-05-01T00:00:00Z"
	fleetReportWindowEnd   = "2026-06-01T00:00:00Z"
	fleetReportEmittedAt   = "2026-05-15T12:00:00Z"
	fleetReportReceivedAt  = "2026-05-15T12:01:00Z"
)

// fleetReceiptFixtureSpec describes one fixture file and its expected verification outcome.
type fleetReceiptFixtureSpec struct {
	name string
	// genFn produces the fixture bytes.
	genFn func(baseline fleetreceipt.Statement, pub ed25519.PublicKey, priv ed25519.PrivateKey) ([]byte, error)
	// verifyFn overrides the default verification. If nil, verification uses the
	// standard trusted-key map for the signer key.
	verifyFn func(data []byte) error
	// wantPass is true when the verifier should accept this fixture.
	wantPass bool
	// wantErrSubstring is the expected error substring for negative fixtures.
	wantErrSubstring string
}

// validFleetReceiptStatement builds the canonical valid L1 fleet receipt statement
// used as the baseline for all fixtures.
func validFleetReceiptStatement() fleetreceipt.Statement {
	batchID := "audit-batch-001"
	instanceID := "follower-1"
	orgID := "org-example"
	fleetID := "fleet-example"

	envelopeHash := fixedDigest("fleet-envelope-1")
	payloadHash := fixedDigest("fleet-payload-1")
	segmentTailHash := fixedDigest("fleet-segment-tail-1")

	batch := fleetreceipt.SourceBatch{
		OrgID:           orgID,
		FleetID:         fleetID,
		InstanceID:      instanceID,
		BatchID:         batchID,
		SeqStart:        0,
		SeqEnd:          9,
		EventCount:      10,
		PayloadSHA256:   payloadHash,
		PayloadBytes:    4096,
		EnvelopeHash:    envelopeHash,
		SegmentTailHash: segmentTailHash,
		DroppedCount:    0,
		EmittedAt:       fleetReportEmittedAt,
		ReceivedAt:      fleetReportReceivedAt,
		SignatureKeyIDs: []string{"follower-audit-key-1"},
	}

	subjectName := fmt.Sprintf("conductor-audit-batch:%s/%s/%s/%s", orgID, fleetID, instanceID, batchID)

	return fleetreceipt.Statement{
		Type: fleetreceipt.StatementType,
		Subject: []fleetreceipt.Subject{{
			Name:   subjectName,
			Digest: fleetreceipt.Digest{SHA256: envelopeHash},
		}},
		PredicateType: fleetreceipt.PredicateType,
		Predicate: fleetreceipt.Predicate{
			SchemaVersion: 1,
			ReportID:      "rpt-frozen-001",
			GeneratedAt:   fleetReportGeneratedAt,
			OrgID:         orgID,
			FleetID:       fleetID,
			ReportWindow: fleetreceipt.TimeWindow{
				Start: fleetReportWindowStart,
				End:   fleetReportWindowEnd,
			},
			VerificationLevel: fleetreceipt.VerificationLevelL1,
			Conductor: fleetreceipt.Conductor{
				ID:      "conductor-test",
				Version: "v0.0.0-test",
			},
			SourceBatches: []fleetreceipt.SourceBatch{batch},
			Summary: fleetreceipt.Summary{
				TotalActions: 10,
				ByFollower:   map[string]uint64{instanceID: 10},
				ByTransport:  map[string]uint64{"forward_proxy": 10},
				ByActionType: map[string]uint64{"http_request": 10},
				ByVerdict:    map[string]uint64{"allowed": 10},
				ByLayer:      map[string]uint64{"domain_blocklist": 10},
				BySeverity:   map[string]uint64{"info": 10},
			},
			Completeness: fleetreceipt.Completeness{
				ObservedActions:        10,
				DroppedObservedActions: 0,
				MediatedActions:        10,
				MediatedFraction:       "1",
				Basis:                  "included_signed_audit_batches",
				Claim:                  "fraction of observed fleet action records in included signed audit batches that were mediated by Pipelock",
				NonClaim:               "does not prove no bypass occurred outside Pipelock, outside enrolled followers, or outside the report window",
			},
			Limits: []string{
				"L1 verifies the signed report, source-batch anchors, ordering, summary arithmetic, and completeness arithmetic.",
				"L1 does not replay raw audit-batch payloads during offline verification.",
				"Actions outside included signed audit batches are not claimed by this report.",
			},
		},
	}
}

// signEnvelopeForFixture signs a statement and marshals to indented JSON with trailing newline.
func signEnvelopeForFixture(stmt fleetreceipt.Statement, keyID string, priv ed25519.PrivateKey) ([]byte, error) {
	env, err := fleetreceipt.SignStatement(stmt, keyID, priv)
	if err != nil {
		return nil, fmt.Errorf("sign statement: %w", err)
	}
	return marshalFleetEnvelopeBytes(env)
}

func marshalFleetEnvelopeBytes(env fleetreceipt.Envelope) ([]byte, error) {
	data, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal envelope: %w", err)
	}
	return append(data, '\n'), nil
}

// buildTamperedPayloadEnvelope replaces a valid envelope's payload with a tampered
// statement (raw JSON, base64-encoded). The original signature stays, so the verifier
// rejects on structural validation or signature mismatch, whichever fires first.
func buildTamperedPayloadEnvelope(validEnv fleetreceipt.Envelope, tampered fleetreceipt.Statement) ([]byte, error) {
	raw, err := json.Marshal(tampered)
	if err != nil {
		return nil, fmt.Errorf("marshal tampered statement: %w", err)
	}
	env := fleetreceipt.Envelope{
		PayloadType: validEnv.PayloadType,
		Payload:     base64.StdEncoding.EncodeToString(raw),
		Signatures:  validEnv.Signatures,
	}
	return marshalFleetEnvelopeBytes(env)
}

// fleetReceiptTrustedKeyMap builds the trusted-key map for the test signer.
func fleetReceiptTrustedKeyMap(pub ed25519.PublicKey) map[string]ed25519.PublicKey {
	return map[string]ed25519.PublicKey{
		fleetReportSignerKeyID: pub,
	}
}

// formatFleetGoldenOutput renders the human verifier output for a passing L1
// report. It MUST mirror verifyFleetReportWithOptions in internal/cli/signing
// (the shipped `pipelock verify-receipt --fleet-report` path) field-for-field,
// including the "FLEET RECEIPT OK: <path>" banner (the CLI prints the verified
// file path) and the predicate Limits block, so the auditor-facing golden
// sample matches what the real CLI emits. A single helper keeps the generation
// and check sides from drifting apart.
func formatFleetGoldenOutput(result fleetreceipt.Verification, path string) string {
	var b strings.Builder
	_, _ = fmt.Fprintf(&b, "FLEET RECEIPT OK: %s\n", path)
	_, _ = fmt.Fprintf(&b, "  Signer:           %s\n", result.SignerKeyID)
	_, _ = fmt.Fprintf(&b, "  Payload SHA-256:  %s\n", result.PayloadSHA256)
	_, _ = fmt.Fprintf(&b, "  Org/Fleet:        %s/%s\n", result.Statement.Predicate.OrgID, result.Statement.Predicate.FleetID)
	_, _ = fmt.Fprintf(&b, "  Report ID:        %s\n", result.Statement.Predicate.ReportID)
	_, _ = fmt.Fprintf(&b, "  Level:            %s\n", result.Statement.Predicate.VerificationLevel)
	_, _ = fmt.Fprintf(&b, "  Source batches:   %d\n", result.SourceBatches)
	_, _ = fmt.Fprintf(&b, "  Total actions:    %d\n", result.TotalActions)
	_, _ = fmt.Fprintf(&b, "  Mediated fraction: %s\n", result.MediatedFraction)
	for _, limit := range result.Statement.Predicate.Limits {
		_, _ = fmt.Fprintf(&b, "  Limit:            %s\n", limit)
	}
	return b.String()
}

func fleetReceiptFixtures() []fleetReceiptFixtureSpec {
	return []fleetReceiptFixtureSpec{
		{
			name: "valid-l1",
			genFn: func(baseline fleetreceipt.Statement, _ ed25519.PublicKey, priv ed25519.PrivateKey) ([]byte, error) {
				return signEnvelopeForFixture(baseline, fleetReportSignerKeyID, priv)
			},
			wantPass: true,
		},
		{
			name:             "wrong-key",
			wantErrSubstring: "signature verification failed",
			// Sign with an untrusted key under the trusted signer's key id. The
			// standard verifier resolves the trusted public key for that id, and
			// ed25519.Verify fails because the signature was produced by a different
			// key. Signing with the wrong key (rather than re-verifying a valid file
			// under a swapped trust map) makes this fixture genuinely distinct from
			// valid-l1 instead of a byte-identical copy.
			genFn: func(baseline fleetreceipt.Statement, _ ed25519.PublicKey, _ ed25519.PrivateKey) ([]byte, error) {
				_, wrongPriv := keyFromSeed(seedFleetReportWrong)
				return signEnvelopeForFixture(baseline, fleetReportSignerKeyID, wrongPriv)
			},
		},
		{
			name:             "wrong-key-purpose",
			wantErrSubstring: "key_purpose",
			genFn: func(baseline fleetreceipt.Statement, _ ed25519.PublicKey, priv ed25519.PrivateKey) ([]byte, error) {
				env, err := fleetreceipt.SignStatement(baseline, fleetReportSignerKeyID, priv)
				if err != nil {
					return nil, err
				}
				env.Signatures[0].KeyPurpose = signing.PurposeReceiptSigning.String()
				return marshalFleetEnvelopeBytes(env)
			},
		},
		{
			name:             "tampered-summary-arithmetic",
			wantErrSubstring: "want 999",
			genFn: func(baseline fleetreceipt.Statement, _ ed25519.PublicKey, priv ed25519.PrivateKey) ([]byte, error) {
				validEnv, err := fleetreceipt.SignStatement(baseline, fleetReportSignerKeyID, priv)
				if err != nil {
					return nil, err
				}
				tampered := baseline
				tampered.Predicate.Summary.TotalActions = 999
				return buildTamperedPayloadEnvelope(validEnv, tampered)
			},
		},
		{
			name:             "duplicate-source-batch",
			wantErrSubstring: "duplicate",
			genFn: func(baseline fleetreceipt.Statement, _ ed25519.PublicKey, priv ed25519.PrivateKey) ([]byte, error) {
				validEnv, err := fleetreceipt.SignStatement(baseline, fleetReportSignerKeyID, priv)
				if err != nil {
					return nil, err
				}
				tampered := baseline
				tampered.Predicate.SourceBatches = append(
					tampered.Predicate.SourceBatches,
					tampered.Predicate.SourceBatches[0],
				)
				return buildTamperedPayloadEnvelope(validEnv, tampered)
			},
		},
		{
			name:             "reordered-source-batch",
			wantErrSubstring: "reordered",
			genFn: func(baseline fleetreceipt.Statement, _ ed25519.PublicKey, priv ed25519.PrivateKey) ([]byte, error) {
				validEnv, err := fleetreceipt.SignStatement(baseline, fleetReportSignerKeyID, priv)
				if err != nil {
					return nil, err
				}
				// Build two batches from the same follower, reversed order.
				batch1 := baseline.Predicate.SourceBatches[0]
				batch2 := batch1
				batch2.BatchID = "audit-batch-002"
				batch2.SeqStart = 10
				batch2.SeqEnd = 19
				batch2.EnvelopeHash = fixedDigest("fleet-envelope-2")
				batch2.PayloadSHA256 = fixedDigest("fleet-payload-2")
				batch2.SegmentTailHash = fixedDigest("fleet-segment-tail-2")

				tampered := baseline
				// Put batch2 (seqStart=10) before batch1 (seqStart=0): a reorder.
				tampered.Predicate.SourceBatches = []fleetreceipt.SourceBatch{batch2, batch1}

				subjectName2 := fmt.Sprintf("conductor-audit-batch:%s/%s/%s/%s",
					batch2.OrgID, batch2.FleetID, batch2.InstanceID, batch2.BatchID)
				tampered.Subject = []fleetreceipt.Subject{
					{Name: subjectName2, Digest: fleetreceipt.Digest{SHA256: batch2.EnvelopeHash}},
					tampered.Subject[0],
				}
				tampered.Predicate.Summary.TotalActions = 20
				tampered.Predicate.Summary.ByFollower = map[string]uint64{"follower-1": 20}
				tampered.Predicate.Summary.ByTransport = map[string]uint64{"forward_proxy": 20}
				tampered.Predicate.Summary.ByActionType = map[string]uint64{"http_request": 20}
				tampered.Predicate.Summary.ByVerdict = map[string]uint64{"allowed": 20}
				tampered.Predicate.Summary.ByLayer = map[string]uint64{"domain_blocklist": 20}
				tampered.Predicate.Summary.BySeverity = map[string]uint64{"info": 20}
				tampered.Predicate.Completeness.ObservedActions = 20
				tampered.Predicate.Completeness.MediatedActions = 20
				return buildTamperedPayloadEnvelope(validEnv, tampered)
			},
		},
		{
			name:             "unpinned-rejected",
			wantErrSubstring: "unpinned",
			genFn: func(baseline fleetreceipt.Statement, _ ed25519.PublicKey, priv ed25519.PrivateKey) ([]byte, error) {
				// Sign with hex keyid so unpinned path can resolve the public key
				// from the keyid directly.
				pubHex := hex.EncodeToString(priv.Public().(ed25519.PublicKey))
				return signEnvelopeForFixture(baseline, pubHex, priv)
			},
			// Verify with no trusted keys (unpinned).
			verifyFn: func(data []byte) error {
				result, err := fleetreceipt.Verify(data, nil)
				if err != nil {
					return err
				}
				if result.Unpinned {
					return fmt.Errorf("fleet receipt verification unpinned: pass --key for provenance")
				}
				return nil
			},
		},
		{
			name:             "l2-rejected",
			wantErrSubstring: "verificationLevel",
			genFn: func(baseline fleetreceipt.Statement, _ ed25519.PublicKey, priv ed25519.PrivateKey) ([]byte, error) {
				validEnv, err := fleetreceipt.SignStatement(baseline, fleetReportSignerKeyID, priv)
				if err != nil {
					return nil, err
				}
				tampered := baseline
				tampered.Predicate.VerificationLevel = "L2"
				return buildTamperedPayloadEnvelope(validEnv, tampered)
			},
		},
	}
}

// pinnedFleetReceiptFixtureHashes is the frozen byte-level fixture manifest.
// Keep this map explicit: computing the expected hash from the file under test
// would make the drift guard self-referential and unable to catch fixture edits.
var pinnedFleetReceiptFixtureHashes = map[string]string{
	"duplicate-source-batch":      "202ecc3e7be3e4089266ee6ef789a26838d42bca669a50c0e6d9c13b2ffa32c6",
	"l2-rejected":                 "5a4ab373b3dd4f466d867afa2ee688958dc61db8f94e53ff287c077329f0c519",
	"reordered-source-batch":      "782c53bbeb1aff3879c0f793aee8ecc97679e64abfce5b2007bed31fe5e11a32",
	"tampered-summary-arithmetic": "c830783974a68a37d12024821b698bdaa01ef29a7c3f61be97b22d9c7aa920b6",
	"unpinned-rejected":           "4497ae09d76988e07ccbd2d7824f2f2ff6a568f6ae87631627209eb272bbdc0f",
	"valid-l1":                    "548eec2cfcd69440a09c2226e78f0d16143c90ba81490c754990ef4ce9a1edb8",
	"wrong-key":                   "edaf00d25f80a8bd4326ccd433f9c416cb175c7e83123e8561ac5c2e08396a2c",
	"wrong-key-purpose":           "111499c7c99fc9755b0099ddc0706dfd0faf9517fdac39093db5157803d42fe6",
}

// TestGenerateFleetReceiptCorpus generates the frozen fleet receipt fixtures when
// -update-fleet-receipt is passed. Without the flag the test is a no-op.
func TestGenerateFleetReceiptCorpus(t *testing.T) {
	if !*updateFleetReceipt {
		t.Skip("pass -update-fleet-receipt to regenerate fixtures")
	}

	pub, priv := keyFromSeed(seedFleetReportSigner)
	baseline := validFleetReceiptStatement()

	// Write the trusted public key file.
	keyFile := filepath.Join(fleetReceiptFixtureDir, "test-key.json")
	keyData := map[string]string{
		"note":           "TEST KEY ONLY. Derived from sha256(seed_phrase). Never use for production signing.",
		"public_key_hex": hex.EncodeToString(pub),
		"seed_phrase":    seedFleetReportSigner,
		"key_id":         fleetReportSignerKeyID,
		"key_purpose":    signing.PurposeFleetReportSigning.String(),
	}
	keyJSON, err := json.MarshalIndent(keyData, "", "  ")
	if err != nil {
		t.Fatalf("marshal key file: %v", err)
	}
	keyJSON = append(keyJSON, '\n')
	if err := os.WriteFile(keyFile, keyJSON, 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}
	t.Logf("wrote %s", keyFile)

	for _, fx := range fleetReceiptFixtures() {
		data, err := fx.genFn(baseline, pub, priv)
		if err != nil {
			t.Fatalf("generate %s: %v", fx.name, err)
		}
		path := filepath.Join(fleetReceiptFixtureDir, fx.name+".dsse.json")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
		t.Logf("wrote %s (%d bytes)", path, len(data))
	}

	// Write the golden output for the valid fixture.
	validPath := filepath.Join(fleetReceiptFixtureDir, "valid-l1.dsse.json")
	validData, err := os.ReadFile(filepath.Clean(validPath))
	if err != nil {
		t.Fatalf("read valid fixture: %v", err)
	}
	keyMap := fleetReceiptTrustedKeyMap(pub)
	result, err := fleetreceipt.Verify(validData, keyMap)
	if err != nil {
		t.Fatalf("verify valid fixture for golden output: %v", err)
	}
	golden := formatFleetGoldenOutput(result, validPath)
	goldenPath := filepath.Join(fleetReceiptFixtureDir, "valid-l1.golden")
	if err := os.WriteFile(goldenPath, []byte(golden), 0o600); err != nil {
		t.Fatalf("write golden: %v", err)
	}
	t.Logf("wrote %s", goldenPath)
}

// TestFleetReceiptV1Conformance is the conformance test suite for frozen fleet
// receipt fixtures. Each fixture is verified for drift (SHA-256 pinning) and then
// run through the verifier.
func TestFleetReceiptV1Conformance(t *testing.T) {
	t.Parallel()

	pub, _ := keyFromSeed(seedFleetReportSigner)
	keyMap := fleetReceiptTrustedKeyMap(pub)
	fixtures := fleetReceiptFixtures()
	if len(pinnedFleetReceiptFixtureHashes) != len(fixtures) {
		t.Fatalf("pinned fixture hash manifest has %d entries, want %d", len(pinnedFleetReceiptFixtureHashes), len(fixtures))
	}

	for _, fx := range fixtures {
		fx := fx
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join(fleetReceiptFixtureDir, fx.name+".dsse.json")
			data, err := os.ReadFile(filepath.Clean(path))
			if err != nil {
				t.Fatalf("read fixture %s: %v", path, err)
			}

			// Drift guard: SHA-256 of the fixture bytes must match the pinned hash.
			sum := sha256.Sum256(data)
			got := hex.EncodeToString(sum[:])
			want, ok := pinnedFleetReceiptFixtureHashes[fx.name]
			if !ok {
				t.Fatalf("no pinned hash for %s; regenerate with -update-fleet-receipt and update pinnedFleetReceiptFixtureHashes", fx.name)
			}
			if got != want {
				t.Fatalf("frozen fixture drift for %s:\n  want sha256 %s\n   got sha256 %s\n"+
					"Frozen files must never be edited; regenerate with -update-fleet-receipt",
					path, want, got)
			}

			// Run the verification.
			var verifyErr error
			if fx.verifyFn != nil {
				verifyErr = fx.verifyFn(data)
			} else {
				_, verifyErr = fleetreceipt.Verify(data, keyMap)
			}

			if fx.wantPass {
				if verifyErr != nil {
					t.Errorf("expected PASS but got error: %v", verifyErr)
				}
			} else {
				if verifyErr == nil {
					t.Fatalf("expected FAIL CLOSED for %s but verification passed (this is a broken test)", fx.name)
				}
				if fx.wantErrSubstring != "" && !strings.Contains(verifyErr.Error(), fx.wantErrSubstring) {
					t.Errorf("expected error containing %q, got: %v", fx.wantErrSubstring, verifyErr)
				}
			}
		})
	}

	// Golden output check for the valid fixture.
	t.Run("golden-output", func(t *testing.T) {
		t.Parallel()

		validPath := filepath.Join(fleetReceiptFixtureDir, "valid-l1.dsse.json")
		validData, err := os.ReadFile(filepath.Clean(validPath))
		if err != nil {
			t.Fatalf("read valid fixture: %v", err)
		}
		result, err := fleetreceipt.Verify(validData, keyMap)
		if err != nil {
			t.Fatalf("verify valid fixture: %v", err)
		}

		actualOutput := formatFleetGoldenOutput(result, validPath)

		goldenPath := filepath.Join(fleetReceiptFixtureDir, "valid-l1.golden")
		goldenData, err := os.ReadFile(filepath.Clean(goldenPath))
		if err != nil {
			t.Fatalf("read golden file: %v", err)
		}
		if actualOutput != string(goldenData) {
			t.Errorf("golden output mismatch:\n--- want ---\n%s\n--- got ---\n%s", string(goldenData), actualOutput)
		}
	})

	// The "wrong-key" fixture is a structurally valid report signed by an
	// untrusted key. It verifies cleanly when the trust map points to the key
	// that actually signed it, proving the payload is well-formed and that only
	// the trusted-key mismatch (not a malformed report) causes the standard
	// rejection above.
	t.Run("wrong-key-verifies-with-its-signing-key", func(t *testing.T) {
		t.Parallel()

		path := filepath.Join(fleetReceiptFixtureDir, "wrong-key.dsse.json")
		data, err := os.ReadFile(filepath.Clean(path))
		if err != nil {
			t.Fatalf("read fixture: %v", err)
		}
		wrongPub, _ := keyFromSeed(seedFleetReportWrong)
		signingKeyMap := map[string]ed25519.PublicKey{fleetReportSignerKeyID: wrongPub}
		if _, err := fleetreceipt.Verify(data, signingKeyMap); err != nil {
			t.Errorf("wrong-key fixture should verify with the key that signed it: %v", err)
		}
	})
}
