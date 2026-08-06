// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	contractreceipt "github.com/luckyPipewrench/pipelock/internal/contract/receipt"
	"github.com/luckyPipewrench/pipelock/internal/normalize"
)

func TestVerifyProvenanceFixtureStages(t *testing.T) {
	fixture := validProvenanceFixture(t, "A💩B", 1, 5)
	report := verifyProvenanceFixture(fixture)
	if report.Signature != "verified" || report.Chain != "verified" || report.Artifacts != "not_attested" || report.ViewReproduction != "reproduced" || report.Location != "exact_coordinates" || report.MatchCommitment != "opened" || report.SourceCommitment != "not_checked" || report.Overall != "incomplete" {
		t.Fatalf("report = %+v", report)
	}
}

func TestProvenanceReportDisclosesFixtureSuppliedTrustRoots(t *testing.T) {
	report := verifyProvenanceFixture(validProvenanceFixture(t, "view", 0, 4))
	if report.TrustRoots != "fixture supplied; self-attested; not authenticated" {
		t.Fatalf("trust_roots = %q", report.TrustRoots)
	}
}

func TestProvenanceReportNeverClaimsAuthenticatedProvenance(t *testing.T) {
	report := verifyProvenanceFixture(validProvenanceFixture(t, "view", 0, 4))
	if report.AuthenticatedProvenance {
		t.Fatal("fixture-supplied trust roots were reported as authenticated provenance")
	}
}

func TestVerifyProvenanceFixtureDoesNotOpenAbsentProofSources(t *testing.T) {
	fixture := validProvenanceFixture(t, "view", 0, 4)
	resignProvenanceFixture(t, &fixture, func(signed *signedProvenanceProof) {
		signed.Proof.Sources = nil
	})
	report := verifyProvenanceFixture(fixture)
	if report.ViewReproduction != "not_checked" || report.Location != "not_checked" || report.MatchCommitment != "not_checked" {
		t.Fatalf("report = %+v", report)
	}
}

func TestVerifyProvenanceFixtureRejectsCriticalFeature(t *testing.T) {
	fixture := validProvenanceFixture(t, "view", 0, 4)
	resignProvenanceFixture(t, &fixture, func(signed *signedProvenanceProof) {
		signed.CriticalFeatures = []string{"unknown"}
	})
	report := verifyProvenanceFixture(fixture)
	if report.FailureStage != "critical_features" || report.Overall != "invalid" {
		t.Fatalf("report = %+v", report)
	}
}

func TestVerifyProvenanceFixtureRejectsByteBoundary(t *testing.T) {
	fixture := validProvenanceFixture(t, "A💩B", 1, 5)
	resignProvenanceFixture(t, &fixture, func(signed *signedProvenanceProof) {
		signed.Proof.Sources[0].Matches[0].ByteStart = 2
	})
	report := verifyProvenanceFixture(fixture)
	if report.ViewReproduction != "reproduced" || report.Location != "mismatch" || report.FailureStage != "location" {
		t.Fatalf("report = %+v", report)
	}
}

func TestVerifyProvenanceFixtureRejectsCommitmentContexts(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*signedProvenanceProof)
		stage  string
	}{
		{"source ordinal", func(s *signedProvenanceProof) { s.Proof.Sources[0].SourceOrdinal++ }, "view_commitment"},
		{"match ordinal", func(s *signedProvenanceProof) { s.Proof.Sources[0].Matches[0].MatchOrdinal++ }, "match_commitment"},
		{"match class", func(s *signedProvenanceProof) { s.Proof.Sources[0].Matches[0].MatchClass = "token" }, "match_commitment"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := validProvenanceFixture(t, "view", 0, 4)
			resignProvenanceFixture(t, &fixture, tc.mutate)
			report := verifyProvenanceFixture(fixture)
			if report.FailureStage != tc.stage {
				t.Fatalf("report = %+v", report)
			}
		})
	}
}

func TestVerifyProvenanceFixtureChecksSignatureBeforeSemantics(t *testing.T) {
	fixture := validProvenanceFixture(t, "view", 0, 4)
	fixture.Entries[0].Signature = "ed25519:" + strings.Repeat("00", ed25519.SignatureSize)
	report := verifyProvenanceFixture(fixture)
	if report.Signature != "invalid" || report.Chain != "not_checked" || report.FailureStage != "signature" {
		t.Fatalf("report = %+v", report)
	}
}

func TestVerifyProvenanceFixtureRejectsGlobalWorkLimits(t *testing.T) {
	t.Run("source references", func(t *testing.T) {
		fixture := validProvenanceFixture(t, "view", 0, 4)
		resignProvenanceFixture(t, &fixture, func(signed *signedProvenanceProof) {
			source := signed.Proof.Sources[0]
			signed.Proof.Sources = make([]contractreceipt.ProvenanceSource, provenanceMaxSources)
			for index := range signed.Proof.Sources {
				source.SourceOrdinal = uint64(index + 1)
				source.SourceID = fmt.Sprintf("source-%d", index)
				signed.Proof.Sources[index] = source
			}
		})
		for len(fixture.Entries)*provenanceMaxSources < provenanceMaxSourceReferences {
			appendProvenanceTestEntry(t, &fixture)
		}
		if got := len(fixture.Entries) * provenanceMaxSources; got != provenanceMaxSourceReferences {
			t.Fatalf("source references at boundary = %d, want %d", got, provenanceMaxSourceReferences)
		}
		boundary := verifyProvenanceFixture(fixture)
		if boundary.Overall != "incomplete" || boundary.FailureStage != "" {
			t.Fatalf("boundary report = %+v, want accepted incomplete fixture", boundary)
		}

		appendProvenanceTestEntry(t, &fixture)
		last := len(fixture.Entries) - 1
		raw, err := base64.StdEncoding.DecodeString(fixture.Entries[last].SignedB64)
		if err != nil {
			t.Fatal(err)
		}
		var signed signedProvenanceProof
		if err := json.Unmarshal(raw, &signed); err != nil {
			t.Fatal(err)
		}
		signed.Proof.Sources = signed.Proof.Sources[:1]
		raw, err = json.Marshal(signed)
		if err != nil {
			t.Fatal(err)
		}
		fixture.Entries[last] = provenanceFixtureEntry{
			SignedB64: base64.StdEncoding.EncodeToString(raw),
			Signature: "ed25519:" + hex.EncodeToString(ed25519.Sign(provenanceFixtureSigningKey(), raw)),
		}
		if got := (len(fixture.Entries)-1)*provenanceMaxSources + len(signed.Proof.Sources); got != provenanceMaxSourceReferences+1 {
			t.Fatalf("source references over boundary = %d, want %d", got, provenanceMaxSourceReferences+1)
		}
		assertProvenanceProofStructureRejection(t, fixture)
	})

	t.Run("match checks", func(t *testing.T) {
		fixture := validProvenanceFixture(t, "view", 0, 4)
		resignProvenanceFixture(t, &fixture, func(signed *signedProvenanceProof) {
			source := signed.Proof.Sources[0]
			match := source.Matches[0]
			source.Matches = make([]contractreceipt.ProvenanceMatch, provenanceMaxMatchesPerSource)
			for index := range source.Matches {
				match.MatchOrdinal = uint64(index + 1)
				match.ByteStart = uint64(index)
				match.ByteEnd = uint64(index + 1)
				source.Matches[index] = match
			}
			signed.Proof.Sources = make([]contractreceipt.ProvenanceSource, provenanceMaxMatchChecks/provenanceMaxMatchesPerSource+1)
			for index := range signed.Proof.Sources {
				source.SourceOrdinal = uint64(index + 1)
				source.SourceID = fmt.Sprintf("source-%d", index)
				signed.Proof.Sources[index] = source
			}
		})
		assertProvenanceProofStructureRejection(t, fixture)
	})

	t.Run("recipe processing bytes", func(t *testing.T) {
		fixture := validProvenanceFixture(t, strings.Repeat("a", 1<<20), 0, 1)
		const sourceCount = 8
		sourceInput := fixture.Verification.Sources[0]
		fixture.Verification.Sources = make([]provenanceFixtureSource, sourceCount)
		for index := range fixture.Verification.Sources {
			sourceInput.SourceID = fmt.Sprintf("source-%d", index)
			fixture.Verification.Sources[index] = sourceInput
		}
		resignProvenanceFixture(t, &fixture, func(signed *signedProvenanceProof) {
			source := signed.Proof.Sources[0]
			source.Recipe.Operations = []normalize.Operation{
				{Kind: normalize.OperationIdentity},
				{Kind: normalize.OperationIdentity},
				{Kind: normalize.OperationIdentity},
				{Kind: normalize.OperationIdentity},
				{Kind: normalize.OperationIdentity},
				{Kind: normalize.OperationIdentity},
				{Kind: normalize.OperationIdentity},
				{Kind: normalize.OperationIdentity},
				{Kind: normalize.OperationIdentity},
			}
			signed.Proof.Sources = make([]contractreceipt.ProvenanceSource, sourceCount)
			for index := range signed.Proof.Sources {
				source.SourceOrdinal = uint64(index + 1)
				source.SourceID = fmt.Sprintf("source-%d", index)
				signed.Proof.Sources[index] = source
			}
		})
		assertProvenanceProofStructureRejection(t, fixture)
	})

	t.Run("per-recipe budget takes precedence", func(t *testing.T) {
		fixture := validProvenanceFixture(t, strings.Repeat("a", 1<<20), 0, 1)
		const sourceCount = 7
		sourceInput := fixture.Verification.Sources[0]
		fixture.Verification.Sources = make([]provenanceFixtureSource, sourceCount)
		for index := range fixture.Verification.Sources {
			sourceInput.SourceID = fmt.Sprintf("source-%d", index)
			fixture.Verification.Sources[index] = sourceInput
		}
		resignProvenanceFixture(t, &fixture, func(signed *signedProvenanceProof) {
			source := signed.Proof.Sources[0]
			signed.Proof.Sources = make([]contractreceipt.ProvenanceSource, sourceCount)
			for index := range signed.Proof.Sources {
				operationCount := 8
				if index == sourceCount-1 {
					operationCount = 17
				}
				source.SourceOrdinal = uint64(index + 1)
				source.SourceID = fmt.Sprintf("source-%d", index)
				source.Recipe.Operations = make([]normalize.Operation, operationCount)
				for operationIndex := range source.Recipe.Operations {
					source.Recipe.Operations[operationIndex] = normalize.Operation{Kind: normalize.OperationIdentity}
				}
				signed.Proof.Sources[index] = source
			}
		})

		report := verifyProvenanceFixture(fixture)
		if report.FailureStage != "view_reproduction" || report.Overall != "invalid" {
			t.Fatalf("report = %+v, want per-recipe view_reproduction failure", report)
		}
	})
}

func TestVerifyProvenanceFixtureReusesViewsForCommitments(t *testing.T) {
	input := strings.Repeat("a", 1<<20)
	fixture := validProvenanceFixture(t, input, 0, 1)
	resignProvenanceFixture(t, &fixture, func(signed *signedProvenanceProof) {
		source := &signed.Proof.Sources[0]
		source.Recipe.Operations = make([]normalize.Operation, 8)
		for index := range source.Recipe.Operations {
			source.Recipe.Operations[index] = normalize.Operation{Kind: normalize.OperationIdentity}
		}
		key := sha256.Sum256([]byte("pipelock-provenance-fixture-commitment-key-v1"))
		viewCommitment, err := contractreceipt.CommitView(key[:], *source, input)
		if err != nil {
			t.Fatal(err)
		}
		source.ViewCommitment = viewCommitment
		matchCommitment, err := contractreceipt.CommitMatch(key[:], source.SourceID, source.Recipe, viewCommitment, source.Matches[0])
		if err != nil {
			t.Fatal(err)
		}
		source.Matches[0].MatchCommitment = matchCommitment
	})
	// Without cross-entry view caching, nine eight-MiB recipe executions would
	// exceed the 64 MiB fixture budget. The identical source/recipe pair runs once.
	for len(fixture.Entries) < 9 {
		appendProvenanceTestEntry(t, &fixture)
	}

	report := verifyProvenanceFixture(fixture)
	if report.Overall != "incomplete" || report.ViewReproduction != "reproduced" || report.MatchCommitment != "opened" {
		t.Fatalf("report = %+v, want cached successful verification", report)
	}
}

func assertProvenanceProofStructureRejection(t *testing.T, fixture provenanceFixture) {
	t.Helper()
	report := verifyProvenanceFixture(fixture)
	if report.Overall != "invalid" || report.FailureStage != "proof_structure" {
		t.Fatalf("report = %+v, want invalid at proof_structure", report)
	}
}

func appendProvenanceTestEntry(t *testing.T, fixture *provenanceFixture) {
	t.Helper()
	previous, err := base64.StdEncoding.DecodeString(fixture.Entries[len(fixture.Entries)-1].SignedB64)
	if err != nil {
		t.Fatal(err)
	}
	var signed signedProvenanceProof
	if err := json.Unmarshal(previous, &signed); err != nil {
		t.Fatal(err)
	}
	previousHash := sha256.Sum256(previous)
	signed.ChainSeq++
	signed.ChainPrevHash = "sha256:" + hex.EncodeToString(previousHash[:])
	raw, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	privateKey := provenanceFixtureSigningKey()
	fixture.Entries = append(fixture.Entries, provenanceFixtureEntry{
		SignedB64: base64.StdEncoding.EncodeToString(raw),
		Signature: "ed25519:" + hex.EncodeToString(ed25519.Sign(privateKey, raw)),
	})
}

func validProvenanceFixture(t *testing.T, input string, start, end uint64) provenanceFixture {
	t.Helper()
	privateKey := provenanceFixtureSigningKey()
	publicKey := privateKey.Public().(ed25519.PublicKey)
	commitmentKey := sha256.Sum256([]byte("pipelock-provenance-fixture-commitment-key-v1"))
	recipe := normalize.Recipe{TransformProfileDigest: normalize.EvidenceProvenanceProfileV1Digest, Operations: []normalize.Operation{{Kind: normalize.OperationIdentity}}}
	source := contractreceipt.ProvenanceSource{SourceOrdinal: 1, SourceID: "fixture-source", Recipe: recipe}
	viewCommitment, err := contractreceipt.CommitView(commitmentKey[:], source, input)
	if err != nil {
		t.Fatal(err)
	}
	source.ViewCommitment = viewCommitment
	match := contractreceipt.ProvenanceMatch{MatchOrdinal: 1, ByteStart: start, ByteEnd: end, MatchClass: "credential"}
	matchCommitment, err := contractreceipt.CommitMatch(commitmentKey[:], source.SourceID, recipe, viewCommitment, match)
	if err != nil {
		t.Fatal(err)
	}
	match.MatchCommitment = matchCommitment
	source.Matches = []contractreceipt.ProvenanceMatch{match}
	proof := contractreceipt.EvidenceProvenanceProof{Version: contractreceipt.EvidenceProvenanceProofVersionV1, TransformProfileDigest: normalize.EvidenceProvenanceProfileV1Digest, Sources: []contractreceipt.ProvenanceSource{source}}
	signed := signedProvenanceProof{ChainSeq: 0, ChainPrevHash: "genesis", CriticalFeatures: []string{provenanceFeature}, Proof: proof}
	raw, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	return provenanceFixture{
		Format:  provenanceFixtureFormat,
		Entries: []provenanceFixtureEntry{{SignedB64: base64.StdEncoding.EncodeToString(raw), Signature: "ed25519:" + hex.EncodeToString(ed25519.Sign(privateKey, raw))}},
		Verification: provenanceVerificationInputs{
			SignerPublicKeyHex: hex.EncodeToString(publicKey), CommitmentKeyHex: hex.EncodeToString(commitmentKey[:]),
			Sources: []provenanceFixtureSource{{SourceID: source.SourceID, BytesB64: base64.StdEncoding.EncodeToString([]byte(input))}},
		},
	}
}

func resignProvenanceFixture(t *testing.T, fixture *provenanceFixture, mutate func(*signedProvenanceProof)) {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(fixture.Entries[0].SignedB64)
	if err != nil {
		t.Fatal(err)
	}
	var signed signedProvenanceProof
	if err := json.Unmarshal(raw, &signed); err != nil {
		t.Fatal(err)
	}
	mutate(&signed)
	raw, err = json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	privateKey := provenanceFixtureSigningKey()
	fixture.Entries[0] = provenanceFixtureEntry{SignedB64: base64.StdEncoding.EncodeToString(raw), Signature: "ed25519:" + hex.EncodeToString(ed25519.Sign(privateKey, raw))}
}

func provenanceFixtureSigningKey() ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("pipelock-provenance-fixture-signing-key-v1"))
	return ed25519.NewKeyFromSeed(seed[:])
}
