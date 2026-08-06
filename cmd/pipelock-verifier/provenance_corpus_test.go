// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	contractreceipt "github.com/luckyPipewrench/pipelock/internal/contract/receipt"
	"github.com/luckyPipewrench/pipelock/internal/normalize"
)

func TestCommittedProvenanceCorpusCoverageAndKnownAnswers(t *testing.T) {
	dir := filepath.Clean(filepath.Join("..", "..", "sdk", "conformance", "testdata", "provenance"))
	fixtures, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	caseCount := 0
	operationCount := 0
	propertyCount := 0
	for _, path := range fixtures {
		if strings.HasSuffix(path, ".expect.json") {
			continue
		}
		caseCount++
		base := filepath.Base(path)
		if strings.HasPrefix(base, "o") {
			operationCount++
		}
		if strings.HasPrefix(base, "r") {
			propertyCount++
		}
		if _, err := os.Stat(strings.TrimSuffix(path, ".json") + ".expect.json"); err != nil {
			t.Fatalf("%s lacks exact expected staged output: %v", base, err)
		}
	}
	const proofCases = 41
	const propertyCases = 16
	wantCases := proofCases + len(normalize.SupportedOperationKinds()) + propertyCases
	if caseCount != wantCases || operationCount != len(normalize.SupportedOperationKinds()) || propertyCount != propertyCases {
		t.Fatalf("corpus counts = cases %d operations %d properties %d; want %d, %d, %d", caseCount, operationCount, propertyCount, wantCases, len(normalize.SupportedOperationKinds()), propertyCases)
	}

	data, err := os.ReadFile(filepath.Join(dir, "p00-valid.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture provenanceFixture
	if err := decodeStrictJSON(data, &fixture); err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(fixture.Entries[0].SignedB64)
	if err != nil {
		t.Fatal(err)
	}
	var signed signedProvenanceProof
	if err := decodeStrictJSON(raw, &signed); err != nil {
		t.Fatal(err)
	}
	const knownView = "hmac-sha256:95019d8bbcbb7138e9a3c3a00ba701c3b29283da60dfbf56cedb068572928902"
	const knownMatch = "hmac-sha256:91d664ec3a3385a30910ffd5e4433051ff853b5eacdbdd941468d32d0b00ac2f"
	if signed.Proof.Sources[0].ViewCommitment != knownView || signed.Proof.Sources[0].Matches[0].MatchCommitment != knownMatch {
		t.Fatalf("known-answer commitments drifted: view %q match %q", signed.Proof.Sources[0].ViewCommitment, signed.Proof.Sources[0].Matches[0].MatchCommitment)
	}
	commitmentKey := sha256.Sum256([]byte("pipelock-provenance-fixture-commitment-key-v1"))
	if got := corpusMatchCommitment(t, commitmentKey[:], signed.Proof.Sources[0], signed.Proof.Sources[0].Matches[0]); got != knownMatch {
		t.Fatalf("corpus commitment helper = %q, want %q", got, knownMatch)
	}

	data, err = os.ReadFile(filepath.Join(dir, "p33-coordinate-non-positive-length.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := decodeStrictJSON(data, &fixture); err != nil {
		t.Fatal(err)
	}
	raw, err = base64.StdEncoding.DecodeString(fixture.Entries[0].SignedB64)
	if err != nil {
		t.Fatal(err)
	}
	if err := decodeStrictJSON(raw, &signed); err != nil {
		t.Fatal(err)
	}
	match := signed.Proof.Sources[0].Matches[0]
	if got := corpusMatchCommitment(t, commitmentKey[:], signed.Proof.Sources[0], match); match.MatchCommitment != got {
		t.Fatalf("p33 match commitment = %q, want recomputed %q", match.MatchCommitment, got)
	}
}

// TestGenerateProvenanceCorpus is an explicit, deterministic fixture writer.
// Normal test runs only exercise the committed corpus through the cross-language
// gate; regeneration requires UPDATE_PROVENANCE_FIXTURES=1.
func TestGenerateProvenanceCorpus(t *testing.T) {
	if os.Getenv("UPDATE_PROVENANCE_FIXTURES") != "1" {
		t.Skip("set UPDATE_PROVENANCE_FIXTURES=1 to regenerate fixtures")
	}
	dir := filepath.Clean(filepath.Join("..", "..", "sdk", "conformance", "testdata", "provenance"))
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}

	baseline := corpusFixture(t, normalize.Recipe{TransformProfileDigest: normalize.EvidenceProvenanceProfileV1Digest, Operations: []normalize.Operation{{Kind: normalize.OperationIdentity}}}, "A💩B", 1, 5)
	writeProvenanceCase(t, dir, "p00-valid", baseline)

	chain := cloneCorpusFixture(t, baseline)
	appendCorpusEntry(t, &chain)
	writeProvenanceCase(t, dir, "p01-valid-chain", chain)

	signature := cloneCorpusFixture(t, baseline)
	signature.Entries[0].Signature = "ed25519:" + repeatHexByte(0, ed25519.SignatureSize)
	writeProvenanceCase(t, dir, "p02-signature-invalid", signature)

	for _, tc := range []struct {
		id     string
		mutate func(*signedProvenanceProof, *provenanceFixture)
	}{
		{"p03-chain-sequence", func(s *signedProvenanceProof, _ *provenanceFixture) { s.ChainSeq = 1 }},
		{"p03b-chain-previous-hash", func(s *signedProvenanceProof, _ *provenanceFixture) {
			s.ChainPrevHash = "sha256:" + repeatHexByte(0, sha256.Size)
		}},
		{"p04-critical-missing", func(s *signedProvenanceProof, _ *provenanceFixture) { s.CriticalFeatures = nil }},
		{"p05-critical-unknown", func(s *signedProvenanceProof, _ *provenanceFixture) { s.CriticalFeatures = []string{"unknown"} }},
		{"p06-critical-duplicate", func(s *signedProvenanceProof, _ *provenanceFixture) {
			s.CriticalFeatures = []string{provenanceFeature, provenanceFeature}
		}},
		{"p07-proof-version", func(s *signedProvenanceProof, _ *provenanceFixture) {
			s.Proof.Version = "pipelock-evidence-provenance-proof/v2"
		}},
		{"p08-profile-digest", func(s *signedProvenanceProof, _ *provenanceFixture) {
			s.Proof.TransformProfileDigest = "sha256:" + repeatHexByte(0xaa, sha256.Size)
		}},
		{"p09-source-ordinal-context", func(s *signedProvenanceProof, _ *provenanceFixture) { s.Proof.Sources[0].SourceOrdinal = 2 }},
		{"p10-source-id-context", func(s *signedProvenanceProof, f *provenanceFixture) {
			s.Proof.Sources[0].SourceID = "renamed"
			f.Verification.Sources[0].SourceID = "renamed"
		}},
		{"p11-match-ordinal-context", func(s *signedProvenanceProof, _ *provenanceFixture) { s.Proof.Sources[0].Matches[0].MatchOrdinal = 2 }},
		{"p12-match-class-context", func(s *signedProvenanceProof, _ *provenanceFixture) {
			s.Proof.Sources[0].Matches[0].MatchClass = "token"
		}},
		{"p13-view-commitment", func(s *signedProvenanceProof, _ *provenanceFixture) {
			s.Proof.Sources[0].ViewCommitment = "hmac-sha256:" + repeatHexByte(0, sha256.Size)
		}},
		{"p14-match-commitment", func(s *signedProvenanceProof, _ *provenanceFixture) {
			s.Proof.Sources[0].Matches[0].MatchCommitment = "hmac-sha256:" + repeatHexByte(0, sha256.Size)
		}},
		{"p15-coordinate-start-boundary", func(s *signedProvenanceProof, _ *provenanceFixture) { s.Proof.Sources[0].Matches[0].ByteStart = 2 }},
		{"p16-coordinate-end-boundary", func(s *signedProvenanceProof, _ *provenanceFixture) { s.Proof.Sources[0].Matches[0].ByteEnd = 4 }},
		{"p17-coordinate-out-of-bounds", func(s *signedProvenanceProof, _ *provenanceFixture) { s.Proof.Sources[0].Matches[0].ByteEnd = 7 }},
		{"p18-coordinate-context", func(s *signedProvenanceProof, _ *provenanceFixture) { s.Proof.Sources[0].Matches[0].ByteStart = 0 }},
		{"p19-source-bytes-context", func(_ *signedProvenanceProof, f *provenanceFixture) {
			f.Verification.Sources[0].BytesB64 = base64.StdEncoding.EncodeToString([]byte("Z💩B"))
		}},
		{"p20-wrong-commitment-key", func(_ *signedProvenanceProof, f *provenanceFixture) {
			f.Verification.CommitmentKeyHex = repeatHexByte(0xbb, sha256.Size)
		}},
		{"p21-missing-source", func(_ *signedProvenanceProof, f *provenanceFixture) { f.Verification.Sources = nil }},
		{"p22-missing-commitment-key", func(_ *signedProvenanceProof, f *provenanceFixture) { f.Verification.CommitmentKeyHex = "" }},
	} {
		fixture := cloneCorpusFixture(t, baseline)
		mutateCorpusFixture(t, &fixture, tc.mutate)
		writeProvenanceCase(t, dir, tc.id, fixture)
	}

	binary := "fixture-binary"
	rules := "fixture-rules"
	artifacts := cloneCorpusFixture(t, baseline)
	mutateCorpusFixture(t, &artifacts, func(s *signedProvenanceProof, f *provenanceFixture) {
		binarySum := sha256.Sum256([]byte(binary))
		rulesSum := sha256.Sum256([]byte(rules))
		s.Proof.Producer.BinaryDigest = stringRef("sha256:" + hex.EncodeToString(binarySum[:]))
		s.Proof.Producer.RulesetDigest = stringRef("sha256:" + hex.EncodeToString(rulesSum[:]))
		f.Verification.BinaryB64 = stringRef(base64.StdEncoding.EncodeToString([]byte(binary)))
		f.Verification.RulesetB64 = stringRef(base64.StdEncoding.EncodeToString([]byte(rules)))
	})
	writeProvenanceCase(t, dir, "p23-artifacts-matched", artifacts)
	artifactMismatch := cloneCorpusFixture(t, artifacts)
	artifactMismatch.Verification.BinaryB64 = stringRef(base64.StdEncoding.EncodeToString([]byte("wrong")))
	writeProvenanceCase(t, dir, "p24-artifact-digest", artifactMismatch)
	artifactUnchecked := cloneCorpusFixture(t, artifacts)
	artifactUnchecked.Verification.BinaryB64 = nil
	writeProvenanceCase(t, dir, "p25-artifact-unchecked", artifactUnchecked)
	artifactMismatchAfterUnavailable := cloneCorpusFixture(t, artifacts)
	artifactMismatchAfterUnavailable.Verification.BinaryB64 = nil
	artifactMismatchAfterUnavailable.Verification.RulesetB64 = stringRef(base64.StdEncoding.EncodeToString([]byte("wrong")))
	writeProvenanceCase(t, dir, "p26-artifact-mismatch-after-unavailable", artifactMismatchAfterUnavailable)

	sourceMismatchAfterUnavailable := cloneCorpusFixture(t, baseline)
	mutateCorpusFixture(t, &sourceMismatchAfterUnavailable, func(s *signedProvenanceProof, f *provenanceFixture) {
		commitmentKey := sha256.Sum256([]byte("pipelock-provenance-fixture-commitment-key-v1"))
		input := "second-view"
		second := s.Proof.Sources[0]
		second.SourceOrdinal = 2
		second.SourceID = "second-source"
		second.Matches = []contractreceipt.ProvenanceMatch{}
		var err error
		second.ViewCommitment, err = contractreceipt.CommitView(commitmentKey[:], second, input)
		if err != nil {
			t.Fatal(err)
		}
		match := contractreceipt.ProvenanceMatch{MatchOrdinal: 1, ByteStart: 0, ByteEnd: 6, MatchClass: "credential"}
		match.MatchCommitment, err = contractreceipt.CommitMatch(commitmentKey[:], second.SourceID, second.Recipe, second.ViewCommitment, match)
		if err != nil {
			t.Fatal(err)
		}
		second.Matches = []contractreceipt.ProvenanceMatch{match}
		s.Proof.Sources = append(s.Proof.Sources, second)
		f.Verification.Sources = []provenanceFixtureSource{{SourceID: second.SourceID, BytesB64: base64.StdEncoding.EncodeToString([]byte("second-viex"))}}
	})
	writeProvenanceCase(t, dir, "p27-source-mismatch-after-unavailable", sourceMismatchAfterUnavailable)

	missingThenValid := cloneCorpusFixture(t, baseline)
	mutateCorpusFixture(t, &missingThenValid, func(s *signedProvenanceProof, f *provenanceFixture) {
		commitmentKey := sha256.Sum256([]byte("pipelock-provenance-fixture-commitment-key-v1"))
		input := "second-view"
		second := s.Proof.Sources[0]
		second.SourceOrdinal = 2
		second.SourceID = "second-source"
		second.Matches = []contractreceipt.ProvenanceMatch{}
		var err error
		second.ViewCommitment, err = contractreceipt.CommitView(commitmentKey[:], second, input)
		if err != nil {
			t.Fatal(err)
		}
		s.Proof.Sources = append(s.Proof.Sources, second)
		f.Verification.Sources = []provenanceFixtureSource{{SourceID: second.SourceID, BytesB64: base64.StdEncoding.EncodeToString([]byte(input))}}
	})
	writeProvenanceCase(t, dir, "p28-missing-source-before-valid-source", missingThenValid)

	duplicateSignedKey := cloneCorpusFixture(t, baseline)
	raw, err := base64.StdEncoding.DecodeString(duplicateSignedKey.Entries[0].SignedB64)
	if err != nil {
		t.Fatal(err)
	}
	raw = bytes.Replace(raw, []byte(`{"chain_seq":0,`), []byte(`{"chain_seq":0,"chain_seq":0,`), 1)
	if bytes.Count(raw, []byte(`"chain_seq":0`)) != 2 {
		t.Fatal("failed to construct duplicate signed chain_seq key")
	}
	privateKey := provenanceFixtureSigningKey()
	duplicateSignedKey.Entries[0] = provenanceFixtureEntry{
		SignedB64: base64.StdEncoding.EncodeToString(raw),
		Signature: "ed25519:" + hex.EncodeToString(ed25519.Sign(privateKey, raw)),
	}
	writeProvenanceCase(t, dir, "p29-duplicate-signed-key", duplicateSignedKey)

	for _, tc := range []struct {
		id      string
		matches []contractreceipt.ProvenanceMatch
	}{
		{"p30-coordinate-overlap", []contractreceipt.ProvenanceMatch{{MatchOrdinal: 1, ByteStart: 0, ByteEnd: 3, MatchClass: "first"}, {MatchOrdinal: 2, ByteStart: 2, ByteEnd: 5, MatchClass: "second"}}},
		{"p31-coordinate-unsorted", []contractreceipt.ProvenanceMatch{{MatchOrdinal: 1, ByteStart: 3, ByteEnd: 5, MatchClass: "first"}, {MatchOrdinal: 2, ByteStart: 0, ByteEnd: 1, MatchClass: "second"}}},
		{"p32-coordinate-duplicate-start", []contractreceipt.ProvenanceMatch{{MatchOrdinal: 1, ByteStart: 0, ByteEnd: 1, MatchClass: "first"}, {MatchOrdinal: 2, ByteStart: 0, ByteEnd: 2, MatchClass: "second"}}},
	} {
		fixture := cloneCorpusFixture(t, baseline)
		replaceCorpusMatches(t, &fixture, tc.matches)
		writeProvenanceCase(t, dir, tc.id, fixture)
	}
	invalidLength := cloneCorpusFixture(t, baseline)
	replaceCorpusMatches(t, &invalidLength, []contractreceipt.ProvenanceMatch{
		{MatchOrdinal: 1, ByteStart: 1, ByteEnd: 1, MatchClass: "credential"},
	})
	writeProvenanceCase(t, dir, "p33-coordinate-non-positive-length", invalidLength)

	emptyMatchClass := cloneCorpusFixture(t, baseline)
	replaceCorpusMatches(t, &emptyMatchClass, []contractreceipt.ProvenanceMatch{
		{MatchOrdinal: 1, ByteStart: 1, ByteEnd: 5, MatchClass: ""},
	})
	writeProvenanceCase(t, dir, "p34-empty-match-class", emptyMatchClass)

	nonCanonicalEnvelope := corpusMustJSON(t, baseline)
	nonCanonicalEnvelope = bytes.Replace(nonCanonicalEnvelope, []byte(`"format":`), []byte(`"FORMAT":`), 1)
	if bytes.Contains(nonCanonicalEnvelope, []byte(`"format":`)) {
		t.Fatal("failed to construct non-canonical envelope key")
	}
	writeRawProvenanceCase(t, dir, "p35-noncanonical-envelope-key", nonCanonicalEnvelope)

	nonCanonicalSignedKey := cloneCorpusFixture(t, baseline)
	raw, err = base64.StdEncoding.DecodeString(nonCanonicalSignedKey.Entries[0].SignedB64)
	if err != nil {
		t.Fatal(err)
	}
	raw = bytes.Replace(raw, []byte(`{"chain_seq":0,`), []byte(`{"CHAIN_SEQ":0,`), 1)
	if bytes.Contains(raw, []byte(`"chain_seq":0`)) {
		t.Fatal("failed to construct non-canonical signed key")
	}
	nonCanonicalSignedKey.Entries[0] = provenanceFixtureEntry{
		SignedB64: base64.StdEncoding.EncodeToString(raw),
		Signature: "ed25519:" + hex.EncodeToString(ed25519.Sign(privateKey, raw)),
	}
	writeProvenanceCase(t, dir, "p36-noncanonical-signed-key", nonCanonicalSignedKey)

	zeroMatches := cloneCorpusFixture(t, baseline)
	replaceCorpusMatches(t, &zeroMatches, []contractreceipt.ProvenanceMatch{})
	writeProvenanceCase(t, dir, "p37-zero-matches", zeroMatches)

	missingThenBadLocation := cloneCorpusFixture(t, baseline)
	mutateCorpusFixture(t, &missingThenBadLocation, func(s *signedProvenanceProof, f *provenanceFixture) {
		commitmentKey := sha256.Sum256([]byte("pipelock-provenance-fixture-commitment-key-v1"))
		missing := s.Proof.Sources[0]
		missing.SourceID = "missing-source"
		missing.SourceOrdinal = 2
		available := s.Proof.Sources[0]
		match := available.Matches[0]
		match.ByteEnd = 99
		match.MatchCommitment = corpusMatchCommitment(t, commitmentKey[:], available, match)
		available.Matches = []contractreceipt.ProvenanceMatch{match}
		s.Proof.Sources = []contractreceipt.ProvenanceSource{available, missing}
		f.Verification.Sources = []provenanceFixtureSource{{
			SourceID: available.SourceID,
			BytesB64: base64.StdEncoding.EncodeToString([]byte("A💩B")),
		}}
	})
	writeProvenanceCase(t, dir, "p38-bad-location-before-missing-source", missingThenBadLocation)

	artifactUncheckedThenMatched := cloneCorpusFixture(t, baseline)
	mutateCorpusFixture(t, &artifactUncheckedThenMatched, func(s *signedProvenanceProof, _ *provenanceFixture) {
		digest := sha256.Sum256([]byte("unavailable-binary"))
		s.Proof.Producer.BinaryDigest = stringRef("sha256:" + hex.EncodeToString(digest[:]))
	})
	appendCorpusEntry(t, &artifactUncheckedThenMatched)
	raw, err = base64.StdEncoding.DecodeString(artifactUncheckedThenMatched.Entries[1].SignedB64)
	if err != nil {
		t.Fatal(err)
	}
	var secondEntry signedProvenanceProof
	if err := json.Unmarshal(raw, &secondEntry); err != nil {
		t.Fatal(err)
	}
	secondEntry.Proof.Producer = contractreceipt.ProducerAttestation{}
	raw = corpusMustJSON(t, secondEntry)
	artifactUncheckedThenMatched.Entries[1] = provenanceFixtureEntry{
		SignedB64: base64.StdEncoding.EncodeToString(raw),
		Signature: "ed25519:" + hex.EncodeToString(ed25519.Sign(privateKey, raw)),
	}
	writeProvenanceCase(t, dir, "p39-artifact-unchecked-before-matched", artifactUncheckedThenMatched)

	operationCases := successfulOperationCases()
	for index, operationCase := range operationCases {
		view, err := operationCase.recipe.Apply(operationCase.input)
		if err != nil {
			t.Fatalf("%s: apply recipe: %v", operationCase.name, err)
		}
		if view != operationCase.output {
			t.Fatalf("%s: recipe produced %q, declared output %q", operationCase.name, view, operationCase.output)
		}
		fixture := corpusFixture(t, operationCase.recipe, operationCase.input, 0, uint64(len(view)))
		mutateCorpusFixture(t, &fixture, func(s *signedProvenanceProof, _ *provenanceFixture) {
			s.Proof.Sources[0].Recipe.Operations = append(s.Proof.Sources[0].Recipe.Operations, normalize.Operation{Kind: normalize.OperationIdentity})
		})
		writeProvenanceCase(t, dir, "o"+twoDigits(index)+"-"+operationCase.name+"-recipe-context", fixture)
	}

	for seed := 0; seed < 16; seed++ {
		input := "prefix-" + strconv.Itoa(seed) + "-💩-suffix"
		fixture := corpusFixture(t, normalize.Recipe{TransformProfileDigest: normalize.EvidenceProvenanceProfileV1Digest, Operations: []normalize.Operation{{Kind: normalize.OperationIdentity}}}, input, 0, 6)
		fixture.Verification.Sources[0].BytesB64 = base64.StdEncoding.EncodeToString([]byte(input[:len(input)-6] + "tuffix"))
		writeProvenanceCase(t, dir, "r"+twoDigits(seed)+"-deterministic-property", fixture)
	}
}

type corpusOperationCase struct {
	name   string
	recipe normalize.Recipe
	input  string
	output string
}

func successfulOperationCases() []corpusOperationCase {
	digest := normalize.EvidenceProvenanceProfileV1Digest
	return []corpusOperationCase{
		{"identity", normalize.Recipe{TransformProfileDigest: digest, Operations: []normalize.Operation{{Kind: normalize.OperationIdentity}}}, "Value", "Value"},
		// The query parameter is deliberately named "q" rather than a credential
		// word. This case only exercises repeated-parameter occurrence selection,
		// and a name like "token" makes the dogfood self-scan flag the fixture as
		// a credential in a URL, which is a false positive on the parameter name.
		{"url-component", normalize.Recipe{TransformProfileDigest: digest, Operations: []normalize.Operation{{Kind: normalize.OperationURLComponent, Component: normalize.ComponentQueryVal, Selector: "q", Occurrence: 1}}}, "https://api.vendor.example/?q=first&q=second", "second"},
		{"percent-decode", normalize.Recipe{TransformProfileDigest: digest, Operations: []normalize.Operation{{Kind: normalize.OperationPercentDecode, Passes: 2}}}, "%2561", "a"},
		{"dlp-normalize", normalize.Recipe{TransformProfileDigest: digest, Operations: []normalize.Operation{{Kind: normalize.OperationDLPNormalize, Profile: "pipelock-dlp-v1"}}}, "Ｓｅｃｒｅｔ", "Secret"},
		{"lowercase", normalize.Recipe{TransformProfileDigest: digest, Operations: []normalize.Operation{{Kind: normalize.OperationLowercase}}}, "VaLuE", "value"},
		{"invisible-strip", normalize.Recipe{TransformProfileDigest: digest, Operations: []normalize.Operation{{Kind: normalize.OperationInvisibleStrip}}}, "se\u200bcret", "secret"},
		{"hex-decode", normalize.Recipe{TransformProfileDigest: digest, Operations: []normalize.Operation{{Kind: normalize.OperationHexDecode}}}, "76616c7565", "value"},
		{"base32-decode", normalize.Recipe{TransformProfileDigest: digest, Operations: []normalize.Operation{{Kind: normalize.OperationBase32Decode, DecodePadding: true}}}, "OZQWY5LF", "value"},
		{"base64-decode", normalize.Recipe{TransformProfileDigest: digest, Operations: []normalize.Operation{{Kind: normalize.OperationBase64Decode, DecodePadding: true}}}, "dmFsdWU=", "value"},
		{"leetspeak", normalize.Recipe{TransformProfileDigest: digest, Operations: []normalize.Operation{{Kind: normalize.OperationLeetspeak}}}, "s3cr3t", "secret"},
		{"vowel-fold", normalize.Recipe{TransformProfileDigest: digest, Operations: []normalize.Operation{{Kind: normalize.OperationVowelFold}}}, "ignore", "agnara"},
		{"query-unescape", normalize.Recipe{TransformProfileDigest: digest, Operations: []normalize.Operation{{Kind: normalize.OperationQueryUnescape}}}, "a%2521", "a!"},
		{"invisible-space", normalize.Recipe{TransformProfileDigest: digest, Operations: []normalize.Operation{{Kind: normalize.OperationInvisibleSpace}}}, "a\u200bb", "a b"},
		{"matching-normalize", normalize.Recipe{TransformProfileDigest: digest, Operations: []normalize.Operation{{Kind: normalize.OperationMatchingNormalize, Profile: "pipelock-matching-v1"}}}, "Ａ\u200bB\u00a0C", "AB C"},
		{"hex-decode-liberal", normalize.Recipe{TransformProfileDigest: digest, Operations: []normalize.Operation{{Kind: normalize.OperationHexDecodeLiberal}}}, "4A", "J"},
		{"base32-decode-liberal", normalize.Recipe{TransformProfileDigest: digest, Operations: []normalize.Operation{{Kind: normalize.OperationBase32DecodeLiberal}}}, "MY", "f"},
		{"base64-decode-liberal", normalize.Recipe{TransformProfileDigest: digest, Operations: []normalize.Operation{{Kind: normalize.OperationBase64DecodeLiberal, Alphabet: "standard", DecodePadding: true}}}, "Zh==", "f"},
		{"encoded-token-normalize", normalize.Recipe{TransformProfileDigest: digest, Operations: []normalize.Operation{{Kind: normalize.OperationEncodedTokenNormalize, Alphabet: "base64_standard"}}}, "S G.k=", "SGk="},
		{"text-segment", normalize.Recipe{TransformProfileDigest: digest, Operations: []normalize.Operation{{Kind: normalize.OperationTextSegment, Occurrence: 1}}}, "one/two", "two"},
		{"html-entity-decode", normalize.Recipe{TransformProfileDigest: digest, Operations: []normalize.Operation{{Kind: normalize.OperationHTMLEntityDecode}}}, "&amp;", "&"},
		{"whitespace-compact", normalize.Recipe{TransformProfileDigest: digest, Operations: []normalize.Operation{{Kind: normalize.OperationWhitespaceCompact}}}, "a b\n", "ab"},
		{"url-noise-strip", normalize.Recipe{TransformProfileDigest: digest, Operations: []normalize.Operation{{Kind: normalize.OperationURLNoiseStrip}}}, "a./ b", "ab"},
		{"ordered-query-concat", normalize.Recipe{TransformProfileDigest: digest, Operations: []normalize.Operation{{Kind: normalize.OperationOrderedQueryConcat}}}, "a=x&b=y", "xy"},
		{"query-subsequence", normalize.Recipe{TransformProfileDigest: digest, Operations: []normalize.Operation{{Kind: normalize.OperationQuerySubsequence, Indices: normalize.QueryIndices{0, 2}}}}, "a=one&b=two&c=three", "onethree"},
		{"hostname-dot-remove", normalize.Recipe{TransformProfileDigest: digest, Operations: []normalize.Operation{{Kind: normalize.OperationHostnameDotRemove}}}, "api.vendor.example", "apivendorexample"},
		{"encoded-run", normalize.Recipe{TransformProfileDigest: digest, Operations: []normalize.Operation{{Kind: normalize.OperationEncodedRun, Occurrence: 1, MinimumLength: 6}}}, "prefix:QUJDRA== suffix", "QUJDRA=="},
		{"canary-canonicalize", normalize.Recipe{TransformProfileDigest: digest, Operations: []normalize.Operation{{Kind: normalize.OperationCanaryCanonicalize}}}, "Ab-c_d/e?f", "Abcdef"},
	}
}

func corpusFixture(t *testing.T, recipe normalize.Recipe, input string, start, end uint64) provenanceFixture {
	t.Helper()
	seed := sha256.Sum256([]byte("pipelock-provenance-fixture-signing-key-v1"))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	publicKey := privateKey.Public().(ed25519.PublicKey)
	commitmentKey := sha256.Sum256([]byte("pipelock-provenance-fixture-commitment-key-v1"))
	source := contractreceipt.ProvenanceSource{SourceOrdinal: 1, SourceID: "fixture-source", Recipe: recipe}
	view, err := recipe.Apply(input)
	if err != nil {
		t.Fatal(err)
	}
	source.ViewCommitment, err = contractreceipt.CommitView(commitmentKey[:], source, view)
	if err != nil {
		t.Fatal(err)
	}
	match := contractreceipt.ProvenanceMatch{MatchOrdinal: 1, ByteStart: start, ByteEnd: end, MatchClass: "credential"}
	match.MatchCommitment, err = contractreceipt.CommitMatch(commitmentKey[:], source.SourceID, recipe, source.ViewCommitment, match)
	if err != nil {
		t.Fatal(err)
	}
	source.Matches = []contractreceipt.ProvenanceMatch{match}
	proof := contractreceipt.EvidenceProvenanceProof{Version: contractreceipt.EvidenceProvenanceProofVersionV1, TransformProfileDigest: normalize.EvidenceProvenanceProfileV1Digest, Sources: []contractreceipt.ProvenanceSource{source}}
	signed := signedProvenanceProof{ChainSeq: 0, ChainPrevHash: "genesis", CriticalFeatures: []string{provenanceFeature}, Proof: proof}
	raw := corpusMustJSON(t, signed)
	return provenanceFixture{Format: provenanceFixtureFormat, Entries: []provenanceFixtureEntry{{SignedB64: base64.StdEncoding.EncodeToString(raw), Signature: "ed25519:" + hex.EncodeToString(ed25519.Sign(privateKey, raw))}}, Verification: provenanceVerificationInputs{SignerPublicKeyHex: hex.EncodeToString(publicKey), CommitmentKeyHex: hex.EncodeToString(commitmentKey[:]), Sources: []provenanceFixtureSource{{SourceID: source.SourceID, BytesB64: base64.StdEncoding.EncodeToString([]byte(input))}}}}
}

func mutateCorpusFixture(t *testing.T, fixture *provenanceFixture, mutate func(*signedProvenanceProof, *provenanceFixture)) {
	t.Helper()
	var signed signedProvenanceProof
	raw, err := base64.StdEncoding.DecodeString(fixture.Entries[0].SignedB64)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &signed); err != nil {
		t.Fatal(err)
	}
	mutate(&signed, fixture)
	raw = corpusMustJSON(t, signed)
	seed := sha256.Sum256([]byte("pipelock-provenance-fixture-signing-key-v1"))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	fixture.Entries[0] = provenanceFixtureEntry{SignedB64: base64.StdEncoding.EncodeToString(raw), Signature: "ed25519:" + hex.EncodeToString(ed25519.Sign(privateKey, raw))}
}

func replaceCorpusMatches(t *testing.T, fixture *provenanceFixture, matches []contractreceipt.ProvenanceMatch) {
	t.Helper()
	mutateCorpusFixture(t, fixture, func(s *signedProvenanceProof, _ *provenanceFixture) {
		commitmentKey := sha256.Sum256([]byte("pipelock-provenance-fixture-commitment-key-v1"))
		source := &s.Proof.Sources[0]
		for index := range matches {
			matches[index].MatchCommitment = corpusMatchCommitment(t, commitmentKey[:], *source, matches[index])
		}
		source.Matches = matches
	})
}

func corpusMatchCommitment(t *testing.T, key []byte, source contractreceipt.ProvenanceSource, match contractreceipt.ProvenanceMatch) string {
	t.Helper()
	recipe := corpusRecipeBytes(t, source.Recipe)
	mac := hmac.New(sha256.New, key)
	for _, part := range [][]byte{
		[]byte("pipelock/evidence-provenance/match/v1"),
		[]byte(source.SourceID),
		[]byte(source.Recipe.TransformProfileDigest),
		recipe,
		[]byte(source.ViewCommitment),
		corpusUint64(match.MatchOrdinal),
		corpusUint64(match.ByteStart),
		corpusUint64(match.ByteEnd),
		[]byte(match.MatchClass),
	} {
		_, _ = mac.Write(corpusFrame(part))
	}
	return "hmac-sha256:" + hex.EncodeToString(mac.Sum(nil))
}

func corpusRecipeBytes(t *testing.T, recipe normalize.Recipe) []byte {
	t.Helper()
	result := corpusFrame([]byte("pipelock/evidence-provenance/recipe/v1"))
	result = append(result, corpusFrame([]byte(recipe.TransformProfileDigest))...)
	result = append(result, corpusFrame(corpusUint64(uint64(len(recipe.Operations))))...)
	for _, operation := range recipe.Operations {
		var kind byte
		switch operation.Kind {
		case normalize.OperationIdentity:
			kind = 1
		case normalize.OperationURLComponent:
			kind = 2
		case normalize.OperationPercentDecode:
			kind = 3
		case normalize.OperationDLPNormalize:
			kind = 4
		case normalize.OperationLowercase:
			kind = 5
		case normalize.OperationInvisibleStrip:
			kind = 6
		case normalize.OperationHexDecode:
			kind = 7
		case normalize.OperationBase32Decode:
			kind = 8
		case normalize.OperationBase64Decode:
			kind = 9
		case normalize.OperationLeetspeak:
			kind = 10
		case normalize.OperationVowelFold:
			kind = 11
		case normalize.OperationQueryUnescape:
			kind = 12
		case normalize.OperationInvisibleSpace:
			kind = 13
		case normalize.OperationMatchingNormalize:
			kind = 14
		case normalize.OperationHexDecodeLiberal:
			kind = 15
		case normalize.OperationBase32DecodeLiberal:
			kind = 16
		case normalize.OperationBase64DecodeLiberal:
			kind = 17
		case normalize.OperationEncodedTokenNormalize:
			kind = 18
		case normalize.OperationTextSegment:
			kind = 19
		case normalize.OperationHTMLEntityDecode:
			kind = 20
		case normalize.OperationWhitespaceCompact:
			kind = 21
		case normalize.OperationURLNoiseStrip:
			kind = 22
		case normalize.OperationOrderedQueryConcat:
			kind = 23
		case normalize.OperationQuerySubsequence:
			kind = 24
		case normalize.OperationHostnameDotRemove:
			kind = 25
		case normalize.OperationEncodedRun:
			kind = 26
		case normalize.OperationCanaryCanonicalize:
			kind = 27
		default:
			t.Fatalf("unsupported corpus operation kind %q", operation.Kind)
		}
		component := byte(0)
		switch operation.Component {
		case "":
		case normalize.ComponentURL:
			component = 1
		case normalize.ComponentHostname:
			component = 2
		case normalize.ComponentPath:
			component = 3
		case normalize.ComponentQueryKey:
			component = 4
		case normalize.ComponentQueryVal:
			component = 5
		case normalize.ComponentRawQuery:
			component = 6
		default:
			t.Fatalf("unsupported corpus component %q", operation.Component)
		}
		var occurrence [4]byte
		binary.BigEndian.PutUint32(occurrence[:], operation.Occurrence)
		padding := byte(0)
		if operation.DecodePadding {
			padding = 1
		}
		encoded := make([]byte, 0, 64)
		for _, part := range [][]byte{{kind}, {component}, []byte(operation.Selector), occurrence[:], {operation.Passes}, []byte(operation.Profile), {padding}} {
			encoded = append(encoded, corpusFrame(part)...)
		}
		if kind >= 12 {
			var minimumLength [4]byte
			binary.BigEndian.PutUint32(minimumLength[:], operation.MinimumLength)
			for _, part := range [][]byte{[]byte(operation.Alphabet), operation.Indices, minimumLength[:]} {
				encoded = append(encoded, corpusFrame(part)...)
			}
		}
		result = append(result, corpusFrame(encoded)...)
	}
	return result
}

func corpusFrame(value []byte) []byte {
	result := make([]byte, 8, 8+len(value))
	binary.BigEndian.PutUint64(result, uint64(len(value)))
	return append(result, value...)
}

func corpusUint64(value uint64) []byte {
	result := make([]byte, 8)
	binary.BigEndian.PutUint64(result, value)
	return result
}

func appendCorpusEntry(t *testing.T, fixture *provenanceFixture) {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(fixture.Entries[0].SignedB64)
	if err != nil {
		t.Fatal(err)
	}
	var signed signedProvenanceProof
	if err := json.Unmarshal(raw, &signed); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	signed.ChainSeq = 1
	signed.ChainPrevHash = "sha256:" + hex.EncodeToString(sum[:])
	next := corpusMustJSON(t, signed)
	seed := sha256.Sum256([]byte("pipelock-provenance-fixture-signing-key-v1"))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	fixture.Entries = append(fixture.Entries, provenanceFixtureEntry{SignedB64: base64.StdEncoding.EncodeToString(next), Signature: "ed25519:" + hex.EncodeToString(ed25519.Sign(privateKey, next))})
}

func writeProvenanceCase(t *testing.T, dir, id string, fixture provenanceFixture) {
	t.Helper()
	writeJSONFile(t, filepath.Join(dir, id+".json"), fixture)
	// Expected staged reports are normative known answers, not generated
	// output. Recomputing them through the Go verifier would let a shared bug
	// bless itself during regeneration and make four-way agreement vacuous.
	// New cases require a separately reviewed, hand-authored .expect.json file.
}

func writeRawProvenanceCase(t *testing.T, dir, id string, data []byte) {
	t.Helper()
	data = append(data, '\n')
	if err := os.WriteFile(filepath.Join(dir, id+".json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeJSONFile(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func corpusMustJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func cloneCorpusFixture(t *testing.T, value provenanceFixture) provenanceFixture {
	t.Helper()
	data := corpusMustJSON(t, value)
	var clone provenanceFixture
	if err := json.Unmarshal(data, &clone); err != nil {
		t.Fatal(err)
	}
	return clone
}

func repeatHexByte(value byte, count int) string {
	values := make([]byte, count)
	for index := range values {
		values[index] = value
	}
	return hex.EncodeToString(values)
}

func stringRef(value string) *string { return &value }

func twoDigits(value int) string {
	if value < 10 {
		return "0" + strconv.Itoa(value)
	}
	return strconv.Itoa(value)
}
