// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"encoding/hex"
	"fmt"
	"math"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/normalize"
)

const provenanceTestCommitmentKey = "corpus-only-hmac-key-32-bytes-long!"

func TestProvenanceSourceValidateView(t *testing.T) {
	base := ProvenanceSource{SourceID: "fixture", Recipe: normalize.Recipe{TransformProfileDigest: normalize.EvidenceProvenanceProfileV1Digest, Operations: []normalize.Operation{{Kind: normalize.OperationIdentity}}}}
	for _, tc := range []struct {
		name    string
		matches []ProvenanceMatch
		want    string
	}{
		{"valid non-BMP and adjacency", []ProvenanceMatch{{ByteStart: 1, ByteEnd: 5}, {ByteStart: 5, ByteEnd: 6}}, ""},
		{"interval-inside-codepoint", []ProvenanceMatch{{ByteStart: 2, ByteEnd: 5}}, "splits UTF-8"},
		{"end-inside-codepoint", []ProvenanceMatch{{ByteStart: 1, ByteEnd: 4}}, "splits UTF-8"},
		{"out-of-bounds", []ProvenanceMatch{{ByteStart: 1, ByteEnd: 7}}, "out of bounds"},
		{"maximum interval end", []ProvenanceMatch{{ByteStart: 0, ByteEnd: math.MaxUint64}}, "out of bounds"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := base
			source.Matches = tc.matches
			err := source.ValidateView("A💩B")
			if tc.want == "" && err != nil {
				t.Fatal(err)
			}
			if tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestProvenanceSourceValidateViewRecipeAndUTF8Errors(t *testing.T) {
	for _, tc := range []struct {
		name   string
		source ProvenanceSource
		input  string
		want   string
	}{
		{
			name:   "recipe error",
			source: ProvenanceSource{SourceID: "fixture", Recipe: normalize.Recipe{TransformProfileDigest: normalize.EvidenceProvenanceProfileV1Digest, Operations: []normalize.Operation{{Kind: normalize.OperationPercentDecode}}}},
			input:  "value",
			want:   "recipe operation",
		},
		{
			name:   "invalid UTF-8 view",
			source: ProvenanceSource{SourceID: "fixture", Recipe: normalize.Recipe{TransformProfileDigest: normalize.EvidenceProvenanceProfileV1Digest, Operations: []normalize.Operation{{Kind: normalize.OperationHexDecode}}}},
			input:  "ff",
			want:   "hex decode output: invalid UTF-8",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.source.ValidateView(tc.input)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestEvidenceProvenanceProofValidate(t *testing.T) {
	valid := completeSources(t)
	for _, tc := range []struct {
		name    string
		sources []ProvenanceSource
		want    string
	}{
		{"valid", valid, ""},
		{"missing source ID", []ProvenanceSource{{SourceOrdinal: 1, Recipe: valid[0].Recipe, ViewCommitment: valid[0].ViewCommitment}}, "missing source ID"},
		{"duplicate source ID", []ProvenanceSource{{SourceOrdinal: 1, SourceID: "same", Recipe: valid[0].Recipe, ViewCommitment: valid[0].ViewCommitment}, {SourceOrdinal: 2, SourceID: "same", Recipe: valid[0].Recipe, ViewCommitment: valid[0].ViewCommitment}}, "duplicate source ID"},
		{"duplicate source ordinal", []ProvenanceSource{{SourceOrdinal: 2, SourceID: "first", Recipe: valid[0].Recipe, ViewCommitment: valid[0].ViewCommitment}, {SourceOrdinal: 2, SourceID: "second", Recipe: valid[0].Recipe, ViewCommitment: valid[0].ViewCommitment}}, "duplicate source ordinal"},
		{"non-increasing source ordinal", []ProvenanceSource{{SourceOrdinal: 2, SourceID: "first", Recipe: valid[0].Recipe, ViewCommitment: valid[0].ViewCommitment}, {SourceOrdinal: 1, SourceID: "second", Recipe: valid[0].Recipe, ViewCommitment: valid[0].ViewCommitment}}, "source ordinals must be strictly increasing"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := (EvidenceProvenanceProof{Version: EvidenceProvenanceProofVersionV1, TransformProfileDigest: normalize.EvidenceProvenanceProfileV1Digest, Sources: tc.sources}).Validate()
			if tc.want == "" && err != nil {
				t.Fatal(err)
			}
			if tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestEvidenceProvenanceProofValidateRejectsStructuralGaps(t *testing.T) {
	valid := completeSources(t)
	for _, tc := range []struct {
		name  string
		proof EvidenceProvenanceProof
		want  string
	}{
		{"malformed envelope profile", EvidenceProvenanceProof{Version: EvidenceProvenanceProofVersionV1, TransformProfileDigest: "not-a-digest", Sources: valid}, "invalid SHA-256 digest"},
		{"unknown envelope profile", EvidenceProvenanceProof{Version: EvidenceProvenanceProofVersionV1, TransformProfileDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Sources: valid}, "unknown profile"},
		{"source profile differs", EvidenceProvenanceProof{Version: EvidenceProvenanceProofVersionV1, TransformProfileDigest: normalize.EvidenceProvenanceProfileV1Digest, Sources: []ProvenanceSource{{SourceOrdinal: 1, SourceID: "first", Recipe: normalize.Recipe{TransformProfileDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, ViewCommitment: valid[0].ViewCommitment}}}, "differs from envelope"},
		{"malformed view commitment", EvidenceProvenanceProof{Version: EvidenceProvenanceProofVersionV1, TransformProfileDigest: normalize.EvidenceProvenanceProfileV1Digest, Sources: []ProvenanceSource{{SourceOrdinal: 1, SourceID: "first", Recipe: valid[0].Recipe, ViewCommitment: "sha256:bad"}}}, "view commitment"},
		{"malformed match commitment", EvidenceProvenanceProof{Version: EvidenceProvenanceProofVersionV1, TransformProfileDigest: normalize.EvidenceProvenanceProfileV1Digest, Sources: []ProvenanceSource{{SourceOrdinal: 1, SourceID: "first", Recipe: valid[0].Recipe, ViewCommitment: valid[0].ViewCommitment, Matches: []ProvenanceMatch{{ByteEnd: 1, MatchClass: "credential", MatchCommitment: "hmac-sha256:not-hex"}}}}}, "match 0 commitment"},
		{"invalid operation", EvidenceProvenanceProof{Version: EvidenceProvenanceProofVersionV1, TransformProfileDigest: normalize.EvidenceProvenanceProfileV1Digest, Sources: []ProvenanceSource{{SourceOrdinal: 1, SourceID: "first", Recipe: normalize.Recipe{TransformProfileDigest: normalize.EvidenceProvenanceProfileV1Digest, Operations: []normalize.Operation{{Kind: normalize.OperationIdentity, Selector: "ignored"}}}, ViewCommitment: valid[0].ViewCommitment}}}, "unsupported selector"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.proof.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestEvidenceProvenanceProofValidateRejectsMatchStructure(t *testing.T) {
	valid := completeSources(t)
	base := valid[0]
	commitment := validCommitment()
	for _, tc := range []struct {
		name    string
		sources []ProvenanceSource
		want    string
	}{
		{"zero-length interval", []ProvenanceSource{{SourceOrdinal: 1, SourceID: base.SourceID, Recipe: base.Recipe, ViewCommitment: base.ViewCommitment, Matches: []ProvenanceMatch{{MatchOrdinal: 1, ByteStart: 1, ByteEnd: 1, MatchClass: "credential", MatchCommitment: commitment}}}}, "byte end must be greater"},
		{"reversed interval", []ProvenanceSource{{SourceOrdinal: 1, SourceID: base.SourceID, Recipe: base.Recipe, ViewCommitment: base.ViewCommitment, Matches: []ProvenanceMatch{{MatchOrdinal: 1, ByteStart: 2, ByteEnd: 1, MatchClass: "credential", MatchCommitment: commitment}}}}, "byte end must be greater"},
		{"missing match class", []ProvenanceSource{{SourceOrdinal: 1, SourceID: base.SourceID, Recipe: base.Recipe, ViewCommitment: base.ViewCommitment, Matches: []ProvenanceMatch{{MatchOrdinal: 1, ByteEnd: 1, MatchCommitment: commitment}}}}, "missing match class"},
		{"non-increasing match ordinal", []ProvenanceSource{{SourceOrdinal: 1, SourceID: base.SourceID, Recipe: base.Recipe, ViewCommitment: base.ViewCommitment, Matches: []ProvenanceMatch{{MatchOrdinal: 2, ByteStart: 0, ByteEnd: 1, MatchClass: "first", MatchCommitment: commitment}, {MatchOrdinal: 2, ByteStart: 2, ByteEnd: 3, MatchClass: "second", MatchCommitment: commitment}}}}, "match ordinals must be strictly increasing"},
		{"unsorted intervals", []ProvenanceSource{{SourceOrdinal: 1, SourceID: base.SourceID, Recipe: base.Recipe, ViewCommitment: base.ViewCommitment, Matches: []ProvenanceMatch{{MatchOrdinal: 1, ByteStart: 2, ByteEnd: 3, MatchClass: "first", MatchCommitment: commitment}, {MatchOrdinal: 2, ByteStart: 0, ByteEnd: 1, MatchClass: "second", MatchCommitment: commitment}}}}, "intervals are unsorted"},
		{"duplicate intervals", []ProvenanceSource{{SourceOrdinal: 1, SourceID: base.SourceID, Recipe: base.Recipe, ViewCommitment: base.ViewCommitment, Matches: []ProvenanceMatch{{MatchOrdinal: 1, ByteStart: 0, ByteEnd: 1, MatchClass: "first", MatchCommitment: commitment}, {MatchOrdinal: 2, ByteStart: 0, ByteEnd: 1, MatchClass: "second", MatchCommitment: commitment}}}}, "duplicate interval start"},
		{"overlapping intervals", []ProvenanceSource{{SourceOrdinal: 1, SourceID: base.SourceID, Recipe: base.Recipe, ViewCommitment: base.ViewCommitment, Matches: []ProvenanceMatch{{MatchOrdinal: 1, ByteStart: 0, ByteEnd: 2, MatchClass: "first", MatchCommitment: commitment}, {MatchOrdinal: 2, ByteStart: 1, ByteEnd: 3, MatchClass: "second", MatchCommitment: commitment}}}}, "intervals overlap"},
		{"duplicate source ordinal", []ProvenanceSource{{SourceOrdinal: 1, SourceID: "first", Recipe: base.Recipe, ViewCommitment: base.ViewCommitment}, {SourceOrdinal: 1, SourceID: "second", Recipe: base.Recipe, ViewCommitment: base.ViewCommitment}}, "duplicate source ordinal"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			proof := EvidenceProvenanceProof{Version: EvidenceProvenanceProofVersionV1, TransformProfileDigest: normalize.EvidenceProvenanceProfileV1Digest, Sources: tc.sources}
			err := proof.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestEvidenceProvenanceProofValidateVersionAndProducer(t *testing.T) {
	sources := completeSources(t)
	validDigest := "sha256:" + strings.Repeat("a", 64)
	upperDigest := "sha256:" + strings.Repeat("A", 64)
	for _, tc := range []struct {
		name     string
		version  string
		producer ProducerAttestation
		want     string
	}{
		{"valid absent producer", EvidenceProvenanceProofVersionV1, ProducerAttestation{}, ""},
		{"missing version", "", ProducerAttestation{}, "unsupported evidence provenance proof version"},
		{"unsupported version", "pipelock-evidence-provenance-proof/v2", ProducerAttestation{}, "unsupported evidence provenance proof version"},
		{"empty present binary digest", EvidenceProvenanceProofVersionV1, ProducerAttestation{BinaryDigest: stringPointer("")}, "binary digest"},
		{"malformed binary digest", EvidenceProvenanceProofVersionV1, ProducerAttestation{BinaryDigest: stringPointer("sha256:bad")}, "binary digest"},
		{"uppercase binary digest", EvidenceProvenanceProofVersionV1, ProducerAttestation{BinaryDigest: stringPointer(upperDigest)}, "lowercase SHA-256 hex"},
		{"malformed ruleset digest", EvidenceProvenanceProofVersionV1, ProducerAttestation{RulesetDigest: stringPointer("sha512:" + strings.Repeat("a", 64))}, "ruleset digest"},
		{"valid attested digests", EvidenceProvenanceProofVersionV1, ProducerAttestation{BinaryDigest: stringPointer(validDigest), RulesetDigest: stringPointer(validDigest)}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			proof := EvidenceProvenanceProof{Version: tc.version, TransformProfileDigest: normalize.EvidenceProvenanceProfileV1Digest, Sources: sources, Producer: tc.producer}
			err := proof.Validate()
			if tc.want == "" && err != nil {
				t.Fatal(err)
			}
			if tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestCommitmentsBindAllFields(t *testing.T) {
	key := []byte(provenanceTestCommitmentKey)
	recipe := normalize.Recipe{TransformProfileDigest: normalize.EvidenceProvenanceProfileV1Digest, Operations: []normalize.Operation{{Kind: normalize.OperationLowercase}}}
	source := ProvenanceSource{SourceOrdinal: 1, SourceID: "source-a", Recipe: recipe}
	view := mustCommitView(t, key, source, "before secret after")
	match := ProvenanceMatch{MatchOrdinal: 1, ByteStart: 7, ByteEnd: 13, MatchClass: "credential"}
	baseline := mustCommitMatch(t, key, "source-a", recipe, view, match)
	viewBaseline := view
	for _, tc := range []struct {
		name       string
		commitment string
	}{
		{"source ordinal", mustCommitView(t, key, ProvenanceSource{SourceOrdinal: 2, SourceID: "source-a", Recipe: recipe}, "before secret after")},
		{"source ID", mustCommitView(t, key, ProvenanceSource{SourceOrdinal: 1, SourceID: "source-b", Recipe: recipe}, "before secret after")},
		{"recipe", mustCommitView(t, key, ProvenanceSource{SourceOrdinal: 1, SourceID: "source-a", Recipe: normalize.Recipe{TransformProfileDigest: recipe.TransformProfileDigest, Operations: []normalize.Operation{{Kind: normalize.OperationIdentity}}}}, "before secret after")},
		{"complete view", mustCommitView(t, key, source, "before secret after!")},
	} {
		t.Run("view "+tc.name, func(t *testing.T) {
			if tc.commitment == viewBaseline {
				t.Fatalf("view commitment did not bind mutation: %q", tc.name)
			}
		})
	}
	for _, tc := range []struct {
		name       string
		commitment string
	}{
		{"source ID in match", mustCommitMatch(t, key, "source-b", recipe, view, match)},
		{"recipe in match", mustCommitMatch(t, key, "source-a", normalize.Recipe{TransformProfileDigest: recipe.TransformProfileDigest, Operations: []normalize.Operation{{Kind: normalize.OperationIdentity}}}, view, match)},
		{"changed view commitment in match", mustCommitMatch(t, key, "source-a", recipe, mustCommitView(t, key, source, "before secret after!"), match)},
		{"match ordinal", mustCommitMatch(t, key, "source-a", recipe, view, ProvenanceMatch{MatchOrdinal: 2, ByteStart: 7, ByteEnd: 13, MatchClass: "credential"})},
		{"byte start", mustCommitMatch(t, key, "source-a", recipe, view, ProvenanceMatch{MatchOrdinal: 1, ByteStart: 6, ByteEnd: 13, MatchClass: "credential"})},
		{"byte end", mustCommitMatch(t, key, "source-a", recipe, view, ProvenanceMatch{MatchOrdinal: 1, ByteStart: 7, ByteEnd: 12, MatchClass: "credential"})},
		{"match class", mustCommitMatch(t, key, "source-a", recipe, view, ProvenanceMatch{MatchOrdinal: 1, ByteStart: 7, ByteEnd: 13, MatchClass: "other"})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.commitment == baseline || tc.commitment == view {
				t.Fatalf("commitment did not bind mutation: %q", tc.name)
			}
		})
	}
}

func TestEvidenceProvenanceProofValidateRejectsReorderedMatches(t *testing.T) {
	key := []byte(provenanceTestCommitmentKey)
	recipe := normalize.Recipe{TransformProfileDigest: normalize.EvidenceProvenanceProfileV1Digest, Operations: []normalize.Operation{{Kind: normalize.OperationIdentity}}}
	source := ProvenanceSource{SourceOrdinal: 1, SourceID: "source-a", Recipe: recipe}
	view := mustCommitView(t, key, source, "before secret after")
	first := ProvenanceMatch{MatchOrdinal: 1, ByteStart: 0, ByteEnd: 6, MatchClass: "prefix"}
	first.MatchCommitment = mustCommitMatch(t, key, source.SourceID, recipe, view, first)
	second := ProvenanceMatch{MatchOrdinal: 2, ByteStart: 7, ByteEnd: 13, MatchClass: "credential"}
	second.MatchCommitment = mustCommitMatch(t, key, source.SourceID, recipe, view, second)
	source.ViewCommitment = view
	source.Matches = []ProvenanceMatch{second, first}
	proof := EvidenceProvenanceProof{Version: EvidenceProvenanceProofVersionV1, TransformProfileDigest: normalize.EvidenceProvenanceProfileV1Digest, Sources: []ProvenanceSource{source}}
	if err := proof.Validate(); err == nil || !strings.Contains(err.Error(), "match ordinals must be strictly increasing") {
		t.Fatalf("error = %v, want reordered matches rejection", err)
	}
}

func TestCommitmentConstructionRejectsInvalidInputs(t *testing.T) {
	key := []byte(provenanceTestCommitmentKey)
	recipe := normalize.Recipe{TransformProfileDigest: normalize.EvidenceProvenanceProfileV1Digest, Operations: []normalize.Operation{{Kind: normalize.OperationIdentity}}}
	for _, tc := range []struct {
		name   string
		source ProvenanceSource
		view   string
		want   string
	}{
		{"empty source ID", ProvenanceSource{SourceOrdinal: 1, Recipe: recipe}, "view", "source ID: missing"},
		{"invalid UTF-8 source ID", ProvenanceSource{SourceOrdinal: 1, SourceID: string([]byte{0xff}), Recipe: recipe}, "view", "source ID: invalid UTF-8"},
		{"invalid UTF-8 view", ProvenanceSource{SourceOrdinal: 1, SourceID: "source", Recipe: recipe}, string([]byte{0xff}), "view: recipe output: invalid UTF-8"},
		{"over-limit view", ProvenanceSource{SourceOrdinal: 1, SourceID: "source", Recipe: recipe}, strings.Repeat("x", 1<<20+1), "output exceeds profile byte limit"},
	} {
		t.Run("view "+tc.name, func(t *testing.T) {
			if _, err := CommitView(key, tc.source, tc.view); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
	validView := mustCommitView(t, key, ProvenanceSource{SourceOrdinal: 1, SourceID: "source", Recipe: recipe}, "view")
	for _, tc := range []struct {
		name           string
		sourceID       string
		viewCommitment string
		match          ProvenanceMatch
		want           string
	}{
		{"empty source ID", "", validView, ProvenanceMatch{MatchOrdinal: 1, ByteStart: 0, ByteEnd: 1}, "source ID: missing"},
		{"invalid UTF-8 source ID", string([]byte{0xff}), validView, ProvenanceMatch{MatchOrdinal: 1, ByteStart: 0, ByteEnd: 1}, "source ID: invalid UTF-8"},
		{"malformed view commitment", "source", "sha256:bad", ProvenanceMatch{MatchOrdinal: 1, ByteStart: 0, ByteEnd: 1}, "view commitment"},
		{"zero-length interval", "source", validView, ProvenanceMatch{MatchOrdinal: 1, ByteStart: 1, ByteEnd: 1}, "byte end must be greater"},
		{"reversed interval", "source", validView, ProvenanceMatch{MatchOrdinal: 1, ByteStart: 2, ByteEnd: 1}, "byte end must be greater"},
	} {
		t.Run("match "+tc.name, func(t *testing.T) {
			if _, err := CommitMatch(key, tc.sourceID, recipe, tc.viewCommitment, tc.match); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestCommitmentConstructionRejectsShortKeys(t *testing.T) {
	recipe := normalize.Recipe{TransformProfileDigest: normalize.EvidenceProvenanceProfileV1Digest, Operations: []normalize.Operation{{Kind: normalize.OperationIdentity}}}
	source := ProvenanceSource{SourceOrdinal: 1, SourceID: "source", Recipe: recipe}
	match := ProvenanceMatch{MatchOrdinal: 1, ByteStart: 0, ByteEnd: 1}
	for _, key := range [][]byte{nil, {}, make([]byte, minimumCommitmentKeyBytes-1)} {
		if _, err := CommitView(key, source, "view"); err == nil || !strings.Contains(err.Error(), "commitment key must be at least") {
			t.Fatalf("CommitView(%d-byte key) error = %v", len(key), err)
		}
		if _, err := CommitMatch(key, source.SourceID, recipe, validCommitment(), match); err == nil || !strings.Contains(err.Error(), "commitment key must be at least") {
			t.Fatalf("CommitMatch(%d-byte key) error = %v", len(key), err)
		}
	}
}

func TestCommitmentEnumBytesAreStable(t *testing.T) {
	// Pinned by literal value: these bytes are inside every commitment
	// preimage, so changing one silently invalidates all previously issued
	// evidence.
	kinds := map[normalize.OperationKind]byte{
		normalize.OperationIdentity: 1, normalize.OperationURLComponent: 2, normalize.OperationPercentDecode: 3,
		normalize.OperationDLPNormalize: 4, normalize.OperationLowercase: 5, normalize.OperationInvisibleStrip: 6,
		normalize.OperationHexDecode: 7, normalize.OperationBase32Decode: 8, normalize.OperationBase64Decode: 9,
		normalize.OperationLeetspeak: 10, normalize.OperationVowelFold: 11,
		normalize.OperationQueryUnescape: 12, normalize.OperationInvisibleSpace: 13, normalize.OperationMatchingNormalize: 14,
		normalize.OperationHexDecodeLiberal: 15, normalize.OperationBase32DecodeLiberal: 16, normalize.OperationBase64DecodeLiberal: 17,
		normalize.OperationEncodedTokenNormalize: 18, normalize.OperationTextSegment: 19, normalize.OperationHTMLEntityDecode: 20,
		normalize.OperationWhitespaceCompact: 21, normalize.OperationURLNoiseStrip: 22, normalize.OperationOrderedQueryConcat: 23,
		normalize.OperationQuerySubsequence: 24, normalize.OperationHostnameDotRemove: 25, normalize.OperationEncodedRun: 26,
		normalize.OperationCanaryCanonicalize: 27,
	}
	for kind, want := range kinds {
		t.Run("kind/"+string(kind), func(t *testing.T) {
			got, err := operationKindByte(kind)
			if err != nil || got != want {
				t.Fatalf("operationKindByte(%q) = %d, %v; want %d, nil", kind, got, err, want)
			}
		})
	}
	// Completeness: without this, adding a twelfth operation ships with no
	// committed enum byte. operationKindByte would return an error for it and
	// the pinned table above would still pass, because it only asserts the
	// kinds it happens to list.
	for _, kind := range normalize.SupportedOperationKinds() {
		if _, pinned := kinds[kind]; !pinned {
			t.Fatalf("operation %q is in the supported vocabulary but has no pinned commitment enum byte", kind)
		}
	}
	if len(kinds) != len(normalize.SupportedOperationKinds()) {
		t.Fatalf("pinned enum table has %d kinds, vocabulary has %d", len(kinds), len(normalize.SupportedOperationKinds()))
	}
	components := map[normalize.Component]byte{
		"": 0, normalize.ComponentURL: 1, normalize.ComponentHostname: 2,
		normalize.ComponentPath: 3, normalize.ComponentQueryKey: 4, normalize.ComponentQueryVal: 5,
		normalize.ComponentRawQuery: 6,
	}
	for component, want := range components {
		t.Run("component/"+string(component), func(t *testing.T) {
			got, err := componentByte(component)
			if err != nil || got != want {
				t.Fatalf("componentByte(%q) = %d, %v; want %d, nil", component, got, err, want)
			}
		})
	}
	if _, err := operationKindByte("unknown"); err == nil || !strings.Contains(err.Error(), "unknown operation") {
		t.Fatalf("operationKindByte unknown error = %v", err)
	}
	if _, err := componentByte("unknown"); err == nil || !strings.Contains(err.Error(), "unknown URL component") {
		t.Fatalf("componentByte unknown error = %v", err)
	}
}

func TestAppendedOperationCommitmentTailBindsParameters(t *testing.T) {
	for _, tc := range []struct {
		name  string
		left  normalize.Operation
		right normalize.Operation
	}{
		{"alphabet", normalize.Operation{Kind: normalize.OperationBase64DecodeLiberal, Alphabet: "standard"}, normalize.Operation{Kind: normalize.OperationBase64DecodeLiberal, Alphabet: "url"}},
		{"indices", normalize.Operation{Kind: normalize.OperationQuerySubsequence, Indices: normalize.QueryIndices{0, 1}}, normalize.Operation{Kind: normalize.OperationQuerySubsequence, Indices: normalize.QueryIndices{0, 2}}},
		{"minimum length", normalize.Operation{Kind: normalize.OperationEncodedRun, MinimumLength: 6}, normalize.Operation{Kind: normalize.OperationEncodedRun, MinimumLength: 7}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			left, err := operationBytes(tc.left)
			if err != nil {
				t.Fatal(err)
			}
			right, err := operationBytes(tc.right)
			if err != nil {
				t.Fatal(err)
			}
			if string(left) == string(right) {
				t.Fatal("operation commitment did not bind appended parameter")
			}
		})
	}
}

func TestLegacyOperationCommitmentOmitsAppendedTail(t *testing.T) {
	for _, tc := range []struct {
		name string
		op   normalize.Operation
		want string
	}{
		{
			name: "identity",
			op:   normalize.Operation{Kind: normalize.OperationIdentity},
			want: "00000000000000010100000000000000010000000000000000000000000000000004000000000000000000000001000000000000000000000000000000000100",
		},
		{
			name: "vowel fold",
			op:   normalize.Operation{Kind: normalize.OperationVowelFold},
			want: "00000000000000010b00000000000000010000000000000000000000000000000004000000000000000000000001000000000000000000000000000000000100",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			encoded, err := operationBytes(tc.op)
			if err != nil {
				t.Fatal(err)
			}
			if got := hex.EncodeToString(encoded); got != tc.want {
				t.Fatalf("legacy operation preimage = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestProvenanceValidationFormatErrors(t *testing.T) {
	for _, value := range []string{"hmac-sha256:bad", "hmac-sha256:" + strings.Repeat("A", 64), "sha256:" + strings.Repeat("0", 64)} {
		if err := validateCommitment(value); err == nil {
			t.Fatalf("validateCommitment(%q) unexpectedly succeeded", value)
		}
	}
	if err := validateMatchStructure(ProvenanceMatch{ByteEnd: 1, MatchClass: string([]byte{0xff})}); err == nil || !strings.Contains(err.Error(), "invalid UTF-8") {
		t.Fatalf("invalid match class error = %v", err)
	}
	base := completeSources(t)[0]
	base.SourceID = string([]byte{0xff})
	proof := EvidenceProvenanceProof{Version: EvidenceProvenanceProofVersionV1, TransformProfileDigest: normalize.EvidenceProvenanceProfileV1Digest, Sources: []ProvenanceSource{base}}
	if err := proof.Validate(); err == nil || !strings.Contains(err.Error(), "source ID: invalid UTF-8") {
		t.Fatalf("invalid source ID error = %v", err)
	}
}

func TestRecipeBytesEncodesAllOperationFields(t *testing.T) {
	recipe := normalize.Recipe{TransformProfileDigest: normalize.EvidenceProvenanceProfileV1Digest, Operations: []normalize.Operation{
		{Kind: normalize.OperationURLComponent, Component: normalize.ComponentQueryVal, Selector: "marker", Occurrence: 1},
		{Kind: normalize.OperationPercentDecode, Passes: 2},
		{Kind: normalize.OperationDLPNormalize, Profile: "pipelock-dlp-v1"},
		{Kind: normalize.OperationBase32Decode},
		{Kind: normalize.OperationBase64Decode, DecodePadding: true},
	}}
	want, err := recipeBytes(recipe)
	if err != nil {
		t.Fatal(err)
	}
	got, err := CanonicalRecipeBytes(recipe)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatal("exported canonical recipe encoding differs from commitment encoding")
	}
	if _, err := recipeBytes(normalize.Recipe{}); err == nil || !strings.Contains(err.Error(), "missing transform profile digest") {
		t.Fatalf("invalid recipe error = %v", err)
	}
	if _, err := operationBytes(normalize.Operation{Kind: "unknown"}); err == nil || !strings.Contains(err.Error(), "unknown operation") {
		t.Fatalf("unknown operation encoding error = %v", err)
	}
	if _, err := operationBytes(normalize.Operation{Kind: normalize.OperationIdentity, Component: "unknown"}); err == nil || !strings.Contains(err.Error(), "unknown URL component") {
		t.Fatalf("unknown component encoding error = %v", err)
	}
	key := []byte(provenanceTestCommitmentKey)
	if _, err := CommitView(key, ProvenanceSource{SourceID: "source", Recipe: normalize.Recipe{}}, "view"); err == nil || !strings.Contains(err.Error(), "missing transform profile digest") {
		t.Fatalf("CommitView invalid recipe error = %v", err)
	}
	if _, err := CommitMatch(key, "source", normalize.Recipe{}, validCommitment(), ProvenanceMatch{ByteEnd: 1}); err == nil || !strings.Contains(err.Error(), "missing transform profile digest") {
		t.Fatalf("CommitMatch invalid recipe error = %v", err)
	}
}

func TestCommitmentsSeparateLegacyRecipeCollision(t *testing.T) {
	key := []byte(provenanceTestCommitmentKey)
	first := normalize.Operation{Kind: normalize.OperationURLComponent, Component: normalize.ComponentQueryVal, Selector: "marker\x000/0/false/\x00identity\x00\x00"}
	second := normalize.Operation{Kind: normalize.OperationURLComponent, Component: normalize.ComponentQueryVal, Selector: "marker"}
	left := normalize.Recipe{TransformProfileDigest: normalize.EvidenceProvenanceProfileV1Digest, Operations: []normalize.Operation{first}}
	right := normalize.Recipe{TransformProfileDigest: normalize.EvidenceProvenanceProfileV1Digest, Operations: []normalize.Operation{second, {Kind: normalize.OperationIdentity}}}
	if legacyRecipeBytes(left) != legacyRecipeBytes(right) {
		t.Fatal("test recipes no longer collide under delimiter encoding")
	}
	if _, err := CommitView(key, ProvenanceSource{SourceOrdinal: 1, SourceID: "source", Recipe: left}, "view"); err == nil || !strings.Contains(err.Error(), "selector for url_component contains control character") {
		t.Fatalf("colliding selector error = %v, want normative control-character rejection", err)
	}
	// The benign twin still commits normally, so the rejection is targeted at
	// the control bytes rather than at this shape of recipe generally.
	if _, err := CommitView(key, ProvenanceSource{SourceOrdinal: 1, SourceID: "source", Recipe: right}, "view"); err != nil {
		t.Fatalf("control-character-free recipe was rejected: %v", err)
	}
}

func completeSources(t *testing.T) []ProvenanceSource {
	t.Helper()
	key := []byte(provenanceTestCommitmentKey)
	recipe := normalize.Recipe{TransformProfileDigest: normalize.EvidenceProvenanceProfileV1Digest, Operations: []normalize.Operation{{Kind: normalize.OperationIdentity}}}
	first := ProvenanceSource{SourceOrdinal: 1, SourceID: "first", Recipe: recipe}
	first.ViewCommitment = mustCommitView(t, key, first, "one")
	second := ProvenanceSource{SourceOrdinal: 2, SourceID: "second", Recipe: recipe}
	second.ViewCommitment = mustCommitView(t, key, second, "two")
	return []ProvenanceSource{first, second}
}

func mustCommitView(t *testing.T, key []byte, source ProvenanceSource, view string) string {
	t.Helper()
	value, err := CommitView(key, source, view)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func mustCommitMatch(t *testing.T, key []byte, sourceID string, recipe normalize.Recipe, viewCommitment string, match ProvenanceMatch) string {
	t.Helper()
	value, err := CommitMatch(key, sourceID, recipe, viewCommitment, match)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func legacyRecipeBytes(recipe normalize.Recipe) string {
	result := recipe.TransformProfileDigest
	for _, operation := range recipe.Operations {
		result += "\x00" + string(operation.Kind) + "\x00" + string(operation.Component) + "\x00" + operation.Selector + "\x00" + fmt.Sprintf("%d/%d/%t/%s", operation.Occurrence, operation.Passes, operation.DecodePadding, operation.Profile)
	}
	return result
}

func validCommitment() string {
	return "hmac-sha256:" + strings.Repeat("0", 64)
}

func stringPointer(value string) *string {
	return &value
}
