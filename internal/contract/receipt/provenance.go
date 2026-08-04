// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/luckyPipewrench/pipelock/internal/normalize"
)

// EvidenceProvenanceProof is experimental and fixture-only. It is deliberately
// not registered as a receipt payload and must not be emitted by production.
type EvidenceProvenanceProof struct {
	Version                string              `json:"version"`
	TransformProfileDigest string              `json:"transform_profile_digest"`
	Sources                []ProvenanceSource  `json:"sources"`
	Producer               ProducerAttestation `json:"producer"`
}

type ProducerAttestation struct {
	BinaryDigest  *string `json:"binary_digest,omitempty"`
	RulesetDigest *string `json:"ruleset_digest,omitempty"`
}

// EvidenceProvenanceProofVersionV1 is the only supported experimental proof
// wire version.
const EvidenceProvenanceProofVersionV1 = "pipelock-evidence-provenance-proof/v1"

const minimumCommitmentKeyBytes = sha256.Size

type ProvenanceSource struct {
	SourceOrdinal  uint64            `json:"source_ordinal"`
	SourceID       string            `json:"source_id"`
	Recipe         normalize.Recipe  `json:"recipe"`
	ViewCommitment string            `json:"view_commitment"`
	Matches        []ProvenanceMatch `json:"matches"`
}

type ProvenanceMatch struct {
	MatchOrdinal    uint64 `json:"match_ordinal"`
	ByteStart       uint64 `json:"byte_start"`
	ByteEnd         uint64 `json:"byte_end"`
	MatchClass      string `json:"match_class"`
	MatchCommitment string `json:"match_commitment"`
}

// Validate checks ordering and identity invariants across sources.
func (p EvidenceProvenanceProof) Validate() error {
	if p.Version != EvidenceProvenanceProofVersionV1 {
		return fmt.Errorf("unsupported evidence provenance proof version %q", p.Version)
	}
	if err := (normalize.Recipe{TransformProfileDigest: p.TransformProfileDigest}).Validate(); err != nil {
		return fmt.Errorf("transform profile digest: %w", err)
	}
	if err := p.Producer.Validate(); err != nil {
		return fmt.Errorf("producer: %w", err)
	}
	seenIDs := make(map[string]struct{}, len(p.Sources))
	seenOrdinals := make(map[uint64]struct{}, len(p.Sources))
	var previous uint64
	for index, source := range p.Sources {
		if source.SourceID == "" {
			return fmt.Errorf("source %d: missing source ID", index)
		}
		if !utf8.ValidString(source.SourceID) {
			return fmt.Errorf("source %d: source ID: invalid UTF-8", index)
		}
		if _, ok := seenIDs[source.SourceID]; ok {
			return fmt.Errorf("source %d: duplicate source ID %q", index, source.SourceID)
		}
		if _, ok := seenOrdinals[source.SourceOrdinal]; ok {
			return fmt.Errorf("source %d: duplicate source ordinal %d", index, source.SourceOrdinal)
		}
		if index > 0 && source.SourceOrdinal <= previous {
			return fmt.Errorf("source %d: source ordinals must be strictly increasing", index)
		}
		if source.Recipe.TransformProfileDigest != p.TransformProfileDigest {
			return fmt.Errorf("source %d: recipe transform profile digest differs from envelope", index)
		}
		if err := source.Recipe.Validate(); err != nil {
			return fmt.Errorf("source %d recipe: %w", index, err)
		}
		if err := validateCommitment(source.ViewCommitment); err != nil {
			return fmt.Errorf("source %d view commitment: %w", index, err)
		}
		for matchIndex, match := range source.Matches {
			if err := validateMatchStructure(match); err != nil {
				return fmt.Errorf("source %d match %d: %w", index, matchIndex, err)
			}
			if err := validateCommitment(match.MatchCommitment); err != nil {
				return fmt.Errorf("source %d match %d commitment: %w", index, matchIndex, err)
			}
			if matchIndex > 0 {
				previousMatch := source.Matches[matchIndex-1]
				switch {
				case match.MatchOrdinal <= previousMatch.MatchOrdinal:
					return fmt.Errorf("source %d match %d: match ordinals must be strictly increasing", index, matchIndex)
				case match.ByteStart < previousMatch.ByteStart:
					return fmt.Errorf("source %d match %d: intervals are unsorted", index, matchIndex)
				case match.ByteStart == previousMatch.ByteStart:
					return fmt.Errorf("source %d match %d: duplicate interval start", index, matchIndex)
				case match.ByteStart < previousMatch.ByteEnd:
					return fmt.Errorf("source %d match %d: intervals overlap", index, matchIndex)
				}
			}
		}
		seenIDs[source.SourceID] = struct{}{}
		seenOrdinals[source.SourceOrdinal] = struct{}{}
		previous = source.SourceOrdinal
	}
	return nil
}

// Validate checks that each present producer digest is a canonical SHA-256
// attestation. Nil is an explicit absent attestation; independent verification
// is a verifier-local result and is never producer-controlled wire data.
func (p ProducerAttestation) Validate() error {
	for _, digest := range []struct {
		name  string
		value *string
	}{{"binary digest", p.BinaryDigest}, {"ruleset digest", p.RulesetDigest}} {
		if digest.value == nil {
			continue
		}
		if err := validatePrefixedSHA256Digest(*digest.value, "sha256:"); err != nil {
			return fmt.Errorf("%s: %w", digest.name, err)
		}
	}
	return nil
}

func validatePrefixedSHA256Digest(value, prefix string) error {
	if !strings.HasPrefix(value, prefix) {
		return fmt.Errorf("must use %q prefix", prefix)
	}
	encoded := strings.TrimPrefix(value, prefix)
	if len(encoded) != sha256.Size*2 {
		return fmt.Errorf("must contain a SHA-256 hex value")
	}
	decoded, err := hex.DecodeString(encoded)
	if err != nil || len(decoded) != sha256.Size || strings.ToLower(encoded) != encoded {
		return fmt.Errorf("must contain lowercase SHA-256 hex")
	}
	return nil
}

func validateMatchStructure(match ProvenanceMatch) error {
	if match.ByteEnd <= match.ByteStart {
		return fmt.Errorf("byte end must be greater than byte start")
	}
	if !utf8.ValidString(match.MatchClass) {
		return fmt.Errorf("match class: invalid UTF-8")
	}
	return nil
}

func validateCommitment(value string) error {
	return validatePrefixedSHA256Digest(value, "hmac-sha256:")
}

// ValidateView verifies all offset invariants against the reconstructed view.
func (s ProvenanceSource) ValidateView(input string) error {
	view, err := s.Recipe.Apply(input)
	if err != nil {
		return fmt.Errorf("source %q recipe: %w", s.SourceID, err)
	}
	if !utf8.ValidString(view) {
		return fmt.Errorf("source %q view: invalid UTF-8", s.SourceID)
	}
	for index, match := range s.Matches {
		if match.ByteStart >= match.ByteEnd || match.ByteEnd > uint64(len(view)) {
			return fmt.Errorf("source %q match %d: interval out of bounds", s.SourceID, index)
		}
		if !byteBoundary(view, match.ByteStart) || !byteBoundary(view, match.ByteEnd) {
			return fmt.Errorf("source %q match %d: interval splits UTF-8 code point", s.SourceID, index)
		}
	}
	return nil
}

func byteBoundary(value string, offset uint64) bool {
	if offset == 0 || offset == uint64(len(value)) {
		return true
	}
	return offset < uint64(len(value)) && (value[offset]&0xc0) != 0x80
}

// CommitView produces a length-framed, domain-separated HMAC commitment. The
// secret key is intentionally not serialized: publishing an unkeyed digest of
// undisclosed content would create an offline oracle for guessed secrets.
func CommitView(key []byte, source ProvenanceSource, view string) (string, error) {
	if err := validateCommitmentKey(key); err != nil {
		return "", err
	}
	if source.SourceID == "" {
		return "", fmt.Errorf("source ID: missing")
	}
	if !utf8.ValidString(source.SourceID) {
		return "", fmt.Errorf("source ID: invalid UTF-8")
	}
	if err := source.Recipe.ValidateOutput(view); err != nil {
		return "", fmt.Errorf("view: %w", err)
	}
	recipe, err := recipeBytes(source.Recipe)
	if err != nil {
		return "", err
	}
	return commitment(key, "pipelock/evidence-provenance/view/v1", uint64Bytes(source.SourceOrdinal), []byte(source.SourceID), []byte(source.Recipe.TransformProfileDigest), recipe, []byte(view)), nil
}

// CommitMatch binds a match to its source, recipe, complete-view commitment,
// location, and class; reordering or moving data therefore changes the value.
func CommitMatch(key []byte, sourceID string, recipe normalize.Recipe, viewCommitment string, match ProvenanceMatch) (string, error) {
	if err := validateCommitmentKey(key); err != nil {
		return "", err
	}
	if sourceID == "" {
		return "", fmt.Errorf("source ID: missing")
	}
	if !utf8.ValidString(sourceID) {
		return "", fmt.Errorf("source ID: invalid UTF-8")
	}
	if err := validateCommitment(viewCommitment); err != nil {
		return "", fmt.Errorf("view commitment: %w", err)
	}
	if err := validateMatchStructure(match); err != nil {
		return "", err
	}
	encodedRecipe, err := recipeBytes(recipe)
	if err != nil {
		return "", err
	}
	return commitment(key, "pipelock/evidence-provenance/match/v1", []byte(sourceID), []byte(recipe.TransformProfileDigest), encodedRecipe, []byte(viewCommitment), uint64Bytes(match.MatchOrdinal), uint64Bytes(match.ByteStart), uint64Bytes(match.ByteEnd), []byte(match.MatchClass)), nil
}

func validateCommitmentKey(key []byte) error {
	if len(key) < minimumCommitmentKeyBytes {
		return fmt.Errorf("commitment key must be at least %d bytes", minimumCommitmentKeyBytes)
	}
	return nil
}

func commitment(key []byte, domain string, parts ...[]byte) string {
	mac := hmac.New(sha256.New, key)
	writePart(mac, []byte(domain))
	for _, part := range parts {
		writePart(mac, part)
	}
	return "hmac-sha256:" + hex.EncodeToString(mac.Sum(nil))
}

// writePart streams one normative frame into mac. It delegates to appendFrame
// so there is exactly ONE implementation of `u64be(byte_length) || bytes`.
// Two copies would let a change to one silently diverge commitments from the
// specification while the other copy still matched it.
func writePart(mac interface{ Write([]byte) (int, error) }, value []byte) {
	_, _ = mac.Write(appendFrame(nil, value))
}

func uint64Bytes(value uint64) []byte {
	var out [8]byte
	binary.BigEndian.PutUint64(out[:], value)
	return out[:]
}

func recipeBytes(recipe normalize.Recipe) ([]byte, error) {
	if err := recipe.Validate(); err != nil {
		return nil, err
	}
	result := make([]byte, 0, 128)
	result = appendFrame(result, []byte("pipelock/evidence-provenance/recipe/v1"))
	result = appendFrame(result, []byte(recipe.TransformProfileDigest))
	result = appendFrame(result, uint64Bytes(uint64(len(recipe.Operations))))
	for _, operation := range recipe.Operations {
		encoded, err := operationBytes(operation)
		if err != nil {
			return nil, err
		}
		result = appendFrame(result, encoded)
	}
	return result, nil
}

func operationBytes(operation normalize.Operation) ([]byte, error) {
	kind, err := operationKindByte(operation.Kind)
	if err != nil {
		return nil, err
	}
	component, err := componentByte(operation.Component)
	if err != nil {
		return nil, err
	}
	var occurrence [4]byte
	binary.BigEndian.PutUint32(occurrence[:], operation.Occurrence)
	result := make([]byte, 0, 64)
	result = appendFrame(result, []byte{kind})
	result = appendFrame(result, []byte{component})
	result = appendFrame(result, []byte(operation.Selector))
	result = appendFrame(result, occurrence[:])
	result = appendFrame(result, []byte{operation.Passes})
	result = appendFrame(result, []byte(operation.Profile))
	if operation.DecodePadding {
		result = appendFrame(result, []byte{1})
	} else {
		result = appendFrame(result, []byte{0})
	}
	return result, nil
}

func appendFrame(destination, value []byte) []byte {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	destination = append(destination, length[:]...)
	return append(destination, value...)
}

func operationKindByte(kind normalize.OperationKind) (byte, error) {
	switch kind {
	case normalize.OperationIdentity:
		return 1, nil
	case normalize.OperationURLComponent:
		return 2, nil
	case normalize.OperationPercentDecode:
		return 3, nil
	case normalize.OperationDLPNormalize:
		return 4, nil
	case normalize.OperationLowercase:
		return 5, nil
	case normalize.OperationInvisibleStrip:
		return 6, nil
	case normalize.OperationHexDecode:
		return 7, nil
	case normalize.OperationBase32Decode:
		return 8, nil
	case normalize.OperationBase64Decode:
		return 9, nil
	case normalize.OperationLeetspeak:
		return 10, nil
	case normalize.OperationVowelFold:
		return 11, nil
	default:
		return 0, fmt.Errorf("unknown operation %q", kind)
	}
}

func componentByte(component normalize.Component) (byte, error) {
	switch component {
	case "":
		return 0, nil
	case normalize.ComponentURL:
		return 1, nil
	case normalize.ComponentHostname:
		return 2, nil
	case normalize.ComponentPath:
		return 3, nil
	case normalize.ComponentQueryKey:
		return 4, nil
	case normalize.ComponentQueryVal:
		return 5, nil
	default:
		return 0, fmt.Errorf("unknown URL component %q", component)
	}
}
