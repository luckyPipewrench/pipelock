// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf8"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	contractreceipt "github.com/luckyPipewrench/pipelock/internal/contract/receipt"
)

const (
	provenanceFixtureFormat = "pipelock-evidence-provenance-verification-fixture/v1"
	provenanceFeature       = "evidence_provenance"
	provenanceTrustRoots    = "fixture supplied; self-attested; not authenticated"
)

type provenanceFixture struct {
	Format       string                       `json:"format"`
	Entries      []provenanceFixtureEntry     `json:"entries"`
	Verification provenanceVerificationInputs `json:"verification"`
}

type provenanceFixtureEntry struct {
	SignedB64 string `json:"signed_b64"`
	Signature string `json:"signature"`
}

type provenanceVerificationInputs struct {
	SignerPublicKeyHex string                    `json:"signer_public_key_hex"`
	CommitmentKeyHex   string                    `json:"commitment_key_hex,omitempty"`
	Sources            []provenanceFixtureSource `json:"sources,omitempty"`
	BinaryB64          *string                   `json:"binary_b64,omitempty"`
	RulesetB64         *string                   `json:"ruleset_b64,omitempty"`
}

type provenanceFixtureSource struct {
	SourceID string `json:"source_id"`
	BytesB64 string `json:"bytes_b64"`
}

type signedProvenanceProof struct {
	ChainSeq         uint64                                  `json:"chain_seq"`
	ChainPrevHash    string                                  `json:"chain_prev_hash"`
	CriticalFeatures []string                                `json:"critical_features"`
	Proof            contractreceipt.EvidenceProvenanceProof `json:"proof"`
}

type provenanceStageReport struct {
	TrustRoots              string `json:"trust_roots"`
	AuthenticatedProvenance bool   `json:"authenticated_provenance"`
	Signature               string `json:"signature"`
	Chain                   string `json:"chain"`
	Artifacts               string `json:"artifacts"`
	SourceCommitment        string `json:"source_commitment"`
	ViewReproduction        string `json:"view_reproduction"`
	Location                string `json:"location"`
	MatchCommitment         string `json:"match_commitment"`
	Overall                 string `json:"overall"`
	FailureStage            string `json:"failure_stage,omitempty"`
}

func newProvenanceCmd() *cobra.Command {
	var allowIncomplete bool
	cmd := &cobra.Command{
		Use:           "provenance PATH",
		Short:         "Verify an experimental evidence-provenance fixture",
		Args:          exactOneArg,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runProvenance(cmd.OutOrStdout(), args[0], allowIncomplete)
		},
	}
	cmd.Flags().BoolVar(&allowIncomplete, "allow-incomplete", false, "return success for an incomplete fixture inspection")
	return cmd
}

func runProvenance(stdout io.Writer, path string, allowIncomplete bool) error {
	data, err := os.ReadFile(path) // #nosec G304 -- explicit CLI input
	if err != nil {
		return cliutil.ExitCodeError(cliutil.ExitConfig, fmt.Errorf("read provenance fixture: %w", err))
	}
	var fixture provenanceFixture
	if err := decodeStrictJSON(data, &fixture); err != nil {
		report := rejectProvenance(initialProvenanceReport(), "proof_structure")
		if writeErr := writeProvenanceReport(stdout, report); writeErr != nil {
			return writeErr
		}
		return cliutil.ExitCodeError(cliutil.ExitGeneral, fmt.Errorf("decode provenance fixture: %w", err))
	}
	report := verifyProvenanceFixture(fixture)
	if err := writeProvenanceReport(stdout, report); err != nil {
		return err
	}
	switch report.Overall {
	case "verified":
		return nil
	case "incomplete":
		if allowIncomplete {
			return nil
		}
		return cliutil.ExitCodeError(cliutil.ExitGeneral, errors.New("provenance fixture verification is incomplete; pass --allow-incomplete for inspection-only use"))
	default:
		return cliutil.ExitCodeError(cliutil.ExitGeneral, fmt.Errorf("provenance fixture rejected at %s", report.FailureStage))
	}
}

func writeProvenanceReport(stdout io.Writer, report provenanceStageReport) error {
	encoded, err := json.Marshal(report)
	if err != nil {
		return cliutil.ExitCodeError(cliutil.ExitConfig, fmt.Errorf("encode provenance report: %w", err))
	}
	_, _ = fmt.Fprintf(stdout, "%s\n", encoded)
	return nil
}

func initialProvenanceReport() provenanceStageReport {
	return provenanceStageReport{
		TrustRoots: provenanceTrustRoots, AuthenticatedProvenance: false,
		Signature: "not_checked", Chain: "not_checked", Artifacts: "attested_unchecked",
		SourceCommitment: "not_checked", ViewReproduction: "not_checked", Location: "not_checked",
		MatchCommitment: "not_checked", Overall: "incomplete",
	}
}

func rejectProvenance(report provenanceStageReport, stage string) provenanceStageReport {
	report.Overall = "invalid"
	report.FailureStage = stage
	return report
}

func verifyProvenanceFixture(fixture provenanceFixture) provenanceStageReport {
	report := initialProvenanceReport()
	if fixture.Format != provenanceFixtureFormat || len(fixture.Entries) == 0 {
		return rejectProvenance(report, "proof_structure")
	}
	publicKey, err := hex.DecodeString(fixture.Verification.SignerPublicKeyHex)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		report.Signature = "invalid"
		return rejectProvenance(report, "signature")
	}

	signedProofs := make([]signedProvenanceProof, 0, len(fixture.Entries))
	signedBytes := make([][]byte, 0, len(fixture.Entries))
	for _, entry := range fixture.Entries {
		raw, decodeErr := base64.StdEncoding.Strict().DecodeString(entry.SignedB64)
		sig, sigErr := decodePrefixedHex(entry.Signature, "ed25519:", ed25519.SignatureSize)
		if decodeErr != nil || !utf8.Valid(raw) || sigErr != nil {
			report.Signature = "invalid"
			return rejectProvenance(report, "signature")
		}
		var signed signedProvenanceProof
		if err := decodeStrictJSON(raw, &signed); err != nil {
			return rejectProvenance(report, "proof_structure")
		}
		if !ed25519.Verify(publicKey, raw, sig) {
			report.Signature = "invalid"
			return rejectProvenance(report, "signature")
		}
		signedBytes = append(signedBytes, raw)
		signedProofs = append(signedProofs, signed)
	}
	report.Signature = "verified"

	for index, signed := range signedProofs {
		wantPrev := "genesis"
		if index > 0 {
			sum := sha256.Sum256(signedBytes[index-1])
			wantPrev = "sha256:" + hex.EncodeToString(sum[:])
		}
		if signed.ChainSeq != uint64(index) || signed.ChainPrevHash != wantPrev {
			report.Chain = "invalid"
			return rejectProvenance(report, "chain")
		}
	}
	report.Chain = "verified"

	for _, signed := range signedProofs {
		if len(signed.CriticalFeatures) != 1 || signed.CriticalFeatures[0] != provenanceFeature {
			return rejectProvenance(report, "critical_features")
		}
		if err := signed.Proof.Validate(); err != nil {
			return rejectProvenance(report, "proof_structure")
		}
	}

	artifactStatus, artifactErr := verifyProvenanceArtifacts(signedProofs, fixture.Verification)
	report.Artifacts = artifactStatus
	if artifactErr != nil {
		return rejectProvenance(report, "artifacts")
	}

	sources, err := provenanceSources(fixture.Verification.Sources)
	if err != nil {
		return rejectProvenance(report, "proof_structure")
	}
	if len(sources) == 0 {
		return report
	}
	sourceUnavailable := false
	sourceVisited := false
	for _, signed := range signedProofs {
		for _, source := range signed.Proof.Sources {
			sourceVisited = true
			input, ok := sources[source.SourceID]
			if !ok {
				sourceUnavailable = true
				continue
			}
			view, err := source.Recipe.Apply(input)
			if err != nil {
				report.ViewReproduction = "mismatch"
				return rejectProvenance(report, "view_reproduction")
			}
			report.ViewReproduction = "reproduced"
			if err := validateProvenanceLocations(view, source.Matches); err != nil {
				report.Location = "mismatch"
				return rejectProvenance(report, "location")
			}
		}
	}
	if sourceVisited && !sourceUnavailable {
		report.ViewReproduction = "reproduced"
		report.Location = "exact_coordinates"
	} else {
		report.ViewReproduction = "not_checked"
		report.Location = "not_checked"
	}

	if fixture.Verification.CommitmentKeyHex == "" {
		return report
	}
	commitmentKey, err := hex.DecodeString(fixture.Verification.CommitmentKeyHex)
	if err != nil || len(commitmentKey) < sha256.Size {
		return rejectProvenance(report, "proof_structure")
	}
	for _, signed := range signedProofs {
		for _, source := range signed.Proof.Sources {
			input, ok := sources[source.SourceID]
			if !ok {
				continue
			}
			view, err := source.Recipe.Apply(input)
			if err != nil {
				report.ViewReproduction = "mismatch"
				return rejectProvenance(report, "view_reproduction")
			}
			viewCommitment, err := contractreceipt.CommitView(commitmentKey, source, view)
			if err != nil || !hmacStringEqual(viewCommitment, source.ViewCommitment) {
				report.MatchCommitment = "mismatch"
				return rejectProvenance(report, "view_commitment")
			}
			for _, match := range source.Matches {
				got, err := contractreceipt.CommitMatch(commitmentKey, source.SourceID, source.Recipe, source.ViewCommitment, match)
				if err != nil || !hmacStringEqual(got, match.MatchCommitment) {
					report.MatchCommitment = "mismatch"
					return rejectProvenance(report, "match_commitment")
				}
			}
		}
	}
	if sourceUnavailable || !sourceVisited {
		return report
	}
	report.MatchCommitment = "opened"
	return report
}

func verifyProvenanceArtifacts(proofs []signedProvenanceProof, inputs provenanceVerificationInputs) (string, error) {
	unchecked := false
	for _, signed := range proofs {
		for _, artifact := range []struct {
			attested *string
			encoded  *string
		}{{signed.Proof.Producer.BinaryDigest, inputs.BinaryB64}, {signed.Proof.Producer.RulesetDigest, inputs.RulesetB64}} {
			if artifact.attested == nil {
				continue
			}
			if artifact.encoded == nil {
				unchecked = true
				continue
			}
			data, err := base64.StdEncoding.Strict().DecodeString(*artifact.encoded)
			if err != nil {
				return "mismatch", err
			}
			sum := sha256.Sum256(data)
			if *artifact.attested != "sha256:"+hex.EncodeToString(sum[:]) {
				return "mismatch", errors.New("artifact digest mismatch")
			}
		}
	}
	if unchecked {
		return "attested_unchecked", nil
	}
	return "matched", nil
}

func provenanceSources(values []provenanceFixtureSource) (map[string]string, error) {
	result := make(map[string]string, len(values))
	for _, source := range values {
		if source.SourceID == "" {
			return nil, errors.New("missing source ID")
		}
		if _, exists := result[source.SourceID]; exists {
			return nil, fmt.Errorf("duplicate source ID %q", source.SourceID)
		}
		decoded, err := base64.StdEncoding.Strict().DecodeString(source.BytesB64)
		if err != nil || !utf8.Valid(decoded) {
			return nil, fmt.Errorf("source %q is not canonical base64 UTF-8", source.SourceID)
		}
		result[source.SourceID] = string(decoded)
	}
	return result, nil
}

func validateProvenanceLocations(view string, matches []contractreceipt.ProvenanceMatch) error {
	for _, match := range matches {
		if match.ByteStart >= match.ByteEnd || match.ByteEnd > uint64(len(view)) {
			return errors.New("interval out of bounds")
		}
		if !provenanceByteBoundary(view, match.ByteStart) || !provenanceByteBoundary(view, match.ByteEnd) {
			return errors.New("interval splits UTF-8 code point")
		}
	}
	return nil
}

func provenanceByteBoundary(value string, offset uint64) bool {
	if offset == 0 || offset == uint64(len(value)) {
		return true
	}
	return offset < uint64(len(value)) && (value[offset]&0xc0) != 0x80
}

func decodePrefixedHex(value, prefix string, size int) ([]byte, error) {
	if !strings.HasPrefix(value, prefix) {
		return nil, fmt.Errorf("missing %q prefix", prefix)
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, prefix))
	if err != nil || len(decoded) != size {
		return nil, fmt.Errorf("invalid %s value", prefix)
	}
	return decoded, nil
}

func hmacStringEqual(left, right string) bool {
	return len(left) == len(right) && hmac.Equal([]byte(left), []byte(right))
}

func decodeStrictJSON(data []byte, destination any) error {
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("found trailing JSON value")
		}
		return fmt.Errorf("decode trailing JSON: %w", err)
	}
	return nil
}

func rejectDuplicateJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := scanJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("found trailing JSON value")
		}
		return fmt.Errorf("decode trailing JSON: %w", err)
	}
	return nil
}

func scanJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("JSON object key is not a string")
			}
			if _, exists := seen[key]; exists {
				return fmt.Errorf("duplicate JSON object key %q", key)
			}
			seen[key] = struct{}{}
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delim)
	}
}
