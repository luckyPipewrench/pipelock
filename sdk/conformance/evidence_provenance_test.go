// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package conformance_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	contractreceipt "github.com/luckyPipewrench/pipelock/internal/contract/receipt"
	"github.com/luckyPipewrench/pipelock/internal/normalize"
)

type provenanceCorpus struct {
	Format            string             `json:"format"`
	ProfileDigest     string             `json:"profile_digest"`
	OperationCoverage []string           `json:"operation_coverage"`
	ErrorCoverage     []string           `json:"error_coverage"`
	ErrorDefinitions  map[string]string  `json:"error_definitions"`
	Vectors           []provenanceVector `json:"vectors"`
	IntervalVectors   []intervalVector   `json:"interval_vectors"`
}

type intervalVector struct {
	ID        string      `json:"id"`
	ViewB64   string      `json:"view_b64"`
	Matches   [][2]uint64 `json:"matches"`
	WantError string      `json:"want_error"`
}

type provenanceVector struct {
	ID                     string                `json:"id"`
	Operations             []string              `json:"operations"`
	Errors                 []string              `json:"errors"`
	InputB64               string                `json:"input_b64"`
	OutputB64              string                `json:"output_b64"`
	WantError              string                `json:"want_error"`
	TransformProfileDigest *string               `json:"transform_profile_digest"`
	Recipe                 []normalize.Operation `json:"recipe"`
}

func TestEvidenceProvenanceTransformCorpus(t *testing.T) {
	corpus := loadProvenanceCorpus(t)
	if corpus.Format != "pipelock-evidence-transform-corpus/v1" {
		t.Fatalf("format = %q", corpus.Format)
	}
	covered := make(map[string]bool)
	errors := make(map[string]bool)
	for _, vector := range corpus.Vectors {
		t.Run(vector.ID, func(t *testing.T) {
			input, err := base64.StdEncoding.DecodeString(vector.InputB64)
			if err != nil {
				t.Fatalf("input: %v", err)
			}
			recipe := normalize.Recipe{TransformProfileDigest: corpus.ProfileDigest, Operations: vector.Recipe}
			if vector.TransformProfileDigest != nil {
				recipe.TransformProfileDigest = *vector.TransformProfileDigest
			}
			output, err := recipe.Apply(string(input))
			actualOperations := executedOperationKinds(recipe, string(input), err)
			// The coverage gate below must prove every operation has a WORKING
			// vector. executedOperationKinds includes the operation that
			// failed, which is right for the declared-metadata cross-check but
			// wrong here: counting it would let an operation satisfy coverage
			// with error vectors alone and never run successfully once.
			if err == nil {
				for kind := range actualOperations {
					covered[kind] = true
				}
			}
			if err := validateDeclaredOperations(vector, actualOperations); err != nil {
				t.Fatal(err)
			}
			if vector.WantError != "" {
				if err == nil || !strings.Contains(err.Error(), vector.WantError) {
					t.Fatalf("error = %v, want %q", err, vector.WantError)
				}
				// Bind each declared code to its corpus-defined message via
				// error_definitions, then require the OBSERVED error to match
				// that definition. Without this a vector could declare a code
				// while asserting an unrelated message, and the coverage gate
				// below would pass without ever exercising the declared path.
				for _, code := range vector.Errors {
					want, defined := corpus.ErrorDefinitions[code]
					if !defined {
						t.Fatalf("declares error code %q with no entry in error_definitions", code)
					}
					if !strings.Contains(err.Error(), want) {
						t.Fatalf("declares error code %q (defined as %q) but observed error %v does not match", code, want, err)
					}
					errors[code] = true
				}
				return
			}
			if len(vector.Errors) != 0 {
				t.Fatal("declares errors but expects success")
			}
			if err != nil {
				t.Fatal(err)
			}
			want, err := base64.StdEncoding.DecodeString(vector.OutputB64)
			if err != nil {
				t.Fatalf("output: %v", err)
			}
			if output != string(want) {
				t.Fatalf("output = %q, want %q", output, string(want))
			}
		})
	}
	for _, kind := range normalize.SupportedOperationKinds() {
		if !covered[string(kind)] {
			t.Fatalf("operation %q has no corpus vector", kind)
		}
		if !slices.Contains(corpus.OperationCoverage, string(kind)) {
			t.Fatalf("operation %q missing declared coverage", kind)
		}
	}
	for _, code := range corpus.ErrorCoverage {
		if !errors[code] {
			t.Fatalf("error %q has no corpus vector", code)
		}
	}
	for _, vector := range corpus.IntervalVectors {
		t.Run(vector.ID, func(t *testing.T) {
			view, err := base64.StdEncoding.DecodeString(vector.ViewB64)
			if err != nil {
				t.Fatalf("view: %v", err)
			}
			matches := make([]contractreceipt.ProvenanceMatch, len(vector.Matches))
			for index, bounds := range vector.Matches {
				matches[index] = contractreceipt.ProvenanceMatch{MatchOrdinal: uint64(index + 1), ByteStart: bounds[0], ByteEnd: bounds[1], MatchClass: "fixture", MatchCommitment: conformanceCommitment}
			}
			source := contractreceipt.ProvenanceSource{SourceOrdinal: 1, SourceID: vector.ID, Recipe: normalize.Recipe{TransformProfileDigest: corpus.ProfileDigest, Operations: []normalize.Operation{{Kind: normalize.OperationIdentity}}}, ViewCommitment: conformanceCommitment, Matches: matches}
			proof := contractreceipt.EvidenceProvenanceProof{Version: contractreceipt.EvidenceProvenanceProofVersionV1, TransformProfileDigest: corpus.ProfileDigest, Sources: []contractreceipt.ProvenanceSource{source}}
			err = proof.Validate()
			if err == nil {
				err = source.ValidateView(string(view))
			}
			if vector.WantError == "" && err != nil {
				t.Fatal(err)
			}
			if vector.WantError != "" && (err == nil || !strings.Contains(err.Error(), vector.WantError)) {
				t.Fatalf("error = %v, want %q", err, vector.WantError)
			}
		})
	}
}

const conformanceCommitment = "hmac-sha256:0000000000000000000000000000000000000000000000000000000000000000"

func TestEvidenceProvenanceCorpusRejectsMetadataThatDoesNotExecute(t *testing.T) {
	vector := provenanceVector{ID: "declared-but-not-executed", Operations: []string{"lowercase"}, Recipe: []normalize.Operation{{Kind: normalize.OperationIdentity}}}
	err := validateDeclaredOperations(vector, map[string]bool{string(normalize.OperationIdentity): true})
	if err == nil || !strings.Contains(err.Error(), "executed operations") {
		t.Fatalf("error = %v, want metadata mismatch", err)
	}
}

func TestExecutedOperationKindsStopsAtFailingOperation(t *testing.T) {
	recipe := normalize.Recipe{TransformProfileDigest: normalize.EvidenceProvenanceProfileV1Digest, Operations: []normalize.Operation{{Kind: normalize.OperationPercentDecode, Passes: 1}, {Kind: normalize.OperationLowercase}}}
	_, err := recipe.Apply("%ff")
	if err == nil {
		t.Fatal("recipe unexpectedly succeeded")
	}
	got := executedOperationKinds(recipe, "%ff", err)
	want := map[string]bool{string(normalize.OperationPercentDecode): true}
	if !mapsEqual(got, want) {
		t.Fatalf("executed operations = %v, want %v", got, want)
	}
}

func TestEvidenceProvenanceCorpusRejectsTrailingJSONValue(t *testing.T) {
	_, err := decodeProvenanceCorpus([]byte(`{"format":"pipelock-evidence-transform-corpus/v1"} {}`))
	if err == nil || !strings.Contains(err.Error(), "found a trailing value") {
		t.Fatalf("error = %v, want a readable trailing-value rejection", err)
	}
	// Assert the message is READABLE, not merely present. The previous form
	// formatted a nil error through %w and emitted "%!w(<nil>)", which the
	// substring assertion happily accepted.
	if strings.Contains(err.Error(), "%!w") {
		t.Fatalf("error message contains a formatting artifact: %v", err)
	}
	// A genuinely malformed trailing token is a different failure and must
	// still surface the decoder's own error.
	_, err = decodeProvenanceCorpus([]byte(`{"format":"pipelock-evidence-transform-corpus/v1"} @`))
	if err == nil || !strings.Contains(err.Error(), "exactly one JSON value") {
		t.Fatalf("malformed trailing token error = %v", err)
	}
}

func loadProvenanceCorpus(t *testing.T) provenanceCorpus {
	t.Helper()
	path := filepath.Clean(filepath.Join(testdataDir, "transform-profile", "evidence-provenance-v1.json"))
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	corpus, err := decodeProvenanceCorpus(data)
	if err != nil {
		t.Fatal(err)
	}
	return corpus
}

func decodeProvenanceCorpus(data []byte) (provenanceCorpus, error) {
	var corpus provenanceCorpus
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&corpus); err != nil {
		return provenanceCorpus{}, err
	}
	// The two failure modes are distinct and must read differently. A trailing
	// VALUE decodes successfully, so err is nil; formatting nil through %w
	// produced "%!w(<nil>)" and buried the actual problem.
	var trailing any
	switch err := decoder.Decode(&trailing); {
	case err == nil:
		return provenanceCorpus{}, fmt.Errorf("corpus must contain exactly one JSON value, found a trailing value")
	case !errors.Is(err, io.EOF):
		return provenanceCorpus{}, fmt.Errorf("corpus must contain exactly one JSON value: %w", err)
	}
	return corpus, nil
}

func mapsEqual(left, right map[string]bool) bool {
	if len(left) != len(right) {
		return false
	}
	for key := range left {
		if !right[key] {
			return false
		}
	}
	return true
}

func validateDeclaredOperations(vector provenanceVector, actual map[string]bool) error {
	declared := make(map[string]bool, len(vector.Operations))
	for _, operation := range vector.Operations {
		if declared[operation] {
			return fmt.Errorf("%s declares operation %q more than once", vector.ID, operation)
		}
		declared[operation] = true
	}
	if !mapsEqual(declared, actual) {
		return fmt.Errorf("%s operations = %v, executed operations = %v", vector.ID, vector.Operations, operationKindsFromSet(actual))
	}
	return nil
}

func operationKindsFromSet(kinds map[string]bool) []string {
	result := make([]string, 0, len(kinds))
	for _, kind := range normalize.SupportedOperationKinds() {
		if kinds[string(kind)] {
			result = append(result, string(kind))
		}
	}
	return result
}

func executedOperationKinds(recipe normalize.Recipe, input string, applyErr error) map[string]bool {
	executed := make(map[string]bool)
	if !utf8.ValidString(input) || recipe.Validate() != nil || (applyErr != nil && strings.Contains(applyErr.Error(), "recipe input: exceeds profile byte limit")) {
		return executed
	}
	for index, operation := range recipe.Operations {
		prefix := recipe
		prefix.Operations = recipe.Operations[:index+1]
		_, err := prefix.Apply(input)
		executed[string(operation.Kind)] = true
		if err != nil {
			break
		}
	}
	return executed
}
