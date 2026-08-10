// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package completeness

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

var updateLifecycleVectors = flag.Bool("update-lifecycle-vectors", false, "write lifecycle vector verdicts computed by Go")

type lifecycleVectorFile struct {
	GeneratedBy string            `json:"generated_by"`
	Vectors     []lifecycleVector `json:"vectors"`
}

type lifecycleVector struct {
	Name          string            `json:"name"`
	Receipts      []json.RawMessage `json:"receipts"`
	ChainResult   lifecycleChain    `json:"chain_result"`
	Expected      lifecycleExpected `json:"expected"`
	GoDecodeError bool              `json:"go_decode_error,omitempty"`
}

type lifecycleChain struct {
	Valid             bool   `json:"valid"`
	IntegrityVerified bool   `json:"integrity_verified,omitempty"`
	FailureKind       string `json:"failure_kind,omitempty"`
}

type lifecycleExpected struct {
	Status Status `json:"status"`
	Reason Reason `json:"reason"`
}

func TestLifecycleVerdictVectorsMatchGo(t *testing.T) {
	path := filepath.Join("..", "..", "..", "sdk", "conformance", "testdata", "lifecycle-verdict-vectors.json")
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("read lifecycle vectors: %v", err)
	}
	var file lifecycleVectorFile
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatalf("decode lifecycle vectors: %v", err)
	}
	if len(file.Vectors) == 0 {
		t.Fatal("lifecycle vector file is empty")
	}
	required := map[string]bool{
		"no_receipts": false, "no_lifecycle": false, "no_open": false,
		"bounded_closed": false, "abnormal_end": false, "open_action": false,
		"heartbeat_gap": false, "orphan_outcome": false, "duplicate_outcome": false,
		"durability_decrease": false, "missing_run_nonce": false,
		"null_session_control": false,
	}
	sawGoDecodeError := false

	for i := range file.Vectors {
		vector := &file.Vectors[i]
		t.Run(vector.Name, func(t *testing.T) {
			if _, ok := required[vector.Name]; ok {
				required[vector.Name] = true
			}
			receipts, err := decodeLifecycleVectorReceipts(vector.Receipts)
			if vector.GoDecodeError {
				sawGoDecodeError = true
				if err == nil {
					t.Fatalf("decoded successfully, want Go parser rejection")
				}
				return
			}
			if err != nil {
				t.Fatalf("decode receipts: %v", err)
			}
			report := Analyze(receipts, receipt.ChainResult{
				Valid:             vector.ChainResult.Valid,
				IntegrityVerified: vector.ChainResult.IntegrityVerified,
				FailureKind:       receipt.ChainFailureKind(vector.ChainResult.FailureKind),
			})
			actual := lifecycleExpected{Status: report.Status, Reason: report.Reason}
			if *updateLifecycleVectors {
				vector.Expected = actual
				return
			}
			if actual != vector.Expected {
				t.Fatalf("got %s/%s, want %s/%s", actual.Status, actual.Reason, vector.Expected.Status, vector.Expected.Reason)
			}
		})
	}
	for name, present := range required {
		if !present {
			t.Fatalf("lifecycle vector %q is missing", name)
		}
	}
	if !sawGoDecodeError {
		t.Fatal("lifecycle vector file has no Go parser rejection vector")
	}
	if !*updateLifecycleVectors {
		return
	}
	file.GeneratedBy = "go test ./internal/evidence/completeness -run TestLifecycleVerdictVectorsMatchGo -update-lifecycle-vectors"
	encoded, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		t.Fatalf("encode generated lifecycle vectors: %v", err)
	}
	if err := os.WriteFile(path, append(encoded, '\n'), 0o600); err != nil {
		t.Fatalf("write generated lifecycle vectors: %v", err)
	}
}

func decodeLifecycleVectorReceipts(raw []json.RawMessage) ([]receipt.Receipt, error) {
	receipts := make([]receipt.Receipt, len(raw))
	for i := range raw {
		if err := json.Unmarshal(raw[i], &receipts[i]); err != nil {
			return nil, err
		}
	}
	return receipts, nil
}
