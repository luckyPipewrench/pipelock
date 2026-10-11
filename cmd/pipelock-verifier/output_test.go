// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestEmitReceiptReport_HumanEvidencePolicyHash(t *testing.T) {
	t.Parallel()
	policyHash := "sha256:" + strings.Repeat("3", 64)
	var stdout, stderr bytes.Buffer

	emitReceiptReport(&stdout, &stderr, receiptReport{
		Valid:       true,
		Path:        "receipt.json",
		RecordType:  recordTypeEvidenceV2,
		PayloadKind: "proxy_decision",
		SignerKeyID: "receipt-key",
		PolicyHash:  policyHash,
		ChainSeq:    7,
	}, false)

	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
	if !strings.Contains(stdout.String(), "  policy_hash:  "+policyHash+"\n") {
		t.Fatalf("stdout missing policy_hash line:\n%s", stdout.String())
	}
}

func TestEmitChainReportActionTailWarning(t *testing.T) {
	t.Parallel()
	var out, errOut bytes.Buffer
	emitChainReport(&out, &errOut, chainReport{Valid: true, Path: "evidence.jsonl"}, false)
	if !strings.Contains(out.String(), "CHAIN VALID") || !strings.Contains(out.String(), "WARNING: chain end is unanchored") {
		t.Fatalf("output: %s", out.String())
	}
}

func TestEmitChainReportJSONTailWarning(t *testing.T) {
	t.Parallel()
	var out, errOut bytes.Buffer
	emitChainReport(&out, &errOut, chainReport{Valid: true, Path: "evidence.jsonl"}, true)
	var report struct {
		Valid    bool     `json:"valid"`
		Warnings []string `json:"warnings"`
	}
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if !report.Valid || len(report.Warnings) != 1 || !strings.Contains(report.Warnings[0], "chain end is unanchored") {
		t.Fatalf("missing tail warning: %s", out.String())
	}
}
