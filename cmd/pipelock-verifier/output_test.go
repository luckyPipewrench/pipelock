// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
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
