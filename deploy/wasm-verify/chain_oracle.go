// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build ignore

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

type oracleCase struct {
	Name string   `json:"name"`
	Path string   `json:"path"`
	Keys []string `json:"keys"`
}

type oracleResult struct {
	Name               string               `json:"name"`
	Valid              bool                 `json:"valid"`
	Observed           int                  `json:"observed"`
	Error              string               `json:"error,omitempty"`
	Reason             string               `json:"reason,omitempty"`
	IntegrityVerified  bool                 `json:"integrityVerified,omitempty"`
	ReceiptCount       uint64               `json:"receiptCount,omitempty"`
	FinalSeq           uint64               `json:"finalSeq,omitempty"`
	RootHash           string               `json:"rootHash,omitempty"`
	StartTime          string               `json:"startTime,omitempty"`
	EndTime            string               `json:"endTime,omitempty"`
	FailureKind        string               `json:"failureKind,omitempty"`
	BrokenAtSeq        *uint64              `json:"brokenAtSeq,omitempty"`
	BrokenAtIndex      *int                 `json:"brokenAtIndex,omitempty"`
	SignerKeys         []string             `json:"signerKeys,omitempty"`
	Segments           []oracleChainSegment `json:"segments,omitempty"`
	UntrustedSignerKey string               `json:"untrustedSignerKey,omitempty"`
}

type oracleChainSegment struct {
	SignerKey string `json:"signerKey"`
	FirstSeq  uint64 `json:"firstSeq"`
	FinalSeq  uint64 `json:"finalSeq"`
	Count     uint64 `json:"count"`
	Boundary  bool   `json:"boundary"`
}

func main() {
	var cases []oracleCase
	if err := json.NewDecoder(os.Stdin).Decode(&cases); err != nil {
		fatalf("decode cases: %v", err)
	}
	results := make([]oracleResult, 0, len(cases))
	for _, tc := range cases {
		result, err := runCase(tc)
		if err != nil {
			fatalf("%s: %v", tc.Name, err)
		}
		results = append(results, result)
	}
	if err := json.NewEncoder(os.Stdout).Encode(results); err != nil {
		fatalf("encode results: %v", err)
	}
}

func runCase(tc oracleCase) (oracleResult, error) {
	data, err := os.ReadFile(tc.Path)
	if err != nil {
		return oracleResult{}, fmt.Errorf("read fixture: %w", err)
	}
	receipts, err := receipt.ExtractReceiptsBytes(data)
	if err != nil {
		return oracleResult{
			Name:  tc.Name,
			Valid: false,
			Error: err.Error(),
		}, nil
	}
	if len(receipts) == 0 {
		return oracleResult{
			Name:  tc.Name,
			Valid: false,
			Error: "no receipts found in chain",
		}, nil
	}
	return chainResult(tc.Name, receipt.VerifyChainTrusted(receipts, tc.Keys), len(receipts)), nil
}

func chainResult(name string, result receipt.ChainResult, observed int) oracleResult {
	out := oracleResult{
		Name:               name,
		Valid:              result.Valid,
		Observed:           observed,
		Error:              result.Error,
		Reason:             result.Error,
		IntegrityVerified:  result.IntegrityVerified,
		ReceiptCount:       result.ReceiptCount,
		FinalSeq:           result.FinalSeq,
		RootHash:           result.RootHash,
		FailureKind:        string(result.FailureKind),
		SignerKeys:         result.SignerKeys,
		UntrustedSignerKey: result.UntrustedSignerKey,
	}
	if !result.Valid {
		brokenAtSeq := result.BrokenAtSeq
		brokenAtIndex := result.BrokenAtIndex
		out.BrokenAtSeq = &brokenAtSeq
		out.BrokenAtIndex = &brokenAtIndex
	}
	if !result.StartTime.IsZero() {
		out.StartTime = result.StartTime.Format(time.RFC3339Nano)
	}
	if !result.EndTime.IsZero() {
		out.EndTime = result.EndTime.Format(time.RFC3339Nano)
	}
	if len(result.Segments) > 0 {
		out.Segments = make([]oracleChainSegment, 0, len(result.Segments))
		for _, segment := range result.Segments {
			out.Segments = append(out.Segments, oracleChainSegment{
				SignerKey: segment.SignerKey,
				FirstSeq:  segment.FirstSeq,
				FinalSeq:  segment.FinalSeq,
				Count:     segment.Count,
				Boundary:  segment.Boundary,
			})
		}
	}
	return out
}

func fatalf(format string, args ...any) {
	_, _ = fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
