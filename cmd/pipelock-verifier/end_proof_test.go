// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/evidence/endproof"
)

func TestChainEndProofParity(t *testing.T) {
	root := filepath.Join("..", "..", "sdk", "conformance", "testdata", "end-proof")
	data, err := os.ReadFile(filepath.Clean(filepath.Join(root, "expect.json")))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Key   string
		Cases []struct {
			Name, File, Status string
			Flags              []string
			Exit               int
			Proven             bool
		}
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, c := range fixture.Cases {
		t.Run(c.Name, func(t *testing.T) {
			args := append([]string{"chain", filepath.Join(root, c.File), "--key", fixture.Key}, c.Flags...)
			for _, jsonMode := range []bool{false, true} {
				var stdout, stderr bytes.Buffer
				invocation := append([]string(nil), args...)
				if jsonMode {
					invocation = append(invocation, "--json")
				}
				code := execute(invocation, &stdout, &stderr)
				if code != c.Exit {
					t.Fatalf("exit=%d want=%d: %s %s", code, c.Exit, stdout.String(), stderr.String())
				}
				if jsonMode {
					var report endproof.Report
					if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
						t.Fatal(err)
					}
					if report.Status != c.Status || report.EndProof.Proven != c.Proven || report.Scope != "receipt_chain" {
						t.Fatalf("report=%+v", report)
					}
					if (report.Integrity == "valid") != (c.Exit != 1) {
						t.Fatalf("integrity=%s", report.Integrity)
					}
				} else if !strings.Contains(stdout.String()+stderr.String(), c.Status) {
					t.Fatalf("missing %s: %s %s", c.Status, stdout.String(), stderr.String())
				}
			}
		})
	}
}

func TestEvidenceOutputWithSequenceEndProof(t *testing.T) {
	var stdout, stderr bytes.Buffer
	report := chainReport{
		Report:     endproof.New(true, "receipt_chain", "operator_seq"),
		Path:       "evidence.jsonl",
		Valid:      true,
		RecordType: recordTypeEvidenceV2,
	}
	emitChainReport(&stdout, &stderr, report, false)
	if strings.Contains(stdout.String()+stderr.String(), endproof.Prefix) || !strings.Contains(stdout.String(), "endpoint verified") {
		t.Fatalf("sequence proof contradicted: %s %s", stdout.String(), stderr.String())
	}
}
