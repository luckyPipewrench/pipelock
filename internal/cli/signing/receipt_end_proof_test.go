// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/evidence/endproof"
)

func TestVerifyReceiptEndProofParity(t *testing.T) {
	root := filepath.Join("..", "..", "..", "sdk", "conformance", "testdata", "end-proof")
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
			for _, jsonMode := range []bool{false, true} {
				cmd := VerifyReceiptCmd()
				var stdout, stderr bytes.Buffer
				cmd.SetOut(&stdout)
				cmd.SetErr(&stderr)
				cmd.SilenceErrors = true
				cmd.SilenceUsage = true
				args := append([]string{filepath.Join(root, c.File), "--key", fixture.Key}, c.Flags...)
				if jsonMode {
					args = append(args, "--json")
				}
				cmd.SetArgs(args)
				err := cmd.Execute()
				code := 0
				if err != nil {
					code = 1
					var ee *cliutil.ExitError
					if errors.As(err, &ee) {
						code = ee.Code
					}
				}
				if code != c.Exit {
					t.Fatalf("exit=%d want=%d: %v %s", code, c.Exit, err, stdout.String())
				}
				if jsonMode {
					var report endproof.Report
					if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
						t.Fatal(err)
					}
					if report.Status != c.Status || report.EndProof.Proven != c.Proven || report.Scope != "receipt_chain" {
						t.Fatalf("report=%+v", report)
					}
				} else if !strings.Contains(stdout.String(), c.Status) {
					t.Fatalf("missing %s: %s", c.Status, stdout.String())
				}
			}
		})
	}
}

// Existing structural tests deliberately inspect prefixes. New contract tests
// execute the command directly to exercise its default endpoint requirement.
func legacyReceiptPrefixArgs(cmd *cobra.Command, args []string) []string {
	if cmd.Name() != "verify-receipt" {
		return args
	}
	chain := false
	for _, arg := range args {
		if arg == "--fleet-report" {
			return args
		}
		chain = chain || arg == "--chain" || strings.HasSuffix(arg, ".jsonl")
	}
	if chain {
		return append(append([]string{}, args...), "--allow-prefix")
	}
	return args
}

func TestCleanReportEndProof(t *testing.T) {
	root := filepath.Join("..", "..", "..", "sdk", "conformance", "testdata", "end-proof")
	data, err := os.ReadFile(filepath.Clean(filepath.Join(root, "expect.json")))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct{ Key string }
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		file   string
		allow  bool
		code   int
		proven bool
	}{
		{"truncated.jsonl", false, 3, false}, {"truncated.jsonl", true, 0, false}, {"closed.jsonl", false, 0, true},
	} {
		t.Run(tc.file+fmt.Sprint(tc.allow), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "clean.json")
			cmd := VerifyReceiptCmd()
			var out bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetErr(&out)
			cmd.SilenceUsage = true
			cmd.SilenceErrors = true
			args := []string{filepath.Join(root, tc.file), "--key", fixture.Key, "--clean-report", path}
			if tc.allow {
				args = append(args, "--allow-prefix")
			}
			cmd.SetArgs(args)
			err := cmd.Execute()
			code := 0
			if err != nil {
				code = 1
				var ee *cliutil.ExitError
				if errors.As(err, &ee) {
					code = ee.Code
				}
			}
			if code != tc.code {
				t.Fatalf("code=%d: %v %s", code, err, out.String())
			}
			data, err := os.ReadFile(filepath.Clean(path))
			if err != nil {
				t.Fatal(err)
			}
			var report cleanActionReport
			if err := json.Unmarshal(data, &report); err != nil {
				t.Fatal(err)
			}
			if report.EndProof.Proven != tc.proven || report.Integrity != "valid" || report.Scope != "receipt_chain" {
				t.Fatalf("%s", data)
			}
			if !tc.proven && (!strings.Contains(out.String(), endproof.Prefix) || report.Status != endproof.Prefix) {
				t.Fatalf("missing prefix: %s %s", out.String(), data)
			}
			if err := validateCleanReportSchema(t, data); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// writeEvidenceJSONL writes the historical receipt-only wrapper, without
// recorder metadata. The signed receipts come from the shared runtime corpus.

func writeEvidenceJSONL(t *testing.T, path string) {
	t.Helper()
	source := filepath.Join("..", "..", "..", "sdk", "conformance", "testdata", "run-chains", "valid", "evidence-proxy.run.03b13ee13e01e7f770480f62ea42f1fe-0.jsonl")
	data, err := os.ReadFile(filepath.Clean(source))
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	for _, line := range bytes.Split(bytes.TrimSpace(data), []byte("\n")) {
		var entry struct {
			Type   string          `json:"type"`
			Detail json.RawMessage `json:"detail"`
		}
		if err := json.Unmarshal(line, &entry); err != nil {
			t.Fatal(err)
		}
		if entry.Type != "evidence_receipt" {
			continue
		}
		if err := json.NewEncoder(&out).Encode(entry); err != nil {
			t.Fatal(err)
		}
	}
	if out.Len() == 0 {
		t.Fatal("no evidence receipts")
	}
	if err := os.WriteFile(path, out.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyReceiptBareEvidenceDirectory(t *testing.T) {
	key := parityKey(t)
	for _, mixed := range []bool{false, true} {
		t.Run(fmt.Sprint(mixed), func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "evidence-proxy-0.jsonl")
			writeEvidenceJSONL(t, path)
			if mixed {
				f, err := os.OpenFile(filepath.Clean(path), os.O_APPEND|os.O_WRONLY, 0o600)
				if err != nil {
					t.Fatal(err)
				}
				_, err = f.WriteString(`{"v":2,"type":"decision"}` + "\n")
				if err != nil {
					t.Fatal(err)
				}
				if err := f.Close(); err != nil {
					t.Fatal(err)
				}
			}
			for _, allow := range []bool{false, true} {
				cmd := VerifyReceiptCmd()
				var out bytes.Buffer
				cmd.SetOut(&out)
				cmd.SetErr(&out)
				cmd.SilenceUsage = true
				cmd.SilenceErrors = true
				args := []string{"--chain", dir, "--key", key}
				if allow {
					args = append(args, "--allow-prefix")
				}
				cmd.SetArgs(args)
				err := cmd.Execute()
				if mixed {
					if err == nil || isPrefixError(err) {
						t.Fatalf("mixed input accepted: %v %s", err, out.String())
					}
					continue
				}
				if allow && err != nil || !allow && !isPrefixError(err) {
					t.Fatalf("allow=%v err=%v %s", allow, err, out.String())
				}
				if !strings.Contains(out.String(), endproof.Prefix) {
					t.Fatal(out.String())
				}
			}
		})
	}
}

func TestCleanReportStructuralPrefixAPI(t *testing.T) {
	source := parityFile(filepath.Join(parityFixtureDir, "valid"), parityRun1)
	actions, evidence, err := extractFileChains(filepath.Base(source), source)
	if err != nil {
		t.Fatal(err)
	}
	if len(evidence) == 0 {
		t.Fatal("expected mixed signed fixture")
	}
	for _, allowUnpinned := range []bool{false, true} {
		var keys []string
		if !allowUnpinned {
			keys = []string{parityKey(t)}
		}
		if err := verifyCleanReport(io.Discard, source, actions, evidence, keys, allowUnpinned, filepath.Join(t.TempDir(), "clean.json")); err != nil {
			t.Fatal(err)
		}
	}
}

func TestWholeRecorderEndProof(t *testing.T) {
	sealed, sealedKey := buildSealedRecorderJSONL(t)
	open, openKey := buildChainJSONL(t, 1)
	for _, tc := range []struct {
		name, path, key string
		flags           []string
		code            int
		proven          bool
	}{
		{"sealed", sealed, hex.EncodeToString(sealedKey), nil, 0, true},
		{"open", open, hex.EncodeToString(openKey), nil, 3, false},
		{"accepted-prefix", open, hex.EncodeToString(openKey), []string{"--allow-prefix"}, 0, false},
		{"required-seal", open, hex.EncodeToString(openKey), []string{"--require-seal", "--allow-prefix"}, 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, jsonMode := range []bool{false, true} {
				cmd := VerifyReceiptCmd()
				var out bytes.Buffer
				cmd.SetOut(&out)
				cmd.SetErr(&out)
				cmd.SilenceUsage = true
				cmd.SilenceErrors = true
				args := append([]string{tc.path, "--whole-recorder", "--key", tc.key}, tc.flags...)
				if jsonMode {
					args = append(args, "--json")
				}
				cmd.SetArgs(args)
				err := cmd.Execute()
				code := 0
				if err != nil {
					code = 1
					var ee *cliutil.ExitError
					if errors.As(err, &ee) {
						code = ee.Code
					}
				}
				if code != tc.code {
					t.Fatalf("code=%d want=%d: %v %s", code, tc.code, err, out.String())
				}
				if jsonMode {
					var report endproof.Report
					if err := json.Unmarshal(out.Bytes(), &report); err != nil {
						t.Fatal(err)
					}
					if report.EndProof.Proven != tc.proven || report.Scope != "whole_recorder" {
						t.Fatalf("report=%+v", report)
					}
					if tc.proven && strings.Join(report.EndProof.Evidence, ",") != "transcript_root,trailing_checkpoint" {
						t.Fatalf("proof=%+v", report.EndProof)
					}
				} else if tc.code != 1 && !tc.proven && !strings.Contains(out.String(), endproof.Prefix) {
					t.Fatalf("missing prefix label: %s", out.String())
				}
			}
		})
	}
}
