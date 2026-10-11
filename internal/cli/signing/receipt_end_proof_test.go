// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
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
	"github.com/luckyPipewrench/pipelock/internal/contract/proxydecision"
	"github.com/luckyPipewrench/pipelock/internal/evidence/endproof"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
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
		file     string
		allow    bool
		code     int
		proven   bool
		unpinned bool
	}{
		{"truncated.jsonl", false, 3, false, false},
		{"truncated.jsonl", true, 0, false, false},
		{"closed.jsonl", false, 0, true, false},
		{"closed.jsonl", false, 0, true, true},
		{"truncated.jsonl", false, 3, false, true},
		{"truncated.jsonl", true, 0, false, true},
	} {
		t.Run(tc.file+fmt.Sprint(tc.allow, tc.unpinned), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "clean.json")
			cmd := VerifyReceiptCmd()
			var out bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetErr(&out)
			cmd.SilenceUsage = true
			cmd.SilenceErrors = true
			args := []string{filepath.Join(root, tc.file), "--key", fixture.Key, "--clean-report", path}
			if tc.unpinned {
				args = []string{filepath.Join(root, tc.file), "--allow-unpinned", "--clean-report", path}
			}
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
			wantStatus := endproof.Prefix
			if tc.proven {
				wantStatus = endproof.Valid
				if tc.unpinned {
					wantStatus = "CHAIN UNPINNED"
				}
			}
			if report.SchemaVersion != "pipelock.clean_report.v2" || report.Status != wantStatus {
				t.Fatalf("status/schema: %s", data)
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
	sealed, sealedKey := buildRunSealedRecorderJSONL(t)
	legacy, legacyKey := buildSealedRecorderJSONL(t)
	open, openKey := buildChainJSONL(t, 1)
	for _, tc := range []struct {
		name, path, key string
		flags           []string
		code            int
		proven          bool
	}{
		{"sealed", sealed, hex.EncodeToString(sealedKey), nil, 0, true},
		// A legacy shared session's seal is not its end: the next restart
		// resumed the same recorder chain after it.
		{"legacy-sealed", legacy, hex.EncodeToString(legacyKey), nil, 3, false},
		{"legacy-sealed-prefix", legacy, hex.EncodeToString(legacyKey), []string{"--allow-prefix"}, 0, false},
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

// buildRunSealedRecorderJSONL builds the production shape: a per-run recorder
// session, sealed by a transcript_root with a trailing signed checkpoint.
func buildRunSealedRecorderJSONL(t *testing.T) (string, ed25519.PublicKey) {
	t.Helper()
	dir := t.TempDir()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, CheckpointInterval: 1000, SignCheckpoints: true}, nil, priv)
	if err != nil {
		t.Fatal(err)
	}
	session, err := recorder.AcquireRunSession(rec, recorder.DefaultSessionBase)
	if err != nil {
		t.Fatal(err)
	}
	emitter := receipt.NewEmitter(receipt.EmitterConfig{Recorder: rec, PrivKey: priv, ConfigHash: "test-chain-hash", Principal: "test", Actor: "test", Session: session})
	if err := emitter.EmitSessionOpen(); err != nil {
		t.Fatal(err)
	}
	if err := emitter.Emit(receipt.EmitOpts{ActionID: receipt.NewActionID(), Verdict: "allow", Transport: "fetch", Method: "GET", Target: "https://api.vendor.example/data"}); err != nil {
		t.Fatal(err)
	}
	if err := emitter.EmitTranscriptRoot(session); err != nil {
		t.Fatal(err)
	}
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
	matches, err := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	if err != nil || len(matches) != 1 {
		t.Fatalf("run-session recorder files = %v, %v", matches, err)
	}
	return matches[0], priv.Public().(ed25519.PublicKey)
}

// An evidence-only recorder has no transcript_root to seal, so whole-recorder
// verification can never prove its end. --allow-prefix must accept that valid
// prefix instead of reporting it as invalid evidence, and a pin stays a check
// that cannot stand in for the missing seal.
func TestWholeRecorderEvidenceOnlyPrefix(t *testing.T) {
	dir := t.TempDir()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, SignCheckpoints: true}, nil, priv)
	if err != nil {
		t.Fatal(err)
	}
	session, err := recorder.AcquireRunSession(rec, recorder.DefaultSessionBase)
	if err != nil {
		t.Fatal(err)
	}
	v2 := proxydecision.NewEmitter(proxydecision.EmitterConfig{Recorder: rec, Signer: proxydecision.NewKeyedSigner(priv), Sanitize: proxydecision.SanitizeFromRedactor(rec.ReceiptRedactor()), Principal: "local", Actor: "pipelock", Session: session})
	for range 2 {
		if err := v2.Emit(proxydecision.Decision{ActionType: "http_request", Transport: "forward", Target: "https://api.vendor.example/a", Verdict: "allow", WinningSource: proxydecision.SourceScanner, PolicySources: []string{proxydecision.SourceScanner}, PolicyHash: strings.Repeat("b", 64)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	if err != nil || len(files) != 1 {
		t.Fatalf("recorder files = %v, %v", files, err)
	}
	key := hex.EncodeToString(pub)
	var head string
	{
		cmd := VerifyReceiptCmd()
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetArgs([]string{files[0], "--key", key, "--allow-prefix", "--json"})
		if err := cmd.Execute(); err != nil {
			t.Fatal(err)
		}
		var report struct {
			Chains []chainCLIReport `json:"chains"`
		}
		if err := json.Unmarshal(out.Bytes(), &report); err != nil || len(report.Chains) != 1 {
			t.Fatalf("report %q: %v", out.String(), err)
		}
		head = report.Chains[0].RootHash
	}
	for _, tc := range []struct {
		name string
		args []string
		code int
	}{
		{"file", []string{files[0]}, 3},
		{"file-allow-prefix", []string{files[0], "--allow-prefix"}, 0},
		{"session-allow-prefix", []string{"--chain", dir, "--session", session, "--allow-prefix"}, 0},
		{"pin-is-not-proof", []string{files[0], "--expect-head", head}, 3},
		{"pin-mismatch", []string{files[0], "--expect-head", strings.Repeat("0", 64), "--allow-prefix"}, 1},
		{"require-seal", []string{files[0], "--require-seal", "--allow-prefix"}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := VerifyReceiptCmd()
			var out bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetErr(&out)
			cmd.SilenceUsage, cmd.SilenceErrors = true, true
			cmd.SetArgs(append(tc.args, "--whole-recorder", "--key", key))
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
				t.Fatalf("exit=%d want=%d: %v\n%s", code, tc.code, err, out.String())
			}
		})
	}
}

func TestChainJSONUsageStatus(t *testing.T) {
	cmd := VerifyReceiptCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(io.Discard)
	cmd.SilenceErrors = true
	cmd.SilenceUsage = true
	cmd.SetArgs([]string{"unused.jsonl", "--json", "--clean-report", "unused.json"})
	err := cmd.Execute()
	if cliutil.ExitCodeOf(err) != 2 {
		t.Fatalf("error=%v", err)
	}
	var report endproof.Report
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.Status != "USAGE ERROR" || report.Integrity != "invalid" || report.EndProof.Proven {
		t.Fatalf("report=%+v", report)
	}
}

func TestChainJSONUnpinnedStatus(t *testing.T) {
	root := filepath.Join("..", "..", "..", "sdk", "conformance", "testdata", "end-proof")
	cmd := VerifyReceiptCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(io.Discard)
	cmd.SilenceErrors = true
	cmd.SilenceUsage = true
	cmd.SetArgs([]string{filepath.Join(root, "closed.jsonl"), "--json", "--allow-unpinned"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	var report struct {
		endproof.Report
		Chains []chainCLIReport
	}
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.Status != "CHAIN UNPINNED" || len(report.Chains) != 1 || report.Chains[0].Status != "CHAIN UNPINNED" {
		t.Fatalf("report=%+v", report)
	}
}
