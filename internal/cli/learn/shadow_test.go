// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package learn

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/capture"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/contract"
	"github.com/luckyPipewrench/pipelock/internal/contract/shadow"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

const testUnknownContractHash = "sha256:unknown"

func TestResolveShadowSessionsUsesExplicitDirAndRejectsSymlink(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	got, err := resolveShadowSessions(config.Defaults(), shadowFlags{sessionsDir: dir})
	if err != nil {
		t.Fatalf("resolveShadowSessions: %v", err)
	}
	if got != dir {
		t.Fatalf("sessions dir = %q, want %q", got, dir)
	}

	link := filepath.Join(t.TempDir(), "sessions-link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	if _, err := resolveShadowSessions(config.Defaults(), shadowFlags{sessionsDir: link}); err == nil ||
		!strings.Contains(err.Error(), "symlink") {
		t.Fatalf("resolve symlink error = %v, want symlink rejection", err)
	}
}

func TestFilterShadowDurationKeepsZeroTimestampAndRecentRecords(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 30, 12, 0, 0, 0, time.UTC)
	records := []capture.ReplayedRecord{
		{},
		{Timestamp: now.Add(-30 * time.Minute)},
		{Timestamp: now.Add(-2 * time.Hour)},
	}
	got := filterShadowDuration(records, now, time.Hour)
	if len(got) != 2 {
		t.Fatalf("filtered records = %d, want zero timestamp + recent", len(got))
	}
}

func TestRunDiffPrintsAndWritesMarkdown(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	first := filepath.Join(dir, "first.json")
	second := filepath.Join(dir, "second.json")
	writeShadowReport(t, first, shadow.Report{
		ReportVersion: 1,
		ContractHash:  "sha256:a",
		TotalRecords:  10,
		NewBlocks:     1,
		Rules: []shadow.RuleStats{{
			RuleID:      "rule-a",
			Evaluations: 10,
			NewBlocks:   1,
		}},
	})
	writeShadowReport(t, second, shadow.Report{
		ReportVersion: 1,
		ContractHash:  "sha256:b",
		TotalRecords:  12,
		NewBlocks:     3,
		Rules: []shadow.RuleStats{{
			RuleID:      "rule-a",
			Evaluations: 12,
			NewBlocks:   3,
		}},
	})

	cmd := &cobra.Command{}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	if err := runDiff(cmd, first, second, ""); err != nil {
		t.Fatalf("runDiff stdout: %v", err)
	}
	if !strings.Contains(stdout.String(), "Shadow Diff") || !strings.Contains(stdout.String(), "+2") {
		t.Fatalf("stdout diff =\n%s", stdout.String())
	}
	var stdoutAudit auditEvent
	if err := json.Unmarshal(bytes.TrimSpace(stderr.Bytes()), &stdoutAudit); err != nil {
		t.Fatalf("Unmarshal stdout audit: %v", err)
	}
	if stdoutAudit.Dest != "" || len(stdoutAudit.Inputs) != 2 || stdoutAudit.Inputs[1] != filepath.Clean(second) {
		t.Fatalf("stdout audit = %+v, want both inputs and no dest", stdoutAudit)
	}

	out := filepath.Join(dir, "diff.md")
	stderr.Reset()
	if err := runDiff(cmd, first, second, out); err != nil {
		t.Fatalf("runDiff out: %v", err)
	}
	data, err := os.ReadFile(filepath.Clean(out))
	if err != nil {
		t.Fatalf("ReadFile diff: %v", err)
	}
	if !bytes.Contains(data, []byte("new_blocks_delta")) {
		t.Fatalf("written diff =\n%s", data)
	}
	var fileAudit auditEvent
	if err := json.Unmarshal(bytes.TrimSpace(stderr.Bytes()), &fileAudit); err != nil {
		t.Fatalf("Unmarshal file audit: %v", err)
	}
	if fileAudit.Dest != filepath.Clean(out) || len(fileAudit.Inputs) != 2 || fileAudit.Inputs[0] != filepath.Clean(first) {
		t.Fatalf("file audit = %+v, want inputs plus output dest", fileAudit)
	}
}

func TestDiffCmdRunEAndErrorBranches(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	first := filepath.Join(dir, "first.json")
	second := filepath.Join(dir, "second.json")
	writeShadowReport(t, first, shadow.Report{ReportVersion: 1, ContractHash: "sha256:a"})
	writeShadowReport(t, second, shadow.Report{ReportVersion: 1, ContractHash: "sha256:b"})

	cmd := diffCmd()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{first, second})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("diff command Execute: %v", err)
	}
	if !strings.Contains(stdout.String(), "Shadow Diff") {
		t.Fatalf("diff stdout =\n%s", stdout.String())
	}

	for _, tc := range []struct {
		name       string
		firstPath  string
		secondPath string
		outPath    string
		want       string
	}{
		{name: "first", firstPath: "relative.json", secondPath: second, want: "absolute"},
		{name: "second", firstPath: first, secondPath: "relative.json", want: "absolute"},
		{name: "out", firstPath: first, secondPath: second, outPath: dir, want: "regular file"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := runDiff(&cobra.Command{}, tc.firstPath, tc.secondPath, tc.outPath)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("runDiff error = %v, want %q", err, tc.want)
			}
		})
	}
}

func writeShadowReport(t *testing.T, path string, report shadow.Report) {
	t.Helper()
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("Marshal report: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile report: %v", err)
	}
}

func TestRunShadowWritesReportsThenReceipts(t *testing.T) {
	dir := t.TempDir()
	sessionsDir := writeShadowCaptureSession(t, filepath.Join(dir, "sessions"))
	contractPath, _ := writeSignedShadowContract(t, dir)
	recorderDir := filepath.Join(dir, "receipts")
	outPath := filepath.Join(dir, "shadow.md")
	jsonPath := filepath.Join(dir, "shadow.json")

	cmd := &cobra.Command{}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	withTestShadowConfig(t)

	err := runShadow(cmd, shadowFlags{
		contractPath:  contractPath,
		allowUnsigned: true,
		sessionsDir:   sessionsDir,
		duration:      365 * 24 * time.Hour,
		outPath:       outPath,
		outJSONPath:   jsonPath,
		recorderDir:   recorderDir,
		deterministic: true,
	})
	if err != nil {
		t.Fatalf("runShadow: %v", err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want report written to files", stdout.String())
	}
	for _, path := range []string{outPath, jsonPath} {
		if _, err := os.Stat(filepath.Clean(path)); err != nil {
			t.Fatalf("Stat(%s): %v", path, err)
		}
	}
	var report shadow.Report
	rawJSON, err := os.ReadFile(filepath.Clean(jsonPath))
	if err != nil {
		t.Fatalf("ReadFile json report: %v", err)
	}
	if err := json.Unmarshal(rawJSON, &report); err != nil {
		t.Fatalf("Unmarshal json report: %v", err)
	}
	if report.Changed != 1 || len(report.Batches) != 1 {
		t.Fatalf("report changed/batches = %d/%d, want one changed batch", report.Changed, len(report.Batches))
	}
	entries := readRecorderEntries(t, recorderDir)
	if countEntries(entries, "evidence_receipt") != 1 {
		t.Fatalf("receipt entries = %d, want 1", countEntries(entries, "evidence_receipt"))
	}
	var audit auditEvent
	if err := json.Unmarshal(lastJSONLine(stderr.Bytes()), &audit); err != nil {
		t.Fatalf("Unmarshal audit: %v\nstderr:\n%s", err, stderr.String())
	}
	if audit.ReceiptsEmitted != 1 || audit.Output != outPath || audit.Review != jsonPath {
		t.Fatalf("audit = %+v, want receipt and output fields", audit)
	}
}

func TestRunShadowDoesNotEmitReceiptsWhenReportWriteFails(t *testing.T) {
	dir := t.TempDir()
	sessionsDir := writeShadowCaptureSession(t, filepath.Join(dir, "sessions"))
	contractPath, _ := writeSignedShadowContract(t, dir)
	recorderDir := filepath.Join(dir, "receipts")
	withTestShadowConfig(t)

	err := runShadow(&cobra.Command{}, shadowFlags{
		contractPath:  contractPath,
		allowUnsigned: true,
		sessionsDir:   sessionsDir,
		duration:      365 * 24 * time.Hour,
		outPath:       dir,
		recorderDir:   recorderDir,
		deterministic: true,
	})
	if err == nil {
		t.Fatal("runShadow succeeded, want report write error")
	}
	if _, statErr := os.Stat(filepath.Clean(recorderDir)); !os.IsNotExist(statErr) {
		t.Fatalf("recorder dir stat = %v, want no receipt side effect", statErr)
	}
}

func TestLoadShadowContractRequiresKeyAndVerifiesSignature(t *testing.T) {
	dir := t.TempDir()
	contractPath, publicKey := writeSignedShadowContract(t, dir)
	if _, _, _, err := loadShadowContract(contractPath, "", false); err == nil ||
		!strings.Contains(err.Error(), "--contract-key is required") {
		t.Fatalf("load without key error = %v, want required key", err)
	}
	env, clean, verified, err := loadShadowContract(contractPath, publicKey, false)
	if err != nil {
		t.Fatalf("load verified contract: %v", err)
	}
	if clean != contractPath || !verified || env.Body.Selector.SelectorID == "" {
		t.Fatalf("load result clean=%q verified=%v env=%+v", clean, verified, env.Body.Selector)
	}
	if _, _, _, err := loadShadowContract(contractPath, strings.Repeat("0", ed25519.PublicKeySize*2), false); err == nil ||
		!strings.Contains(err.Error(), "signature verification failed") {
		t.Fatalf("load wrong key error = %v, want verification failure", err)
	}
}

func TestWriteShadowReportsStdoutAndCheckedWriteDir(t *testing.T) {
	t.Parallel()
	cmd := &cobra.Command{}
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	report := shadow.Report{
		ReportVersion: 1,
		GeneratedAt:   time.Date(2026, 4, 30, 12, 0, 0, 0, time.UTC),
		ContractHash:  "sha256:contract",
	}
	if err := writeShadowReports(cmd, report, shadowFlags{}); err != nil {
		t.Fatalf("write stdout report: %v", err)
	}
	if !strings.Contains(stdout.String(), "Shadow Report") {
		t.Fatalf("stdout report =\n%s", stdout.String())
	}

	relDir := filepath.Join("relative", "recorder")
	if _, err := checkedWriteDir(relDir); err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("checkedWriteDir relative error = %v, want absolute rejection", err)
	}
	link := filepath.Join(t.TempDir(), "recorder-link")
	if err := os.Symlink(t.TempDir(), link); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	if _, err := checkedWriteDir(link); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("checkedWriteDir symlink error = %v, want symlink rejection", err)
	}
}

func TestReadShadowReportRejectsBadInputs(t *testing.T) {
	t.Parallel()
	if _, err := readShadowReport("relative.json"); err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("read relative error = %v, want absolute rejection", err)
	}
	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := readShadowReport(path); err == nil || !strings.Contains(err.Error(), "decode report") {
		t.Fatalf("read bad json error = %v, want decode error", err)
	}
	if _, err := readShadowReport(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Fatal("read missing report succeeded, want error")
	}
}

func TestRunShadowErrorBranches(t *testing.T) {
	dir := t.TempDir()
	contractPath, _ := writeSignedShadowContract(t, dir)
	sessionsDir := writeShadowCaptureSession(t, filepath.Join(dir, "sessions"))
	corruptSessionsDir := filepath.Join(dir, "corrupt-sessions")
	corruptSession := filepath.Join(corruptSessionsDir, "session-a")
	if err := os.MkdirAll(corruptSession, 0o750); err != nil {
		t.Fatalf("MkdirAll corrupt session: %v", err)
	}
	if err := os.WriteFile(filepath.Join(corruptSession, "evidence-session-a-0.jsonl"), []byte("{\n"), 0o600); err != nil {
		t.Fatalf("WriteFile corrupt session: %v", err)
	}
	withTestShadowConfig(t)

	tests := []struct {
		name  string
		flags shadowFlags
		want  string
	}{
		{
			name: "duration",
			flags: shadowFlags{
				contractPath:  contractPath,
				allowUnsigned: true,
				sessionsDir:   sessionsDir,
			},
			want: "--duration must be positive",
		},
		{
			name: "contract",
			flags: shadowFlags{
				contractPath:  filepath.Join(dir, "missing.json"),
				allowUnsigned: true,
				sessionsDir:   sessionsDir,
				duration:      time.Hour,
			},
			want: "read candidate",
		},
		{
			name: "sessions",
			flags: shadowFlags{
				contractPath:  contractPath,
				allowUnsigned: true,
				sessionsDir:   filepath.Join(dir, "missing-sessions"),
				duration:      time.Hour,
			},
			want: "inspect sessions dir",
		},
		{
			name: "escrow",
			flags: shadowFlags{
				contractPath:  contractPath,
				allowUnsigned: true,
				sessionsDir:   sessionsDir,
				duration:      time.Hour,
				escrowKeyHex:  "not-hex",
			},
			want: "must be hex",
		},
		{
			name: "replay",
			flags: shadowFlags{
				contractPath:  contractPath,
				allowUnsigned: true,
				sessionsDir:   corruptSessionsDir,
				duration:      time.Hour,
			},
			want: "replay captures",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := runShadow(&cobra.Command{}, tc.flags)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("runShadow error = %v, want %q", err, tc.want)
			}
		})
	}

	original := loadConfig
	loadConfig = func(string) (*config.Config, error) {
		return nil, errors.New("config boom")
	}
	err := runShadow(&cobra.Command{}, shadowFlags{
		contractPath:  contractPath,
		allowUnsigned: true,
		sessionsDir:   sessionsDir,
		duration:      time.Hour,
	})
	loadConfig = original
	if err == nil || !strings.Contains(err.Error(), "config boom") {
		t.Fatalf("runShadow config error = %v, want config boom", err)
	}
}

func TestRunShadowReceiptErrorAfterSuccessfulReportWrite(t *testing.T) {
	dir := t.TempDir()
	contractPath, _ := writeSignedShadowContract(t, dir)
	sessionsDir := writeShadowCaptureSession(t, filepath.Join(dir, "sessions"))
	outPath := filepath.Join(dir, "shadow.md")
	withTestShadowConfig(t)

	err := runShadow(&cobra.Command{}, shadowFlags{
		contractPath:  contractPath,
		allowUnsigned: true,
		sessionsDir:   sessionsDir,
		duration:      365 * 24 * time.Hour,
		outPath:       outPath,
		recorderDir:   filepath.Join(dir, "receipts"),
	})
	if err == nil || !strings.Contains(err.Error(), "load receipt signing key") {
		t.Fatalf("runShadow receipt error = %v, want missing signing key", err)
	}
	if _, statErr := os.Stat(filepath.Clean(outPath)); statErr != nil {
		t.Fatalf("report stat = %v, want report written before receipt failure", statErr)
	}
}

func TestLoadShadowContractRejectsMalformedInputs(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	badJSON := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(badJSON, []byte(`{"body":{"unknown":true},"signature":"ed25519:00"}`), 0o600); err != nil {
		t.Fatalf("WriteFile bad json: %v", err)
	}
	if _, _, _, err := loadShadowContract(badJSON, "", true); err == nil || !strings.Contains(err.Error(), "decode contract") {
		t.Fatalf("bad json error = %v, want decode contract", err)
	}

	invalidContract := filepath.Join(dir, "invalid-contract.json")
	data, err := json.Marshal(contract.ContractEnvelope{
		Body: contract.Contract{
			SchemaVersion:    contract.SchemaVersionContract,
			ContractKind:     contract.ContractKind,
			DataClassRoot:    string(contract.DataClassInternal),
			FieldDataClasses: map[string]string{},
			Rules: []contract.Rule{{
				RuleKind:       "http_destination",
				LifecycleState: "enforce",
			}},
		},
		Signature: "ed25519:00",
	})
	if err != nil {
		t.Fatalf("Marshal invalid contract: %v", err)
	}
	if err := os.WriteFile(invalidContract, data, 0o600); err != nil {
		t.Fatalf("WriteFile invalid contract: %v", err)
	}
	if _, _, _, err := loadShadowContract(invalidContract, "", true); err == nil || !strings.Contains(err.Error(), "validate contract") {
		t.Fatalf("invalid contract error = %v, want validate contract", err)
	}

	contractPath, _ := writeSignedShadowContract(t, dir)
	if _, _, _, err := loadShadowContract(contractPath, "zz", false); err == nil || !strings.Contains(err.Error(), "load contract verification key") {
		t.Fatalf("bad public key error = %v, want load key error", err)
	}
}

func TestVerifyShadowContractEnvelopeRejectsMalformedSignature(t *testing.T) {
	t.Parallel()
	contractPath, publicKey := writeSignedShadowContract(t, t.TempDir())
	env, _, _, err := loadShadowContract(contractPath, publicKey, false)
	if err != nil {
		t.Fatalf("load verified contract: %v", err)
	}
	pub, err := hex.DecodeString(publicKey)
	if err != nil {
		t.Fatalf("DecodeString public key: %v", err)
	}
	for _, tc := range []struct {
		name string
		mut  func(*contract.ContractEnvelope)
		want string
	}{
		{
			name: "purpose",
			mut:  func(env *contract.ContractEnvelope) { env.Body.KeyPurpose = "wrong" },
			want: "key_purpose",
		},
		{
			name: "prefix",
			mut:  func(env *contract.ContractEnvelope) { env.Signature = "sha256:00" },
			want: "signature must use",
		},
		{
			name: "hex",
			mut:  func(env *contract.ContractEnvelope) { env.Signature = "ed25519:zz" },
			want: "decode signature",
		},
		{
			name: "length",
			mut:  func(env *contract.ContractEnvelope) { env.Signature = "ed25519:00" },
			want: "signature length",
		},
		{
			name: "preimage",
			mut: func(env *contract.ContractEnvelope) {
				env.Body.Defaults.Confidence = map[string]any{"bad": make(chan int)}
			},
			want: "build preimage",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			next := env
			tc.mut(&next)
			err := verifyShadowContractEnvelope(next, ed25519.PublicKey(pub))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("verify error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestResolveShadowSessionsAgentConfigBranches(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	agentDir := filepath.Join(root, "agent-a")
	if err := os.Mkdir(agentDir, 0o750); err != nil {
		t.Fatalf("Mkdir agent dir: %v", err)
	}
	cfg := config.Defaults()
	cfg.Learn.CaptureDir = root
	got, err := resolveShadowSessions(cfg, shadowFlags{agent: "agent-a"})
	if err != nil {
		t.Fatalf("resolve by agent: %v", err)
	}
	if got != root {
		t.Fatalf("agent sessions root = %q, want %q", got, root)
	}
	filter := shadowSessionFilter(shadowFlags{agent: "agent-a"})
	// Empty session dirs satisfy the validator (no contents to misattribute),
	// so name-prefix-matching is the effective check for these cases.
	emptyA := filepath.Join(root, "agent-a")
	emptyAIP := filepath.Join(root, "agent-a|10.0.0.1")
	emptyABIP := filepath.Join(root, "agent-ab|10.0.0.2")
	if err := os.MkdirAll(emptyAIP, 0o750); err != nil {
		t.Fatalf("MkdirAll emptyAIP: %v", err)
	}
	if err := os.MkdirAll(emptyABIP, 0o750); err != nil {
		t.Fatalf("MkdirAll emptyABIP: %v", err)
	}
	if !filter("agent-a", emptyA) || !filter("agent-a|10.0.0.1", emptyAIP) || filter("agent-ab|10.0.0.2", emptyABIP) {
		t.Fatalf("shadow session filter did not match only agent-a sessions")
	}
	if shadowSessionFilter(shadowFlags{sessionsDir: agentDir}) != nil {
		t.Fatalf("explicit sessions dir should not install an agent filter")
	}
	if _, err := resolveShadowSessions(cfg, shadowFlags{}); err == nil {
		t.Fatal("resolve empty agent succeeded, want validation error")
	}
	cfg.Learn.CaptureDir = ""
	if _, err := resolveShadowSessions(cfg, shadowFlags{agent: "agent-a"}); !errors.Is(err, errNoCaptureDir) {
		t.Fatalf("resolve no capture dir error = %v, want errNoCaptureDir", err)
	}
	cfg.Learn.CaptureDir = "relative"
	if _, err := resolveShadowSessions(cfg, shadowFlags{agent: "agent-a"}); !errors.Is(err, errRelativeCaptureDir) {
		t.Fatalf("resolve relative capture dir error = %v, want errRelativeCaptureDir", err)
	}
}

func TestCheckedReadDirRejectsRelativeMissingAndFile(t *testing.T) {
	t.Parallel()
	if _, err := checkedReadDir("relative"); err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("checkedReadDir relative error = %v, want absolute", err)
	}
	if _, err := checkedReadDir(filepath.Join(t.TempDir(), "missing")); err == nil || !strings.Contains(err.Error(), "inspect sessions dir") {
		t.Fatalf("checkedReadDir missing error = %v, want inspect failure", err)
	}
	file := filepath.Join(t.TempDir(), "sessions-file")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := checkedReadDir(file); err == nil || !strings.Contains(err.Error(), "must be a directory") {
		t.Fatalf("checkedReadDir file error = %v, want directory rejection", err)
	}
}

func TestEmitShadowReceiptsBranches(t *testing.T) {
	t.Parallel()
	body := validShadowContractBody()
	report := shadow.Report{Batches: []shadow.Batch{{
		ContractHash:     body.ContractHash,
		RuleID:           "rule-api",
		OriginalVerdict:  config.ActionAllow,
		CandidateVerdict: config.ActionBlock,
		WindowStart:      time.Date(2026, 4, 30, 12, 0, 0, 0, time.UTC),
		WindowEnd:        time.Date(2026, 4, 30, 13, 0, 0, 0, time.UTC),
		LosslessCount:    1,
		ExemplarIDs:      []string{"ex-1"},
	}}}
	if got, err := emitShadowReceipts(shadowFlags{}, body, report, time.Now()); err != nil || got != 0 {
		t.Fatalf("emit no recorder = %d/%v, want 0 nil", got, err)
	}
	empty := report
	empty.Batches = nil
	if got, err := emitShadowReceipts(shadowFlags{recorderDir: t.TempDir()}, body, empty, time.Now()); err != nil || got != 0 {
		t.Fatalf("emit no batches = %d/%v, want 0 nil", got, err)
	}
	if _, err := emitShadowReceipts(shadowFlags{recorderDir: "relative", deterministic: true}, body, report, time.Now()); err == nil ||
		!strings.Contains(err.Error(), "absolute") {
		t.Fatalf("emit relative recorder error = %v, want absolute", err)
	}
	if _, err := emitShadowReceipts(shadowFlags{recorderDir: t.TempDir()}, body, report, time.Now()); err == nil ||
		!strings.Contains(err.Error(), "load receipt signing key") {
		t.Fatalf("emit signer error = %v, want missing key", err)
	}
	bad := report
	bad.Batches = append([]shadow.Batch(nil), report.Batches...)
	bad.Batches[0].ContractHash = ""
	if got, err := emitShadowReceipts(shadowFlags{recorderDir: t.TempDir(), deterministic: true}, body, bad, time.Now()); err == nil || got != 0 {
		t.Fatalf("emit invalid batch = %d/%v, want index 0 error", got, err)
	}
}

func TestCheckedWriteDirRejectsFile(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "recorder-file")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := checkedWriteDir(path); err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("checkedWriteDir file error = %v, want directory rejection", err)
	}
}

func TestResolveShadowSignerDefaultAgentMissingKey(t *testing.T) {
	t.Parallel()
	signer, err := resolveShadowSigner(shadowFlags{deterministic: true})
	if err != nil {
		t.Fatalf("resolve deterministic signer: %v", err)
	}
	if signer.KeyID() != "deterministic-receipt-signing" {
		t.Fatalf("deterministic signer key id = %q", signer.KeyID())
	}
	if _, err := resolveShadowSigner(shadowFlags{keystore: t.TempDir()}); err == nil ||
		!strings.Contains(err.Error(), defaultReceiptKeyAgent) {
		t.Fatalf("resolve default signer error = %v, want missing default agent", err)
	}
	keyDir := t.TempDir()
	if _, err := signing.NewKeystore(keyDir).GenerateAgent(defaultReceiptKeyAgent); err != nil {
		t.Fatalf("GenerateAgent: %v", err)
	}
	signer, err = resolveShadowSigner(shadowFlags{keystore: keyDir})
	if err != nil {
		t.Fatalf("resolve default signer: %v", err)
	}
	if signer.KeyID() != defaultReceiptKeyAgent {
		t.Fatalf("signer key id = %q, want default", signer.KeyID())
	}
}

func TestWriteShadowReportsRejectsInvalidJSONPath(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	report := shadow.Report{
		ReportVersion: 1,
		GeneratedAt:   time.Date(2026, 4, 30, 12, 0, 0, 0, time.UTC),
		ContractHash:  "sha256:contract",
	}
	cmd := &cobra.Command{}
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	err := writeShadowReports(cmd, report, shadowFlags{
		outJSONPath: dir,
	})
	if err == nil || !strings.Contains(err.Error(), "must be a regular file") {
		t.Fatalf("writeShadowReports JSON dir error = %v, want non-regular rejection", err)
	}
}

func TestContractHashFallbacks(t *testing.T) {
	t.Parallel()
	body := validShadowContractBody()
	if got := contractHash(body); got != body.ContractHash {
		t.Fatalf("contractHash = %q, want existing hash", got)
	}
	body.ContractHash = ""
	if got := contractHash(body); !strings.HasPrefix(got, "sha256:") || got == testUnknownContractHash {
		t.Fatalf("contractHash derived = %q, want derived sha256", got)
	}
	body.Defaults.Confidence = map[string]any{"bad": make(chan int)}
	if got := contractHash(body); got != testUnknownContractHash {
		t.Fatalf("contractHash error = %q, want unknown", got)
	}
}

func writeShadowCaptureSession(t *testing.T, dir string) string {
	t.Helper()
	w, err := capture.NewWriter(capture.WriterConfig{
		RecorderConfig: recorder.Config{
			Enabled:            true,
			Dir:                dir,
			CheckpointInterval: 1000,
		},
		QueueSize:    8,
		BuildVersion: "test",
		BuildSHA:     "test",
	})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	w.ObserveURLVerdict(context.Background(), &capture.URLVerdictRecord{
		Subsurface:      "url",
		Transport:       "http",
		SessionID:       "session-a",
		RequestID:       "req-1",
		ConfigHash:      "sha256:old",
		Agent:           "agent-a",
		Profile:         "test",
		Request:         capture.CaptureRequest{Method: "GET", URL: "https://api.example.com/repos/bar"},
		EffectiveAction: config.ActionAllow,
		Outcome:         capture.OutcomeClean,
	})
	if err := w.Close(); err != nil {
		t.Fatalf("Close writer: %v", err)
	}
	return dir
}

func writeSignedShadowContract(t *testing.T, dir string) (string, string) {
	t.Helper()
	seed := sha256.Sum256([]byte("learn shadow contract verification test"))
	priv := ed25519.NewKeyFromSeed(seed[:])
	body := validShadowContractBody()
	preimage, err := body.SignablePreimage()
	if err != nil {
		t.Fatalf("SignablePreimage: %v", err)
	}
	env := contract.ContractEnvelope{
		Body:      body,
		Signature: "ed25519:" + hex.EncodeToString(ed25519.Sign(priv, preimage)),
	}
	data, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("Marshal contract: %v", err)
	}
	path := filepath.Join(dir, "contract.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile contract: %v", err)
	}
	return path, hex.EncodeToString(priv.Public().(ed25519.PublicKey))
}

func validShadowContractBody() contract.Contract {
	return contract.Contract{
		SchemaVersion:    contract.SchemaVersionContract,
		ContractKind:     contract.ContractKind,
		ContractHash:     "sha256:test-contract",
		SignerKeyID:      "test",
		KeyPurpose:       signing.PurposeContractCompileSigning.String(),
		DataClassRoot:    string(contract.DataClassInternal),
		FieldDataClasses: map[string]string{},
		Selector:         contract.Selector{Agent: "agent-a", SelectorID: "selector-a"},
		ObservationWindow: contract.ObservationWindow{
			Start:                 time.Date(2026, 4, 30, 11, 0, 0, 0, time.UTC),
			End:                   time.Date(2026, 4, 30, 12, 0, 0, 0, time.UTC),
			EventCount:            1,
			SessionCount:          1,
			ObservationWindowRoot: "sha256:window",
		},
		Compile: contract.ContractCompile{
			PipelockVersion:        "test",
			PipelockBuildSHA:       "test",
			GoVersion:              "test",
			ModuleDigestRoot:       "sha256:modules",
			CompileConfigHash:      "sha256:config",
			InferenceAlgorithm:     "test",
			NormalizationAlgorithm: "test",
		},
		Defaults: contract.ContractDefaults{
			Fidelity:   "full",
			Confidence: map[string]any{},
			Privacy: contract.ContractDefaultsPrivacy{
				DefaultDataClass: contract.DataClassInternal,
				ForbidClasses:    []contract.DataClass{},
			},
		},
		Rules: []contract.Rule{{
			RuleID:               "rule-api",
			DisplayName:          "API rule",
			RuleKind:             "http_destination",
			LifecycleState:       "enforce",
			RequiredCaptureGrade: contract.CaptureGradeFull,
			ObservedCaptureGrade: contract.CaptureGradeFull,
			Confidence:           "stable",
			WilsonLower:          "0.99",
			Observation:          map[string]any{},
			Selector: map[string]any{
				"host": map[string]any{"value": "api.example.com"},
				"paths": []any{
					map[string]any{"value": "/repos/foo"},
				},
			},
			Rationale:         map[string]any{},
			RecurringSupport:  map[string]any{},
			OpportunityHealth: map[string]any{},
		}},
	}
}

func withTestShadowConfig(t *testing.T) {
	t.Helper()
	original := loadConfig
	loadConfig = func(string) (*config.Config, error) {
		cfg := config.Defaults()
		cfg.Internal = nil
		cfg.DLP.ScanEnv = false
		return cfg, nil
	}
	t.Cleanup(func() {
		loadConfig = original
	})
}

func readRecorderEntries(t *testing.T, dir string) []recorder.Entry {
	t.Helper()
	var entries []recorder.Entry
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if !strings.HasSuffix(d.Name(), ".jsonl") {
			return nil
		}
		chunk, err := recorder.ReadEntries(path)
		if err != nil {
			return err
		}
		entries = append(entries, chunk...)
		return nil
	})
	if err != nil {
		t.Fatalf("WalkDir recorder entries: %v", err)
	}
	return entries
}

func countEntries(entries []recorder.Entry, entryType string) int {
	count := 0
	for _, entry := range entries {
		if entry.Type == entryType {
			count++
		}
	}
	return count
}

func lastJSONLine(data []byte) []byte {
	lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
	if len(lines) == 0 {
		return nil
	}
	return lines[len(lines)-1]
}
