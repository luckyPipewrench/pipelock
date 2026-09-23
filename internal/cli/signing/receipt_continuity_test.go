// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

func TestReceiptDirectoryListingFailureIsNotSuccess(t *testing.T) {
	t.Parallel()
	location := recorder.EvidenceLocation{Dir: filepath.Join(t.TempDir(), "missing")}
	if session, err := resolveOneReceiptSession(location, "proxy"); err == nil || session != "" || !strings.Contains(err.Error(), "listing receipt chains") {
		t.Fatalf("resolve missing directory: session=%q, err=%v; want no session and listing error", session, err)
	}
	var output bytes.Buffer
	if err := verifyWholeRecorderDir(&output, location, "proxy", false, nil, verifyReceiptOptions{}); err == nil || !strings.Contains(err.Error(), "listing receipt chains") || strings.Contains(output.String(), "VALID") {
		t.Fatalf("whole-recorder missing directory: err=%v, output=%q; want listing error without success", err, output.String())
	}
	output.Reset()
	if err := verifyChainDirWithContinuity(&output, location, "proxy", false, nil, verifyReceiptOptions{}); err == nil || !strings.Contains(err.Error(), "listing receipt chains") || strings.Contains(output.String(), "VALID") {
		t.Fatalf("chain missing directory: err=%v, output=%q; want listing error without success", err, output.String())
	}
}

// runContinuityChain records one real run chain in dir the way production
// does and returns its session.
func runContinuityChain(t *testing.T, dir string, priv ed25519.PrivateKey, n int) string {
	t.Helper()
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, CheckpointInterval: 1000}, nil, priv)
	if err != nil {
		t.Fatalf("recorder.New: %v", err)
	}
	session, err := recorder.AcquireRunSession(rec, recorder.DefaultSessionBase)
	if err != nil {
		t.Fatalf("AcquireRunSession: %v", err)
	}
	e := receipt.NewEmitter(receipt.EmitterConfig{Recorder: rec, PrivKey: priv, Principal: "verify-test", Actor: "verify-test", Session: session, Notices: io.Discard})
	if err := e.EmitSessionOpen(); err != nil {
		t.Fatalf("EmitSessionOpen: %v", err)
	}
	for i := 0; i < n; i++ {
		if err := e.Emit(receipt.EmitOpts{ActionID: receipt.NewActionID(), Target: "https://api.vendor.example/x", Verdict: config.ActionBlock, Transport: "fetch", Method: http.MethodGet}); err != nil {
			t.Fatalf("Emit: %v", err)
		}
	}
	if err := e.EmitSessionClose("graceful_shutdown"); err != nil {
		t.Fatalf("EmitSessionClose: %v", err)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return session
}

func continuityKey(t *testing.T) (string, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(pub), priv
}

func TestVerifyReceiptRunDirectoryReaders(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	pub, priv := continuityKey(t)
	first := runContinuityChain(t, dir, priv, 1)
	reportPath := filepath.Join(t.TempDir(), "clean.json")
	out, err := runVerifyReceipt(t, "--chain", dir, "--key", pub, "--clean-report", reportPath)
	if err != nil || !strings.Contains(out, "Actions:   3") || !strings.Contains(out, first) {
		t.Fatalf("single run clean report: %v\n%s", err, out)
	}
	if _, err := os.Stat(reportPath); err != nil {
		t.Fatal(err)
	}
	second := runContinuityChain(t, dir, priv, 1)
	if err := os.Remove(reportPath); err != nil {
		t.Fatal(err)
	}
	out, err = runVerifyReceipt(t, "--chain", dir, "--key", pub, "--clean-report", reportPath)
	if err == nil || !strings.Contains(err.Error(), "pass --session") {
		t.Fatalf("multi-run clean report must refuse ambiguous single-chain output: %v\n%s", err, out)
	}
	if _, err := os.Stat(reportPath); !os.IsNotExist(err) {
		t.Fatalf("ambiguous clean report was written: %v", err)
	}
	out, err = runVerifyReceipt(t, "--chain", dir, "--key", pub, "--session", second, "--clean-report", reportPath)
	if err != nil || !strings.Contains(out, second) {
		t.Fatalf("explicit run clean report: %v\n%s", err, out)
	}
	out, err = runVerifyReceipt(t, "--chain", dir, "--key", pub, "--whole-recorder")
	if err != nil || !strings.Contains(out, first) || !strings.Contains(out, second) || !strings.Contains(out, "RESTART CONTINUITY") || !strings.Contains(out, "INCOMPLETE RUNS (2)") {
		t.Fatalf("whole recorder must inspect every run and report their state: %v\n%s", err, out)
	}
}

func TestVerifyReceiptRunDirectoryReadersRejectMissingAndEmpty(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	pub, _ := continuityKey(t)
	for _, args := range [][]string{
		{"--chain", dir, "--key", pub, "--whole-recorder"},
		{"--chain", dir, "--key", pub, "--clean-report", filepath.Join(t.TempDir(), "clean.json")},
	} {
		out, err := runVerifyReceipt(t, args...)
		if err == nil || !strings.Contains(err.Error(), "no ") {
			t.Fatalf("empty directory must fail closed: %v\n%s", err, out)
		}
	}
}

func TestTranscriptRootRunDirectoryResolution(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	pub, priv := continuityKey(t)
	first := runContinuityChain(t, dir, priv, 1)
	cmd := TranscriptRootCmd()
	var out strings.Builder
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--chain", dir, "--key", pub})
	if err := cmd.Execute(); err != nil || !strings.Contains(out.String(), first) {
		t.Fatalf("one run root: %v\n%s", err, out.String())
	}
	_ = runContinuityChain(t, dir, priv, 1)
	cmd = TranscriptRootCmd()
	cmd.SetArgs([]string{"--chain", dir, "--key", pub})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "pass --session") {
		t.Fatalf("ambiguous root must fail: %v", err)
	}
}

func TestCleanReportRejectsNoReceipts(t *testing.T) {
	t.Parallel()
	pub, _ := continuityKey(t)
	err := verifyCleanReport(io.Discard, "empty run", nil, []string{pub}, false, filepath.Join(t.TempDir(), "clean.json"))
	if err == nil || !strings.Contains(err.Error(), "no receipts") {
		t.Fatalf("empty clean report must fail closed: %v", err)
	}
}

func TestVerifyReceiptChainDirVerifiesEveryRunAndContinuity(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	pub, priv := continuityKey(t)
	a := runContinuityChain(t, dir, priv, 2)
	b := runContinuityChain(t, dir, priv, 1)

	out, err := runVerifyReceipt(t, "--chain", dir, "--key", pub)
	if err != nil {
		t.Fatalf("a linked pair of run chains must verify: %v\n%s", err, out)
	}
	if n := strings.Count(out, "CHAIN VALID"); n != 2 {
		t.Fatalf("both run chains must be verified, got %d CHAIN VALID:\n%s", n, out)
	}
	for _, want := range []string{
		"RESTART CONTINUITY OK",
		"2 chain(s), 1 linked, 1 unlinked, 0 link finding(s)",
		"linked:   " + b + " continues " + a,
		"(same_key)",
		"unlinked: " + a,
		"does not prove no run's evidence is missing",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q:\n%s", want, out)
		}
	}

	out, err = runVerifyReceipt(t, "--chain", dir, "--key", pub, "--session", b)
	if err != nil {
		t.Fatalf("--session on one run chain: %v\n%s", err, out)
	}
	if strings.Count(out, "CHAIN VALID") != 1 || !strings.Contains(out, "RESTART CONTINUITY OK") {
		t.Fatalf("--session must verify one chain and still report continuity:\n%s", out)
	}
}

func TestVerifyReceiptChainDirDeletedLinkReportsUnlinked(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	pub, priv := continuityKey(t)
	a := runContinuityChain(t, dir, priv, 1)
	b := runContinuityChain(t, dir, priv, 1)
	if err := os.Remove(filepath.Join(dir, receipt.ChainLinkFileName(a))); err != nil {
		t.Fatal(err)
	}
	out, err := runVerifyReceipt(t, "--chain", dir, "--key", pub)
	if err != nil {
		t.Fatalf("an unlinked run is reported, not failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "0 linked, 2 unlinked") || !strings.Contains(out, "unlinked: "+b) {
		t.Fatalf("the successor must be listed unlinked:\n%s", out)
	}
}

func TestVerifyReceiptChainDirBadLinkFails(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	pub, priv := continuityKey(t)
	a := runContinuityChain(t, dir, priv, 1)
	_ = runContinuityChain(t, dir, priv, 1)
	if err := os.WriteFile(filepath.Join(dir, receipt.ChainLinkFileName(a)), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := runVerifyReceipt(t, "--chain", dir, "--key", pub)
	if err == nil || !strings.Contains(err.Error(), "restart continuity") {
		t.Fatalf("a bad link file must fail: err=%v\n%s", err, out)
	}
	if strings.Count(out, "CHAIN VALID") != 2 || !strings.Contains(out, "RESTART CONTINUITY FAILED") || !strings.Contains(out, receipt.FindingInvalidLink) {
		t.Fatalf("chains stay valid; continuity fails with the finding named:\n%s", out)
	}
}

func TestVerifyReceiptChainDirKeyChangeNeedsTrust(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	pubA, privA := continuityKey(t)
	pubB, privB := continuityKey(t)
	_ = runContinuityChain(t, dir, privA, 1)
	_ = runContinuityChain(t, dir, privB, 1)

	out, err := runVerifyReceipt(t, "--chain", dir, "--key", pubA)
	if err == nil {
		t.Fatalf("a successor under an untrusted key must fail:\n%s", out)
	}
	if !strings.Contains(out, receipt.FindingUntrustedSuccessorKey) && !strings.Contains(out, "CHAIN BROKEN") {
		t.Fatalf("the untrusted key must be named:\n%s", out)
	}
	out, err = runVerifyReceipt(t, "--chain", dir, "--key", pubA, "--key", pubB)
	if err != nil || !strings.Contains(out, "(trusted_key)") {
		t.Fatalf("both keys pinned must pass with trusted_key: %v\n%s", err, out)
	}
}

// The documented rotation ceremony across a restart: close the run under key
// A, endorse B with the shipped command against that run session, restart
// under B, and verify from A alone.
func TestVerifyReceiptChainDirEndorsedRotationAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	keys := t.TempDir()
	pubA, privA := continuityKey(t)
	_, privB := continuityKey(t)
	a := runContinuityChain(t, dir, privA, 1)

	endorsement := filepath.Join(keys, "rotation.json")
	cmd := receiptRotationEndorseCmd(time.Now)
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{
		"--chain", dir, "--session", a,
		"--prior-key-file", saveRotationTestKey(t, keys, "prior.key", privA),
		"--new-key-file", saveRotationTestKey(t, keys, "new.key", privB),
		"--root-key", pubA, "--out", endorsement,
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("endorse the closed run session: %v", err)
	}
	b := runContinuityChain(t, dir, privB, 1)

	out, err := runVerifyReceipt(t, "--chain", dir, "--key", pubA)
	if err == nil {
		t.Fatalf("without the endorsement the successor key is untrusted:\n%s", out)
	}
	out, err = runVerifyReceipt(t, "--chain", dir, "--key", pubA, "--rotation-endorsement", endorsement)
	if err != nil {
		t.Fatalf("an endorsed restart rotation must verify from the root key: %v\n%s", err, out)
	}
	if strings.Count(out, "CHAIN VALID") != 2 || !strings.Contains(out, "linked:   "+b+" continues "+a) || !strings.Contains(out, "(endorsed)") {
		t.Fatalf("both chains valid and the link endorsed:\n%s", out)
	}
}

// A run chain on disk that fails verification fails the command even when
// continuity itself is clean.
func TestVerifyReceiptChainDirFailedChainFails(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	_, priv := continuityKey(t)
	_ = runContinuityChain(t, dir, priv, 1)
	otherPub, _ := continuityKey(t)
	out, err := runVerifyReceipt(t, "--chain", dir, "--key", otherPub)
	if err == nil || !strings.Contains(err.Error(), "chain verification failed for 1 of 1") {
		t.Fatalf("an untrusted chain must fail: %v\n%s", err, out)
	}
}

// TestWholeRecorderReportsIncompleteRunsWithoutFailing covers the behavior a
// crashed run used to break permanently: an unsealed run is reported as
// INCOMPLETE and does not by itself fail the directory-wide check, while
// --require-seal still turns it into a failure.
func TestWholeRecorderReportsIncompleteRunsWithoutFailing(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	pub, priv := continuityKey(t)
	unsealed := runContinuityChain(t, dir, priv, 1)

	out, err := runVerifyReceipt(t, "--chain", dir, "--key", pub, "--whole-recorder")
	if err != nil {
		t.Fatalf("an unsealed run must not fail the directory check: %v\n%s", err, out)
	}
	if !strings.Contains(out, "INCOMPLETE") || !strings.Contains(out, unsealed) {
		t.Fatalf("unsealed run %q must be named under INCOMPLETE:\n%s", unsealed, out)
	}

	strict, strictErr := runVerifyReceipt(t, "--chain", dir, "--key", pub, "--whole-recorder", "--require-seal")
	if strictErr == nil {
		t.Fatalf("--require-seal must fail on an unsealed run:\n%s", strict)
	}
}
