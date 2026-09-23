// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

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
	if err := e.EmitSessionClose("test complete"); err != nil {
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
