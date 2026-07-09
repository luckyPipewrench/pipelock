// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
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

const (
	testActorAlpha        = "agent-alpha"
	testActorBravo        = "agent-bravo"
	testBravoTargetSecret = "bravo-only-capability-" + "tok3n"
	testPolicyHash        = "policy-hash-test"
	testPrincipal         = "operator"
	testTarget            = "https://api.vendor.example/evidence"
	testTransport         = "fetch"
)

func genKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return pub, priv
}

func newTestRecorder(t *testing.T, dir string, priv ed25519.PrivateKey) *recorder.Recorder {
	t.Helper()
	rec, err := recorder.New(recorder.Config{
		Enabled:            true,
		Dir:                dir,
		CheckpointInterval: 1000,
	}, nil, priv)
	if err != nil {
		t.Fatalf("recorder.New: %v", err)
	}
	return rec
}

// emitSingleSession emits receipts into a recorder dir. The recorder
// hard-codes the evidence file session ID to "proxy", so there is exactly
// one session per directory. To create a multi-session dir for tests, call
// emitSingleSession into separate temp dirs and then copyEvidenceFiles.
func emitSingleSession(t *testing.T, dir string, priv ed25519.PrivateKey, count int) {
	t.Helper()
	rec := newTestRecorder(t, dir, priv)
	emitter := receipt.NewEmitter(receipt.EmitterConfig{
		Recorder:   rec,
		PrivKey:    priv,
		ConfigHash: testPolicyHash,
		Principal:  testPrincipal,
		Actor:      testActorAlpha,
	})
	if err := emitter.EmitSessionOpen(); err != nil {
		t.Fatalf("EmitSessionOpen: %v", err)
	}
	for i := range count {
		verdict := config.ActionAllow
		if i%3 == 0 {
			verdict = config.ActionBlock
		}
		if err := emitter.Emit(receipt.EmitOpts{
			ActionID:  receipt.NewActionID(),
			Target:    testTarget,
			Verdict:   verdict,
			Transport: testTransport,
			Method:    http.MethodGet,
			Layer:     "allowlist",
			Pattern:   "api.vendor.example",
			SessionID: "proxy",
			Agent:     testActorAlpha,
		}); err != nil {
			t.Fatalf("Emit(%d): %v", i, err)
		}
	}
	_ = rec.Close()
}

// writeEvidenceSession writes a JSONL evidence file with properly-formed
// recorder entries containing signed receipts for the given session ID.
func writeEvidenceSession(t *testing.T, dir string, priv ed25519.PrivateKey, sessionID, actor string, count int) {
	t.Helper()
	writeEvidenceSessionWithTarget(t, dir, priv, sessionID, actor, testTarget, count)
}

func writeEvidenceSessionWithTarget(
	t *testing.T,
	dir string,
	priv ed25519.PrivateKey,
	sessionID string,
	actor string,
	target string,
	count int,
) {
	t.Helper()
	const entryType = "action_receipt"
	path := filepath.Join(dir, fmt.Sprintf("evidence-%s-000000.jsonl", sessionID))

	prevHash := receipt.GenesisHash
	base := time.Now().UTC()
	var lines []byte

	for i := range count {
		ar := receipt.ActionRecord{
			Version:       receipt.ActionRecordVersion,
			ActionID:      receipt.NewActionID(),
			ActionType:    receipt.ActionRead,
			Timestamp:     base.Add(time.Duration(i) * time.Second),
			Principal:     testPrincipal,
			Actor:         actor,
			Target:        target,
			PolicyHash:    testPolicyHash,
			Verdict:       config.ActionAllow,
			SessionID:     sessionID,
			Transport:     testTransport,
			Method:        http.MethodGet,
			Layer:         "allowlist",
			Pattern:       "api.vendor.example",
			ChainPrevHash: prevHash,
			ChainSeq:      uint64(i),
		}
		r, err := receipt.Sign(ar, priv)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		hash, err := receipt.ReceiptHash(r)
		if err != nil {
			t.Fatalf("ReceiptHash: %v", err)
		}

		detail, err := json.Marshal(r)
		if err != nil {
			t.Fatalf("Marshal receipt: %v", err)
		}

		entry := recorder.Entry{
			Version:   1,
			Sequence:  uint64(i),
			Timestamp: ar.Timestamp,
			SessionID: sessionID,
			Type:      entryType,
			Transport: testTransport,
			Summary:   "test",
			Detail:    json.RawMessage(detail),
			PrevHash:  prevHash,
			Hash:      hash,
		}
		line, err := json.Marshal(entry)
		if err != nil {
			t.Fatalf("Marshal entry: %v", err)
		}
		lines = append(lines, line...)
		lines = append(lines, '\n')
		prevHash = hash
	}

	if err := os.WriteFile(path, lines, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}

// emitMultiSessionDir creates a combined evidence directory with two
// sessions ("alpha" and "bravo") with different actors.
func emitMultiSessionDir(t *testing.T, priv ed25519.PrivateKey) string {
	t.Helper()
	dir := t.TempDir()
	writeEvidenceSession(t, dir, priv, "alpha", testActorAlpha, 2)
	writeEvidenceSessionWithTarget(t, dir, priv, "bravo", testActorBravo, "https://api.vendor.example/"+testBravoTargetSecret, 2)
	return dir
}

func TestViewCmd_SingleSession_RendersHTML(t *testing.T) {
	t.Parallel()
	pub, priv := genKey(t)
	keyHex := hex.EncodeToString(pub)
	dir := t.TempDir()
	emitSingleSession(t, dir, priv, 3)

	var stdout, stderr bytes.Buffer
	cmd := Cmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{
		"view",
		"--receipt-dir", dir,
		"--trusted-signer", "inline=" + keyHex + ",source=test",
		"--title", "Test Report",
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	html := stdout.String()
	// Must contain the four bounded scorecard line labels.
	for _, label := range []string{"Authentic", "Untampered", "Anchored", "Completeness"} {
		if !strings.Contains(html, label) {
			t.Errorf("output missing scorecard label %q", label)
		}
	}
	// Must be self-contained: no external-origin URLs.
	for _, scheme := range []string{"http://", "https://"} {
		for _, line := range strings.Split(html, "\n") {
			trimmed := strings.TrimSpace(line)
			// Skip the generated-at meta and data lines that may contain the
			// test target URL as receipt data. Only flag external asset refs.
			if strings.Contains(trimmed, "src=") || strings.Contains(trimmed, "href=") {
				if strings.Contains(trimmed, scheme) {
					t.Errorf("external URL in asset reference: %s", trimmed)
				}
			}
		}
	}
	// Must contain the agent label.
	if !strings.Contains(html, testActorAlpha) {
		t.Errorf("output missing agent label %q", testActorAlpha)
	}
	// Title must appear.
	if !strings.Contains(html, "Test Report") {
		t.Error("output missing custom title")
	}
}

func TestViewCmd_NonexistentSession_Errors(t *testing.T) {
	t.Parallel()
	pub, priv := genKey(t)
	keyHex := hex.EncodeToString(pub)
	dir := t.TempDir()
	emitSingleSession(t, dir, priv, 2)

	var stdout, stderr bytes.Buffer
	cmd := Cmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{
		"view",
		"--receipt-dir", dir,
		"--session", "does-not-exist",
		"--trusted-signer", "inline=" + keyHex,
	})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("view --session <nonexistent> must error, not render empty evidence")
	}
	if !strings.Contains(err.Error(), "does-not-exist") {
		t.Errorf("error should mention session ID, got: %v", err)
	}
}

func TestViewCmd_MultiSession_OnlySelectedAgent(t *testing.T) {
	t.Parallel()
	_, priv := genKey(t)
	dir := emitMultiSessionDir(t, priv)

	var stdout, stderr bytes.Buffer
	cmd := Cmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{
		"view",
		"--receipt-dir", dir,
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	html := stdout.String()
	stderrStr := stderr.String()

	// Stderr must mention "Pro" for multi-agent note.
	if !strings.Contains(stderrStr, "Pro") {
		t.Errorf("stderr should mention Pro for multi-agent dir, got: %s", stderrStr)
	}

	// The rendered HTML must NOT contain the other agent's actor.
	// "alpha" sorts first, so its actor (agent-alpha) is picked.
	sessions, err := recorder.ListSessions(dir)
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(sessions) < 2 {
		t.Fatalf("expected 2 sessions, got %d", len(sessions))
	}
	// "alpha" < "bravo" alphabetically, so sessions[0]="alpha" is rendered.
	// agent-bravo (the other actor) must NOT appear in the HTML.
	if strings.Contains(html, testActorBravo) {
		t.Errorf("output should NOT contain non-selected agent %q", testActorBravo)
	}
	if strings.Contains(html, testBravoTargetSecret) {
		t.Errorf("output should NOT contain non-selected agent target secret %q", testBravoTargetSecret)
	}
}

func TestViewCmd_ExplicitSession(t *testing.T) {
	t.Parallel()
	_, priv := genKey(t)
	dir := emitMultiSessionDir(t, priv)

	var stdout, stderr bytes.Buffer
	cmd := Cmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{
		"view",
		"--receipt-dir", dir,
		"--session", "bravo",
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	html := stdout.String()
	if !strings.Contains(html, testActorBravo) {
		t.Errorf("output missing explicitly selected agent %q", testActorBravo)
	}
	// No Pro note when session is explicit.
	if strings.Contains(stderr.String(), "Pro") {
		t.Error("stderr should not mention Pro when --session is explicit")
	}
}

func TestViewCmd_OutputToFile(t *testing.T) {
	t.Parallel()
	_, priv := genKey(t)
	dir := t.TempDir()
	emitSingleSession(t, dir, priv, 2)

	outFile := filepath.Join(t.TempDir(), "report.html")
	var stdout bytes.Buffer
	cmd := Cmd()
	cmd.SetOut(&stdout)
	cmd.SetArgs([]string{
		"view",
		"--receipt-dir", dir,
		"--out", outFile,
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	// stdout should be empty when --out is set.
	if stdout.Len() != 0 {
		t.Errorf("expected empty stdout with --out, got %d bytes", stdout.Len())
	}
	data, err := os.ReadFile(filepath.Clean(outFile))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !strings.Contains(string(data), "Authentic") {
		t.Error("output file missing scorecard label")
	}
}

func TestViewCmd_BadReceiptDir(t *testing.T) {
	t.Parallel()

	t.Run("nonexistent", func(t *testing.T) {
		t.Parallel()
		var buf bytes.Buffer
		cmd := Cmd()
		cmd.SetOut(&buf)
		cmd.SetErr(&buf)
		cmd.SetArgs([]string{
			"view",
			"--receipt-dir", filepath.Join(t.TempDir(), "does-not-exist"),
		})
		err := cmd.Execute()
		if err == nil {
			t.Fatal("expected error for nonexistent dir")
		}
		if !strings.Contains(err.Error(), "--receipt-dir") {
			t.Errorf("error should mention --receipt-dir, got: %v", err)
		}
	})

	t.Run("is a file", func(t *testing.T) {
		t.Parallel()
		f := filepath.Join(t.TempDir(), "notadir")
		if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		var buf bytes.Buffer
		cmd := Cmd()
		cmd.SetOut(&buf)
		cmd.SetErr(&buf)
		cmd.SetArgs([]string{
			"view",
			"--receipt-dir", f,
		})
		err := cmd.Execute()
		if err == nil {
			t.Fatal("expected error for file-as-dir")
		}
		if !strings.Contains(err.Error(), "not a directory") {
			t.Errorf("error should mention 'not a directory', got: %v", err)
		}
	})
}

func TestViewCmd_BadTrustedSigner(t *testing.T) {
	t.Parallel()
	_, priv := genKey(t)
	dir := t.TempDir()
	emitSingleSession(t, dir, priv, 1)

	var buf bytes.Buffer
	cmd := Cmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{
		"view",
		"--receipt-dir", dir,
		"--trusted-signer", "inline=zz-not-a-key",
	})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for bad trusted signer")
	}
	if !strings.Contains(err.Error(), "parse public key") {
		t.Errorf("error should mention 'parse public key', got: %v", err)
	}
}

func TestViewCmd_EmptyDir(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	var buf bytes.Buffer
	cmd := Cmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{
		"view",
		"--receipt-dir", dir,
	})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for empty dir")
	}
	if !strings.Contains(err.Error(), "no sessions") {
		t.Errorf("error should mention 'no sessions', got: %v", err)
	}
}

func TestViewCmd_NoLicenseRequired(t *testing.T) {
	// This test confirms the free viewer works without any license
	// infrastructure. It is the same as the single-session test but
	// exists as an explicit gate: if someone adds a license check,
	// this test name makes the violation obvious.
	t.Parallel()
	_, priv := genKey(t)
	dir := t.TempDir()
	emitSingleSession(t, dir, priv, 1)

	var stdout bytes.Buffer
	cmd := Cmd()
	cmd.SetOut(&stdout)
	cmd.SetArgs([]string{
		"view",
		"--receipt-dir", dir,
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("free viewer should work without a license: %v", err)
	}
	if !strings.Contains(stdout.String(), "Authentic") {
		t.Error("output missing scorecard — free viewer failed")
	}
}
