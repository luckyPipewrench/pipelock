// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/coveragecert"
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

type serveListenCapture struct {
	mu sync.Mutex
	ch chan string
	bytes.Buffer
}

func newServeListenCapture() *serveListenCapture {
	return &serveListenCapture{ch: make(chan string, 1)}
}

func (c *serveListenCapture) Write(p []byte) (int, error) {
	c.mu.Lock()
	n, err := c.Buffer.Write(p)
	text := c.Buffer.String()
	c.mu.Unlock()
	if strings.Contains(text, "http://") {
		select {
		case c.ch <- text:
		default:
		}
	}
	return n, err
}

func (c *serveListenCapture) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.Buffer.String()
}

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
	writeEvidenceSessionWithPlan(t, dir, priv, sessionID, count, func(_ int) (string, string) {
		return actor, target
	})
}

func writeEvidenceSessionWithPlan(
	t *testing.T,
	dir string,
	priv ed25519.PrivateKey,
	sessionID string,
	count int,
	receiptPlan func(int) (actor string, target string),
) {
	t.Helper()
	const entryType = "action_receipt"
	path := filepath.Join(dir, fmt.Sprintf("evidence-%s-000000.jsonl", sessionID))

	prevHash := receipt.GenesisHash
	base := time.Now().UTC()
	var lines []byte

	for i := range count {
		actor, target := receiptPlan(i)
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

func TestServeCmd_ExplicitSessionServesBoundReport(t *testing.T) {
	t.Parallel()
	_, priv := genKey(t)
	dir := emitMultiSessionDir(t, priv)

	sessionID, err := resolveServeSession(dir, "bravo")
	if err != nil {
		t.Fatalf("resolveServeSession: %v", err)
	}
	handler := evidenceServeHandler(dir, sessionID)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET / status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, testActorBravo) {
		t.Fatalf("GET / missing bound agent %q: %s", testActorBravo, body)
	}
	if strings.Contains(body, testActorAlpha) {
		t.Fatalf("GET / rendered unbound agent %q: %s", testActorAlpha, body)
	}
	assertEvidenceServeSecurityHeaders(t, rec.Header())
	for header, want := range map[string]string{
		"X-Content-Type-Options": "nosniff",
	} {
		if got := rec.Header().Get(header); got != want {
			t.Fatalf("%s = %q, want %q", header, got, want)
		}
	}
}

func assertEvidenceServeSecurityHeaders(t *testing.T, headers http.Header) {
	t.Helper()
	if got := headers.Get("Content-Security-Policy"); got != evidenceServeCSP {
		t.Fatalf("Content-Security-Policy = %q, want %q", got, evidenceServeCSP)
	}
	for header, want := range map[string]string{
		"Cache-Control":   "no-store",
		"Referrer-Policy": "no-referrer",
	} {
		if got := headers.Get(header); got != want {
			t.Fatalf("%s = %q, want %q", header, got, want)
		}
	}
}

func TestServeCmd_NoLicenseRequired(t *testing.T) {
	t.Parallel()
	_, priv := genKey(t)
	dir := t.TempDir()
	emitSingleSession(t, dir, priv, 1)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stdout := newServeListenCapture()
	cmd := Cmd()
	cmd.SetContext(ctx)
	cmd.SetOut(stdout)
	cmd.SetErr(stdout)
	errCh := make(chan error, 1)
	go func() {
		errCh <- runServe(cmd, serveOptions{
			receiptDir: dir,
			listen:     "127.0.0.1:0",
		})
	}()

	var listenLine string
	select {
	case listenLine = <-stdout.ch:
	case <-time.After(5 * time.Second):
		t.Fatalf("free serve did not bind without a license; output=%s", stdout.String())
	}
	endpoint := strings.TrimSpace(strings.TrimPrefix(listenLine, "pipelock evidence serve listening on "))
	if endpoint == listenLine {
		t.Fatalf("could not parse serve listen address from %q", listenLine)
	}
	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("free serve should answer GET / without a license: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	body := string(bodyBytes)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET / status = %d, want 200; body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, testActorAlpha) || !strings.Contains(body, "Authentic") {
		t.Fatalf("GET / missing free evidence report content: %s", body)
	}

	cancel()
	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("serve shutdown error = %v, want context canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serve did not shut down after context cancellation")
	}
}

func TestServeCmd_MixedActorSessionFailsClosed(t *testing.T) {
	t.Parallel()
	_, priv := genKey(t)
	dir := t.TempDir()
	writeEvidenceSessionWithPlan(t, dir, priv, "shared", 2, func(i int) (string, string) {
		if i == 0 {
			return testActorAlpha, testTarget
		}
		return testActorBravo, "https://api.vendor.example/" + testBravoTargetSecret
	})

	handler := evidenceServeHandler(dir, "shared")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("GET / status = %d, want 500; body=%s", rec.Code, rec.Body.String())
	}
	assertEvidenceServeSecurityHeaders(t, rec.Header())
	body := rec.Body.String()
	if strings.Contains(body, testActorBravo) || strings.Contains(body, testBravoTargetSecret) {
		t.Fatalf("GET / leaked mixed-actor evidence: %s", body)
	}
}

// A single named agent mixed with unattributed ("anonymous") traffic is a normal
// single-agent session and must render, while two distinct NAMED agents must still
// be rejected. anonymous is pipelock's default actor, not a second agent.
func TestValidateSingleActorReceipts_AnonymousIsNotADistinctAgent(t *testing.T) {
	t.Parallel()
	mk := func(actor string) receipt.Receipt {
		return receipt.Receipt{ActionRecord: receipt.ActionRecord{Actor: actor}}
	}
	if err := validateSingleActorReceipts("proxy", []receipt.Receipt{mk("pipelock"), mk("anonymous"), mk("pipelock")}); err != nil {
		t.Fatalf("named agent + anonymous traffic must render, got: %v", err)
	}
	if err := validateSingleActorReceipts("proxy", []receipt.Receipt{mk("anonymous"), mk("anonymous")}); err != nil {
		t.Fatalf("all-anonymous session must render, got: %v", err)
	}
	if err := validateSingleActorReceipts("proxy", []receipt.Receipt{mk("agent-alpha"), mk("anonymous"), mk("agent-bravo")}); err == nil {
		t.Fatal("two distinct named agents must be rejected even with anonymous present")
	}
}

func TestServeCmd_MultiSessionRequiresExplicitSession(t *testing.T) {
	t.Parallel()
	_, priv := genKey(t)
	dir := emitMultiSessionDir(t, priv)

	var buf bytes.Buffer
	cmd := Cmd()
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	err := runServe(cmd, serveOptions{
		receiptDir: dir,
		listen:     defaultEvidenceServeListen,
	})
	if err == nil {
		t.Fatal("serve without --session must error for a multi-session receipt directory")
	}
	for _, want := range []string{"sessions found", "pass --session"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error = %v, want it to contain %q", err, want)
		}
	}
	if buf.Len() != 0 {
		t.Fatalf("serve should not start or print a listen address on multi-session error, got: %s", buf.String())
	}
}

func TestServeCmd_NoEndpointCanSwitchBoundSession(t *testing.T) {
	t.Parallel()
	_, priv := genKey(t)
	dir := emitMultiSessionDir(t, priv)

	handler := evidenceServeHandler(dir, "bravo")
	for _, target := range []string{"/", "/?session=alpha", "/?agent=agent-alpha"} {
		t.Run(target, func(t *testing.T) {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, target, nil))
			if rec.Code != http.StatusOK {
				t.Fatalf("GET %s status = %d, want 200; body=%s", target, rec.Code, rec.Body.String())
			}
			body := rec.Body.String()
			if !strings.Contains(body, testActorBravo) {
				t.Fatalf("GET %s missing bound agent %q: %s", target, testActorBravo, body)
			}
			if strings.Contains(body, testActorAlpha) {
				t.Fatalf("GET %s rendered unbound agent %q: %s", target, testActorAlpha, body)
			}
		})
	}

	for _, target := range []string{"/session/alpha", "/session/bravo", "/agent/agent-alpha"} {
		t.Run(target, func(t *testing.T) {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, target, nil))
			if rec.Code != http.StatusNotFound {
				t.Fatalf("GET %s status = %d, want 404; body=%s", target, rec.Code, rec.Body.String())
			}
			assertEvidenceServeSecurityHeaders(t, rec.Header())
		})
	}
}

func TestServeCmd_NonGETRootReturnsMethodNotAllowed(t *testing.T) {
	t.Parallel()
	_, priv := genKey(t)
	dir := t.TempDir()
	writeEvidenceSession(t, dir, priv, "alpha", testActorAlpha, 1)

	handler := evidenceServeHandler(dir, "alpha")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST / status = %d, want 405; body=%s", rec.Code, rec.Body.String())
	}
	assertEvidenceServeSecurityHeaders(t, rec.Header())
	if rec.Header().Get("Allow") != http.MethodGet {
		t.Fatalf("Allow = %q, want GET", rec.Header().Get("Allow"))
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

// --- verify-cert tests ---

func signTestCert(t *testing.T, pub ed25519.PublicKey, priv ed25519.PrivateKey) []byte {
	t.Helper()
	now := time.Now().UTC()
	body := coveragecert.Body{
		Schema:      coveragecert.Schema,
		KeyPurpose:  coveragecert.KeyPurpose,
		Agent:       "agent-alpha",
		WindowStart: now.Add(-1 * time.Hour),
		WindowEnd:   now,
		Sessions: []coveragecert.SessionCoverage{
			{
				ID:                 "session-001",
				ReceiptCount:       10,
				ChainIntact:        true,
				Anchored:           "local",
				CompletenessStatus: "LIMITED",
				CompletenessReason: "bounded_closed",
			},
		},
		TotalReceipts:      10,
		ChainGaps:          0,
		SessionsCovered:    1,
		ChainsIntact:       1,
		ChainsBroken:       0,
		TrustedSignerKey:   hex.EncodeToString(pub),
		Boundary:           coveragecert.DefaultBoundary(),
		StandingExclusions: coveragecert.DefaultStandingExclusions(),
	}

	cert, err := coveragecert.Sign(body, priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	data, err := coveragecert.Marshal(cert)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return data
}

func signUncheckedTestCert(t *testing.T, body coveragecert.Body, pub ed25519.PublicKey, priv ed25519.PrivateKey) []byte {
	t.Helper()
	preimage, err := body.SignablePreimage()
	if err != nil {
		t.Fatalf("SignablePreimage: %v", err)
	}
	cert := coveragecert.Certificate{
		Body:      body,
		Signature: hex.EncodeToString(ed25519.Sign(priv, preimage)),
		SignerKey: hex.EncodeToString(pub),
	}
	data, err := coveragecert.Marshal(cert)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return data
}

func TestVerifyCertCmd_TrustedSigner_Success(t *testing.T) {
	t.Parallel()
	pub, priv := genKey(t)
	certData := signTestCert(t, pub, priv)
	certFile := filepath.Join(t.TempDir(), "cert.json")
	if err := os.WriteFile(certFile, certData, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	keyHex := hex.EncodeToString(pub)
	var stdout, stderr bytes.Buffer
	cmd := Cmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{
		"verify-cert",
		"--cert", certFile,
		"--trusted-signer", "inline=" + keyHex + ",source=test-signer",
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	out := stdout.String()
	// Must contain bounded per-fact lines.
	if !strings.Contains(out, "Signature: valid") {
		t.Error("output missing 'Signature: valid' line")
	}
	if !strings.Contains(out, "Signer: TRUSTED") {
		t.Error("output missing 'Signer: TRUSTED' line")
	}
	if !strings.Contains(out, "Agent: agent-alpha") {
		t.Error("output missing Agent line")
	}
	if !strings.Contains(out, "Boundary:") {
		t.Error("output missing Boundary line")
	}
	if !strings.Contains(out, "Exclusion:") {
		t.Error("output missing Exclusion line")
	}
}

func TestVerifyCertCmd_UntrustedSigner_Reported(t *testing.T) {
	t.Parallel()
	pub, priv := genKey(t)
	certData := signTestCert(t, pub, priv)
	certFile := filepath.Join(t.TempDir(), "cert.json")
	if err := os.WriteFile(certFile, certData, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Use a different key as trusted.
	otherPub, _ := genKey(t)
	otherKeyHex := hex.EncodeToString(otherPub)
	var stdout, stderr bytes.Buffer
	cmd := Cmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{
		"verify-cert",
		"--cert", certFile,
		"--trusted-signer", "inline=" + otherKeyHex,
	})

	execErr := cmd.Execute()
	if execErr == nil || !strings.Contains(execErr.Error(), "not in the trusted-signer set") {
		t.Fatalf("Execute err = %v, want fail-closed untrusted-signer error", execErr)
	}

	// The diagnostic line is still emitted to stdout before the fail-closed return.
	out := stdout.String()
	if !strings.Contains(out, "Signer: NOT TRUSTED") {
		t.Error("output should report untrusted signer")
	}
}

func TestVerifyCertCmd_Tampered_NonZero(t *testing.T) {
	t.Parallel()
	pub, priv := genKey(t)
	certData := signTestCert(t, pub, priv)

	// Tamper the cert JSON: replace agent name.
	tampered := strings.Replace(string(certData), "agent-alpha", "agent-tampered", 1)
	certFile := filepath.Join(t.TempDir(), "cert.json")
	if err := os.WriteFile(certFile, []byte(tampered), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	keyHex := hex.EncodeToString(pub)
	var stdout, stderr bytes.Buffer
	cmd := Cmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{
		"verify-cert",
		"--cert", certFile,
		"--trusted-signer", "inline=" + keyHex,
	})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected non-zero exit for tampered cert")
	}
	if !strings.Contains(err.Error(), "invalid") {
		t.Errorf("error should mention invalid signature, got: %v", err)
	}
}

func TestVerifyCertCmd_SignedAggregateMismatch_NonZero(t *testing.T) {
	t.Parallel()
	pub, priv := genKey(t)
	now := time.Now().UTC()
	body := coveragecert.Body{
		Schema:      coveragecert.Schema,
		KeyPurpose:  coveragecert.KeyPurpose,
		Agent:       "agent-alpha",
		WindowStart: now.Add(-1 * time.Hour),
		WindowEnd:   now,
		Sessions: []coveragecert.SessionCoverage{
			{
				ID:                 "session-001",
				ReceiptCount:       10,
				ChainIntact:        true,
				Anchored:           "local",
				CompletenessStatus: "LIMITED",
				CompletenessReason: "bounded_closed",
			},
		},
		TotalReceipts:      999,
		ChainGaps:          0,
		SessionsCovered:    1,
		ChainsIntact:       1,
		ChainsBroken:       0,
		TrustedSignerKey:   hex.EncodeToString(pub),
		Boundary:           coveragecert.DefaultBoundary(),
		StandingExclusions: coveragecert.DefaultStandingExclusions(),
	}
	certData := signUncheckedTestCert(t, body, pub, priv)
	certFile := filepath.Join(t.TempDir(), "cert.json")
	if err := os.WriteFile(certFile, certData, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	var stdout, stderr bytes.Buffer
	cmd := Cmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{
		"verify-cert",
		"--cert", certFile,
		"--trusted-signer", "inline=" + hex.EncodeToString(pub),
	})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected non-zero exit for signed aggregate mismatch")
	}
	if !strings.Contains(err.Error(), "aggregate") {
		t.Fatalf("error = %q, want aggregate mismatch", err.Error())
	}
	if !strings.Contains(stdout.String(), "MISMATCH") {
		t.Fatalf("stdout = %q, want MISMATCH line", stdout.String())
	}
}

func TestVerifyCertCmd_SignedAgentLineInjection_NonZero(t *testing.T) {
	t.Parallel()
	pub, priv := genKey(t)
	now := time.Now().UTC()
	body := coveragecert.Body{
		Schema:      coveragecert.Schema,
		KeyPurpose:  coveragecert.KeyPurpose,
		Agent:       "agent-alpha\nFORGED: sessions covered",
		WindowStart: now.Add(-1 * time.Hour),
		WindowEnd:   now,
		Sessions: []coveragecert.SessionCoverage{
			{
				ID:                 "session-001",
				ReceiptCount:       1,
				ChainIntact:        true,
				Anchored:           "local",
				CompletenessStatus: "LIMITED",
				CompletenessReason: "bounded_closed",
			},
		},
		TotalReceipts:      2,
		ChainGaps:          0,
		SessionsCovered:    1,
		ChainsIntact:       1,
		ChainsBroken:       0,
		TrustedSignerKey:   hex.EncodeToString(pub),
		Boundary:           coveragecert.DefaultBoundary(),
		StandingExclusions: coveragecert.DefaultStandingExclusions(),
	}
	certData := signUncheckedTestCert(t, body, pub, priv)
	certFile := filepath.Join(t.TempDir(), "cert.json")
	if err := os.WriteFile(certFile, certData, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	var stdout, stderr bytes.Buffer
	cmd := Cmd()
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{
		"verify-cert",
		"--cert", certFile,
		"--trusted-signer", "inline=" + hex.EncodeToString(pub),
	})

	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "control") {
		t.Fatalf("Execute err = %v, want fail-closed control-character error", err)
	}
	if strings.Contains(stdout.String(), "FORGED") {
		t.Fatalf("stdout = %q, must not emit injected over-claim lines", stdout.String())
	}
}

func TestVerifyCertCmd_NoLicenseRequired(t *testing.T) {
	// Explicit gate test: the free verify-cert must work without any
	// license infrastructure. If someone adds a license check, this
	// test name makes the violation obvious.
	t.Parallel()
	pub, priv := genKey(t)
	certData := signTestCert(t, pub, priv)
	certFile := filepath.Join(t.TempDir(), "cert.json")
	if err := os.WriteFile(certFile, certData, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	var stdout bytes.Buffer
	cmd := Cmd()
	cmd.SetOut(&stdout)
	cmd.SetArgs([]string{
		"verify-cert",
		"--cert", certFile,
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("free verify-cert should work without a license: %v", err)
	}
	if !strings.Contains(stdout.String(), "Signature: valid") {
		t.Error("output missing 'Signature: valid' line")
	}
}

func TestVerifyCertCmd_BadCertFile(t *testing.T) {
	t.Parallel()

	t.Run("nonexistent", func(t *testing.T) {
		t.Parallel()
		var buf bytes.Buffer
		cmd := Cmd()
		cmd.SetOut(&buf)
		cmd.SetErr(&buf)
		cmd.SetArgs([]string{
			"verify-cert",
			"--cert", filepath.Join(t.TempDir(), "nope.json"),
		})
		err := cmd.Execute()
		if err == nil {
			t.Fatal("expected error for nonexistent cert file")
		}
	})

	t.Run("invalid json", func(t *testing.T) {
		t.Parallel()
		certFile := filepath.Join(t.TempDir(), "bad.json")
		if err := os.WriteFile(certFile, []byte("not json"), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		var buf bytes.Buffer
		cmd := Cmd()
		cmd.SetOut(&buf)
		cmd.SetErr(&buf)
		cmd.SetArgs([]string{
			"verify-cert",
			"--cert", certFile,
		})
		err := cmd.Execute()
		if err == nil {
			t.Fatal("expected error for invalid JSON cert file")
		}
	})
}
