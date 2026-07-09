//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package entcli

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/coveragecert"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

// writeCoverageCertSession emits one signed session into dir for the coverage
// certificate generate path.
func writeCoverageCertSession(t *testing.T, dir string, priv ed25519.PrivateKey, actor string, count int) {
	t.Helper()
	rec, err := recorder.New(recorder.Config{
		Enabled:            true,
		Dir:                dir,
		CheckpointInterval: 1000,
	}, nil, priv)
	if err != nil {
		t.Fatalf("recorder.New: %v", err)
	}
	emitter := receipt.NewEmitter(receipt.EmitterConfig{
		Recorder:   rec,
		PrivKey:    priv,
		ConfigHash: "policy-hash-test",
		Principal:  "operator",
		Actor:      actor,
	})
	if err := emitter.EmitSessionOpen(); err != nil {
		t.Fatalf("EmitSessionOpen: %v", err)
	}
	for i := range count {
		verdict := config.ActionAllow
		if i%2 == 0 {
			verdict = config.ActionBlock
		}
		if err := emitter.Emit(receipt.EmitOpts{
			ActionID:  receipt.NewActionID(),
			Target:    "https://api.vendor.example/resource",
			Verdict:   verdict,
			Transport: "fetch",
			Method:    http.MethodGet,
			Agent:     actor,
		}); err != nil {
			t.Fatalf("Emit(%d): %v", i, err)
		}
	}
	_ = rec.Close()
}

func writeCoverageCertEvidenceSession(t *testing.T, dir string, priv ed25519.PrivateKey, sessionID, actor string, count int) {
	t.Helper()
	path := filepath.Join(dir, fmt.Sprintf("evidence-%s-000000.jsonl", sessionID))
	prevHash := receipt.GenesisHash
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	var lines []byte
	for i := range count {
		ar := receipt.ActionRecord{
			Version:       receipt.ActionRecordVersion,
			ActionID:      receipt.NewActionID(),
			ActionType:    receipt.ActionRead,
			Timestamp:     base.Add(time.Duration(i) * time.Second),
			Principal:     "operator",
			Actor:         actor,
			Target:        "https://api.vendor.example/resource",
			PolicyHash:    "policy-hash-test",
			Verdict:       config.ActionAllow,
			SessionID:     sessionID,
			Transport:     "fetch",
			Method:        http.MethodGet,
			ChainPrevHash: prevHash,
			ChainSeq:      uint64(i),
		}
		r, err := receipt.Sign(ar, priv)
		if err != nil {
			t.Fatalf("Sign receipt: %v", err)
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
			Type:      "action_receipt",
			Transport: "fetch",
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

// TestRunCoverageCertGenerate_RoundTrip exercises the Pro generate path end to
// end (bypassing the license gate, which is a thin RunE wrapper) and verifies
// the produced certificate offline. It is the regression that would have caught
// the priv.Public() type-assertion panic.
func TestRunCoverageCertGenerate_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	pub, priv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	const actor = "agent-a"
	writeCoverageCertSession(t, dir, priv, actor, 3)

	keyFile := filepath.Join(t.TempDir(), "signing.key")
	if err := signing.SavePrivateKey(priv, keyFile); err != nil {
		t.Fatalf("SavePrivateKey: %v", err)
	}
	certFile := filepath.Join(t.TempDir(), "cert.json")

	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	opts := coverageCertGenerateOptions{
		agent:          actor,
		receiptDir:     dir,
		signingKeyFile: keyFile,
		windowStart:    start.Format(time.RFC3339),
		windowEnd:      start.Add(24 * time.Hour).Format(time.RFC3339),
		outFile:        certFile,
	}
	cmd := &cobra.Command{}
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	if err := runCoverageCertGenerate(cmd, opts); err != nil {
		t.Fatalf("runCoverageCertGenerate: %v", err)
	}

	data, err := os.ReadFile(filepath.Clean(certFile))
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	cert, err := coveragecert.Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal cert: %v", err)
	}

	trusted := map[string]struct{}{hex.EncodeToString(pub): {}}
	res, err := coveragecert.Verify(cert, trusted)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.SignatureValid {
		t.Fatal("generated certificate signature did not verify")
	}
	if !res.SignerTrusted {
		t.Fatal("generated certificate signer should be trusted")
	}
	if cert.Body.Agent != actor {
		t.Errorf("cert agent = %q, want %q", cert.Body.Agent, actor)
	}
	// Honest boundary wording is present and never over-claims.
	if !bytes.Contains(data, []byte("mediated egress inside the declared Pipelock boundary")) {
		t.Error("cert boundary is missing the required mediated-egress phrase")
	}
	if bytes.Contains(data, []byte("all agent activity")) {
		t.Error("cert must not claim coverage of all agent activity")
	}
	if len(cert.Body.Sessions) == 0 {
		t.Error("cert should summarize at least one session")
	}
}

func TestRunCoverageCertGenerate_FiltersDeclaredAgent(t *testing.T) {
	dir := t.TempDir()
	pub, priv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	writeCoverageCertEvidenceSession(t, dir, priv, "alpha", "agent-a", 2)
	writeCoverageCertEvidenceSession(t, dir, priv, "bravo", "agent-b", 2)

	keyFile := filepath.Join(t.TempDir(), "signing.key")
	if err := signing.SavePrivateKey(priv, keyFile); err != nil {
		t.Fatalf("SavePrivateKey: %v", err)
	}
	certFile := filepath.Join(t.TempDir(), "cert.json")
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	opts := coverageCertGenerateOptions{
		agent:          "agent-a",
		receiptDir:     dir,
		signingKeyFile: keyFile,
		windowStart:    start.Format(time.RFC3339),
		windowEnd:      start.Add(time.Hour).Format(time.RFC3339),
		outFile:        certFile,
	}
	cmd := &cobra.Command{}
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	if err := runCoverageCertGenerate(cmd, opts); err != nil {
		t.Fatalf("runCoverageCertGenerate: %v", err)
	}

	data, err := os.ReadFile(filepath.Clean(certFile))
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	cert, err := coveragecert.Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal cert: %v", err)
	}
	res, err := coveragecert.Verify(cert, map[string]struct{}{hex.EncodeToString(pub): {}})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.SignatureValid || !res.SignerTrusted || !res.AggregateValid {
		t.Fatalf("generated cert verification = signature:%v trusted:%v aggregate:%v", res.SignatureValid, res.SignerTrusted, res.AggregateValid)
	}
	if cert.Body.TotalReceipts != 2 || cert.Body.SessionsCovered != 1 {
		t.Fatalf("agent-a cert summarized total=%d sessions=%d, want total=2 sessions=1", cert.Body.TotalReceipts, cert.Body.SessionsCovered)
	}
	if cert.Body.Sessions[0].ID != "alpha" {
		t.Fatalf("cert session = %q, want alpha", cert.Body.Sessions[0].ID)
	}
}

// genCoverageCertForTest generates a signed cert file for agent-a and returns
// its path plus the signer public-key hex.
func genCoverageCertForTest(t *testing.T) (certFile, pubHex string) {
	t.Helper()
	dir := t.TempDir()
	pub, priv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	writeCoverageCertSession(t, dir, priv, "agent-a", 2)
	keyFile := filepath.Join(t.TempDir(), "signing.key")
	if err := signing.SavePrivateKey(priv, keyFile); err != nil {
		t.Fatalf("SavePrivateKey: %v", err)
	}
	certFile = filepath.Join(t.TempDir(), "cert.json")
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cmd := &cobra.Command{}
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	if err := runCoverageCertGenerate(cmd, coverageCertGenerateOptions{
		agent:          "agent-a",
		receiptDir:     dir,
		signingKeyFile: keyFile,
		windowStart:    start.Format(time.RFC3339),
		windowEnd:      start.Add(24 * time.Hour).Format(time.RFC3339),
		outFile:        certFile,
	}); err != nil {
		t.Fatalf("generate: %v", err)
	}
	return certFile, hex.EncodeToString(pub)
}

func TestRunCoverageCertVerify(t *testing.T) {
	certFile, pubHex := genCoverageCertForTest(t)

	newCmd := func() (*cobra.Command, *bytes.Buffer) {
		cmd := &cobra.Command{}
		var buf bytes.Buffer
		cmd.SetOut(&buf)
		cmd.SetErr(&buf)
		return cmd, &buf
	}

	t.Run("trusted signer verifies", func(t *testing.T) {
		cmd, buf := newCmd()
		err := runCoverageCertVerify(cmd, coverageCertVerifyOptions{
			certFile:       certFile,
			trustedSigners: []string{"inline=" + pubHex},
		})
		if err != nil {
			t.Fatalf("verify (trusted) error: %v", err)
		}
		if buf.Len() == 0 {
			t.Error("expected bounded verification lines in output")
		}
	})

	t.Run("untrusted signer warns but does not fail", func(t *testing.T) {
		_, otherPriv, _ := signing.GenerateKeyPair()
		otherPub := otherPriv.Public().(ed25519.PublicKey)
		cmd, buf := newCmd()
		err := runCoverageCertVerify(cmd, coverageCertVerifyOptions{
			certFile:       certFile,
			trustedSigners: []string{"inline=" + hex.EncodeToString(otherPub)},
		})
		if err != nil {
			t.Fatalf("verify (untrusted) should not error: %v", err)
		}
		if !strings.Contains(buf.String(), "not in the trusted-signer set") {
			t.Errorf("expected untrusted-signer warning, got: %s", buf.String())
		}
	})

	t.Run("tampered cert fails closed", func(t *testing.T) {
		data, err := os.ReadFile(filepath.Clean(certFile))
		if err != nil {
			t.Fatalf("read cert: %v", err)
		}
		tampered := filepath.Join(t.TempDir(), "tampered.json")
		// Flip the agent name in the signed body; the signature no longer matches.
		bad := strings.Replace(string(data), `"agent": "agent-a"`, `"agent": "agent-evil"`, 1)
		if bad == string(data) {
			t.Fatal("test fixture did not tamper the cert")
		}
		if err := os.WriteFile(tampered, []byte(bad), 0o600); err != nil {
			t.Fatalf("write tampered: %v", err)
		}
		cmd, _ := newCmd()
		err = runCoverageCertVerify(cmd, coverageCertVerifyOptions{
			certFile:       tampered,
			trustedSigners: []string{"inline=" + pubHex},
		})
		if err == nil {
			t.Fatal("tampered cert must fail verification")
		}
	})

	t.Run("bad cert file errors", func(t *testing.T) {
		cmd, _ := newCmd()
		if err := runCoverageCertVerify(cmd, coverageCertVerifyOptions{certFile: "/nonexistent/cert.json"}); err == nil {
			t.Fatal("missing cert file must error")
		}
	})
}

func TestCoverageCertCmd_Structure(t *testing.T) {
	root := coverageCertCmd()
	if root.Use != "coverage-cert" {
		t.Fatalf("Use = %q, want coverage-cert", root.Use)
	}
	subs := map[string]bool{}
	for _, c := range root.Commands() {
		subs[c.Name()] = true
	}
	for _, want := range []string{"generate", "verify"} {
		if !subs[want] {
			t.Errorf("missing subcommand %q", want)
		}
	}
	// The generate subcommand registers its required flags.
	gen := coverageCertGenerateCmd()
	for _, f := range []string{"agent", "receipt-dir", "signing-key", "window-start", "window-end"} {
		if gen.Flags().Lookup(f) == nil {
			t.Errorf("generate missing --%s flag", f)
		}
	}
	if coverageCertVerifyCmd().Flags().Lookup("cert") == nil {
		t.Error("verify missing --cert flag")
	}
}
