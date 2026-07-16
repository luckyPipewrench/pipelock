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
const coverageCertTestActor = "agent-a"

func writeCoverageCertSession(t *testing.T, dir string, priv ed25519.PrivateKey, count int) {
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
		Actor:      coverageCertTestActor,
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
			Agent:     coverageCertTestActor,
		}); err != nil {
			t.Fatalf("Emit(%d): %v", i, err)
		}
	}
	_ = rec.Close()
}

func writeCoverageCertEvidenceSession(t *testing.T, dir string, priv ed25519.PrivateKey, sessionID, actor string, count int) {
	t.Helper()
	writeCoverageCertEvidenceSessionAt(t, dir, priv, sessionID, actor, count, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
}

func writeCoverageCertEvidenceSessionAt(t *testing.T, dir string, priv ed25519.PrivateKey, sessionID, actor string, count int, base time.Time) {
	t.Helper()
	path := filepath.Join(dir, fmt.Sprintf("evidence-%s-000000.jsonl", sessionID))
	prevHash := receipt.GenesisHash
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
	writeCoverageCertEvidenceSession(t, dir, priv, "roundtrip", actor, 3)

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
	if !strings.Contains(out.String(), "receipt chains: self-consistent only") {
		t.Fatalf("generate output = %q, want self-consistent-only receipt-chain label", out.String())
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

func TestRunCoverageCertGenerate_TrustedReceiptSignerMode(t *testing.T) {
	dir := t.TempDir()
	pub, priv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	writeCoverageCertEvidenceSession(t, dir, priv, "trusted-chain", "agent-a", 2)

	keyFile := filepath.Join(t.TempDir(), "signing.key")
	if err := signing.SavePrivateKey(priv, keyFile); err != nil {
		t.Fatalf("SavePrivateKey: %v", err)
	}
	certFile := filepath.Join(t.TempDir(), "cert.json")
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cmd := &cobra.Command{}
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)

	if err := runCoverageCertGenerate(cmd, coverageCertGenerateOptions{
		agent:                 "agent-a",
		receiptDir:            dir,
		signingKeyFile:        keyFile,
		trustedReceiptSigners: []string{"inline=" + hex.EncodeToString(pub)},
		windowStart:           start.Format(time.RFC3339),
		windowEnd:             start.Add(time.Hour).Format(time.RFC3339),
		outFile:               certFile,
	}); err != nil {
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
	if cert.Body.ChainsIntact != 1 || !cert.Body.Sessions[0].ChainIntact {
		t.Fatalf("trusted receipt signer chain_intact = body:%d session:%v, want trusted intact",
			cert.Body.ChainsIntact, cert.Body.Sessions[0].ChainIntact)
	}
	if !strings.Contains(out.String(), "receipt chains: verified against trusted signer set") {
		t.Fatalf("generate output = %q, want trusted receipt-chain label", out.String())
	}
}

func TestRunCoverageCertGenerate_UntrustedReceiptSignerMarksChainBroken(t *testing.T) {
	dir := t.TempDir()
	_, priv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	otherPub, _, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair other: %v", err)
	}
	writeCoverageCertEvidenceSession(t, dir, priv, "untrusted-chain", "agent-a", 2)

	keyFile := filepath.Join(t.TempDir(), "signing.key")
	if err := signing.SavePrivateKey(priv, keyFile); err != nil {
		t.Fatalf("SavePrivateKey: %v", err)
	}
	certFile := filepath.Join(t.TempDir(), "cert.json")
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cmd := &cobra.Command{}
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)

	if err := runCoverageCertGenerate(cmd, coverageCertGenerateOptions{
		agent:                 "agent-a",
		receiptDir:            dir,
		signingKeyFile:        keyFile,
		trustedReceiptSigners: []string{"inline=" + hex.EncodeToString(otherPub)},
		windowStart:           start.Format(time.RFC3339),
		windowEnd:             start.Add(time.Hour).Format(time.RFC3339),
		outFile:               certFile,
	}); err != nil {
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
	if cert.Body.ChainsBroken != 1 || cert.Body.Sessions[0].ChainIntact {
		t.Fatalf("untrusted receipt signer chain result = broken:%d session:%v, want broken",
			cert.Body.ChainsBroken, cert.Body.Sessions[0].ChainIntact)
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

func TestRunCoverageCertGenerate_FiltersDeclaredWindow(t *testing.T) {
	dir := t.TempDir()
	pub, priv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	windowStart := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	windowEnd := windowStart.Add(time.Hour)
	writeCoverageCertEvidenceSessionAt(t, dir, priv, "before", "agent-a", 2, windowStart.Add(-2*time.Hour))
	writeCoverageCertEvidenceSessionAt(t, dir, priv, "inside", "agent-a", 2, windowStart.Add(10*time.Minute))
	writeCoverageCertEvidenceSessionAt(t, dir, priv, "after", "agent-a", 2, windowEnd.Add(time.Minute))

	keyFile := filepath.Join(t.TempDir(), "signing.key")
	if err := signing.SavePrivateKey(priv, keyFile); err != nil {
		t.Fatalf("SavePrivateKey: %v", err)
	}
	certFile := filepath.Join(t.TempDir(), "cert.json")
	cmd := &cobra.Command{}
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	if err := runCoverageCertGenerate(cmd, coverageCertGenerateOptions{
		agent:          "agent-a",
		receiptDir:     dir,
		signingKeyFile: keyFile,
		windowStart:    windowStart.Format(time.RFC3339),
		windowEnd:      windowEnd.Format(time.RFC3339),
		outFile:        certFile,
	}); err != nil {
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
		t.Fatalf("window cert summarized total=%d sessions=%d, want total=2 sessions=1", cert.Body.TotalReceipts, cert.Body.SessionsCovered)
	}
	if cert.Body.Sessions[0].ID != "inside" {
		t.Fatalf("cert session = %q, want inside", cert.Body.Sessions[0].ID)
	}
}

func TestLoadCoverageCertSessionReceipts_FailsClosedOnTruncation(t *testing.T) {
	dir := t.TempDir()
	_, priv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	writeCoverageCertEvidenceSession(t, dir, priv, "limited", "agent-a", 2)

	_, err = loadCoverageCertSessionReceipts(dir, "limited", 1)
	if err == nil {
		t.Fatal("loadCoverageCertSessionReceipts should reject truncated reads")
	}
	if !strings.Contains(err.Error(), "receipt read limit 1 reached") {
		t.Fatalf("error = %q, want read-limit rejection", err.Error())
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
	writeCoverageCertEvidenceSession(t, dir, priv, "verify", "agent-a", 2)
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

	t.Run("no trusted signer fails closed by default", func(t *testing.T) {
		cmd, buf := newCmd()
		err := runCoverageCertVerify(cmd, coverageCertVerifyOptions{
			certFile: certFile,
		})
		if err == nil || !strings.Contains(err.Error(), "no trusted-signer set supplied") {
			t.Fatalf("verify (unpinned default) err = %v, want fail-closed missing trusted-signer error", err)
		}
		if strings.Contains(buf.String(), "STRUCTURAL ONLY") {
			t.Fatalf("verify output = %q, must not report structural-only opt-in by default", buf.String())
		}
	})

	t.Run("no trusted signer structural opt in exits zero", func(t *testing.T) {
		cmd, buf := newCmd()
		err := runCoverageCertVerify(cmd, coverageCertVerifyOptions{
			certFile:      certFile,
			allowUnpinned: true,
		})
		if err != nil {
			t.Fatalf("verify (structural opt-in) error: %v", err)
		}
		if !strings.Contains(buf.String(), "STRUCTURAL ONLY — signer NOT trusted") {
			t.Fatalf("verify output = %q, want explicit structural-only label", buf.String())
		}
	})

	t.Run("untrusted signer fails closed", func(t *testing.T) {
		_, otherPriv, _ := signing.GenerateKeyPair()
		otherPub := otherPriv.Public().(ed25519.PublicKey)
		cmd, _ := newCmd()
		err := runCoverageCertVerify(cmd, coverageCertVerifyOptions{
			certFile:       certFile,
			trustedSigners: []string{"inline=" + hex.EncodeToString(otherPub)},
		})
		if err == nil || !strings.Contains(err.Error(), "not in the trusted-signer set") {
			t.Fatalf("verify (untrusted) err = %v, want fail-closed error", err)
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
	if coverageCertVerifyCmd().Flags().Lookup("allow-unpinned") == nil {
		t.Error("verify missing --allow-unpinned flag")
	}
	if coverageCertGenerateCmd().Flags().Lookup("trusted-receipt-signer") == nil {
		t.Error("generate missing --trusted-receipt-signer flag")
	}
}

func TestRunCoverageCertGenerate_ErrorPaths(t *testing.T) {
	dir := t.TempDir()
	_, priv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	writeCoverageCertSession(t, dir, priv, 2)
	keyFile := filepath.Join(t.TempDir(), "signing.key")
	if err := signing.SavePrivateKey(priv, keyFile); err != nil {
		t.Fatalf("SavePrivateKey: %v", err)
	}
	good := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	base := coverageCertGenerateOptions{
		agent:          "agent-a",
		receiptDir:     dir,
		signingKeyFile: keyFile,
		windowStart:    good.Format(time.RFC3339),
		windowEnd:      good.Add(time.Hour).Format(time.RFC3339),
		outFile:        filepath.Join(t.TempDir(), "c.json"),
	}
	fileAsDir := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(fileAsDir, []byte("x"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(o coverageCertGenerateOptions) coverageCertGenerateOptions
	}{
		{"bad window-start", func(o coverageCertGenerateOptions) coverageCertGenerateOptions { o.windowStart = "nope"; return o }},
		{"bad window-end", func(o coverageCertGenerateOptions) coverageCertGenerateOptions { o.windowEnd = "nope"; return o }},
		{"missing receipt-dir", func(o coverageCertGenerateOptions) coverageCertGenerateOptions {
			o.receiptDir = "/no/such/dir"
			return o
		}},
		{"receipt-dir is a file", func(o coverageCertGenerateOptions) coverageCertGenerateOptions { o.receiptDir = fileAsDir; return o }},
		{"missing signing-key", func(o coverageCertGenerateOptions) coverageCertGenerateOptions {
			o.signingKeyFile = "/no/such/key"
			return o
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := &cobra.Command{}
			var buf bytes.Buffer
			cmd.SetOut(&buf)
			cmd.SetErr(&buf)
			if err := runCoverageCertGenerate(cmd, tc.mutate(base)); err == nil {
				t.Fatalf("%s: expected error", tc.name)
			}
		})
	}
}

func TestRunCoverageCertGenerate_MixedActorSessionRejected(t *testing.T) {
	// A single recorder session whose receipts carry two different actors must
	// be refused for a per-agent certificate (fail closed, no cross-agent leak).
	dir := t.TempDir()
	_, priv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	path := filepath.Join(dir, "evidence-mixed-000000.jsonl")
	prevHash := receipt.GenesisHash
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	var lines []byte
	for i, actor := range []string{"agent-a", "agent-b"} {
		ar := receipt.ActionRecord{
			Version: receipt.ActionRecordVersion, ActionID: receipt.NewActionID(),
			ActionType: receipt.ActionRead, Timestamp: base.Add(time.Duration(i) * time.Second),
			Actor: actor, Target: "https://api.vendor.example/x", Verdict: config.ActionAllow,
			SessionID: "mixed", Transport: "fetch", Method: http.MethodGet,
			ChainPrevHash: prevHash, ChainSeq: uint64(i),
		}
		r, _ := receipt.Sign(ar, priv)
		hash, _ := receipt.ReceiptHash(r)
		detail, _ := json.Marshal(r)
		entry := recorder.Entry{
			Version: 1, Sequence: uint64(i), Timestamp: ar.Timestamp, SessionID: "mixed",
			Type: "action_receipt", Transport: "fetch", Summary: "t",
			Detail: json.RawMessage(detail), PrevHash: prevHash, Hash: hash,
		}
		line, _ := json.Marshal(entry)
		lines = append(lines, line...)
		lines = append(lines, '\n')
		prevHash = hash
	}
	if err := os.WriteFile(path, lines, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	keyFile := filepath.Join(t.TempDir(), "signing.key")
	if err := signing.SavePrivateKey(priv, keyFile); err != nil {
		t.Fatalf("SavePrivateKey: %v", err)
	}
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cmd := &cobra.Command{}
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	err = runCoverageCertGenerate(cmd, coverageCertGenerateOptions{
		agent: "agent-a", receiptDir: dir, signingKeyFile: keyFile,
		windowStart: start.Format(time.RFC3339), windowEnd: start.Add(time.Hour).Format(time.RFC3339),
		outFile: filepath.Join(t.TempDir(), "c.json"),
	})
	if err == nil {
		t.Fatal("mixed-actor session must be rejected for a per-agent certificate")
	}
}

func TestCoverageCertGenerate_Execute_LicenseGated(t *testing.T) {
	// Executing `coverage-cert generate` runs the RunE closure, which enforces
	// the Pro (agents) license gate before any work. In a test environment with
	// no Pro license, the gate fails closed.
	dir := t.TempDir()
	_, priv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	writeCoverageCertSession(t, dir, priv, 1)
	keyFile := filepath.Join(t.TempDir(), "k.key")
	if err := signing.SavePrivateKey(priv, keyFile); err != nil {
		t.Fatalf("SavePrivateKey: %v", err)
	}
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	root := coverageCertCmd()
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	root.SetArgs([]string{
		"generate",
		"--agent", "agent-a",
		"--receipt-dir", dir,
		"--signing-key", keyFile,
		"--window-start", start.Format(time.RFC3339),
		"--window-end", start.Add(time.Hour).Format(time.RFC3339),
		"--out", filepath.Join(t.TempDir(), "c.json"),
	})
	// The RunE ran either way; without a Pro license it must fail closed.
	if err := root.Execute(); err == nil {
		t.Skip("a Pro license is present in this environment; gate did not fail closed")
	}
}

func TestCoverageCertVerify_Execute(t *testing.T) {
	certFile, pubHex := genCoverageCertForTest(t)
	root := coverageCertCmd()
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	root.SetArgs([]string{"verify", "--cert", certFile, "--trusted-signer", "inline=" + pubHex})
	if err := root.Execute(); err != nil {
		t.Fatalf("verify Execute: %v", err)
	}
	if buf.Len() == 0 {
		t.Error("verify should print bounded lines")
	}
}

// TestSessionBelongsToAgent_AnonymousTolerance is the regression guard for the
// coverage-cert generate mixed-actor bug: a normal single-agent session mixes
// the "pipelock" session-control actor with unattributed "anonymous" request
// receipts. The generate guard must tolerate that default proxy shape while
// still rejecting genuine second named agents and named-agent sessions that
// would over-count unattributed traffic in the signed certificate body.
func TestSessionBelongsToAgent_AnonymousTolerance(t *testing.T) {
	rec := func(actor, sessionID string) receipt.Receipt {
		return receipt.Receipt{ActionRecord: receipt.ActionRecord{Actor: actor, SessionID: sessionID}}
	}
	tests := []struct {
		name       string
		agent      string
		receipts   []receipt.Receipt
		wantBelong bool
		wantErr    bool
	}{
		{
			name:  "pipelock control mixed with anonymous requests belongs to pipelock",
			agent: "pipelock",
			receipts: []receipt.Receipt{
				rec("pipelock", "proxy"),
				rec("anonymous", "proxy"),
				rec("anonymous", "proxy"),
				rec("pipelock", "proxy"),
			},
			wantBelong: true,
		},
		{
			name:       "all anonymous does not belong to a named agent (no false claim)",
			agent:      "pipelock",
			receipts:   []receipt.Receipt{rec("anonymous", "proxy"), rec("anonymous", "proxy")},
			wantBelong: false,
		},
		{
			name:  "two distinct named agents still rejected (cross-agent leak guard preserved)",
			agent: "agent-a",
			receipts: []receipt.Receipt{
				rec("agent-a", "s"),
				rec("anonymous", "s"),
				rec("agent-b", "s"),
			},
			wantErr: true,
		},
		{
			name:  "named agent mixed with anonymous is rejected so cert does not over-count unattributed traffic",
			agent: "agent-a",
			receipts: []receipt.Receipt{
				rec("agent-a", "s"),
				rec("anonymous", "s"),
			},
			wantErr: true,
		},
		{
			name:       "empty actor is unattributed, not derived from session id (no over-attribution to a named agent)",
			agent:      "agent-a",
			receipts:   []receipt.Receipt{{ActionRecord: receipt.ActionRecord{Actor: "", SessionID: "agent-a"}}},
			wantBelong: false,
		},
		{
			name:  "empty actors fold into anonymous under the default control actor",
			agent: "pipelock",
			receipts: []receipt.Receipt{
				rec("pipelock", "proxy"),
				{ActionRecord: receipt.ActionRecord{Actor: "", SessionID: "proxy"}},
			},
			wantBelong: true,
		},
		{
			name:       "whitespace-padded actor is normalized before matching",
			agent:      "agent-a",
			receipts:   []receipt.Receipt{rec(" agent-a ", "s")},
			wantBelong: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := sessionBelongsToAgent("proxy", tt.receipts, tt.agent)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected mixed-actor error, got belong=%v err=nil", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.wantBelong {
				t.Errorf("belong = %v, want %v", got, tt.wantBelong)
			}
		})
	}
}

// TestRunCoverageCertGenerate_TrimsAgentWhitespace guards the CodeRabbit finding:
// incidental whitespace on the CLI --agent flag must be normalized so it neither
// breaks actor matching nor lands untrimmed in the signed certificate body.
func TestRunCoverageCertGenerate_TrimsAgentWhitespace(t *testing.T) {
	dir := t.TempDir()
	_, priv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	writeCoverageCertEvidenceSession(t, dir, priv, "roundtrip", "agent-a", 3)

	keyFile := filepath.Join(t.TempDir(), "signing.key")
	if err := signing.SavePrivateKey(priv, keyFile); err != nil {
		t.Fatalf("SavePrivateKey: %v", err)
	}
	certFile := filepath.Join(t.TempDir(), "cert.json")
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	opts := coverageCertGenerateOptions{
		agent:          "  agent-a  ",
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
		t.Fatalf("runCoverageCertGenerate with padded agent: %v", err)
	}
	data, err := os.ReadFile(filepath.Clean(certFile))
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	cert, err := coveragecert.Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal cert: %v", err)
	}
	if got := cert.Body.Agent; got != "agent-a" {
		t.Fatalf("certificate body Agent = %q, want normalized %q", got, "agent-a")
	}
}

// TestRunCoverageCertGenerate_RejectsBlankAgent confirms an all-whitespace agent
// is rejected rather than silently matching unattributed receipts.
func TestRunCoverageCertGenerate_RejectsBlankAgent(t *testing.T) {
	opts := coverageCertGenerateOptions{
		agent:       "   ",
		receiptDir:  t.TempDir(),
		windowStart: "2026-01-01T00:00:00Z",
		windowEnd:   "2026-01-02T00:00:00Z",
	}
	cmd := &cobra.Command{}
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	if err := runCoverageCertGenerate(cmd, opts); err == nil {
		t.Fatal("expected error for blank --agent, got nil")
	}
}
