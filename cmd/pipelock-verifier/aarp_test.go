// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/aarp"
	"github.com/luckyPipewrench/pipelock/internal/cliutil"
)

const (
	testAARPKeyID    = "k-test"
	testAARPMediator = "mediator.test"
	testAARPIssued   = "2026-06-01T00:00:00Z"
)

// aarpEnvFixtures builds a signed envelope plus a trust file pinning the signer,
// writing both to dir and returning their paths and the signer public key.
func aarpEnvFixtures(t *testing.T, dir string) (envPath, trustPath string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	signer, err := aarp.NewEd25519Signer(testAARPKeyID, "mediator", priv)
	if err != nil {
		t.Fatalf("NewEd25519Signer: %v", err)
	}
	env := aarp.Envelope{
		Subject: aarp.Subject{
			ActionRecordSHA256:    strings.Repeat("a", 64),
			ReceiptEnvelopeSHA256: strings.Repeat("b", 64),
			ReceiptSignerKey:      strings.Repeat("c", 64),
			ReceiptType:           aarp.ReceiptTypeActionV1,
		},
		Assertion: aarp.Assertion{
			Claimed:    []string{"mediated"},
			MediatorID: testAARPMediator,
			IssuedAt:   testAARPIssued,
		},
	}
	env, err = aarp.Sign(env, signer)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	envBytes, err := aarp.Marshal(env)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	envPath = filepath.Join(dir, "env.aarp.json")
	writeFileT(t, envPath, envBytes)

	trust := map[string]any{
		"trusted_keys": map[string]string{testAARPKeyID: hex.EncodeToString(pub)},
		"trust_entries": map[string]any{
			testAARPKeyID: map[string]string{"mediator_id": testAARPMediator, "role": "mediator"},
		},
	}
	trustBytes, _ := json.Marshal(trust)
	trustPath = filepath.Join(dir, "trust.json")
	writeFileT(t, trustPath, trustBytes)
	return envPath, trustPath
}

func writeFileT(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestRunAARP_AppraiseJSON(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	envPath, trustPath := aarpEnvFixtures(t, dir)

	var out, errBuf bytes.Buffer
	err := runAARP(&out, &errBuf, envPath, aarpOptions{trustPath: trustPath, jsonOutput: true})
	if err != nil {
		t.Fatalf("runAARP appraise: %v", err)
	}
	var m map[string]any
	if jErr := json.Unmarshal(out.Bytes(), &m); jErr != nil {
		t.Fatalf("output not JSON: %v\n%s", jErr, out.String())
	}
	if m["assertion_signed"] != true {
		t.Errorf("assertion_signed = %v, want true", m["assertion_signed"])
	}
}

func TestRunAARP_AppraiseHuman(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	envPath, trustPath := aarpEnvFixtures(t, dir)

	var out, errBuf bytes.Buffer
	if err := runAARP(&out, &errBuf, envPath, aarpOptions{trustPath: trustPath}); err != nil {
		t.Fatalf("runAARP human: %v", err)
	}
	if !strings.Contains(out.String(), "assertion_signed:") {
		t.Errorf("human output missing assertion_signed line:\n%s", out.String())
	}
}

func TestRunAARP_FatalProfileMismatch(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	envPath, trustPath := aarpEnvFixtures(t, dir)
	// Corrupt the profile to make the envelope fatal.
	raw, err := os.ReadFile(filepath.Clean(envPath))
	if err != nil {
		t.Fatalf("read env: %v", err)
	}
	raw = bytes.Replace(raw, []byte(`"profile":"aarp/v0.1"`), []byte(`"profile":"aarp/v9.9"`), 1)
	writeFileT(t, envPath, raw)

	var out, errBuf bytes.Buffer
	err = runAARP(&out, &errBuf, envPath, aarpOptions{trustPath: trustPath, jsonOutput: true})
	if err == nil {
		t.Fatal("runAARP succeeded on profile mismatch, want fatal")
	}
	assertExitCode(t, err, cliutil.ExitGeneral)
	if !strings.Contains(out.String(), "envelope_fatal") {
		t.Errorf("fatal JSON missing envelope_fatal:\n%s", out.String())
	}
}

func TestRunAARP_MissingFile(t *testing.T) {
	t.Parallel()
	var out, errBuf bytes.Buffer
	err := runAARP(&out, &errBuf, filepath.Join(t.TempDir(), "nope.json"), aarpOptions{})
	if err == nil {
		t.Fatal("runAARP succeeded on missing file")
	}
	assertExitCode(t, err, cliutil.ExitConfig)
}

func TestRunAARPChain_LinkedAndBroken(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	_, trustPath := aarpEnvFixtures(t, dir)

	// Build a genuine 2-link stream.
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := aarp.NewEd25519Signer(testAARPKeyID, "mediator", priv)
	_ = pub
	mk := func(seq, prior, label string) aarp.Envelope {
		e := aarp.Envelope{
			Subject: aarp.Subject{
				ActionRecordSHA256:    strings.Repeat("a", 64),
				ReceiptEnvelopeSHA256: hex64(label),
				ReceiptSignerKey:      strings.Repeat("c", 64),
				ReceiptType:           aarp.ReceiptTypeActionV1,
			},
			Assertion: aarp.Assertion{Claimed: []string{"mediated"}, MediatorID: testAARPMediator, IssuedAt: testAARPIssued},
			Chain:     &aarp.ChainLink{IssuerID: "issuer.test", Seq: seq, PriorHash: prior},
		}
		e, err := aarp.Sign(e, signer)
		if err != nil {
			t.Fatalf("sign chain link: %v", err)
		}
		return e
	}
	e0 := mk("0", aarp.GenesisPriorHash, "a")
	d0, _ := e0.PayloadDigest()
	e1 := mk("1", d0, "b")

	linkedPath := filepath.Join(dir, "linked.jsonl")
	writeFileT(t, linkedPath, chainJSONL(t, e0, e1))
	var out, errBuf bytes.Buffer
	if err := runAARP(&out, &errBuf, linkedPath, aarpOptions{trustPath: trustPath, jsonOutput: true, chain: true}); err != nil {
		t.Fatalf("linked chain rejected: %v", err)
	}
	if !strings.Contains(out.String(), `"chain_linked":true`) {
		t.Errorf("linked chain output: %s", out.String())
	}

	// Reversed order breaks linkage.
	brokenPath := filepath.Join(dir, "broken.jsonl")
	writeFileT(t, brokenPath, chainJSONL(t, e1, e0))
	var out2, err2 bytes.Buffer
	if err := runAARP(&out2, &err2, brokenPath, aarpOptions{trustPath: trustPath, jsonOutput: true, chain: true}); err == nil {
		t.Fatal("broken chain accepted")
	}
}

func TestRunAARPChain_MalformedLine(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.jsonl")
	writeFileT(t, path, []byte("{not json}\n"))
	var out, errBuf bytes.Buffer
	if err := runAARP(&out, &errBuf, path, aarpOptions{jsonOutput: true, chain: true}); err == nil {
		t.Fatal("malformed chain line accepted")
	}
}

func TestLoadTrustFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	// Empty path → empty trust, no error.
	opts, err := loadTrustFile("")
	if err != nil || len(opts.TrustedKeys) != 0 {
		t.Fatalf("empty trust path: opts=%+v err=%v", opts, err)
	}

	// Valid file.
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	good := filepath.Join(dir, "good.json")
	writeFileT(t, good, mustJSON(t, map[string]any{
		"trusted_keys":  map[string]string{"k": hex.EncodeToString(pub)},
		"trust_entries": map[string]any{"k": map[string]string{"mediator_id": "m", "role": "mediator"}},
	}))
	opts, err = loadTrustFile(good)
	if err != nil {
		t.Fatalf("valid trust: %v", err)
	}
	if _, ok := opts.TrustedKeys["k"]; !ok {
		t.Error("trusted key not loaded")
	}
	if opts.Trust["k"].MediatorID != "m" {
		t.Error("trust entry not loaded")
	}

	// Bad hex.
	badHex := filepath.Join(dir, "badhex.json")
	writeFileT(t, badHex, mustJSON(t, map[string]any{"trusted_keys": map[string]string{"k": "zz"}}))
	if _, err := loadTrustFile(badHex); err == nil {
		t.Error("bad hex accepted")
	}

	// Wrong key size.
	badSize := filepath.Join(dir, "badsize.json")
	writeFileT(t, badSize, mustJSON(t, map[string]any{"trusted_keys": map[string]string{"k": "abcd"}}))
	if _, err := loadTrustFile(badSize); err == nil {
		t.Error("wrong-size key accepted")
	}

	// Unknown field rejected.
	unknown := filepath.Join(dir, "unknown.json")
	writeFileT(t, unknown, []byte(`{"trusted_keys":{},"bogus":1}`))
	if _, err := loadTrustFile(unknown); err == nil {
		t.Error("unknown field accepted")
	}

	// Missing file.
	if _, err := loadTrustFile(filepath.Join(dir, "nope.json")); err == nil {
		t.Error("missing trust file accepted")
	}
}

func assertExitCode(t *testing.T, err error, want int) {
	t.Helper()
	var ee *cliutil.ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("error %v is not an ExitError", err)
	}
	if ee.Code != want {
		t.Errorf("exit code = %d, want %d", ee.Code, want)
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func chainJSONL(t *testing.T, envs ...aarp.Envelope) []byte {
	t.Helper()
	var buf bytes.Buffer
	for _, e := range envs {
		b, err := aarp.Marshal(e)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		buf.Write(b)
		buf.WriteByte('\n')
	}
	return buf.Bytes()
}

func hex64(label string) string {
	h := strings.Repeat("0", 64)
	if len(label) > 0 {
		return label[:1] + h[1:]
	}
	return h
}
