// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package keys

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/license"
	domsigning "github.com/luckyPipewrench/pipelock/internal/signing"
)

// TestLicenseVerifyEmbeddedKey covers the embedded-build-key branch: when the
// build embeds a public key, it wins and the env/config override is ignored.
func TestLicenseVerifyEmbeddedKey(t *testing.T) {
	pub, _, err := domsigning.GenerateKeyPair()
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	original := license.PublicKeyHex
	license.PublicKeyHex = hex.EncodeToString(pub)
	t.Cleanup(func() { license.PublicKeyHex = original })

	cfg := config.Defaults()
	// Set a DIFFERENT override to prove embedded wins (override ignored).
	otherPub, _, err := domsigning.GenerateKeyPair()
	if err != nil {
		t.Fatalf("gen other key: %v", err)
	}
	cfg.LicensePublicKey = hex.EncodeToString(otherPub)

	report := buildKeyStatusReport(cfg, "(test)")
	item := findKey(t, report, purposeLicense)
	if !item.Present || !item.Valid {
		t.Fatalf("want embedded key present+valid, got %+v", item)
	}
	if item.Status != statusOK {
		t.Errorf("embedded key status = %q, want ok", item.Status)
	}
	wantFP, err := domsigning.Fingerprint(pub)
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}
	if item.Fingerprint != wantFP {
		t.Errorf("fingerprint = %q, want embedded key %q (override must be ignored)", item.Fingerprint, wantFP)
	}
	if !strings.Contains(item.Note, "embedded") {
		t.Errorf("note should mention embedded key, got %q", item.Note)
	}
}

// TestMultipleTrustedKeysNote covers the >1 trusted-key branch of the public
// key list reporter.
func TestMultipleTrustedKeysNote(t *testing.T) {
	pub1, _, err := domsigning.GenerateKeyPair()
	if err != nil {
		t.Fatalf("gen pub1: %v", err)
	}
	pub2, _, err := domsigning.GenerateKeyPair()
	if err != nil {
		t.Fatalf("gen pub2: %v", err)
	}
	cfg := config.Defaults()
	cfg.Rules.TrustedKeys = []config.TrustedKey{
		{Name: "a", PublicKey: hex.EncodeToString(pub1)},
		{Name: "b", PublicKey: hex.EncodeToString(pub2)},
	}
	report := buildKeyStatusReport(cfg, "(test)")
	item := findKey(t, report, "rules-official-signing")
	if !strings.Contains(item.Note, "2 trusted public keys") {
		t.Errorf("note should report 2 keys, got %q", item.Note)
	}
}

// TestRosterFingerprintOnly covers the branch where only a pinned fingerprint
// is set (no roster file path).
func TestRosterFingerprintOnly(t *testing.T) {
	cfg := config.Defaults()
	cfg.Conductor.TrustRosterRootFingerprint = "sha256:" + strings.Repeat("b", 64)
	report := buildKeyStatusReport(cfg, "(test)")
	item := findKey(t, report, "recovery-root")
	if item.Present {
		t.Errorf("no roster file: want present=false")
	}
	if item.Status != statusInfo {
		t.Errorf("status = %q, want info", item.Status)
	}
	if !strings.Contains(item.Note, "pinned by fingerprint") {
		t.Errorf("note should explain fingerprint pinning, got %q", item.Note)
	}
}

// TestPrinterWithColorAndPresentKey covers the color branch of the renderer and
// the present-key path (path + fingerprint lines).
func TestPrinterWithColorAndPresentKey(t *testing.T) {
	dir := t.TempDir()
	path, fp := writeValidPrivateKey(t, dir, "k.key")
	cfg := config.Defaults()
	cfg.FlightRecorder.SigningKeyPath = path
	report := buildKeyStatusReport(cfg, "(test)")

	cmd := &cobra.Command{}
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	printKeyStatusReport(cmd, report, true) // color on

	out := buf.String()
	if !strings.Contains(out, fp) {
		t.Errorf("colored output missing fingerprint")
	}
	if !strings.Contains(out, path) {
		t.Errorf("colored output missing path line")
	}
	if !strings.Contains(out, "\033[") {
		t.Errorf("color=true should emit ANSI escapes")
	}
}

// TestStatusTagAllBranches exercises every status tag in both modes.
func TestStatusTagAllBranches(t *testing.T) {
	for _, s := range []string{statusOK, statusWarn, statusFail, statusInfo} {
		s := s
		t.Run(s+"_plain", func(t *testing.T) {
			if got := statusTag(s, false); got != "["+strings.ToUpper(s)+"]" {
				t.Errorf("plain tag(%q) = %q", s, got)
			}
		})
		t.Run(s+"_color", func(t *testing.T) {
			if got := statusTag(s, true); !strings.Contains(got, "\033[") {
				t.Errorf("color tag(%q) = %q, want ANSI", s, got)
			}
		})
	}
}

// TestKeyTypeSuffix covers both branches.
func TestKeyTypeSuffix(t *testing.T) {
	if got := keyTypeSuffix(""); got != "" {
		t.Errorf("empty type suffix = %q, want empty", got)
	}
	if got := keyTypeSuffix(keyTypeEd25519); got != " type="+keyTypeEd25519 {
		t.Errorf("ed25519 suffix = %q", got)
	}
}

// TestStatusUnreadableRosterPath covers the roster path that exists in config
// but is not readable here (no fingerprint), exercising the final branch of
// finishRosterRef.
func TestStatusUnreadableRosterPath(t *testing.T) {
	cfg := config.Defaults()
	cfg.Conductor.TrustRosterPath = "/nonexistent/roster/path.json"
	report := buildKeyStatusReport(cfg, "(test)")
	item := findKey(t, report, "policy-bundle-signing")
	if item.Present {
		t.Errorf("nonexistent roster: want present=false")
	}
	if item.Status != statusInfo {
		t.Errorf("status = %q, want info", item.Status)
	}
	if !strings.Contains(item.Note, "not readable") {
		t.Errorf("note should mention unreadable roster, got %q", item.Note)
	}
}

// TestNonRegularKeyFile covers the not-a-regular-file branch (a directory at the
// configured key path).
func TestNonRegularKeyFile(t *testing.T) {
	dir := t.TempDir() // a directory, not a key file
	cfg := config.Defaults()
	cfg.FlightRecorder.SigningKeyPath = dir
	report := buildKeyStatusReport(cfg, "(test)")
	item := findKey(t, report, purposeReceipt)
	// A directory is not a regular file and should fail before attempting to
	// parse it as key material.
	if !item.Present {
		t.Errorf("directory exists: want present=true")
	}
	if item.Valid {
		t.Errorf("a directory must not be a valid key")
	}
	if item.Status != statusFail {
		t.Errorf("status = %q, want fail for a directory path", item.Status)
	}
	if !strings.Contains(item.Note, "not a regular file") {
		t.Errorf("note should explain non-regular path, got %q", item.Note)
	}
}
