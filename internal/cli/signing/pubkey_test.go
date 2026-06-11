// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
	domsigning "github.com/luckyPipewrench/pipelock/internal/signing"
)

func TestPubkeyCmd_KeyFilePrintsPublicOnly(t *testing.T) {
	t.Parallel()

	keyPath, pubHex, priv := writeRecorderSigningKey(t)

	cmd := signingPubkeyTestRoot()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"signing", "pubkey", "--key-file", keyPath})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute(): %v", err)
	}

	got := strings.TrimSpace(out.String())
	if got != pubHex {
		t.Fatalf("output = %q, want %q", got, pubHex)
	}
	if strings.Contains(out.String(), hex.EncodeToString(priv)) {
		t.Fatal("output contains private key hex")
	}
	if strings.Contains(out.String(), base64.StdEncoding.EncodeToString(priv)) {
		t.Fatal("output contains private key base64")
	}
}

func TestPubkeyCmd_ConfigAndDefaultDiscovery(t *testing.T) {
	keyPath, pubHex, _ := writeRecorderSigningKey(t)
	cfgPath := writeRecorderConfig(t, keyPath)

	for _, tc := range []struct {
		name string
		args []string
		env  bool
	}{
		{name: "explicit_config", args: []string{"signing", "pubkey", "--config", cfgPath}},
		{name: "discovered_config", args: []string{"signing", "pubkey"}, env: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.env {
				t.Setenv("PIPELOCK_CONFIG", cfgPath)
			} else {
				t.Setenv("PIPELOCK_CONFIG", "")
			}

			cmd := signingPubkeyTestRoot()
			var out bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetArgs(tc.args)
			if err := cmd.Execute(); err != nil {
				t.Fatalf("Execute(): %v", err)
			}
			if got := strings.TrimSpace(out.String()); got != pubHex {
				t.Fatalf("output = %q, want %q", got, pubHex)
			}
		})
	}
}

func TestPubkeyCmd_OutWritesPublicKeyFile0640(t *testing.T) {
	t.Parallel()

	keyPath, pubHex, _ := writeRecorderSigningKey(t)
	outPath := filepath.Join(t.TempDir(), "flight-recorder-signing.key.pub")

	cmd := signingPubkeyTestRoot()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"signing", "pubkey", "--key-file", keyPath, "--out", outPath})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute(): %v", err)
	}
	if got := strings.TrimSpace(out.String()); got != pubHex {
		t.Fatalf("stdout = %q, want %q", got, pubHex)
	}
	raw, err := os.ReadFile(filepath.Clean(outPath))
	if err != nil {
		t.Fatalf("read out file: %v", err)
	}
	if got := string(raw); got != pubHex+"\n" {
		t.Fatalf("out file = %q, want %q", got, pubHex+"\n")
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(outPath)
		if err != nil {
			t.Fatalf("stat out file: %v", err)
		}
		if got := info.Mode().Perm(); got != recorderPublicKeyFileMode {
			t.Fatalf("out mode = %s, want %s", got, recorderPublicKeyFileMode)
		}
	}
}

func TestPubkeyCmd_RejectsPublicKeyFileAsKeyFile(t *testing.T) {
	t.Parallel()

	pub, _, err := domsigning.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair(): %v", err)
	}
	path := filepath.Join(t.TempDir(), "public.key")
	if err := domsigning.SavePublicKey(pub, path); err != nil {
		t.Fatalf("SavePublicKey(): %v", err)
	}

	cmd := signingPubkeyTestRoot()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"signing", "pubkey", "--key-file", path})
	err = cmd.Execute()
	if err == nil {
		t.Fatal("expected public-key-as-private-key error")
	}
	if !strings.Contains(err.Error(), "contains a public key") {
		t.Fatalf("error = %v, want public-key diagnostic", err)
	}
}

func TestPubkeyCmd_RejectsMutuallyExclusiveInputs(t *testing.T) {
	_, err := resolveRecorderSigningKeyPath("key", "config")
	if err == nil {
		t.Fatal("expected mutually exclusive input error")
	}
	if !strings.Contains(err.Error(), "not both") {
		t.Fatalf("error = %v, want mutually exclusive diagnostic", err)
	}
}

func TestPubkeyCmd_NoDiscoveredConfigFailsClosed(t *testing.T) {
	t.Setenv("PIPELOCK_CONFIG", "")
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(t.TempDir(), "xdg"))
	t.Setenv("HOME", t.TempDir())

	_, err := resolveRecorderSigningKeyPath("", "")
	if err == nil {
		t.Fatal("expected missing config error")
	}
	if strings.Contains(err.Error(), "/etc/pipelock/pipelock.yaml") {
		t.Skip("system pipelock config is installed; cannot force config discovery miss")
	}
	if !strings.Contains(err.Error(), "no pipelock config found") {
		t.Fatalf("error = %v, want no config diagnostic", err)
	}
}

func TestPubkeyCmd_ConfigLoadErrorIncludesPath(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "missing.yaml")

	_, err := resolveRecorderSigningKeyPath("", cfgPath)
	if err == nil {
		t.Fatal("expected config load error")
	}
	if !strings.Contains(err.Error(), cfgPath) {
		t.Fatalf("error = %v, want config path", err)
	}
}

func TestPubkeyCmd_RejectsInvalidDerivedPublicKey(t *testing.T) {
	err := writeRecorderPublicKeyHex(filepath.Join(t.TempDir(), "out.pub"), "not-hex")
	if err == nil {
		t.Fatal("expected invalid derived public key error")
	}
	if !strings.Contains(err.Error(), "invalid derived public key") {
		t.Fatalf("error = %v, want invalid derived public key", err)
	}
}

func TestPubkeyCmd_OutWriteErrorFailsClosed(t *testing.T) {
	t.Parallel()

	_, pubHex, _ := writeRecorderSigningKey(t)
	outPath := filepath.Join(t.TempDir(), "out.pub")
	if err := os.Mkdir(outPath, 0o750); err != nil {
		t.Fatalf("mkdir out path: %v", err)
	}

	err := writeRecorderPublicKeyHex(outPath, pubHex)
	if err == nil {
		t.Fatal("expected write failure")
	}
	if !strings.Contains(err.Error(), "write public key") {
		t.Fatalf("error = %v, want write public key diagnostic", err)
	}
}

func TestPubkeyCmd_DeriveRejectsNonPublicInvalidFile(t *testing.T) {
	t.Parallel()

	keyPath := filepath.Join(t.TempDir(), "not-a-key")
	if err := os.WriteFile(keyPath, []byte("not a private or public key"), 0o600); err != nil {
		t.Fatalf("write invalid key file: %v", err)
	}

	_, err := deriveRecorderPublicKeyHexFromPrivateFile(keyPath)
	if err == nil {
		t.Fatal("expected invalid private key error")
	}
	if strings.Contains(err.Error(), "contains a public key") {
		t.Fatalf("error = %v, should not classify junk as public key", err)
	}
	if !strings.Contains(err.Error(), "load private signing key") {
		t.Fatalf("error = %v, want private key load diagnostic", err)
	}
}

func TestPubkeyCmd_ExportedKeyMatchesReceiptSignerKey(t *testing.T) {
	t.Parallel()

	keyPath, _, priv := writeRecorderSigningKey(t)

	exported, err := deriveRecorderPublicKeyHexFromPrivateFile(keyPath)
	if err != nil {
		t.Fatalf("deriveRecorderPublicKeyHexFromPrivateFile(): %v", err)
	}
	r, err := receipt.Sign(receipt.ActionRecord{
		Version:         receipt.ActionRecordVersion,
		ActionID:        receipt.NewActionID(),
		ActionType:      receipt.ActionRead,
		Timestamp:       time.Now().UTC(),
		Target:          "https://example.com/data",
		Verdict:         "allow",
		Transport:       "fetch",
		SideEffectClass: receipt.SideEffectExternalRead,
		Reversibility:   receipt.ReversibilityFull,
	}, priv)
	if err != nil {
		t.Fatalf("receipt.Sign(): %v", err)
	}
	if r.SignerKey != exported {
		t.Fatalf("receipt signer_key = %q, exported = %q", r.SignerKey, exported)
	}
}

func TestPubkeyCmd_ConfigWithoutSigningKeyFailsClosed(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "pipelock.yaml")
	if err := os.WriteFile(cfgPath, []byte("mode: balanced\nflight_recorder:\n  enabled: true\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cmd := signingPubkeyTestRoot()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"signing", "pubkey", "--config", cfgPath})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected missing signing key path error")
	}
	if !strings.Contains(err.Error(), "flight_recorder.signing_key_path") {
		t.Fatalf("error = %v, want signing key path diagnostic", err)
	}
}

func signingPubkeyTestRoot() *cobra.Command {
	root := &cobra.Command{
		Use:           "pipelock",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(SigningSubtreeCmd())
	return root
}

func writeRecorderSigningKey(t *testing.T) (string, string, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := domsigning.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair(): %v", err)
	}
	keyPath := filepath.Join(t.TempDir(), "flight-recorder-signing.key")
	if err := domsigning.SavePrivateKey(priv, keyPath); err != nil {
		t.Fatalf("SavePrivateKey(): %v", err)
	}
	return keyPath, hex.EncodeToString(pub), priv
}

func writeRecorderConfig(t *testing.T, keyPath string) string {
	t.Helper()
	cfgPath := filepath.Join(t.TempDir(), "pipelock.yaml")
	body := "mode: balanced\nflight_recorder:\n  enabled: true\n  dir: " + filepath.Join(t.TempDir(), "recorder") + "\n  signing_key_path: " + keyPath + "\n"
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return cfgPath
}
