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
