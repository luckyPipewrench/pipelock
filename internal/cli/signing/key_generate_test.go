// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	domsigning "github.com/luckyPipewrench/pipelock/internal/signing"
)

func TestKeyGenerate_WritesValidKeyFile(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "fleet-root.json")

	cmd := keyGenerateCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--purpose", string(domsigning.PurposeRosterRoot), "--out", out})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	info, err := os.Stat(out)
	if err != nil {
		t.Fatalf("stat output: %v", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Errorf("output mode = %o, want 0o600 (group/world bits clear)", info.Mode().Perm())
	}
	if want := fs.FileMode(0o600); info.Mode().Perm() != want {
		t.Errorf("output mode = %o, want %o", info.Mode().Perm(), want)
	}

	raw, err := os.ReadFile(filepath.Clean(out))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var kf keyFile
	if err := json.Unmarshal(raw, &kf); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if kf.SchemaVersion != keyFileSchemaVersion {
		t.Errorf("schema_version = %d, want %d", kf.SchemaVersion, keyFileSchemaVersion)
	}
	if kf.Purpose != string(domsigning.PurposeRosterRoot) {
		t.Errorf("purpose = %q, want %q", kf.Purpose, domsigning.PurposeRosterRoot)
	}
	if !strings.HasPrefix(kf.KeyID, string(domsigning.PurposeRosterRoot)+"-") {
		t.Errorf("derived key_id %q missing purpose prefix", kf.KeyID)
	}
	pub, err := hex.DecodeString(kf.Public)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		t.Fatalf("public hex bad: err=%v len=%d", err, len(pub))
	}
	priv, err := hex.DecodeString(kf.Private)
	if err != nil || len(priv) != ed25519.PrivateKeySize {
		t.Fatalf("private hex bad: err=%v len=%d", err, len(priv))
	}
	if !bytes.Equal(ed25519.PrivateKey(priv).Public().(ed25519.PublicKey), ed25519.PublicKey(pub)) {
		t.Errorf("private key does not derive declared public key")
	}
	if kf.CreatedAt == "" {
		t.Errorf("created_at empty")
	}
}

func TestKeyGenerate_RejectsUnknownPurpose(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "x.json")

	cmd := keyGenerateCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--purpose", "bogus-purpose", "--out", out})
	err := cmd.Execute()
	if err == nil {
		t.Fatalf("expected unknown-purpose error")
	}
	if !errors.Is(err, domsigning.ErrUnknownKeyPurpose) {
		t.Errorf("err = %v, want ErrUnknownKeyPurpose", err)
	}
	if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
		t.Errorf("output file should not exist after error, statErr=%v", statErr)
	}
}

func TestKeyGenerate_RejectsRelativeOutPath(t *testing.T) {
	cmd := keyGenerateCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--purpose", string(domsigning.PurposeRosterRoot), "--out", "relative.json"})
	err := cmd.Execute()
	if err == nil {
		t.Fatalf("expected absolute-path error")
	}
	if !strings.Contains(err.Error(), "absolute") {
		t.Errorf("error %q does not mention absolute requirement", err.Error())
	}
}

func TestKeyGenerate_RefusesOverwriteWithoutForce(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "fleet-root.json")
	if err := os.WriteFile(out, []byte("preexisting"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	cmd := keyGenerateCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--purpose", string(domsigning.PurposeRosterRoot), "--out", out})
	err := cmd.Execute()
	if err == nil {
		t.Fatalf("expected refuse-overwrite error")
	}

	got, _ := os.ReadFile(filepath.Clean(out))
	if string(got) != "preexisting" {
		t.Errorf("file contents changed without --force, got %q", string(got))
	}
}

func TestKeyGenerate_AllowsOverwriteWithForce(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "fleet-root.json")
	if err := os.WriteFile(out, []byte("preexisting"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	cmd := keyGenerateCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--purpose", string(domsigning.PurposeRosterRoot), "--out", out, "--force"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	got, err := os.ReadFile(filepath.Clean(out))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if bytes.Equal(got, []byte("preexisting")) {
		t.Errorf("file contents not overwritten under --force")
	}
}

func TestKeyGenerate_HonoursExplicitID(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "act.json")

	cmd := keyGenerateCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{
		"--purpose", string(domsigning.PurposeContractActivationSigning),
		"--out", out,
		"--id", "activation-primary",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	raw, err := os.ReadFile(filepath.Clean(out))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var kf keyFile
	if err := json.Unmarshal(raw, &kf); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if kf.KeyID != "activation-primary" {
		t.Errorf("key_id = %q, want %q", kf.KeyID, "activation-primary")
	}
}

func TestLoadKeyFile_DetectsPurposeMismatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "k.json")

	gen := keyGenerateCmd()
	gen.SetOut(&bytes.Buffer{})
	gen.SetErr(&bytes.Buffer{})
	gen.SetArgs([]string{"--purpose", string(domsigning.PurposeRosterRoot), "--out", path})
	if err := gen.Execute(); err != nil {
		t.Fatalf("seed: %v", err)
	}

	_, _, _, err := loadKeyFile(path, domsigning.PurposeContractActivationSigning)
	if err == nil {
		t.Fatalf("expected purpose-mismatch error")
	}
	if !strings.Contains(err.Error(), "purpose mismatch") {
		t.Errorf("error %q does not name the mismatch", err.Error())
	}
}

func TestReadPublicKeyForRoster_AcceptsKeyFileJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "k.json")
	gen := keyGenerateCmd()
	gen.SetOut(&bytes.Buffer{})
	gen.SetErr(&bytes.Buffer{})
	gen.SetArgs([]string{"--purpose", string(domsigning.PurposeContractCompileSigning), "--out", path})
	if err := gen.Execute(); err != nil {
		t.Fatalf("seed: %v", err)
	}

	pub, purpose, err := readPublicKeyForRoster(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		t.Errorf("pub len = %d, want %d", len(pub), ed25519.PublicKeySize)
	}
	if purpose != string(domsigning.PurposeContractCompileSigning) {
		t.Errorf("purpose = %q, want %q", purpose, domsigning.PurposeContractCompileSigning)
	}
}

func TestReadPublicKeyForRoster_AcceptsAgentKeystorePub(t *testing.T) {
	dir := t.TempDir()
	pub, _, err := domsigning.GenerateKeyPair()
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	pubPath := filepath.Join(dir, "id_ed25519.pub")
	if err := domsigning.SavePublicKey(pub, pubPath); err != nil {
		t.Fatalf("save: %v", err)
	}

	got, purpose, err := readPublicKeyForRoster(pubPath)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, pub) {
		t.Errorf("public key bytes differ: got=%x want=%x", got, pub)
	}
	if purpose != "" {
		t.Errorf("purpose should be empty for agent keystore .pub, got %q", purpose)
	}
}
