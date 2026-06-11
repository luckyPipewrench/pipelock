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

func TestKeyGenerate_AcceptsConductorPurposes(t *testing.T) {
	dir := t.TempDir()
	for _, purpose := range []domsigning.KeyPurpose{
		domsigning.PurposePolicyBundleSigning,
		domsigning.PurposePolicyBundleRollback,
		domsigning.PurposeRemoteKillSigning,
		domsigning.PurposeTrustRootRotation,
		domsigning.PurposeAuditBatchSigning,
		domsigning.PurposeEnrollmentTokenSigning,
	} {
		t.Run(purpose.String(), func(t *testing.T) {
			out := filepath.Join(dir, purpose.String()+".json")
			var stdout bytes.Buffer
			cmd := keyGenerateCmd()
			cmd.SetOut(&stdout)
			cmd.SetErr(&bytes.Buffer{})
			cmd.SetArgs([]string{"--purpose", purpose.String(), "--out", out})
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
			if kf.Purpose != purpose.String() {
				t.Errorf("purpose = %q, want %q", kf.Purpose, purpose)
			}
			gotWarning := strings.Contains(stdout.String(), "threshold:")
			if gotWarning != purpose.RequiresConductorThreshold() {
				t.Errorf("threshold warning present = %v, want %v; output:\n%s",
					gotWarning, purpose.RequiresConductorThreshold(), stdout.String())
			}
			gotReserved := strings.Contains(stdout.String(), "reserved purpose")
			if gotReserved != isReservedConductorKeyPurpose(purpose) {
				t.Errorf("reserved warning present = %v, want %v; output:\n%s",
					gotReserved, isReservedConductorKeyPurpose(purpose), stdout.String())
			}
		})
	}
}

func TestKeyGenerate_HelpListsConductorPurposes(t *testing.T) {
	cmd := keyGenerateCmd()
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--help"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("help: %v", err)
	}

	help := stdout.String()
	for _, purpose := range []domsigning.KeyPurpose{
		domsigning.PurposePolicyBundleSigning,
		domsigning.PurposePolicyBundleRollback,
		domsigning.PurposeRemoteKillSigning,
		domsigning.PurposeTrustRootRotation,
		domsigning.PurposeAuditBatchSigning,
		domsigning.PurposeEnrollmentTokenSigning,
	} {
		if !strings.Contains(help, purpose.String()) {
			t.Errorf("help missing %q:\n%s", purpose, help)
		}
	}
	if !strings.Contains(help, "threshold") {
		t.Errorf("help missing threshold guidance:\n%s", help)
	}
	if !strings.Contains(help, "reserved") {
		t.Errorf("help missing reserved-purpose guidance:\n%s", help)
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

func TestLoadKeyFile_RejectsMismatchedPrivatePublic(t *testing.T) {
	dir := t.TempDir()
	rootPath := filepath.Join(dir, "root.json")
	otherPath := filepath.Join(dir, "other.json")

	for _, e := range []struct {
		purpose string
		out     string
	}{
		{string(domsigning.PurposeRosterRoot), rootPath},
		{string(domsigning.PurposeContractActivationSigning), otherPath},
	} {
		cmd := keyGenerateCmd()
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		cmd.SetArgs([]string{"--purpose", e.purpose, "--out", e.out})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("seed %s: %v", e.purpose, err)
		}
	}

	rootRaw, err := os.ReadFile(filepath.Clean(rootPath))
	if err != nil {
		t.Fatalf("read root: %v", err)
	}
	otherRaw, err := os.ReadFile(filepath.Clean(otherPath))
	if err != nil {
		t.Fatalf("read other: %v", err)
	}
	var rootKF keyFile
	if err := json.Unmarshal(rootRaw, &rootKF); err != nil {
		t.Fatalf("unmarshal root: %v", err)
	}
	var otherKF keyFile
	if err := json.Unmarshal(otherRaw, &otherKF); err != nil {
		t.Fatalf("unmarshal other: %v", err)
	}
	rootKF.Public = otherKF.Public
	tampered, err := json.Marshal(rootKF)
	if err != nil {
		t.Fatalf("marshal tampered: %v", err)
	}
	if err := os.WriteFile(rootPath, tampered, 0o600); err != nil {
		t.Fatalf("write tampered: %v", err)
	}

	_, _, _, err = loadKeyFile(rootPath, domsigning.PurposeRosterRoot)
	if err == nil {
		t.Fatalf("expected public/private mismatch error")
	}
	if !strings.Contains(err.Error(), "does not match public key") {
		t.Errorf("err %q does not mention public/private mismatch", err.Error())
	}
}

func TestLoadKeyFile_RejectsTrailingJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "k.json")

	gen := keyGenerateCmd()
	gen.SetOut(&bytes.Buffer{})
	gen.SetErr(&bytes.Buffer{})
	gen.SetArgs([]string{"--purpose", string(domsigning.PurposeRosterRoot), "--out", path})
	if err := gen.Execute(); err != nil {
		t.Fatalf("seed: %v", err)
	}
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	raw = append(raw, []byte("\n{}")...)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write trailing: %v", err)
	}

	_, _, _, err = loadKeyFile(path, domsigning.PurposeRosterRoot)
	if err == nil {
		t.Fatalf("expected trailing-json error")
	}
	if !strings.Contains(err.Error(), "trailing JSON") {
		t.Errorf("err %q does not mention trailing JSON", err.Error())
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

func TestReadPublicKeyForRoster_RejectsUnsupportedKeyFileSchema(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "k.json")
	gen := keyGenerateCmd()
	gen.SetOut(&bytes.Buffer{})
	gen.SetErr(&bytes.Buffer{})
	gen.SetArgs([]string{"--purpose", string(domsigning.PurposeContractCompileSigning), "--out", path})
	if err := gen.Execute(); err != nil {
		t.Fatalf("seed: %v", err)
	}

	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var kf keyFile
	if err := json.Unmarshal(raw, &kf); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	kf.SchemaVersion = keyFileSchemaVersion + 1
	tampered, err := json.Marshal(kf)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, _, err = readPublicKeyForRoster(path)
	if err == nil {
		t.Fatalf("expected unsupported-schema error")
	}
	if !strings.Contains(err.Error(), "unsupported key file schema_version") {
		t.Errorf("err %q does not mention schema version", err.Error())
	}
}

func TestReadPublicKeyForRoster_RejectsJSONKeyFileWithMismatchedPriv(t *testing.T) {
	dir := t.TempDir()
	rootPath := filepath.Join(dir, "root.json")
	otherPath := filepath.Join(dir, "other.json")

	for _, e := range []struct {
		purpose string
		out     string
	}{
		{string(domsigning.PurposeContractCompileSigning), rootPath},
		{string(domsigning.PurposeContractCompileSigning), otherPath},
	} {
		gen := keyGenerateCmd()
		gen.SetOut(&bytes.Buffer{})
		gen.SetErr(&bytes.Buffer{})
		gen.SetArgs([]string{"--purpose", e.purpose, "--out", e.out, "--id", filepath.Base(e.out)})
		if err := gen.Execute(); err != nil {
			t.Fatalf("seed %s: %v", e.out, err)
		}
	}

	rootRaw, err := os.ReadFile(filepath.Clean(rootPath))
	if err != nil {
		t.Fatalf("read root: %v", err)
	}
	otherRaw, err := os.ReadFile(filepath.Clean(otherPath))
	if err != nil {
		t.Fatalf("read other: %v", err)
	}
	var rootKF, otherKF keyFile
	if err := json.Unmarshal(rootRaw, &rootKF); err != nil {
		t.Fatalf("unmarshal root: %v", err)
	}
	if err := json.Unmarshal(otherRaw, &otherKF); err != nil {
		t.Fatalf("unmarshal other: %v", err)
	}
	rootKF.Public = otherKF.Public
	tampered, err := json.Marshal(rootKF)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(rootPath, tampered, 0o600); err != nil {
		t.Fatalf("write tampered: %v", err)
	}

	_, _, err = readPublicKeyForRoster(rootPath)
	if err == nil {
		t.Fatalf("expected mismatched-keypair rejection on JSON include path")
	}
	if !strings.Contains(err.Error(), "private") || !strings.Contains(err.Error(), "public") {
		t.Errorf("err %q does not name the priv/pub mismatch", err.Error())
	}
}

func TestReadKeyFileBytes_RejectsNonRegularFile(t *testing.T) {
	// Directory is the most portable non-regular file; FIFOs require mkfifo
	// which is platform-specific. Both fail the IsRegular() gate identically.
	dir := t.TempDir()
	_, err := ReadKeyFileBytes(dir, false)
	if err == nil {
		t.Fatalf("expected non-regular-file rejection on directory")
	}
	if !strings.Contains(err.Error(), "regular file") {
		t.Errorf("err %q does not mention regular file", err.Error())
	}
}

func TestReadKeyFileBytes_RejectsSymlink(t *testing.T) {
	// os.Open follows symlinks, so without the explicit Lstat reject a symlink
	// pointing at a real 0600 key file would be silently accepted (the f.Stat
	// gates check the TARGET). Reject the symlink at the path itself.
	dir := t.TempDir()
	realPath := filepath.Join(dir, "real-key.json")
	if err := os.WriteFile(realPath, []byte("{}"), 0o600); err != nil {
		t.Fatalf("write real key: %v", err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(realPath, link); err != nil {
		t.Skipf("symlink unsupported on this platform: %v", err)
	}
	_, err := ReadKeyFileBytes(link, true)
	if err == nil {
		t.Fatalf("expected symlink rejection")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("err %q does not mention symlink", err.Error())
	}
}

func TestReadKeyFileBytes_RejectsLoosePermissions(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		mode os.FileMode
	}{
		{name: "group write", mode: 0o620},
		{name: "world read", mode: 0o604},
		{name: "world writable", mode: 0o666},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "key.json")
			if err := os.WriteFile(path, []byte("{}"), tc.mode); err != nil {
				t.Fatalf("write key: %v", err)
			}
			if err := os.Chmod(path, tc.mode); err != nil {
				t.Fatalf("chmod key: %v", err)
			}
			_, err := ReadKeyFileBytes(path, true)
			if err == nil {
				t.Fatalf("readKeyFileBytes accepted mode %04o", tc.mode)
			}
			if !strings.Contains(err.Error(), "permissions") {
				t.Fatalf("err = %v, want permissions rejection", err)
			}
		})
	}
}

func TestReadKeyFileBytes_AcceptsGroupReadPermissions(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "key.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	if err := os.Chmod(path, 0o640); err != nil { //nolint:gosec // test intentionally verifies k8s fsGroup-style 0640 is accepted.
		t.Fatalf("chmod key: %v", err)
	}
	raw, err := ReadKeyFileBytes(path, true)
	if err != nil {
		t.Fatalf("readKeyFileBytes should accept 0640: %v", err)
	}
	if string(raw) != "{}" {
		t.Fatalf("raw = %q, want {}", raw)
	}
}

func TestReadKeyFileBytes_RejectsOversizedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "big.json")
	// Slightly above the cap; the LimitReader path also catches grows-after-stat.
	big := bytes.Repeat([]byte("x"), keyFileMaxSize+10)
	if err := os.WriteFile(path, big, 0o600); err != nil {
		t.Fatalf("write big: %v", err)
	}
	_, err := ReadKeyFileBytes(path, false)
	if err == nil {
		t.Fatalf("expected oversize rejection")
	}
	if !errors.Is(err, errKeyFileTooLarge) {
		t.Errorf("err = %v, want errKeyFileTooLarge", err)
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
