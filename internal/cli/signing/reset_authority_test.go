// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResetAuthorityCommandsMintInspectAndCancel(t *testing.T) {
	dir := t.TempDir()
	privatePath := filepath.Join(dir, "reset-authority.json")
	publicPath := filepath.Join(dir, "reset-authority.pub")
	delegationPath := filepath.Join(dir, "delegation.json")

	generate := keyGenerateCmd()
	generate.SetOut(&bytes.Buffer{})
	generate.SetErr(&bytes.Buffer{})
	generate.SetArgs([]string{"--purpose", "mcp-reset-authority", "--out", privatePath, "--id", "operator-primary"})
	if err := generate.Execute(); err != nil {
		t.Fatalf("generate reset authority key: %v", err)
	}

	var exported bytes.Buffer
	export := keyExportPublicCmd()
	export.SetOut(&exported)
	export.SetErr(&bytes.Buffer{})
	export.SetArgs([]string{"--key", privatePath, "--out", publicPath})
	if err := export.Execute(); err != nil {
		t.Fatalf("export reset authority public key: %v", err)
	}
	if !strings.Contains(exported.String(), "fingerprint:") {
		t.Fatalf("export output missing fingerprint: %q", exported.String())
	}
	if info, err := os.Stat(publicPath); err != nil || info.Mode().Perm() != resetAuthorityPublicKeyMode {
		t.Fatalf("public key mode = %v, err=%v, want %o", info.Mode(), err, resetAuthorityPublicKeyMode)
	}

	var minted bytes.Buffer
	mint := resetMintCmd()
	mint.SetOut(&minted)
	mint.SetErr(&bytes.Buffer{})
	mint.SetArgs([]string{
		"--key", privatePath,
		"--kind", "drift",
		"--target", "mcp://fixture-listener",
		"--instance", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"--epoch", "7",
		"--ttl", "1m",
		"--out", delegationPath,
	})
	if err := mint.Execute(); err != nil {
		t.Fatalf("mint reset delegation: %v", err)
	}
	if !strings.Contains(minted.String(), "Minted MCP reset delegation") {
		t.Fatalf("mint output = %q", minted.String())
	}

	var inspected bytes.Buffer
	inspect := resetInspectCmd()
	inspect.SetOut(&inspected)
	inspect.SetErr(&bytes.Buffer{})
	inspect.SetArgs([]string{"--file", delegationPath, "--public-key-file", publicPath})
	if err := inspect.Execute(); err != nil {
		t.Fatalf("inspect reset delegation: %v", err)
	}
	if !strings.Contains(inspected.String(), "MCP reset delegation verified") {
		t.Fatalf("inspect output = %q", inspected.String())
	}

	revoke := resetRevokeCmd()
	revoke.SetOut(&bytes.Buffer{})
	revoke.SetErr(&bytes.Buffer{})
	revoke.SetArgs([]string{"--file", delegationPath})
	if err := revoke.Execute(); err != nil {
		t.Fatalf("cancel pending reset delegation: %v", err)
	}
	if _, err := os.Lstat(delegationPath); !os.IsNotExist(err) {
		t.Fatalf("delegation remained after cancel: %v", err)
	}
}

func TestResetMintRejectsWrongPurposeKey(t *testing.T) {
	dir := t.TempDir()
	privatePath := filepath.Join(dir, "receipt.json")
	outPath := filepath.Join(dir, "delegation.json")
	generate := keyGenerateCmd()
	generate.SetOut(&bytes.Buffer{})
	generate.SetErr(&bytes.Buffer{})
	generate.SetArgs([]string{"--purpose", "receipt-signing", "--out", privatePath})
	if err := generate.Execute(); err != nil {
		t.Fatal(err)
	}
	mint := resetMintCmd()
	mint.SetOut(&bytes.Buffer{})
	mint.SetErr(&bytes.Buffer{})
	mint.SetArgs([]string{
		"--key", privatePath,
		"--kind", "adaptive",
		"--target", "mcp://stdio/fixture",
		"--instance", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		"--out", outPath,
	})
	err := mint.Execute()
	if err == nil || !strings.Contains(err.Error(), "purpose mismatch") {
		t.Fatalf("wrong-purpose mint error = %v", err)
	}
	if _, err := os.Lstat(outPath); !os.IsNotExist(err) {
		t.Fatalf("mint wrote a delegation with the wrong key purpose: %v", err)
	}
}
