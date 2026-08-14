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

func newResetAuthorityKey(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "reset-authority.json")
	cmd := keyGenerateCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--purpose", "mcp-reset-authority", "--out", path, "--id", "operator-primary"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("generate reset authority key: %v", err)
	}
	return path
}

func TestKeyExportPublicRejectsUnsafePathsAndWriteFailures(t *testing.T) {
	dir := t.TempDir()
	keyPath := newResetAuthorityKey(t, dir)

	tests := []struct {
		name string
		args []string
	}{
		{
			name: "relative key",
			args: []string{"--key", "relative.json", "--out", filepath.Join(dir, "public")},
		},
		{
			name: "relative output",
			args: []string{"--key", keyPath, "--out", "relative.pub"},
		},
		{
			name: "malformed key",
			args: func() []string {
				bad := filepath.Join(dir, "bad-key")
				if err := os.WriteFile(bad, []byte("not a key"), 0o600); err != nil {
					t.Fatal(err)
				}
				return []string{"--key", bad, "--out", filepath.Join(dir, "bad.pub")}
			}(),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cmd := keyExportPublicCmd()
			cmd.SetOut(&bytes.Buffer{})
			cmd.SetErr(&bytes.Buffer{})
			cmd.SetArgs(test.args)
			if err := cmd.Execute(); err == nil {
				t.Fatalf("export-public accepted %s", test.name)
			}
		})
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	relativeKey, err := filepath.Rel(cwd, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	cmd := keyExportPublicCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--key", relativeKey, "--out", filepath.Join(dir, "relative-key.pub")})
	if err := cmd.Execute(); err == nil {
		t.Fatal("export-public accepted an existing key via a relative path")
	}

	existing := filepath.Join(dir, "existing.pub")
	if err := os.WriteFile(existing, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd = keyExportPublicCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--key", keyPath, "--out", existing})
	if err := cmd.Execute(); err == nil {
		t.Fatal("export-public overwrote an existing file without --force")
	}
	if got, err := os.ReadFile(existing); err != nil || string(got) != "keep" { // #nosec G304 -- existing is inside t.TempDir.
		t.Fatalf("existing public key changed = %q, %v", got, err)
	}

	parent := filepath.Join(dir, "not-a-directory")
	if err := os.WriteFile(parent, []byte("file"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd = keyExportPublicCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--key", keyPath, "--out", filepath.Join(parent, "public")})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "stat output file") {
		t.Fatalf("export-public file-as-parent error = %v", err)
	}
}

func TestResetMintRejectsOperatorInputAndWriteFailures(t *testing.T) {
	dir := t.TempDir()
	keyPath := newResetAuthorityKey(t, dir)
	validArgs := []string{
		"--key", keyPath,
		"--kind", "drift",
		"--target", "mcp://fixture",
		"--instance", strings.Repeat("a", 32),
		"--epoch", "4",
		"--out", filepath.Join(dir, "delegation"),
	}

	tests := []struct {
		name string
		args []string
	}{
		{name: "relative key", args: []string{"--key", "relative", "--kind", "drift", "--target", "mcp://fixture", "--instance", strings.Repeat("a", 32), "--out", filepath.Join(dir, "out")}},
		{name: "zero ttl", args: append(append([]string(nil), validArgs...), "--ttl", "0s")},
		{name: "invalid kind", args: append(append([]string(nil), validArgs...), "--kind", "other")},
		{name: "ttl above authority limit", args: append(append([]string(nil), validArgs...), "--ttl", "16m")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cmd := resetMintCmd()
			cmd.SetOut(&bytes.Buffer{})
			cmd.SetErr(&bytes.Buffer{})
			cmd.SetArgs(test.args)
			if err := cmd.Execute(); err == nil {
				t.Fatalf("mint accepted %s", test.name)
			}
		})
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	relativeKey, err := filepath.Rel(cwd, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	cmd := resetMintCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{
		"--key", relativeKey,
		"--kind", "drift",
		"--target", "mcp://fixture",
		"--instance", strings.Repeat("a", 32),
		"--out", filepath.Join(dir, "relative-key-delegation"),
	})
	if err := cmd.Execute(); err == nil {
		t.Fatal("mint accepted an existing key via a relative path")
	}

	existing := filepath.Join(dir, "existing-delegation")
	if err := os.WriteFile(existing, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd = resetMintCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{
		"--key", keyPath, "--kind", "drift", "--target", "mcp://fixture", "--instance", strings.Repeat("a", 32), "--out", existing,
	})
	if err := cmd.Execute(); err == nil {
		t.Fatal("mint overwrote an existing delegation without --force")
	}
	if got, err := os.ReadFile(existing); err != nil || string(got) != "keep" { // #nosec G304 -- existing is inside t.TempDir.
		t.Fatalf("existing delegation changed = %q, %v", got, err)
	}

	parent := filepath.Join(dir, "not-a-directory")
	if err := os.WriteFile(parent, []byte("file"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd = resetMintCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{
		"--key", keyPath, "--kind", "drift", "--target", "mcp://fixture", "--instance", strings.Repeat("a", 32), "--out", filepath.Join(parent, "delegation"),
	})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "stat output file") {
		t.Fatalf("mint file-as-parent error = %v", err)
	}
}

func TestResetInspectAndRevokeRejectUntrustedFilesystemState(t *testing.T) {
	dir := t.TempDir()
	keyPath := newResetAuthorityKey(t, dir)
	publicPath := filepath.Join(dir, "authority.pub")
	export := keyExportPublicCmd()
	export.SetOut(&bytes.Buffer{})
	export.SetErr(&bytes.Buffer{})
	export.SetArgs([]string{"--key", keyPath, "--out", publicPath})
	if err := export.Execute(); err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name string
		file string
		key  string
	}{
		{name: "missing delegation", file: filepath.Join(dir, "missing"), key: publicPath},
		{name: "malformed public key", file: filepath.Join(dir, "missing"), key: filepath.Join(dir, "missing-key")},
		{name: "malformed delegation", file: filepath.Join(dir, "malformed"), key: publicPath},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.name == "malformed delegation" {
				if err := os.WriteFile(test.file, []byte("{bad"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			cmd := resetInspectCmd()
			cmd.SetOut(&bytes.Buffer{})
			cmd.SetErr(&bytes.Buffer{})
			cmd.SetArgs([]string{"--file", test.file, "--public-key-file", test.key})
			if err := cmd.Execute(); err == nil {
				t.Fatalf("inspect accepted %s", test.name)
			}
		})
	}

	for _, test := range []struct {
		name string
		path func(t *testing.T) string
	}{
		{name: "missing", path: func(t *testing.T) string { return filepath.Join(dir, "missing-reset") }},
		{name: "directory", path: func(t *testing.T) string { return dir }},
		{name: "symlink", path: func(t *testing.T) string {
			target := filepath.Join(dir, "target")
			if err := os.WriteFile(target, []byte("pending"), 0o600); err != nil {
				t.Fatal(err)
			}
			link := filepath.Join(dir, "reset-link")
			if err := os.Symlink(target, link); err != nil {
				t.Fatal(err)
			}
			return link
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			cmd := resetRevokeCmd()
			cmd.SetOut(&bytes.Buffer{})
			cmd.SetErr(&bytes.Buffer{})
			cmd.SetArgs([]string{"--file", test.path(t)})
			if err := cmd.Execute(); err == nil {
				t.Fatalf("revoke accepted %s path", test.name)
			}
		})
	}
}
