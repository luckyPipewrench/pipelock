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

func TestTLSInitCmd(t *testing.T) {
	dir := t.TempDir()
	cmd := TlsInitCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--out", dir})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("tls init: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "ca.pem")); err != nil {
		t.Error("ca.pem not created")
	}
	if _, err := os.Stat(filepath.Join(dir, "ca-key.pem")); err != nil {
		t.Error("ca-key.pem not created")
	}
	if !bytes.Contains(buf.Bytes(), []byte("CA certificate:")) {
		t.Error("output missing certificate path")
	}
}

func TestTLSInitCmd_RefusesOverwrite(t *testing.T) {
	dir := t.TempDir()

	cmd1 := TlsInitCmd()
	cmd1.SetOut(&bytes.Buffer{})
	cmd1.SetErr(&bytes.Buffer{})
	cmd1.SetArgs([]string{"--out", dir})
	if err := cmd1.Execute(); err != nil {
		t.Fatalf("first init: %v", err)
	}

	cmd2 := TlsInitCmd()
	cmd2.SetOut(&bytes.Buffer{})
	cmd2.SetErr(&bytes.Buffer{})
	cmd2.SetArgs([]string{"--out", dir})
	err := cmd2.Execute()
	if err == nil {
		t.Error("expected error on overwrite without --force")
	}
}

func TestTLSInitCmd_ForceOverwrite(t *testing.T) {
	dir := t.TempDir()

	cmd1 := TlsInitCmd()
	cmd1.SetOut(&bytes.Buffer{})
	cmd1.SetErr(&bytes.Buffer{})
	cmd1.SetArgs([]string{"--out", dir})
	if err := cmd1.Execute(); err != nil {
		t.Fatalf("first init: %v", err)
	}

	cmd2 := TlsInitCmd()
	cmd2.SetOut(&bytes.Buffer{})
	cmd2.SetErr(&bytes.Buffer{})
	cmd2.SetArgs([]string{"--out", dir, "--force"})
	if err := cmd2.Execute(); err != nil {
		t.Fatalf("tls init --force: %v", err)
	}
}

func TestTLSShowCACmd(t *testing.T) {
	dir := t.TempDir()
	initCmd := TlsInitCmd()
	initCmd.SetOut(&bytes.Buffer{})
	initCmd.SetErr(&bytes.Buffer{})
	initCmd.SetArgs([]string{"--out", dir})
	if err := initCmd.Execute(); err != nil {
		t.Fatalf("init: %v", err)
	}

	buf := &bytes.Buffer{}
	showCmd := TlsShowCACmd()
	showCmd.SetOut(buf)
	showCmd.SetErr(&bytes.Buffer{})
	showCmd.SetArgs([]string{"--cert", filepath.Join(dir, "ca.pem")})
	if err := showCmd.Execute(); err != nil {
		t.Fatalf("tls show-ca: %v", err)
	}
	if !bytes.Contains(buf.Bytes(), []byte("BEGIN CERTIFICATE")) {
		t.Error("output does not contain PEM certificate")
	}
}

func TestTLSInstallCACmd(t *testing.T) {
	dir := t.TempDir()
	initCmd := TlsInitCmd()
	initCmd.SetOut(&bytes.Buffer{})
	initCmd.SetErr(&bytes.Buffer{})
	initCmd.SetArgs([]string{"--out", dir})
	if err := initCmd.Execute(); err != nil {
		t.Fatalf("init: %v", err)
	}

	buf := &bytes.Buffer{}
	installCmd := TlsInstallCACmd()
	installCmd.SetOut(buf)
	installCmd.SetErr(&bytes.Buffer{})
	installCmd.SetArgs([]string{"--cert", filepath.Join(dir, "ca.pem")})
	if err := installCmd.Execute(); err != nil {
		t.Fatalf("tls install-ca: %v", err)
	}
	// Should contain platform-specific instructions.
	if buf.Len() == 0 {
		t.Error("install-ca produced no output")
	}
}

func TestTLSInitCmd_InvalidValidity(t *testing.T) {
	cmd := TlsInitCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--validity", "not-a-duration", "--out", t.TempDir()})
	err := cmd.Execute()
	if err == nil {
		t.Error("expected error for invalid validity")
	}
}

func TestTLSShowCACmd_MissingFile(t *testing.T) {
	cmd := TlsShowCACmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--cert", "/nonexistent/ca.pem"})
	err := cmd.Execute()
	if err == nil {
		t.Error("expected error for missing cert file")
	}
}

func TestTLSInitCmd_ForceOverwrite_ContentChanged(t *testing.T) {
	dir := t.TempDir()

	// First init: generate CA.
	cmd1 := TlsInitCmd()
	cmd1.SetOut(&bytes.Buffer{})
	cmd1.SetErr(&bytes.Buffer{})
	cmd1.SetArgs([]string{"--out", dir})
	if err := cmd1.Execute(); err != nil {
		t.Fatalf("first init: %v", err)
	}

	certFile := filepath.Join(dir, "ca.pem")
	origCert, err := os.ReadFile(filepath.Clean(certFile))
	if err != nil {
		t.Fatalf("read original cert: %v", err)
	}

	// Force overwrite: should succeed and produce different cert.
	buf := &bytes.Buffer{}
	cmd2 := TlsInitCmd()
	cmd2.SetOut(buf)
	cmd2.SetErr(&bytes.Buffer{})
	cmd2.SetArgs([]string{"--out", dir, "--force"})
	if err := cmd2.Execute(); err != nil {
		t.Fatalf("tls init --force: %v", err)
	}

	newCert, err := os.ReadFile(filepath.Clean(certFile))
	if err != nil {
		t.Fatalf("read new cert: %v", err)
	}

	if bytes.Equal(origCert, newCert) {
		t.Error("--force should generate a new CA, but cert content is identical")
	}

	// Verify output still contains expected messages.
	output := buf.String()
	if !bytes.Contains([]byte(output), []byte("CA certificate:")) {
		t.Error("force output missing certificate path")
	}
	if !bytes.Contains([]byte(output), []byte("CA private key:")) {
		t.Error("force output missing key path")
	}
	if !bytes.Contains([]byte(output), []byte("install-ca")) {
		t.Error("force output missing next-step hint")
	}
}

func TestTLSInstallCACmd_OutputContent(t *testing.T) {
	dir := t.TempDir()
	initCmd := TlsInitCmd()
	initCmd.SetOut(&bytes.Buffer{})
	initCmd.SetErr(&bytes.Buffer{})
	initCmd.SetArgs([]string{"--out", dir})
	if err := initCmd.Execute(); err != nil {
		t.Fatalf("init: %v", err)
	}

	buf := &bytes.Buffer{}
	installCmd := TlsInstallCACmd()
	installCmd.SetOut(buf)
	installCmd.SetErr(&bytes.Buffer{})
	installCmd.SetArgs([]string{"--cert", filepath.Join(dir, "ca.pem")})
	if err := installCmd.Execute(); err != nil {
		t.Fatalf("tls install-ca: %v", err)
	}

	output := buf.String()
	// Should contain the cert path in the platform-specific instructions.
	certPath := filepath.Join(dir, "ca.pem")
	if !bytes.Contains([]byte(output), []byte(certPath)) {
		t.Errorf("install-ca output should reference cert path %s, got: %s", certPath, output)
	}
	// Should contain platform-specific install instructions (at least one keyword).
	if !bytes.Contains([]byte(output), []byte("Installing CA certificate")) {
		t.Error("install-ca output missing platform header")
	}
}

func TestTLSInstallCACmd_MissingCert(t *testing.T) {
	installCmd := TlsInstallCACmd()
	installCmd.SetOut(&bytes.Buffer{})
	installCmd.SetErr(&bytes.Buffer{})
	installCmd.SetArgs([]string{"--cert", "/nonexistent/path/ca.pem"})
	err := installCmd.Execute()
	if err == nil {
		t.Fatal("expected error for nonexistent cert file")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected 'not found' in error, got: %v", err)
	}
}

func TestTLSInitCmd_DefaultPath(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home) // Windows: os.UserHomeDir reads %USERPROFILE%

	cmd := TlsInitCmd()
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(&bytes.Buffer{})
	// No --out flag: uses DefaultKeystorePath ($HOME/.pipelock).
	cmd.SetArgs([]string{})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("tls init (default path): %v", err)
	}

	expected := filepath.Join(home, ".pipelock", "ca.pem")
	if _, err := os.Stat(expected); err != nil {
		t.Errorf("CA cert not created at default path %s: %v", expected, err)
	}
	if !bytes.Contains(buf.Bytes(), []byte(expected)) {
		t.Errorf("output should reference default cert path %s", expected)
	}
}

func TestTLSShowCACmd_DefaultPath(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home) // Windows: os.UserHomeDir reads %USERPROFILE%

	// First generate a CA at the default location.
	initCmd := TlsInitCmd()
	initCmd.SetOut(&bytes.Buffer{})
	initCmd.SetErr(&bytes.Buffer{})
	initCmd.SetArgs([]string{})
	if err := initCmd.Execute(); err != nil {
		t.Fatalf("init: %v", err)
	}

	// show-ca with no --cert flag should use the default path.
	buf := &bytes.Buffer{}
	showCmd := TlsShowCACmd()
	showCmd.SetOut(buf)
	showCmd.SetErr(&bytes.Buffer{})
	showCmd.SetArgs([]string{})
	if err := showCmd.Execute(); err != nil {
		t.Fatalf("tls show-ca (default path): %v", err)
	}
	if !bytes.Contains(buf.Bytes(), []byte("BEGIN CERTIFICATE")) {
		t.Error("show-ca with default path should output PEM certificate")
	}
}

func TestTLSShowCACmd_DefaultPathMissing(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home) // Windows: os.UserHomeDir reads %USERPROFILE%

	// No init: default path has no CA file.
	showCmd := TlsShowCACmd()
	showCmd.SetOut(&bytes.Buffer{})
	showCmd.SetErr(&bytes.Buffer{})
	showCmd.SetArgs([]string{})
	err := showCmd.Execute()
	if err == nil {
		t.Error("expected error when CA does not exist at default path")
	}
}

func TestTLSInstallCACmd_DefaultPath(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home) // Windows: os.UserHomeDir reads %USERPROFILE%

	// Generate CA at default location.
	initCmd := TlsInitCmd()
	initCmd.SetOut(&bytes.Buffer{})
	initCmd.SetErr(&bytes.Buffer{})
	initCmd.SetArgs([]string{})
	if err := initCmd.Execute(); err != nil {
		t.Fatalf("init: %v", err)
	}

	// install-ca with no --cert flag should use the default path.
	buf := &bytes.Buffer{}
	installCmd := TlsInstallCACmd()
	installCmd.SetOut(buf)
	installCmd.SetErr(&bytes.Buffer{})
	installCmd.SetArgs([]string{})
	if err := installCmd.Execute(); err != nil {
		t.Fatalf("tls install-ca (default path): %v", err)
	}
	if buf.Len() == 0 {
		t.Error("install-ca with default path should produce output")
	}
}

func TestTLSShowCACmd_VerifiesPEMContent(t *testing.T) {
	dir := t.TempDir()
	initCmd := TlsInitCmd()
	initCmd.SetOut(&bytes.Buffer{})
	initCmd.SetErr(&bytes.Buffer{})
	initCmd.SetArgs([]string{"--out", dir})
	if err := initCmd.Execute(); err != nil {
		t.Fatalf("init: %v", err)
	}

	buf := &bytes.Buffer{}
	showCmd := TlsShowCACmd()
	showCmd.SetOut(buf)
	showCmd.SetErr(&bytes.Buffer{})
	showCmd.SetArgs([]string{"--cert", filepath.Join(dir, "ca.pem")})
	if err := showCmd.Execute(); err != nil {
		t.Fatalf("tls show-ca: %v", err)
	}

	output := buf.String()
	if !bytes.Contains([]byte(output), []byte("BEGIN CERTIFICATE")) {
		t.Error("output missing BEGIN CERTIFICATE header")
	}
	if !bytes.Contains([]byte(output), []byte("END CERTIFICATE")) {
		t.Error("output missing END CERTIFICATE footer")
	}

	// Verify output matches the actual file content.
	fileData, err := os.ReadFile(filepath.Clean(filepath.Join(dir, "ca.pem")))
	if err != nil {
		t.Fatalf("read cert file: %v", err)
	}
	if output != string(fileData) {
		t.Error("show-ca output does not match cert file content")
	}
}
