package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestTLSInitCmd(t *testing.T) {
	dir := t.TempDir()
	cmd := tlsInitCmd()
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

	cmd1 := tlsInitCmd()
	cmd1.SetOut(&bytes.Buffer{})
	cmd1.SetErr(&bytes.Buffer{})
	cmd1.SetArgs([]string{"--out", dir})
	if err := cmd1.Execute(); err != nil {
		t.Fatalf("first init: %v", err)
	}

	cmd2 := tlsInitCmd()
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

	cmd1 := tlsInitCmd()
	cmd1.SetOut(&bytes.Buffer{})
	cmd1.SetErr(&bytes.Buffer{})
	cmd1.SetArgs([]string{"--out", dir})
	if err := cmd1.Execute(); err != nil {
		t.Fatalf("first init: %v", err)
	}

	cmd2 := tlsInitCmd()
	cmd2.SetOut(&bytes.Buffer{})
	cmd2.SetErr(&bytes.Buffer{})
	cmd2.SetArgs([]string{"--out", dir, "--force"})
	if err := cmd2.Execute(); err != nil {
		t.Fatalf("tls init --force: %v", err)
	}
}

func TestTLSShowCACmd(t *testing.T) {
	dir := t.TempDir()
	initCmd := tlsInitCmd()
	initCmd.SetOut(&bytes.Buffer{})
	initCmd.SetErr(&bytes.Buffer{})
	initCmd.SetArgs([]string{"--out", dir})
	if err := initCmd.Execute(); err != nil {
		t.Fatalf("init: %v", err)
	}

	buf := &bytes.Buffer{}
	showCmd := tlsShowCACmd()
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
	initCmd := tlsInitCmd()
	initCmd.SetOut(&bytes.Buffer{})
	initCmd.SetErr(&bytes.Buffer{})
	initCmd.SetArgs([]string{"--out", dir})
	if err := initCmd.Execute(); err != nil {
		t.Fatalf("init: %v", err)
	}

	buf := &bytes.Buffer{}
	installCmd := tlsInstallCACmd()
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
	cmd := tlsInitCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--validity", "not-a-duration", "--out", t.TempDir()})
	err := cmd.Execute()
	if err == nil {
		t.Error("expected error for invalid validity")
	}
}

func TestTLSShowCACmd_MissingFile(t *testing.T) {
	cmd := tlsShowCACmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--cert", "/nonexistent/ca.pem"})
	err := cmd.Execute()
	if err == nil {
		t.Error("expected error for missing cert file")
	}
}
