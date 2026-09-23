// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	domsigning "github.com/luckyPipewrench/pipelock/internal/signing"
)

// TestTLSInitCmd_AgreesWithProxyDefaultCAPath is the consistency invariant
// this fix exists for: `pipelock tls init` (via cliutil.ResolveKeystoreDir,
// which delegates to domsigning.ResolveKeystoreDir) and the proxy's
// config.ResolveCAPath must land on the same directory for the same
// --home/PIPELOCK_HOME environment. Before the fix, ResolveCAPath always
// used os.UserHomeDir() and ignored both, so a CA generated under
// PIPELOCK_HOME was invisible to `pipelock run`.
func TestTLSInitCmd_AgreesWithProxyDefaultCAPath(t *testing.T) {
	home := t.TempDir()
	pipelockHome := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home) // Windows: os.UserHomeDir reads %USERPROFILE%
	old := domsigning.PipelockHome
	domsigning.PipelockHome = ""
	t.Cleanup(func() { domsigning.PipelockHome = old })
	t.Setenv("PIPELOCK_HOME", pipelockHome)

	initCmd := TlsInitCmd()
	initCmd.SetOut(&bytes.Buffer{})
	initCmd.SetErr(&bytes.Buffer{})
	initCmd.SetArgs([]string{}) // no --out: uses the default resolution path
	if err := initCmd.Execute(); err != nil {
		t.Fatalf("tls init: %v", err)
	}

	// tls init must have written under PIPELOCK_HOME, not os.UserHomeDir().
	initCertPath := filepath.Join(pipelockHome, "ca.pem")
	if _, err := os.Stat(initCertPath); err != nil {
		t.Fatalf("tls init did not write to PIPELOCK_HOME (%s): %v", initCertPath, err)
	}

	cfg := config.Defaults()
	certPath, keyPath, err := cfg.ResolveCAPath()
	if err != nil {
		t.Fatalf("ResolveCAPath: %v", err)
	}
	if certPath != initCertPath {
		t.Errorf("ResolveCAPath cert = %q, want tls init's output %q", certPath, initCertPath)
	}
	wantKeyPath := filepath.Join(pipelockHome, "ca-key.pem")
	if keyPath != wantKeyPath {
		t.Errorf("ResolveCAPath key = %q, want tls init's output %q", keyPath, wantKeyPath)
	}

	// And the proxy must be able to load exactly what tls init wrote.
	if _, err := os.Stat(certPath); err != nil {
		t.Errorf("ResolveCAPath's cert path does not exist: %v", err)
	}
}
