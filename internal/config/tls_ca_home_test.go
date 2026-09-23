// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/signing"
)

// withPipelockHomeFlag saves and restores signing.PipelockHome, the
// package-level --home flag value that ResolveCAPath now consults so it
// agrees with `pipelock tls init` on where the default CA lives.
func withPipelockHomeFlag(t *testing.T, value string) {
	t.Helper()
	old := signing.PipelockHome
	signing.PipelockHome = value
	t.Cleanup(func() { signing.PipelockHome = old })
}

// TestResolveCAPath_Precedence proves ResolveCAPath's default-directory
// resolution follows the same --home > PIPELOCK_HOME > ~/.pipelock
// precedence as `pipelock tls init` (via signing.ResolveKeystoreDir),
// rather than always reading os.UserHomeDir().
func TestResolveCAPath_Precedence(t *testing.T) {
	home := t.TempDir()
	flagDir := filepath.Join(home, "flag-home")
	envDir := filepath.Join(home, "env-home")

	tests := []struct {
		name           string
		explicitCert   string
		explicitKey    string
		flag           string
		env            string
		wantCertPrefix string // "" means "computed from HOME default"
	}{
		{
			name:         "explicit cert and key both win",
			explicitCert: "/explicit/ca.pem",
			explicitKey:  "/explicit/ca-key.pem",
		},
		{
			name:         "explicit cert only, key still resolves via default dir",
			explicitCert: "/explicit-cert-only/ca.pem",
		},
		{
			name: "neither explicit, no flag or env: falls back to HOME/.pipelock",
		},
		{
			name: "neither explicit, PIPELOCK_HOME set: uses that dir",
			env:  envDir,
		},
		{
			name: "neither explicit, flag and env both set: flag wins",
			flag: flagDir,
			env:  envDir,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("HOME", home)
			t.Setenv("USERPROFILE", home) // Windows: os.UserHomeDir reads %USERPROFILE%
			withPipelockHomeFlag(t, tt.flag)
			t.Setenv("PIPELOCK_HOME", tt.env)

			cfg := Defaults()
			cfg.TLSInterception.CACertPath = tt.explicitCert
			cfg.TLSInterception.CAKeyPath = tt.explicitKey

			certPath, keyPath, err := cfg.ResolveCAPath()
			if err != nil {
				t.Fatalf("ResolveCAPath: %v", err)
			}

			if tt.explicitCert != "" {
				if certPath != tt.explicitCert {
					t.Errorf("certPath = %q, want explicit %q", certPath, tt.explicitCert)
				}
			}
			if tt.explicitKey != "" {
				if keyPath != tt.explicitKey {
					t.Errorf("keyPath = %q, want explicit %q", keyPath, tt.explicitKey)
				}
				return
			}

			// keyPath (and certPath, when not explicit) must come from the
			// resolved default directory.
			wantDir := filepath.Join(home, signing.DefaultPipelockDir)
			switch {
			case tt.flag != "":
				wantDir = tt.flag
			case tt.env != "":
				wantDir = tt.env
			}
			wantKey := filepath.Join(wantDir, "ca-key.pem")
			if keyPath != wantKey {
				t.Errorf("keyPath = %q, want %q", keyPath, wantKey)
			}
			if tt.explicitCert == "" {
				wantCert := filepath.Join(wantDir, "ca.pem")
				if certPath != wantCert {
					t.Errorf("certPath = %q, want %q", certPath, wantCert)
				}
			}
		})
	}
}

// writeFakeCA creates ca.pem/ca-key.pem under dir with permissions the
// validator will accept, so the tests below reach the intended branch.
func writeFakeCA(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("MkdirAll(%s): %v", dir, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ca.pem"), []byte("fake-cert"), 0o600); err != nil {
		t.Fatalf("write ca.pem: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ca-key.pem"), []byte("fake-key"), 0o600); err != nil {
		t.Fatalf("write ca-key.pem: %v", err)
	}
}

func tlsValidateConfig() *Config {
	cfg := Defaults()
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = testLoopbackAllowlist
	cfg.TLSInterception.Enabled = true
	return cfg
}

// TestValidateTLSInterception_HomePrecedence covers the three states that
// matter for the CA-home fix: the CA lives where PIPELOCK_HOME says it
// should (passes), the CA only exists at the OLD bare ~/.pipelock location
// while PIPELOCK_HOME points elsewhere (must name both paths so the
// operator isn't silently signed with a stale CA), and no CA exists
// anywhere (ordinary not-found error, no stale-CA noise).
func TestValidateTLSInterception_HomePrecedence(t *testing.T) {
	t.Run("CA present under PIPELOCK_HOME passes", func(t *testing.T) {
		home := t.TempDir()
		pipelockHome := t.TempDir()
		t.Setenv("HOME", home)
		t.Setenv("USERPROFILE", home)
		withPipelockHomeFlag(t, "")
		t.Setenv("PIPELOCK_HOME", pipelockHome)
		writeFakeCA(t, pipelockHome)

		cfg := tlsValidateConfig()
		if err := cfg.Validate(); err != nil {
			t.Fatalf("Validate: %v", err)
		}
	})

	t.Run("CA only under bare HOME while PIPELOCK_HOME set names both paths", func(t *testing.T) {
		home := t.TempDir()
		pipelockHome := t.TempDir()
		t.Setenv("HOME", home)
		t.Setenv("USERPROFILE", home)
		withPipelockHomeFlag(t, "")
		t.Setenv("PIPELOCK_HOME", pipelockHome)

		// Old CA lives at the bare ~/.pipelock, not under PIPELOCK_HOME.
		staleDir := filepath.Join(home, signing.DefaultPipelockDir)
		writeFakeCA(t, staleDir)

		cfg := tlsValidateConfig()
		err := cfg.Validate()
		if err == nil {
			t.Fatal("expected error: CA not found under PIPELOCK_HOME")
		}
		wantPaths := []string{
			filepath.Join(pipelockHome, "ca.pem"), // where it looked
			filepath.Join(staleDir, "ca.pem"),     // where the stale CA actually is
		}
		for _, p := range wantPaths {
			if !strings.Contains(err.Error(), p) {
				t.Errorf("error %q missing path %q", err.Error(), p)
			}
		}
		if !strings.Contains(err.Error(), "ca_cert") {
			t.Errorf("error %q missing ca_cert remediation hint", err.Error())
		}
		// Positive control for the phrase the no-CA case asserts is absent.
		if !strings.Contains(err.Error(), "an existing CA is at") {
			t.Errorf("error %q missing stale-CA hint", err.Error())
		}
	})

	t.Run("no CA anywhere gives the ordinary not-found error", func(t *testing.T) {
		home := t.TempDir()
		pipelockHome := t.TempDir()
		t.Setenv("HOME", home)
		t.Setenv("USERPROFILE", home)
		withPipelockHomeFlag(t, "")
		t.Setenv("PIPELOCK_HOME", pipelockHome)

		cfg := tlsValidateConfig()
		err := cfg.Validate()
		if err == nil {
			t.Fatal("expected error: no CA anywhere")
		}
		if !strings.Contains(err.Error(), "CA cert not found") {
			t.Errorf("error = %q, want 'CA cert not found'", err.Error())
		}
		// No stale CA exists, so the mismatch hint must not fire.
		if strings.Contains(err.Error(), "an existing CA is at") {
			t.Errorf("error = %q, should not claim a stale CA exists", err.Error())
		}
	})

	t.Run("a lone stale certificate without its key gets no keep-using-it hint", func(t *testing.T) {
		home := t.TempDir()
		pipelockHome := t.TempDir()
		t.Setenv("HOME", home)
		t.Setenv("USERPROFILE", home)
		withPipelockHomeFlag(t, "")
		t.Setenv("PIPELOCK_HOME", pipelockHome)
		staleDir := filepath.Join(home, signing.DefaultPipelockDir)
		writeFakeCA(t, staleDir)
		if err := os.Remove(filepath.Join(staleDir, "ca-key.pem")); err != nil {
			t.Fatalf("remove stale key: %v", err)
		}

		err := tlsValidateConfig().Validate()
		if err == nil {
			t.Fatal("expected error: CA not found under PIPELOCK_HOME")
		}
		if strings.Contains(err.Error(), "an existing CA is at") {
			t.Errorf("error = %q, offered a CA that has no key", err.Error())
		}
	})
}

// TestTLSInit_ResolveCAPath_Consistency proves the invariant this fix
// exists for: for the same environment, the directory `pipelock tls init`
// would write to and the directory ResolveCAPath resolves for its default
// CA path are the same directory.
func TestTLSInit_ResolveCAPath_Consistency(t *testing.T) {
	home := t.TempDir()
	pipelockHome := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	withPipelockHomeFlag(t, "")
	t.Setenv("PIPELOCK_HOME", pipelockHome)

	initDir, err := signing.ResolveKeystoreDir("")
	if err != nil {
		t.Fatalf("signing.ResolveKeystoreDir: %v", err)
	}

	cfg := Defaults()
	certPath, keyPath, err := cfg.ResolveCAPath()
	if err != nil {
		t.Fatalf("ResolveCAPath: %v", err)
	}

	if filepath.Dir(certPath) != initDir {
		t.Errorf("ResolveCAPath cert dir = %q, want %q (tls init's output dir)", filepath.Dir(certPath), initDir)
	}
	if filepath.Dir(keyPath) != initDir {
		t.Errorf("ResolveCAPath key dir = %q, want %q (tls init's output dir)", filepath.Dir(keyPath), initDir)
	}
}

// TestCAPathEdgeCases covers the fail-closed branches around home resolution:
// no resolvable home is an error, and the mismatch hint stays silent whenever
// it cannot honestly name a second, usable CA.
func TestCAPathEdgeCases(t *testing.T) {
	t.Run("no resolvable home is an error naming the explicit fields", func(t *testing.T) {
		t.Setenv("HOME", "")
		t.Setenv("USERPROFILE", "")
		t.Setenv("PIPELOCK_HOME", "")
		withPipelockHomeFlag(t, "")
		var cfg Config
		if _, _, err := cfg.ResolveCAPath(); err == nil || !strings.Contains(err.Error(), "ca_cert and ca_key") {
			t.Fatalf("ResolveCAPath err = %v, want resolve error naming ca_cert and ca_key", err)
		}
	})
	t.Run("hint is silent without a custom home", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		t.Setenv("PIPELOCK_HOME", "")
		withPipelockHomeFlag(t, "")
		writeFakeCA(t, filepath.Join(home, signing.DefaultPipelockDir))
		var cfg Config
		if got := cfg.caPathMismatchHint("x"); got != "" {
			t.Fatalf("hint = %q, want empty", got)
		}
	})
	t.Run("hint is silent when the user home cannot be resolved", func(t *testing.T) {
		t.Setenv("HOME", "")
		t.Setenv("USERPROFILE", "")
		t.Setenv("PIPELOCK_HOME", t.TempDir())
		withPipelockHomeFlag(t, "")
		var cfg Config
		if got := cfg.caPathMismatchHint("x"); got != "" {
			t.Fatalf("hint = %q, want empty", got)
		}
	})
	t.Run("hint is silent when PIPELOCK_HOME is ~/.pipelock itself", func(t *testing.T) {
		home := t.TempDir()
		dir := filepath.Join(home, signing.DefaultPipelockDir)
		t.Setenv("HOME", home)
		t.Setenv("PIPELOCK_HOME", dir+string(filepath.Separator))
		withPipelockHomeFlag(t, "")
		writeFakeCA(t, dir)
		var cfg Config
		if got := cfg.caPathMismatchHint("x"); got != "" {
			t.Fatalf("hint = %q, want empty", got)
		}
	})
	t.Run("positive control: a usable pair elsewhere is named", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		t.Setenv("PIPELOCK_HOME", t.TempDir())
		withPipelockHomeFlag(t, "")
		writeFakeCA(t, filepath.Join(home, signing.DefaultPipelockDir))
		var cfg Config
		if got := cfg.caPathMismatchHint("x"); !strings.Contains(got, "an existing CA is at") {
			t.Fatalf("hint = %q, want the stale-CA hint", got)
		}
	})
}
