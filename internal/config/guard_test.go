// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateGuard_EmptyIsValid(t *testing.T) {
	t.Parallel()
	cfg := Defaults()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("empty guard should be valid: %v", err)
	}
}

func TestValidateGuard_ValidFull(t *testing.T) {
	t.Parallel()
	cfg := Defaults()
	cfg.Guard = Guard{
		Services: []GuardService{
			{Name: "api", Protocol: "tcp", Host: "api.vendor.example", Port: 443},
		},
		Profiles: []GuardProfile{
			{Name: "worker", Manifests: []string{"app-state"}},
		},
		Manifests: []GuardManifest{
			{Name: "app-state", ReadOnly: []string{"/opt/app/config"}, ReadWrite: []string{"/var/lib/app/data"}},
		},
	}
	// A structurally valid declaration passes every path and naming rule and is
	// then refused solely because nothing enforces guard yet. Asserting the
	// exact sentinel keeps this test honest: if a real validation rule started
	// rejecting this config, the error would no longer be the gate and this
	// would fail rather than quietly passing for the wrong reason.
	err := cfg.Validate()
	if err == nil {
		t.Fatal("guard config must be refused while no runtime evaluator enforces it")
	}
	if !errors.Is(err, errGuardNotEnforced) {
		t.Fatalf("valid guard config should fail only on the not-enforced gate, got: %v", err)
	}
}

func TestValidateGuard_Rejections(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		guard   Guard
		wantErr string
	}{
		{
			name: "wildcard_host",
			guard: Guard{Services: []GuardService{
				{Name: "api", Protocol: "tcp", Host: "*.vendor.example", Port: 443},
			}},
			wantErr: "wildcard",
		},
		{
			name: "cidr_host",
			guard: Guard{Services: []GuardService{
				{Name: "api", Protocol: "tcp", Host: "10.0.0.0/8", Port: 443},
			}},
			wantErr: "CIDR",
		},
		{
			name: "port_zero",
			guard: Guard{Services: []GuardService{
				{Name: "api", Protocol: "tcp", Host: "api.vendor.example", Port: 0},
			}},
			wantErr: "port",
		},
		{
			name: "duplicate_service_name",
			guard: Guard{Services: []GuardService{
				{Name: "api", Protocol: "tcp", Host: "a.vendor.example", Port: 443},
				{Name: "api", Protocol: "tcp", Host: "b.vendor.example", Port: 443},
			}},
			wantErr: "duplicate service name",
		},
		{
			name: "duplicate_destination",
			guard: Guard{Services: []GuardService{
				{Name: "api1", Protocol: "tcp", Host: "a.vendor.example", Port: 443},
				{Name: "api2", Protocol: "tcp", Host: "a.vendor.example", Port: 443},
			}},
			wantErr: "duplicate destination",
		},
		{
			name: "duplicate_destination_trailing_dot",
			guard: Guard{Services: []GuardService{
				{Name: "api1", Protocol: "tcp", Host: "a.vendor.example", Port: 443},
				{Name: "api2", Protocol: "tcp", Host: "a.vendor.example.", Port: 443},
			}},
			wantErr: "duplicate destination",
		},
		{
			name: "duplicate_destination_case_insensitive",
			guard: Guard{Services: []GuardService{
				{Name: "api1", Protocol: "tcp", Host: "A.Vendor.Example", Port: 443},
				{Name: "api2", Protocol: "tcp", Host: "a.vendor.example", Port: 443},
			}},
			wantErr: "duplicate destination",
		},
		{
			name: "unknown_protocol",
			guard: Guard{Services: []GuardService{
				{Name: "api", Protocol: "quic", Host: "a.vendor.example", Port: 443},
			}},
			wantErr: "protocol",
		},
		{
			name: "udp_reserved_not_yet_accepted",
			guard: Guard{Services: []GuardService{
				{Name: "dns", Protocol: "udp", Host: "a.vendor.example", Port: 53},
			}},
			wantErr: "protocol",
		},
		{
			name: "empty_service_name",
			guard: Guard{Services: []GuardService{
				{Name: "", Protocol: "tcp", Host: "a.vendor.example", Port: 443},
			}},
			wantErr: "name is required",
		},
		{
			name: "empty_host",
			guard: Guard{Services: []GuardService{
				{Name: "api", Protocol: "tcp", Host: "", Port: 443},
			}},
			wantErr: "host",
		},
		{
			name: "duplicate_manifest_name",
			guard: Guard{Manifests: []GuardManifest{
				{Name: "state"},
				{Name: "state"},
			}},
			wantErr: "duplicate manifest name",
		},
		{
			name: "empty_manifest_name",
			guard: Guard{Manifests: []GuardManifest{
				{Name: ""},
			}},
			wantErr: "name is required",
		},
		{
			name: "rw_whole_home",
			guard: Guard{Manifests: []GuardManifest{
				{Name: "bad", ReadWrite: []string{guardTestHome}},
			}},
			wantErr: "home directory",
		},
		{
			name: "rw_ssh_dir",
			guard: Guard{Manifests: []GuardManifest{
				{Name: "bad", ReadWrite: []string{filepath.Join(guardTestHome, ".ssh")}},
			}},
			wantErr: "trust-bearing",
		},
		{
			name: "rw_ssh_subpath",
			guard: Guard{Manifests: []GuardManifest{
				{Name: "bad", ReadWrite: []string{filepath.Join(guardTestHome, ".ssh", "id_rsa")}},
			}},
			wantErr: "trust-bearing",
		},
		{
			name: "rw_pipelock_state",
			guard: Guard{Manifests: []GuardManifest{
				{Name: "bad", ReadWrite: []string{filepath.Join(guardTestHome, ".local", "share", "pipelock")}},
			}},
			wantErr: "pipelock state",
		},
		{
			name: "rw_pipelock_config",
			guard: Guard{Manifests: []GuardManifest{
				{Name: "bad", ReadWrite: []string{filepath.Join(guardTestHome, ".config", "pipelock")}},
			}},
			wantErr: "pipelock config",
		},
		{
			name: "rw_etc_pipelock",
			guard: Guard{Manifests: []GuardManifest{
				{Name: "bad", ReadWrite: []string{"/etc/pipelock"}},
			}},
			wantErr: "pipelock config",
		},
		{
			name: "rw_path_dir_usr_bin",
			guard: Guard{Manifests: []GuardManifest{
				{Name: "bad", ReadWrite: []string{"/usr/bin"}},
			}},
			wantErr: "PATH directory",
		},
		{
			name: "rw_path_dir_usr_local_bin",
			guard: Guard{Manifests: []GuardManifest{
				{Name: "bad", ReadWrite: []string{"/usr/local/bin"}},
			}},
			wantErr: "PATH directory",
		},
		{
			name: "rw_autostart_xdg",
			guard: Guard{Manifests: []GuardManifest{
				{Name: "bad", ReadWrite: []string{filepath.Join(guardTestHome, ".config", "autostart")}},
			}},
			wantErr: "autostart",
		},
		{
			name: "rw_launchagents",
			guard: Guard{Manifests: []GuardManifest{
				{Name: "bad", ReadWrite: []string{filepath.Join(guardTestHome, "Library", "LaunchAgents")}},
			}},
			wantErr: "autostart",
		},
		{
			name: "rw_socket_run_user",
			guard: Guard{Manifests: []GuardManifest{
				{Name: "bad", ReadWrite: []string{"/run/user/1000"}},
			}},
			wantErr: "socket",
		},
		{
			name: "rw_var_run",
			guard: Guard{Manifests: []GuardManifest{
				{Name: "bad", ReadWrite: []string{"/var/run"}},
			}},
			wantErr: "socket",
		},
		{
			name: "rw_tmp_passes_path_rules",
			guard: Guard{Manifests: []GuardManifest{
				{Name: "ok", ReadWrite: []string{"/tmp/workdir"}},
			}},
			// The path itself is fine. The declaration is refused only by the
			// not-enforced gate, which is the message asserted here.
			wantErr: "not enforced",
		},
		{
			// Inverted deliberately. Read-only is NOT safe for key material
			// under an agent threat model: reading a private key IS the
			// exfiltration, because the copy leaves through any destination
			// the workload is otherwise permitted to reach.
			name: "ro_ssh_rejected",
			guard: Guard{Manifests: []GuardManifest{
				{Name: "bad", ReadOnly: []string{"/home/someoperator/.ssh"}},
			}},
			wantErr: "secret-bearing",
		},
		{
			name: "relative_path_rejected",
			guard: Guard{Manifests: []GuardManifest{
				{Name: "bad", ReadWrite: []string{"relative/path"}},
			}},
			wantErr: "absolute",
		},
		{
			name: "relative_ro_path_rejected",
			guard: Guard{Manifests: []GuardManifest{
				{Name: "bad", ReadOnly: []string{"relative/readonly"}},
			}},
			wantErr: "absolute",
		},
		{
			name: "ro_gnupg_rejected",
			guard: Guard{Manifests: []GuardManifest{
				{Name: "bad", ReadOnly: []string{"/home/someoperator/.gnupg"}},
			}},
			wantErr: "secret-bearing",
		},
		{
			name: "ro_pipelock_config_rejected",
			guard: Guard{Manifests: []GuardManifest{
				{Name: "bad", ReadOnly: []string{"/home/someoperator/.config/pipelock"}},
			}},
			wantErr: "credential material",
		},
		{
			name: "ro_pipelock_state_rejected",
			guard: Guard{Manifests: []GuardManifest{
				{Name: "bad", ReadOnly: []string{"/home/someoperator/.local/share/pipelock"}},
			}},
			wantErr: "credential material",
		},
		{
			name: "ro_etc_pipelock_rejected",
			guard: Guard{Manifests: []GuardManifest{
				{Name: "bad", ReadOnly: []string{"/home/someoperator/etc/pipelock"}},
			}},
			wantErr: "credential material",
		},
		{
			// The absolute system path is the one an operator would actually
			// write; the home-relative case above only proves the suffix
			// marker matches. Pin both directions.
			// Pins a DELIBERATE exemption: validateGuardROPath rejects a
			// forbidden suffix only when the reason names pipelock, so autostart
			// directories pass the read-only rules on purpose (reading what runs
			// at login is reconnaissance, not credential theft). Without this
			// case, widening the read-only rejection to every forbidden suffix
			// would change operator-visible behavior with no test failure.
			name: "ro_autostart_allowed_by_design",
			guard: Guard{Manifests: []GuardManifest{
				{Name: "ok", ReadOnly: []string{filepath.Join(guardTestHome, ".config", "autostart")}},
			}},
			wantErr: "not enforced",
		},
		{
			name: "ro_absolute_etc_pipelock_rejected",
			guard: Guard{Manifests: []GuardManifest{
				{Name: "bad", ReadOnly: []string{"/etc/pipelock"}},
			}},
			wantErr: "credential material",
		},
		{
			name: "rw_etc_shadow_rejected",
			guard: Guard{Manifests: []GuardManifest{
				{Name: "bad", ReadWrite: []string{"/etc/shadow"}},
			}},
			wantErr: "privilege path",
		},
		{
			name: "rw_etc_passwd_rejected",
			guard: Guard{Manifests: []GuardManifest{
				{Name: "bad", ReadWrite: []string{"/etc/passwd"}},
			}},
			wantErr: "privilege path",
		},
		{
			name: "rw_usr_lib_rejected",
			guard: Guard{Manifests: []GuardManifest{
				{Name: "bad", ReadWrite: []string{"/usr/lib"}},
			}},
			wantErr: "system library directory",
		},
		{
			name: "rw_boot_rejected",
			guard: Guard{Manifests: []GuardManifest{
				{Name: "bad", ReadWrite: []string{"/boot"}},
			}},
			wantErr: "boot directory",
		},
		{
			name: "ro_dotpipelock_rejected",
			guard: Guard{Manifests: []GuardManifest{
				{Name: "bad", ReadOnly: []string{"/home/someoperator/.pipelock"}},
			}},
			wantErr: "credential material",
		},
		{
			name: "rw_etc_systemd_system",
			guard: Guard{Manifests: []GuardManifest{
				{Name: "bad", ReadWrite: []string{"/etc/systemd/system"}},
			}},
			wantErr: "persistence",
		},
		{
			name: "rw_etc_init_d",
			guard: Guard{Manifests: []GuardManifest{
				{Name: "bad", ReadWrite: []string{"/etc/init.d"}},
			}},
			wantErr: "persistence",
		},
		{
			name: "rw_etc_cron_d",
			guard: Guard{Manifests: []GuardManifest{
				{Name: "bad", ReadWrite: []string{"/etc/cron.d"}},
			}},
			wantErr: "persistence",
		},
		{
			name: "rw_library_launchdaemons",
			guard: Guard{Manifests: []GuardManifest{
				{Name: "bad", ReadWrite: []string{"/Library/LaunchDaemons"}},
			}},
			wantErr: "autostart",
		},
		{
			name: "rw_etc_sudoers_d",
			guard: Guard{Manifests: []GuardManifest{
				{Name: "bad", ReadWrite: []string{"/etc/sudoers.d"}},
			}},
			wantErr: "privilege",
		},
		{
			name: "profile_refs_nonexistent_manifest",
			guard: Guard{
				Profiles: []GuardProfile{
					{Name: "worker", Manifests: []string{"nonexistent"}},
				},
			},
			wantErr: "unknown manifest",
		},
		{
			name: "duplicate_profile_name",
			guard: Guard{Profiles: []GuardProfile{
				{Name: "worker", Manifests: nil},
				{Name: "worker", Manifests: nil},
			}},
			wantErr: "duplicate profile name",
		},
		{
			name: "empty_profile_name",
			guard: Guard{Profiles: []GuardProfile{
				{Name: ""},
			}},
			wantErr: "name is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := Defaults()
			cfg.Guard = tt.guard
			err := cfg.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("expected no error, got: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErr)
			}
			if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tt.wantErr)) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestValidateGuard_SymlinkAlias(t *testing.T) {
	t.Parallel()

	// Hermetic by construction: the alias points at a .ssh directory this test
	// creates, never at the running user's real home. The previous version
	// symlinked to homeDir()/.ssh, which passed on a developer machine and
	// FAILED on CI runners that have no ~/.ssh, because the unresolvable
	// target silently fell through the check.
	tmp := t.TempDir()
	sshDir := filepath.Join(tmp, "victim-home", ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(tmp, "sneaky-link")
	if err := os.Symlink(sshDir, link); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	cfg := Defaults()
	cfg.Guard = Guard{
		Manifests: []GuardManifest{
			{Name: "bad", ReadWrite: []string{link}},
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected symlink to a trust-bearing path to be rejected")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "trust-bearing") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestValidateGuard_SymlinkedAncestorWithMissingLeaf covers the fail-open that
// CI reproduced by accident. filepath.EvalSymlinks fails outright when the
// FINAL component does not exist yet, which is the normal case for a declared
// writable state path. Falling back to the literal string discards resolution
// of every existing symlinked ANCESTOR, so a path whose parent is an alias to a
// trust-bearing directory would be accepted on the strength of how it is
// spelled.
func TestValidateGuard_SymlinkedAncestorWithMissingLeaf(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	realSSH := filepath.Join(tmp, "victim-home", ".ssh")
	if err := os.MkdirAll(realSSH, 0o700); err != nil {
		t.Fatal(err)
	}
	aliasDir := filepath.Join(tmp, "innocent")
	if err := os.Symlink(realSSH, aliasDir); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	// The leaf deliberately does NOT exist: this is what defeated the old check.
	target := filepath.Join(aliasDir, "authorized_keys")
	if _, err := os.Lstat(target); err == nil {
		t.Fatal("test precondition: leaf must not exist")
	}

	cfg := Defaults()
	cfg.Guard = Guard{
		Manifests: []GuardManifest{
			{Name: "bad", ReadWrite: []string{target}},
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected a write through a symlinked ancestor into .ssh to be rejected even though the leaf does not exist")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "trust-bearing") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestValidateGuard_ForeignHomeTrustPaths proves the protected-path check does
// not depend on which user Pipelock runs as. Pipelock commonly runs as a system
// service, so a home-derived list would protect /root/.ssh while leaving every
// real operator's home unguarded. None of these paths need to exist.
func TestValidateGuard_ForeignHomeTrustPaths(t *testing.T) {
	t.Parallel()

	for _, path := range []string{
		"/home/someoperator/.ssh",
		"/home/someoperator/.ssh/authorized_keys",
		"/home/someoperator/.gnupg",
		"/Users/someoperator/.ssh/id_ed25519",
		"/home/someoperator/.config/pipelock",
		"/home/someoperator/.local/share/pipelock",
		"/home/someoperator/.config/autostart",
		"/Users/someoperator/Library/LaunchAgents",
		"/etc/pipelock",
		"/home/someoperator",
		"/Users/someoperator",
		"/root",
		"/root/.ssh",
		"/",
	} {
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			cfg := Defaults()
			cfg.Guard = Guard{
				Manifests: []GuardManifest{
					{Name: "bad", ReadWrite: []string{path}},
				},
			}
			err := cfg.Validate()
			if err == nil {
				t.Errorf("read-write on %q must be rejected regardless of which user Pipelock runs as", path)
				return
			}
			// Assert the rejection came from a PATH rule, not from the
			// not-enforced gate.
			//
			// This test was proven non-vacuous when written, and then SILENTLY
			// became vacuous when the errGuardNotEnforced gate was added later:
			// the gate rejects every non-empty guard declaration, so a bare
			// err != nil check passes even with every protected-path rule
			// deleted. A guard proven honest at one commit is not proven honest
			// at the next; a later change can hollow it out without touching it.
			if errors.Is(err, errGuardNotEnforced) {
				t.Errorf("read-write on %q was refused only by the not-enforced gate, so no path rule actually rejected it: %v", path, err)
			}
		})
	}
}

// TestValidateGuard_OrdinaryWorkspacePathsStillAllowed is the availability half.
// An over-strict guard that refuses legitimate workspace and session paths gets
// the whole feature switched off, which on a security product is nearly as
// damaging as permitting too much.
func TestValidateGuard_OrdinaryWorkspacePathsStillAllowed(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	for _, path := range []string{
		filepath.Join(tmp, "workspace"),
		filepath.Join(tmp, "session-state"),
		"/home/someoperator/projects/app",
		"/home/someoperator/.cache/some-tool",
		"/var/tmp/agent-scratch",
	} {
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			cfg := Defaults()
			cfg.Guard = Guard{
				Manifests: []GuardManifest{
					{Name: "ok", ReadWrite: []string{path}},
				},
			}
			err := cfg.Validate()
			if err == nil {
				t.Fatalf("guard is refused while unenforced; %q should still reach the gate", path)
			}
			// The point of this test is the DIRECTION of the refusal: an
			// ordinary workspace path must be rejected only by the
			// not-enforced gate, never by a trust-bearing path rule. An
			// over-strict guard that refuses legitimate work gets the whole
			// feature switched off, which on a security product costs nearly
			// as much as permitting too much.
			if !errors.Is(err, errGuardNotEnforced) {
				t.Errorf("ordinary workspace path %q must pass the path rules, got: %v", path, err)
			}
		})
	}
}

func TestCanonicalPolicyHash_GuardExcludedWhileInert(t *testing.T) {
	t.Parallel()

	base := canonicalHashOf(t, func(c *Config) {})

	withGuard := canonicalHashOf(t, func(c *Config) {
		c.Guard = Guard{
			Services: []GuardService{
				{Name: "api", Protocol: "tcp", Host: "a.vendor.example", Port: 443},
			},
			Manifests: []GuardManifest{
				{Name: "session", ReadWrite: []string{"/tmp/pipelock-guard-session"}},
			},
			Profiles: []GuardProfile{
				{Name: "codex", Manifests: []string{"session"}},
			},
		}
	})

	if base != withGuard {
		t.Errorf("inert guard config must not change the canonical policy hash:\n  without guard = %s\n  with guard    = %s", base, withGuard)
	}

	// A semantically different guard must also leave the hash untouched while
	// the section is inert; otherwise the exclusion is only partial.
	differentPort := canonicalHashOf(t, func(c *Config) {
		c.Guard = Guard{
			Services: []GuardService{
				{Name: "api", Protocol: "tcp", Host: "a.vendor.example", Port: 8443},
			},
		}
	})

	if base != differentPort {
		t.Errorf("inert guard config must not change the canonical policy hash for any value:\n  without guard = %s\n  different port = %s", base, differentPort)
	}
}

// guardTestHome is a synthetic home directory path under /home so that
// guardIsHomeRoot recognises it without depending on the running user's
// real $HOME. This keeps the tests hermetic on CI runners.
const guardTestHome = "/home/testoperator"
