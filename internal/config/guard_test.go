// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestValidateGuard_EmptyIsValid(t *testing.T) {
	t.Parallel()
	cfg := Defaults()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("empty guard should be valid: %v", err)
	}
}

func TestExplainGuardPathFloor(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		path        string
		access      GuardAccess
		wantRefused bool
		wantRule    string
		wantMatched string
	}{
		{name: "read_component_case_folded", path: "/workspace/.AWS/credentials", access: GuardAccessRead, wantRefused: true, wantRule: "forbidden_component", wantMatched: ".AWS"},
		{name: "write_component_reasoned", path: "/srv/agent/.kube/config", access: GuardAccessWrite, wantRefused: true, wantRule: "forbidden_component", wantMatched: ".kube"},
		{name: "read_whole_home_case_folded", path: "/users/someoperator", access: GuardAccessRead, wantRefused: true, wantRule: "whole_home", wantMatched: "/users/someoperator"},
		{name: "write_multi_home_root", path: "/var/home", access: GuardAccessWrite, wantRefused: true, wantRule: "credential_path", wantMatched: "/var/home"},
		{name: "read_home_credential_variant", path: "/home/someoperator/.npmrc.bak", access: GuardAccessRead, wantRefused: true, wantRule: "credential_path", wantMatched: ".npmrc"},
		{name: "write_home_credential_shape", path: "/home/someoperator/.pypirc", access: GuardAccessWrite, wantRefused: true, wantRule: "credential_path", wantMatched: ".pypirc"},
		{name: "read_absolute_credential", path: "/run/secrets/api-token", access: GuardAccessRead, wantRefused: true, wantRule: "credential_path", wantMatched: "/run/secrets"},
		{name: "read_pipelock_state", path: "/home/someoperator/.local/share/pipelock/license.token", access: GuardAccessRead, wantRefused: true, wantRule: "forbidden_path_shape", wantMatched: filepath.Join(".local", "share", "pipelock")},
		{name: "read_autostart_allowed", path: "/home/someoperator/.config/autostart/app.desktop", access: GuardAccessRead},
		{name: "write_autostart_refused", path: "/home/someoperator/.config/autostart/app.desktop", access: GuardAccessWrite, wantRefused: true, wantRule: "forbidden_path_shape", wantMatched: filepath.Join(".config", "autostart")},
		{name: "write_path_directory", path: "/usr/local/bin/helper", access: GuardAccessWrite, wantRefused: true, wantRule: "dangerous_write_root", wantMatched: "/usr/local/bin"},
		{name: "ordinary_read", path: "/opt/app/config.yaml", access: GuardAccessRead},
		{name: "ordinary_write", path: "/var/lib/app/state.db", access: GuardAccessWrite},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			decision, err := ExplainGuardPathFloor(tt.path, tt.access)
			if err != nil {
				t.Fatalf("ExplainGuardPathFloor: %v", err)
			}
			if decision.Refused != tt.wantRefused || decision.Rule != tt.wantRule || decision.Matched != tt.wantMatched {
				t.Fatalf("decision = %+v, want refused=%t rule=%q matched=%q", decision, tt.wantRefused, tt.wantRule, tt.wantMatched)
			}
			if decision.ResolvedPath == "" {
				t.Fatal("resolved path must always be reported")
			}
			if decision.Refused && decision.Reason == "" {
				t.Fatal("refusal must include an operator-facing reason")
			}
		})
	}
}

func TestExplainGuardPathFloorErrors(t *testing.T) {
	t.Parallel()

	if _, err := ExplainGuardPathFloor("relative/path", GuardAccessRead); err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("relative path error = %v", err)
	}
	if _, err := ExplainGuardPathFloor("/opt/app/config.yaml", GuardAccess("execute")); err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("unsupported access error = %v", err)
	}
}

func TestExplainGuardPathFloorUsesResolvedSymlinkForBothAccesses(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	target := filepath.Join(root, ".ssh")
	if err := os.Mkdir(target, 0o750); err != nil {
		t.Fatalf("create target: %v", err)
	}
	alias := filepath.Join(root, "innocuous")
	if err := os.Symlink(target, alias); err != nil {
		// A platform that refuses symlink creation for unprivileged users is
		// not a failure of the floor, it is a case that cannot run here.
		t.Skipf("symlink creation unsupported on this platform: %v", err)
	}
	for _, access := range []GuardAccess{GuardAccessRead, GuardAccessWrite} {
		t.Run(string(access), func(t *testing.T) {
			decision, err := ExplainGuardPathFloor(filepath.Join(alias, "id_ed25519"), access)
			if err != nil {
				t.Fatalf("ExplainGuardPathFloor: %v", err)
			}
			if !decision.Refused || decision.Rule != "forbidden_component" || decision.Matched != ".ssh" {
				t.Fatalf("resolved symlink decision = %+v", decision)
			}
		})
	}
}

func TestExplainGuardPathFloorValidatorAntiDrift(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		path     string
		access   GuardAccess
		wantRule string
	}{
		{name: "read_component", path: "/workspace/.docker/config.json", access: GuardAccessRead, wantRule: "forbidden_component"},
		{name: "read_whole_home", path: "/home/someoperator", access: GuardAccessRead, wantRule: "whole_home"},
		{name: "read_credential", path: "/home/someoperator/.netrc.old", access: GuardAccessRead, wantRule: "credential_path"},
		{name: "read_pipelock", path: "/home/someoperator/.config/pipelock/config.yaml", access: GuardAccessRead, wantRule: "forbidden_path_shape"},
		{name: "write_autostart", path: "/home/someoperator/.config/autostart/app.desktop", access: GuardAccessWrite, wantRule: "forbidden_path_shape"},
		{name: "write_whole_home", path: "/app", access: GuardAccessWrite, wantRule: "whole_home"},
		{name: "write_root", path: "/etc/systemd/system/app.service", access: GuardAccessWrite, wantRule: "dangerous_write_root"},
		{name: "write_credential", path: "/home/someoperator/.claude.json~", access: GuardAccessWrite, wantRule: "credential_path"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			decision, err := ExplainGuardPathFloor(tt.path, tt.access)
			if err != nil {
				t.Fatalf("ExplainGuardPathFloor: %v", err)
			}
			if !decision.Refused || decision.Rule != tt.wantRule {
				t.Fatalf("explain decision = %+v, want rule %q", decision, tt.wantRule)
			}

			if tt.access == GuardAccessRead {
				err = validateGuardROPath("guard.manifests[0]", "read_only", 0, tt.path)
			} else {
				err = validateGuardRWPath("guard.manifests[0]", "read_write", 0, tt.path)
			}
			if err == nil || !strings.Contains(err.Error(), decision.Reason) {
				t.Fatalf("validator did not enforce explain rule %q with the same reason: decision=%+v err=%v", decision.Rule, decision, err)
			}
		})
	}
}

func TestGuardInspectionValidationSeparatesStructureFloorAndRuntimeGate(t *testing.T) {
	t.Parallel()

	floorRefused := Defaults()
	floorRefused.Guard.Manifests = []GuardManifest{{
		Name:     "credentials",
		ReadOnly: []string{"/home/someoperator/.netrc"},
	}}
	if err := floorRefused.ValidateGuardStructure(); err != nil {
		t.Fatalf("structure-only validation must retain a floor-refused path for explanation: %v", err)
	}
	if err := floorRefused.ValidateGuardDeclaration(); err == nil || errors.Is(err, errGuardNotEnforced) || !strings.Contains(err.Error(), ".netrc") {
		t.Fatalf("declaration validation must enforce the path floor before the runtime gate: %v", err)
	}

	invalidStructure := Defaults()
	invalidStructure.Guard.Manifests = []GuardManifest{{
		Name:                "bad",
		ReadOnly:            []string{"/opt/app/Config"},
		ReadOnlyDirectories: []string{"/opt/app/config/"},
	}}
	for name, validate := range map[string]func() error{
		"structure":   invalidStructure.ValidateGuardStructure,
		"declaration": invalidStructure.ValidateGuardDeclaration,
	} {
		t.Run(name, func(t *testing.T) {
			err := validate()
			if err == nil || !strings.Contains(err.Error(), "conflicts") {
				t.Fatalf("invalid typed declaration must fail %s validation: %v", name, err)
			}
		})
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
			// Exercises both shapes deliberately, because this is the example a
			// reader copies. The plain lists are FILE grants, so a path that is
			// really a directory belongs in a *_directories list; declaring
			// /opt/app/config as a plain read_only would validate cleanly and
			// then fail to reach anything inside it once enforcement lands.
			{
				Name:                 "app-state",
				ReadOnly:             []string{"/opt/app/config/settings.yaml"},
				ReadOnlyDirectories:  []string{"/opt/app/config"},
				ReadWrite:            []string{"/var/lib/app/data/state.db"},
				ReadWriteDirectories: []string{"/var/lib/app/data"},
			},
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

func TestValidateGuard_PathTypes(t *testing.T) {
	t.Parallel()

	missingFile := filepath.Join(t.TempDir(), "state-file")
	missingDirectory := filepath.Join(t.TempDir(), "state-directory") + string(filepath.Separator)
	for _, path := range []string{missingFile, strings.TrimSuffix(missingDirectory, string(filepath.Separator))} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("test precondition: %q must not exist, got: %v", path, err)
		}
	}

	tests := []struct {
		name      string
		manifest  GuardManifest
		wantErr   string
		wantGate  bool
		noPathErr bool
	}{
		{
			name: "legacy_plain_paths_default_to_files",
			manifest: GuardManifest{
				Name:      "state",
				ReadOnly:  []string{missingFile},
				ReadWrite: []string{filepath.Join(t.TempDir(), "writable-state")},
			},
			wantGate:  true,
			noPathErr: true,
		},
		{
			name: "declared_directories_allow_trailing_separator",
			manifest: GuardManifest{
				Name:                 "state",
				ReadOnlyDirectories:  []string{missingDirectory},
				ReadWriteDirectories: []string{filepath.Join(t.TempDir(), "writable-state") + string(filepath.Separator)},
			},
			wantGate:  true,
			noPathErr: true,
		},
		{
			name: "file_with_trailing_separator_is_inconsistent",
			manifest: GuardManifest{
				Name:     "bad",
				ReadOnly: []string{"/var/lib/app/config/"},
			},
			wantErr: "file path",
		},
		{
			name: "directory_path_must_be_absolute",
			manifest: GuardManifest{
				Name:                "bad",
				ReadOnlyDirectories: []string{"relative/directory"},
			},
			wantErr: "absolute",
		},
		{
			name: "same_path_cannot_be_file_and_directory",
			manifest: GuardManifest{
				Name:                "bad",
				ReadOnly:            []string{"/var/lib/app/config"},
				ReadOnlyDirectories: []string{"/var/lib/app/config/"},
			},
			wantErr: "conflicts",
		},
		{
			name: "same_path_cannot_be_read_only_and_read_write",
			manifest: GuardManifest{
				Name:      "bad",
				ReadOnly:  []string{"/var/lib/app/config/settings.yaml"},
				ReadWrite: []string{"/var/lib/app/config/settings.yaml"},
			},
			wantErr: "only one grant list",
		},
		{
			name: "read_only_directory_still_hits_credential_floor",
			manifest: GuardManifest{
				Name:                "bad",
				ReadOnlyDirectories: []string{"/home/someoperator/.kube/"},
			},
			// Anchored on the protected component rather than on a word in the
			// prose. Which floor rule fires for a given path is an
			// implementation detail that can change without weakening
			// anything, and the assertion above already proves the refusal did
			// not come from the not-enforced gate.
			wantErr: ".kube",
		},
		{
			name: "read_write_directory_still_hits_credential_floor",
			manifest: GuardManifest{
				Name:                 "bad",
				ReadWriteDirectories: []string{"/home/someoperator/.kube/"},
			},
			wantErr: ".kube",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := Defaults()
			cfg.Guard = Guard{Manifests: []GuardManifest{tt.manifest}}
			err := cfg.Validate()
			if err == nil {
				t.Fatal("guard config must be rejected while the evaluator is absent")
			}
			if tt.wantGate && !errors.Is(err, errGuardNotEnforced) {
				t.Fatalf("declared path type must pass path validation and reach the gate, got: %v", err)
			}
			if tt.noPathErr && !errors.Is(err, errGuardNotEnforced) {
				t.Fatalf("path type validation must not depend on an absent path, got: %v", err)
			}
			if tt.wantErr != "" {
				if errors.Is(err, errGuardNotEnforced) {
					t.Fatalf("invalid declaration was refused only by the gate, not its path-type rule: %v", err)
				}
				if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tt.wantErr)) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
				}
			}
		})
	}
}

func TestGuardManifest_PathTypeYAMLSurface(t *testing.T) {
	t.Parallel()

	var cfg Config
	if err := yaml.Unmarshal([]byte(`
guard:
  manifests:
    - name: app-state
      read_only:
        - /etc/resolv.conf
      read_only_directories:
        - /var/lib/app/cache/
      read_write:
        - /var/lib/app/state.db
      read_write_directories:
        - /var/lib/app/data/
`), &cfg); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if len(cfg.Guard.Manifests) != 1 {
		t.Fatalf("manifests = %d, want 1", len(cfg.Guard.Manifests))
	}
	manifest := cfg.Guard.Manifests[0]
	if got, want := manifest.ReadOnly, []string{"/etc/resolv.conf"}; !slices.Equal(got, want) {
		t.Errorf("read_only = %q, want %q", got, want)
	}
	if got, want := manifest.ReadOnlyDirectories, []string{"/var/lib/app/cache/"}; !slices.Equal(got, want) {
		t.Errorf("read_only_directories = %q, want %q", got, want)
	}
	if got, want := manifest.ReadWrite, []string{"/var/lib/app/state.db"}; !slices.Equal(got, want) {
		t.Errorf("read_write = %q, want %q", got, want)
	}
	if got, want := manifest.ReadWriteDirectories, []string{"/var/lib/app/data/"}; !slices.Equal(got, want) {
		t.Errorf("read_write_directories = %q, want %q", got, want)
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

// TestValidateGuard_SecretMaterialRefusedBothDirections is the fail-closed half
// of the credential floor.
//
// Every path here is refused for READ as well as write. Read-only is not a
// safe posture for credential material under an agent threat model: a token
// does not need to be modified to be lost, and the copy leaves through any
// destination the workload is otherwise permitted to reach.
func TestValidateGuard_SecretMaterialRefusedBothDirections(t *testing.T) {
	t.Parallel()

	for _, path := range []string{
		// The credential file itself.
		"/home/someoperator/.aws/credentials",
		// .aws is refused whole, not just its credentials file: config carries
		// SSO settings and credential_process directives, and the sso/cli
		// caches hold live session tokens.
		"/home/someoperator/.aws/config",
		"/home/someoperator/.aws/sso/cache/abc123.json",
		"/home/someoperator/.azure/msal_token_cache.json",
		"/home/someoperator/.cargo/credentials.toml",
		"/home/someoperator/.terraform.d/credentials.tfrc.json",
		"/home/someoperator/.pulumi/credentials.json",
		"/home/someoperator/.config/containers/auth.json",
		"/home/someoperator/.claude/.credentials.json",
		"/home/someoperator/.cursor/mcp.json",
		"/home/someoperator/.gemini/oauth_creds.json",
		// Renamed copies. A credential file is routinely duplicated rather
		// than moved, and each copy carries the full credential under a name
		// no static list can predict. This case is drawn from a real
		// kubeconfig backup found holding client-certificate-data and
		// client-key-data beside a config the floor already refused.
		"/home/someoperator/.kube/config.pre-fedora-removal-20260703T1539",
		"/home/someoperator/.npmrc.bak",
		"/home/someoperator/.netrc.old",
		"/home/someoperator/.pypirc~",
		"/home/someoperator/.claude.json.orig",
		"/home/someoperator/.config/gh/hosts.yml.bak",
		// Regenerable caches inside a credential directory. Refused with the
		// directory rather than carved out, because the carve-out is what
		// would let a renamed credential beside them through.
		"/home/someoperator/.kube/cache",
		"/home/someoperator/.docker/buildx",
		"/home/someoperator/.kube/config",
		"/home/someoperator/.docker/config.json",
		"/home/someoperator/.npmrc",
		"/home/someoperator/.pypirc",
		"/home/someoperator/.netrc",
		"/home/someoperator/.git-credentials",
		"/home/someoperator/.config/gh/hosts.yml",
		"/home/someoperator/.config/gcloud/credentials.db",
		"/home/someoperator/.claude.json",
		"/home/someoperator/.codex/auth.json",
		"/Users/someoperator/.aws/credentials",
		"/root/.kube/config",
		// A directory that CONTAINS credential material. Under Landlock a
		// directory grant reaches the whole subtree, so permitting the parent
		// permits the secret; without this arm every entry above is decorative.
		"/home/someoperator/.aws",
		"/home/someoperator/.docker",
		"/home/someoperator/.kube",
		"/home/someoperator/.config/gh",
		"/home/someoperator/.config/gcloud",
		"/home/someoperator/.config",
		"/home/someoperator/.codex",
		// Roots sitting above every user home at once.
		"/home",
		"/Users",
		// Per-user runtime state. An SSH agent socket lives here, and reaching
		// it is full use of every loaded key without any key file being read,
		// so guarding ~/.ssh alone guards the copy and not the capability.
		// These were already refused for write as "socket path"; the read
		// direction is the one that matters for an agent socket.
		"/run/user",
		"/run/user/1000",
		"/run/user/1000/keyring/ssh",
		"/run/secrets/api-token",
		"/run", // ancestor of /run/user
	} {
		for _, mode := range []string{"read_only", "read_write"} {
			t.Run(mode+"_"+path, func(t *testing.T) {
				t.Parallel()
				m := GuardManifest{Name: "bad"}
				if mode == "read_only" {
					m.ReadOnly = []string{path}
				} else {
					m.ReadWrite = []string{path}
				}
				cfg := Defaults()
				cfg.Guard = Guard{Manifests: []GuardManifest{m}}

				err := cfg.Validate()
				if err == nil {
					t.Fatalf("%s on credential path %q must be rejected", mode, path)
				}
				// The rejection must come from a PATH rule. A bare err != nil
				// check passes with every rule in this file deleted, because
				// errGuardNotEnforced refuses any non-empty guard declaration.
				if errors.Is(err, errGuardNotEnforced) {
					t.Errorf("%s on %q was refused only by the not-enforced gate, so no path rule rejected it: %v", mode, path, err)
				}
			})
		}
	}
}

// TestValidateGuard_NonSecretNeighboursStillAllowed is the availability half of
// the credential floor.
//
// The ancestor rule refuses ~/.aws and ~/.config as whole directories, which is
// only tolerable because the specific non-secret paths beside the credential
// remain grantable. If these regressed, an operator could not express a working
// manifest for cargo, npm, docker or gh, and would switch guard off -- which on
// a security product costs nearly as much as permitting too much.
func TestValidateGuard_NonSecretNeighboursStillAllowed(t *testing.T) {
	t.Parallel()

	for _, path := range []string{
		"/home/someoperator/.config/myapp",                 // unrelated app config
		"/home/someoperator/.config/gcloud/configurations", // named configs, not the credential db
		"/home/someoperator/.cache/some-tool",
		"/home/someoperator/.cargo/registry",
		"/home/someoperator/.npm/_cacache", // the npm CACHE; the token lives in ~/.npmrc
		"/home/someoperator/projects/app",
		// A name that merely STARTS with a credential filename is not a
		// variant of it. The variant rule requires a separator after the
		// name, so these must stay grantable.
		"/home/someoperator/.npmrcfoo",
		"/home/someoperator/.netrcher",
	} {
		for _, mode := range []string{"read_only", "read_write"} {
			t.Run(mode+"_"+path, func(t *testing.T) {
				t.Parallel()
				m := GuardManifest{Name: "ok"}
				if mode == "read_only" {
					m.ReadOnly = []string{path}
				} else {
					m.ReadWrite = []string{path}
				}
				cfg := Defaults()
				cfg.Guard = Guard{Manifests: []GuardManifest{m}}

				err := cfg.Validate()
				if err == nil {
					t.Fatalf("guard is refused while unenforced; %q should still reach the gate", path)
				}
				if !errors.Is(err, errGuardNotEnforced) {
					t.Errorf("non-secret path %q must pass the %s path rules, got: %v", path, mode, err)
				}
			})
		}
	}
}

// TestValidateGuard_WholeHomeReadRefused pins the specific bypass that made the
// pre-existing .ssh refusal reachable-around: the write validator called
// guardIsHomeRoot and the read validator did not, so `read_only: [/home/x]`
// was accepted and carried ~/.ssh with it.
//
// This test asserts the MESSAGE, not merely that the path was refused, and the
// distinction is the whole point. The credential-material ancestor rule also
// refuses every path here (a home directory is an ancestor of ~/.aws/credentials),
// so an outcome-only assertion passes with the home-root arm deleted -- it was
// written that way first and proven vacuous by neutralizing the arm and watching
// it still pass. The home-root arm survives because it runs first and says
// "the entire home directory" instead of naming one incidental credential
// beneath it, which is the difference between an operator fixing the manifest
// and an operator adding an exception for AWS.
func TestValidateGuard_WholeHomeReadRefused(t *testing.T) {
	t.Parallel()

	for _, path := range []string{"/home/someoperator", "/Users/someoperator", "/root", "/"} {
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			cfg := Defaults()
			cfg.Guard = Guard{
				Manifests: []GuardManifest{{Name: "bad", ReadOnlyDirectories: []string{path}}},
			}
			err := cfg.Validate()
			if err == nil {
				t.Fatalf("read access to whole home %q must be rejected", path)
			}
			if errors.Is(err, errGuardNotEnforced) {
				t.Fatalf("read on %q was refused only by the not-enforced gate: %v", path, err)
			}
			if !strings.Contains(err.Error(), "entire home directory") {
				t.Errorf("read on %q must be refused as a whole-home grant, not incidentally by a credential rule, got: %v", path, err)
			}
		})
	}
}

// TestValidateGuard_RunSubtreesStillReadable is the availability half of the
// agent-socket rule.
//
// Read is asserted alone on purpose. The whole of /run has been refused for
// WRITE since the manifest rules landed, as a "socket path", so a both-modes
// assertion here would fail on a pre-existing rule that has nothing to do with
// credentials. Reading resolver config or an application's own runtime state
// is ordinary, so the credential rule must reach only the credential-bearing
// subtrees under /run rather than the whole directory.
func TestValidateGuard_RunSubtreesStillReadable(t *testing.T) {
	t.Parallel()

	for _, path := range []string{
		"/run/systemd/resolve/stub-resolv.conf",
		"/run/myapp/state",
	} {
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			cfg := Defaults()
			cfg.Guard = Guard{
				Manifests: []GuardManifest{{Name: "ok", ReadOnly: []string{path}}},
			}
			err := cfg.Validate()
			if err == nil {
				t.Fatalf("guard is refused while unenforced; %q should still reach the gate", path)
			}
			if !errors.Is(err, errGuardNotEnforced) {
				t.Errorf("non-credential runtime path %q must remain readable, got: %v", path, err)
			}
		})
	}
}

// TestValidateGuard_CredentialFloorIndependentOfHomeLayout closes the
// enumerated-home class.
//
// A deployment sets HOME to whatever it likes. Recognizing only /home, /Users,
// /root, /var/home and /app leaves the floor completely inert for a container
// using /workspace or /srv/agent, which is a straightforward bypass: declare
// /workspace/.aws and the credential is granted. Credential DIRECTORIES are
// therefore matched as path components wherever they appear, which is the idiom
// this file already used for .ssh, rather than by extending the layout list.
func TestValidateGuard_CredentialFloorIndependentOfHomeLayout(t *testing.T) {
	t.Parallel()

	for _, path := range []string{
		"/workspace/.aws/credentials",
		"/srv/agent/.kube/config",
		"/opt/anything/.docker/config.json",
		"/var/home/someoperator/.aws",
		"/app/.azure",
	} {
		for _, mode := range []string{"read_only", "read_write"} {
			t.Run(mode+"_"+path, func(t *testing.T) {
				t.Parallel()
				m := GuardManifest{Name: "bad"}
				if mode == "read_only" {
					m.ReadOnly = []string{path}
				} else {
					m.ReadWrite = []string{path}
				}
				cfg := Defaults()
				cfg.Guard = Guard{Manifests: []GuardManifest{m}}

				err := cfg.Validate()
				if err == nil {
					t.Fatalf("%s on %q must be rejected regardless of home layout", mode, path)
				}
				if errors.Is(err, errGuardNotEnforced) {
					t.Errorf("%s on %q was refused only by the not-enforced gate, so no path rule rejected it: %v", mode, path, err)
				}
			})
		}
	}
}

// TestValidateGuard_CredentialFloorIsCaseInsensitive covers case-insensitive
// volumes, where a differently-spelled path reaches the very same file.
//
// The comparison is folded rather than the input path, which matters: lowering
// the whole path first stops /Users from being recognized as a home root at
// all, silently disabling every home-relative rule instead of strengthening it.
func TestValidateGuard_CredentialFloorIsCaseInsensitive(t *testing.T) {
	t.Parallel()

	for _, path := range []string{
		"/Users/someoperator/.AWS/credentials",
		"/Users/someoperator/Library/application support/Claude/claude_desktop_config.json",
		"/home/someoperator/.NPMRC",
		"/home/someoperator/.Npmrc.bak",
		"/home/someoperator/.Kube/config",
		// The HOME ROOT itself, spelled differently. Detection has to fold as
		// well as the comparison downstream of it: an unrecognized root
		// returns no home at all, which switches every home-relative rule OFF
		// rather than merely loosening one.
		"/users/someoperator/.npmrc",
		"/Home/someoperator/.npmrc",
		"/users/someoperator",
		"/HOME",
	} {
		// Both grant modes. The two validators consult the credential floor
		// through separate call sites, so a fix applied to one does not cover
		// the other; asserting only the read side is what let the write side
		// drift out of parity once already.
		for _, mode := range []string{"read_only", "read_write"} {
			t.Run(mode+"_"+path, func(t *testing.T) {
				t.Parallel()
				m := GuardManifest{Name: "bad"}
				if mode == "read_only" {
					m.ReadOnly = []string{path}
				} else {
					m.ReadWrite = []string{path}
				}
				cfg := Defaults()
				cfg.Guard = Guard{Manifests: []GuardManifest{m}}

				err := cfg.Validate()
				if err == nil {
					t.Fatalf("%s on %q must be rejected on a case-insensitive volume", mode, path)
				}
				if errors.Is(err, errGuardNotEnforced) {
					t.Errorf("%s on %q was refused only by the not-enforced gate: %v", mode, path, err)
				}
			})
		}
	}
}

// TestValidateGuard_DeclaredPathRefusedWhenItResolvesElsewhere covers the
// declared-spelling half of the credential check.
//
// SCOPE, stated plainly: this proves the HELPER, not the call sites. Both
// validators must route through it, and the write validator did not, which is
// the regression this replaced. A test that drove the two validators instead
// was written first and proven VACUOUS: reproducing the divergence needs a
// symlink planted at a credential shape inside a real home directory, and for
// any path a hermetic test can name, resolution equals the declared spelling,
// so the buggy resolved-only form passes too. Call-site parity is therefore
// verified by inspection, not by this test. If a future change makes symlink
// resolution injectable, replace this with a real divergence test.
func TestValidateGuard_DeclaredPathRefusedWhenItResolvesElsewhere(t *testing.T) {
	t.Parallel()

	if guardDeclaredPathSecretMaterialReason("/home/someoperator/.npmrc", "/tmp/innocuous") == "" {
		t.Error("a declared credential path must be refused even when it resolves somewhere innocuous")
	}
	if guardDeclaredPathSecretMaterialReason("/tmp/innocuous", "/home/someoperator/.npmrc") == "" {
		t.Error("an innocuous-looking alias must be refused when it resolves into credential material")
	}
}

// TestValidateGuard_CaseEquivalentGrantsConflict covers the conflict key.
//
// filepath.Clean does not normalize case, so on a case-insensitive volume two
// spellings name one object. The dangerous pairing is read-only in one list and
// read-write in another: once the evaluator consumes both, the object resolves
// to the WIDER grant, so an intended read-only grant becomes writable without
// anything in the manifest looking wrong.
func TestValidateGuard_CaseEquivalentGrantsConflict(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		manifest GuardManifest
	}{
		{
			name: "read_only_and_read_write_case_variants",
			manifest: GuardManifest{
				Name:      "bad",
				ReadOnly:  []string{"/Users/someoperator/state"},
				ReadWrite: []string{"/users/someoperator/STATE"},
			},
		},
		{
			name: "file_and_directory_case_variants",
			manifest: GuardManifest{
				Name:                "bad",
				ReadOnly:            []string{"/var/lib/app/Config"},
				ReadOnlyDirectories: []string{"/var/lib/app/config/"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := Defaults()
			cfg.Guard = Guard{Manifests: []GuardManifest{tt.manifest}}
			err := cfg.Validate()
			if err == nil {
				t.Fatal("case-equivalent declarations of one object must be rejected")
			}
			if errors.Is(err, errGuardNotEnforced) {
				t.Fatalf("case-equivalent declarations were refused only by the not-enforced gate, so no path rule caught the conflict: %v", err)
			}
			if !strings.Contains(err.Error(), "conflicts") {
				t.Errorf("expected a conflict refusal, got: %v", err)
			}
		})
	}
}

// TestValidateGuard_ForbiddenComponentSurvivesSymlink covers the declared
// spelling half of the component floor.
//
// Resolving first and checking only the result is a fail-open. A path declared
// as a key or credential directory that symlinks somewhere innocuous resolves
// to a name carrying no forbidden component, so the floor saw nothing and
// allowed it for read and for write alike. Naming such a directory in a
// manifest is the thing being refused; where the link points today does not
// make the declaration safe, and the link can be repointed afterwards.
//
// This one IS reproducible in a hermetic test, unlike the credential-shape
// variant, because a forbidden component is matched anywhere in the path rather
// than relative to a home root, so a temp directory is enough to build it.
func TestValidateGuard_ForbiddenComponentSurvivesSymlink(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	target := filepath.Join(dir, "innocuous")
	if err := os.MkdirAll(target, 0o750); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	for _, name := range []string{".ssh", ".gnupg", ".aws", ".kube"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			link := filepath.Join(t.TempDir(), name)
			if err := os.Symlink(target, link); err != nil {
				t.Skipf("symlink creation unsupported on this platform: %v", err)
			}
			if err := validateGuardROPath("m", "read_only", 0, link); err == nil {
				t.Errorf("read grant on a %s symlink must be refused on the declared name", name)
			}
			if err := validateGuardRWPath("m", "read_write", 0, link); err == nil {
				t.Errorf("read-write grant on a %s symlink must be refused on the declared name", name)
			}
		})
	}

	// Availability control. An ordinary directory beside the symlinks must stay
	// grantable, so the declared-name check cannot be passing for a blanket
	// reason unrelated to the component.
	ordinary := filepath.Join(dir, "workspace")
	if err := os.MkdirAll(ordinary, 0o750); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := validateGuardROPath("m", "read_only", 0, ordinary); err != nil {
		t.Errorf("ordinary workspace path must remain grantable, got: %v", err)
	}
}
