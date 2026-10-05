// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func allowEval(paths ...string) func(string) (string, bool, error) {
	allowed := map[string]struct{}{}
	for _, p := range paths {
		allowed[p] = struct{}{}
	}
	return func(p string) (string, bool, error) {
		if _, ok := allowed[p]; !ok {
			return "", false, errors.New("missing")
		}
		return p, true, nil
	}
}

func existsAll(paths ...string) func(string) (bool, error) {
	allowed := map[string]struct{}{}
	for _, p := range paths {
		allowed[p] = struct{}{}
	}
	return func(p string) (bool, error) {
		_, ok := allowed[p]
		return ok, nil
	}
}

func enforceInput() filesystemProfileInput {
	return filesystemProfileInput{
		Mode:             config.ContainmentFilesystemModeEnforce,
		AgentUser:        "pipelock-agent",
		AgentHome:        "/srv/agent-home",
		OperatorHome:     "/home/operator",
		ConfigDir:        "/etc/pipelock",
		DataDir:          "/var/lib/pipelock",
		Eval:             allowEval("/srv/agent-home"),
		Exists:           func(string) (bool, error) { return false, nil },
		Now:              time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC),
		PostureProofPath: "/var/lib/pipelock/contain/posture/proof.json",
	}
}

func TestFilesystemProfileProperties_Modes(t *testing.T) {
	tests := []struct {
		name    string
		mode    string
		wantErr bool
		want    string
	}{
		{name: "omitted", mode: "", want: config.ContainmentFilesystemModeOff},
		{name: "blank", mode: "  ", want: config.ContainmentFilesystemModeOff},
		{name: "off", mode: "off", want: config.ContainmentFilesystemModeOff},
		{name: "enforce", mode: "enforce", want: config.ContainmentFilesystemModeEnforce},
		{name: "invalid", mode: "sometimes", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := enforceInput()
			in.Mode = tt.mode
			got, err := filesystemProfileProperties(in)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected refusal")
				}
				return
			}
			if err != nil {
				t.Fatalf("profile: %v", err)
			}
			if got.Mode != tt.want {
				t.Fatalf("mode = %q, want %q", got.Mode, tt.want)
			}
			if tt.want == config.ContainmentFilesystemModeOff && len(got.Properties) != 0 {
				t.Fatalf("off mode properties = %v", got.Properties)
			}
		})
	}
}

func TestFilesystemProfileProperties_EnforceBindsGrantsAndSecrets(t *testing.T) {
	in := enforceInput()
	in.DisplaySocket = "/tmp/.X11-unix/X99"
	in.Grants = []workspaceGrant{
		{Path: "/srv/rw", Mode: workspaceModeReadWrite, AgentUser: "pipelock-agent"},
		{Path: "/srv/ro", Mode: workspaceModeReadOnly, AgentUser: "pipelock-agent"},
		{Path: "/srv/other", Mode: workspaceModeReadWrite, AgentUser: "other-agent"},
		{Path: "/srv/expired", Mode: workspaceModeReadWrite, AgentUser: "pipelock-agent", Expires: "2020-01-01T00:00:00Z"},
	}
	in.Eval = allowEval("/srv/agent-home", "/srv/rw", "/srv/ro", "/srv/other", "/srv/expired")
	in.Exists = existsAll(
		"/etc/pipelock/integrity",
		"/etc/pipelock/tls",
		"/etc/pipelock/keys/flight-recorder-signing.key",
		"/etc/pipelock/keys/mediation-envelope-signing.key",
		"/etc/pipelock/learn-privacy-salt",
		"/var/lib/pipelock/recorder",
		"/var/lib/pipelock/captures",
		"/var/lib/pipelock/baselines",
		"/var/lib/pipelock/contracts",
		"/var/lib/pipelock/quarantine",
		"/var/lib/pipelock/logs",
		"/var/lib/pipelock/rules",
	)
	got, err := filesystemProfileProperties(in)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"ProtectSystem=strict",
		"ProtectHome=tmpfs",
		"BindPaths=/srv/agent-home:/srv/agent-home:norbind",
		"BindPaths=/srv/rw:/srv/rw:norbind",
		"BindReadOnlyPaths=/srv/ro:/srv/ro:norbind",
		"BindReadOnlyPaths=/tmp/.X11-unix/X99",
		"NoNewPrivileges=true",
		"InaccessiblePaths=/etc/pipelock/integrity",
		"InaccessiblePaths=/etc/pipelock/tls",
		"InaccessiblePaths=/etc/pipelock/keys/flight-recorder-signing.key",
		"TemporaryFileSystem=/dev/shm",
		"ProtectKernelTunables=true",
		"ProtectKernelModules=true",
		"ProtectControlGroups=true",
	} {
		if !sliceContains(got.Properties, want) {
			t.Fatalf("missing %s in %v", want, got.Properties)
		}
	}
	for _, forbidden := range []string{"/srv/other", "/srv/expired", "RestrictNamespaces", "SystemCallFilter", "MemoryDenyWriteExecute", "PrivateDevices", "ProcSubset", "UMask", "/var/lib/pipelock/contain"} {
		for _, prop := range got.Properties {
			if strings.Contains(prop, forbidden) {
				t.Fatalf("property %s contains %s", prop, forbidden)
			}
		}
	}
	if !sliceContains(got.BindReadOnlyPaths, "/tmp/.X11-unix/X99:/tmp/.X11-unix/X99:rbind") {
		t.Fatalf("read-only binds = %v", got.BindReadOnlyPaths)
	}
	lines, err := containLaunchPropertyLines(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(lines, "\n") != strings.Join(got.Properties, "\n") {
		t.Fatalf("launch lines differ from profile\nlines=%v\nprops=%v", lines, got.Properties)
	}
}

func TestFilesystemProfileProperties_Refusals(t *testing.T) {
	tests := []struct {
		name string
		edit func(*filesystemProfileInput)
		want string
	}{
		{
			name: "expired grant is not bound",
			edit: func(in *filesystemProfileInput) {
				in.Grants = []workspaceGrant{{Path: "/srv/expired", Mode: workspaceModeReadWrite, Expires: "2020-01-01T00:00:00Z"}}
				in.Eval = allowEval("/srv/agent-home", "/srv/expired")
			},
			want: "",
		},
		{
			name: "malformed expiry",
			edit: func(in *filesystemProfileInput) {
				in.Grants = []workspaceGrant{{Path: "/srv/bad", Mode: workspaceModeReadWrite, Expires: "tomorrow"}}
			},
			want: "/srv/bad",
		},
		{
			name: "colon path",
			edit: func(in *filesystemProfileInput) {
				in.Grants = []workspaceGrant{{Path: "/srv/bad:path", Mode: workspaceModeReadWrite}}
			},
			want: "cannot be represented safely",
		},
		{
			name: "root",
			edit: func(in *filesystemProfileInput) {
				in.Grants = []workspaceGrant{{Path: "/", Mode: workspaceModeReadWrite}}
			},
			want: "workspace grant",
		},
		{
			name: "home root",
			edit: func(in *filesystemProfileInput) {
				in.Grants = []workspaceGrant{{Path: "/home", Mode: workspaceModeReadOnly}}
			},
			want: "/home",
		},
		{
			name: "root home",
			edit: func(in *filesystemProfileInput) {
				in.Grants = []workspaceGrant{{Path: "/root", Mode: workspaceModeReadWrite}}
			},
			want: "/root",
		},
		{
			name: "run user",
			edit: func(in *filesystemProfileInput) {
				in.Grants = []workspaceGrant{{Path: "/run/user", Mode: workspaceModeReadWrite}}
			},
			want: "/run/user",
		},
		{
			name: "parent of operator home",
			edit: func(in *filesystemProfileInput) {
				in.Grants = []workspaceGrant{{Path: "/home/operator", Mode: workspaceModeReadWrite}}
				in.Eval = allowEval("/srv/agent-home", "/home/operator")
			},
			want: "operator home",
		},
		{
			name: "agent home contains operator home",
			edit: func(in *filesystemProfileInput) {
				in.AgentHome = "/home"
				in.Eval = allowEval("/home")
			},
			want: "agent home",
		},
		{
			name: "missing directory",
			edit: func(in *filesystemProfileInput) {
				in.Grants = []workspaceGrant{{Path: "/srv/missing", Mode: workspaceModeReadWrite}}
			},
			want: "/srv/missing",
		},
		{
			name: "symlink escapes to root",
			edit: func(in *filesystemProfileInput) {
				in.Grants = []workspaceGrant{{Path: "/srv/link", Mode: workspaceModeReadWrite}}
				in.Eval = func(p string) (string, bool, error) {
					if p == "/srv/link" {
						return "/", true, nil
					}
					if p == "/srv/agent-home" {
						return p, true, nil
					}
					return "", false, errors.New("missing")
				}
			},
			want: "workspace grant",
		},
		{
			name: "relative grant",
			edit: func(in *filesystemProfileInput) {
				in.Grants = []workspaceGrant{{Path: "relative", Mode: workspaceModeReadWrite}}
			},
			want: "absolute",
		},
		{
			name: "unknown grant mode",
			edit: func(in *filesystemProfileInput) {
				in.Grants = []workspaceGrant{{Path: "/srv/rw", Mode: "write"}}
			},
			want: "workspace grant",
		},
		{
			name: "missing signing key",
			edit: func(in *filesystemProfileInput) {
				in.RequiredSecretPaths = []string{"/etc/pipelock/keys/custom.key"}
			},
			want: "custom.key",
		},
		{
			name: "newline path",
			edit: func(in *filesystemProfileInput) {
				in.Grants = []workspaceGrant{{Path: "/srv/bad\npath", Mode: workspaceModeReadWrite}}
			},
			want: "cannot be represented safely",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := enforceInput()
			tt.edit(&in)
			got, err := filesystemProfileProperties(in)
			if tt.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				for _, prop := range got.Properties {
					if strings.Contains(prop, "/srv/expired") {
						t.Fatalf("expired grant was bound: %v", got.Properties)
					}
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want substring %q", err, tt.want)
			}
		})
	}
}

func TestFilesystemProfileProperties_SkipsInaccessibleParentOfProof(t *testing.T) {
	in := enforceInput()
	in.PostureProofPath = "/var/lib/pipelock/recorder/proof.json"
	in.Exists = existsAll("/var/lib/pipelock/recorder", "/etc/pipelock/tls")
	got, err := filesystemProfileProperties(in)
	if err != nil {
		t.Fatal(err)
	}
	for _, prop := range got.Properties {
		if strings.Contains(prop, "InaccessiblePaths=/var/lib/pipelock/recorder") {
			t.Fatalf("hid the posture proof parent: %v", got.Properties)
		}
	}
	if !sliceContains(got.Properties, "InaccessiblePaths=/etc/pipelock/tls") {
		t.Fatalf("missing tls hide: %v", got.Properties)
	}
}

func TestFilesystemProfileProperties_RefusesOperatorHomeOutsideHomeOrRoot(t *testing.T) {
	in := enforceInput()
	in.OperatorHome = "/srv/operator"
	_, err := filesystemProfileProperties(in)
	if err == nil || !strings.Contains(err.Error(), "/srv/operator") || !strings.Contains(err.Error(), "under /home or /root") {
		t.Fatalf("err = %v", err)
	}
	for _, home := range []string{"/home/operator", "/root", "/root/operator"} {
		in.OperatorHome = home
		if _, err := filesystemProfileProperties(in); err != nil {
			t.Fatalf("operator home %s: %v", home, err)
		}
	}
	in.OperatorHome = "/run/user/1000"
	if _, err := filesystemProfileProperties(in); err == nil || !strings.Contains(err.Error(), "/run/user/1000") {
		t.Fatalf("err = %v", err)
	}
}

func TestFilesystemProfileProperties_RequiredKeyCannotParentReadablePath(t *testing.T) {
	in := enforceInput()
	in.RequiredSecretPaths = []string{"/etc/pipelock"}
	in.Exists = existsAll("/etc/pipelock", "/srv/agent-home")
	_, err := filesystemProfileProperties(in)
	if err == nil || !strings.Contains(err.Error(), "signing key") {
		t.Fatalf("error = %v, want a signing-key refusal", err)
	}
}

func TestFilesystemBindsDigest_OffIsEmpty(t *testing.T) {
	profile, err := filesystemProfileProperties(filesystemProfileInput{Mode: "off"})
	if err != nil {
		t.Fatal(err)
	}
	if got := filesystemBindsDigest(profile); got != "" {
		t.Fatalf("digest = %q, want empty", got)
	}
}

func TestFilesystemCanaryOutcome_OperatorVisibleFails(t *testing.T) {
	status, detail := filesystemCanaryOutcome(11, "")
	if status != statusFail || !strings.Contains(detail, "operator home canary was visible") {
		t.Fatalf("status=%s detail=%s", status, detail)
	}
	if status, _ := filesystemCanaryOutcome(0, ""); status != statusPass {
		t.Fatalf("exit 0 status = %s", status)
	}
}

func TestProbeFilesystemConfinement_OffIsNotPassOrSkip(t *testing.T) {
	env := &probeEnv{filesystem: filesystemProfile{Mode: config.ContainmentFilesystemModeOff}}
	status, detail := probeFilesystemConfinement(context.Background(), env)
	if status != statusFilesystemOff || detail != "filesystem profile: off" {
		t.Fatalf("status=%s detail=%s", status, detail)
	}
	if status == statusPass || status == statusSkip {
		t.Fatal("off must not read as confinement or a skipped probe")
	}
}

func TestContainLaunchPropertyLines_OffKeepsDisplaySocketOnly(t *testing.T) {
	in := enforceInput()
	in.Mode = config.ContainmentFilesystemModeOff
	in.DisplaySocket = "/tmp/.X11-unix/X99"
	lines, err := containLaunchPropertyLines(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 1 || lines[0] != "BindReadOnlyPaths=/tmp/.X11-unix/X99" {
		t.Fatalf("lines = %v", lines)
	}
}

func TestParseSystemdBindShow(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		want    []string
		wantErr bool
	}{
		{name: "empty", value: "  ", want: nil},
		{
			name:  "colon triples",
			value: `/srv/rw:/srv/rw:norbind /tmp/.X11-unix/X99:/tmp/.X11-unix/X99:rbind`,
			want:  []string{"/srv/rw:/srv/rw:norbind", "/tmp/.X11-unix/X99:/tmp/.X11-unix/X99:rbind"},
		},
		{
			name:  "dbus tuples",
			value: `/srv/rw /srv/rw no 0 /tmp/.X11-unix/X99 /tmp/.X11-unix/X99 no 16384`,
			want:  []string{"/srv/rw:/srv/rw:norbind", "/tmp/.X11-unix/X99:/tmp/.X11-unix/X99:rbind"},
		},
		{
			name:  "quoted path",
			value: `"/srv/my proj" "/srv/my proj" false 0`,
			want:  []string{"/srv/my proj:/srv/my proj:norbind"},
		},
		{name: "ignore missing", value: "/srv/rw /srv/rw yes 0", wantErr: true},
		{name: "incomplete", value: "/srv/rw /srv/rw no", wantErr: true},
		{name: "mixed", value: "/srv/rw:/srv/rw:norbind /srv/rw /srv/rw no 0", wantErr: true},
		{name: "unknown flag", value: "/srv/rw /srv/rw no 7", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseSystemdBindShow(tt.value)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected parse error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !sameBindList(got, tt.want) {
				t.Fatalf("binds = %v, want %v", got, tt.want)
			}
		})
	}
}

func sliceContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
