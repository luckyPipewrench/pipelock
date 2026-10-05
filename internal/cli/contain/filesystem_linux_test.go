// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package contain

import (
	"context"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestFilesystemPropertyParity(t *testing.T) {
	in := enforceInput()
	in.DisplaySocket = "/tmp/.X11-unix/X99"
	lines, err := containLaunchPropertyLines(in)
	if err != nil {
		t.Fatal(err)
	}
	profile, err := filesystemProfileProperties(in)
	if err != nil {
		t.Fatal(err)
	}
	opts := containedAgentCommandOptions{
		ctx:           context.Background(),
		agentUserName: "pipelock-agent",
		homeDir:       "/srv/agent-home",
		uid:           966,
		gid:           966,
		display:       ":99",
		args:          []string{"claude"},
		filesystem:    profile,
	}
	cmd, _ := containedAgentPrivateTmpCommand(opts)
	var got []string
	for _, arg := range cmd.Args {
		rest, ok := strings.CutPrefix(arg, "--property=")
		if !ok {
			continue
		}
		if rest == "PrivateTmp=true" || rest == "PrivateNetwork=true" || strings.HasPrefix(rest, "JoinsNamespaceOf=") || strings.HasPrefix(rest, "SupplementaryGroups=") {
			continue
		}
		got = append(got, rest)
	}
	if strings.Join(got, "\n") != strings.Join(lines, "\n") {
		t.Fatalf("run properties:\n%s\nwrapper properties:\n%s", strings.Join(got, "\n"), strings.Join(lines, "\n"))
	}
}

func TestProbeFilesystemConfinement_OperatorCanaryVisibleFails(t *testing.T) {
	root := t.TempDir()
	secret := filepath.Join(root, "secret")
	if err := os.Mkdir(secret, 0o755); err != nil {
		t.Fatal(err)
	}
	prevRoot := filesystemCanaryRoot
	prevOp := filesystemOperatorCanaryParent
	prevWrite := filesystemWriteCanaryParent
	filesystemCanaryRoot = func() bool { return true }
	filesystemOperatorCanaryParent = root
	filesystemWriteCanaryParent = root
	t.Cleanup(func() {
		filesystemCanaryRoot = prevRoot
		filesystemOperatorCanaryParent = prevOp
		filesystemWriteCanaryParent = prevWrite
	})
	env := &probeEnv{
		agentUserName: "pipelock-agent",
		agentHome:     "/srv/agent-home",
		lookupUser: func(name string) (*user.User, error) {
			return &user.User{Uid: "966", Gid: "966", Username: name, HomeDir: "/srv/agent-home"}, nil
		},
		groupIDs: func(*user.User) ([]string, error) { return []string{"966"}, nil },
		filesystem: filesystemProfile{
			Mode: config.ContainmentFilesystemModeEnforce,
			Properties: []string{
				"ProtectSystem=strict",
				"InaccessiblePaths=" + secret,
			},
			BindPaths: []string{"/srv/agent-home:/srv/agent-home:norbind"},
		},
		runCmd: func(context.Context, string, ...string) (string, int, error) {
			return "", 11, nil
		},
	}
	status, detail := probeFilesystemConfinement(context.Background(), env)
	if status != statusFail || !strings.Contains(detail, "operator home canary was visible") {
		t.Fatalf("status=%s detail=%s", status, detail)
	}
}

func TestContainedLaunchWrapperHelperFailureAborts(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash is required to execute the rendered wrapper")
	}
	env, _, _ := newFakeEnv(t)
	dir := t.TempDir()
	marker := filepath.Join(dir, "helper-ran")
	helper := filepath.Join(dir, "pipelock")
	script := "#!/bin/bash\necho ran > " + marker + "\nexit 3\n"
	if err := os.WriteFile(helper, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	env.pipelockTarget = helper
	body := renderContainedLaunchWrapper(env)
	if !strings.Contains(body, helper) || !strings.Contains(body, "|| exit 1") || !strings.Contains(body, "property_args") {
		t.Fatalf("wrapper missing pinned helper or fail-closed capture:\n%s", body)
	}
	body = strings.Replace(body, `if [[ "$(`+containIDPath+` -u)" != "0" ]]; then`, "if false; then", 1)
	start := strings.Index(body, "if ! "+containSystemctlPath)
	if start < 0 {
		t.Fatalf("systemctl check missing:\n%s", body)
	}
	end := strings.Index(body[start:], "\n")
	body = body[:start] + "if false; then" + body[start+end:]
	path := filepath.Join(dir, "plk-contained-launch")
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bash, path)
	out, runErr := cmd.CombinedOutput()
	if runErr == nil {
		t.Fatalf("wrapper succeeded after helper failure: %s", out)
	}
	if _, statErr := os.Stat(marker); statErr != nil {
		t.Fatalf("helper did not run: %v\n%s", statErr, out)
	}
	if strings.Contains(string(out), "systemd-run") {
		t.Fatalf("wrapper continued to systemd-run after helper failure:\n%s", out)
	}
}

func enforceLifecycleRecord(fields map[string]string) containLifecycleRecord {
	fields["ProtectSystem"] = "strict"
	fields["ProtectHome"] = "tmpfs"
	fields["NoNewPrivileges"] = "yes"
	fields["BindReadOnlyPaths"] = ""
	fields["InaccessiblePaths"] = "/etc/pipelock/tls"
	fields["TemporaryFileSystem"] = "/dev/shm"
	fields["ProtectKernelTunables"] = "yes"
	fields["ProtectKernelModules"] = "yes"
	fields["ProtectControlGroups"] = "yes"
	record := containLifecycleRecord{
		FilesystemMode:                  config.ContainmentFilesystemModeEnforce,
		FilesystemInaccessiblePaths:     []string{"/etc/pipelock/tls"},
		FilesystemTemporaryFileSystem:   "/dev/shm",
		FilesystemProtectKernelTunables: "yes",
		FilesystemProtectKernelModules:  "yes",
		FilesystemProtectControlGroups:  "yes",
	}
	record.Unit = fields["Id"]
	record.RunID = strings.TrimPrefix(fields["Description"], lifecycleDescriptionPrefix)
	return record
}

func TestLifecycleOwned_ParsesGrantPathWithSpace(t *testing.T) {
	_, fields := lifecycleFixture()
	record := enforceLifecycleRecord(fields)
	record.FilesystemBindPaths = []string{"/srv/my proj:/srv/my proj:norbind"}
	fields["BindPaths"] = `"/srv/my proj":"/srv/my proj":norbind`
	if err := lifecycleOwned(fields, record, 966); err != nil {
		t.Fatal(err)
	}
	fields["BindPaths"] = `/srv/my proj:/srv/my proj:norbind`
	if err := lifecycleOwned(fields, record, 966); err != nil {
		t.Fatal(err)
	}
}

func TestLifecycleOwned_RejectsBindMismatch(t *testing.T) {
	_, fields := lifecycleFixture()
	record := enforceLifecycleRecord(fields)
	record.FilesystemBindPaths = []string{"/srv/agent-home:/srv/agent-home:norbind"}
	fields["BindPaths"] = "/srv/agent-home:/srv/agent-home:norbind"
	if err := lifecycleOwned(fields, record, 966); err != nil {
		t.Fatalf("matching binds: %v", err)
	}
	record.FilesystemBindPaths = []string{"/srv/other:/srv/other:norbind"}
	if err := lifecycleOwned(fields, record, 966); err == nil || !strings.Contains(err.Error(), "bind paths") {
		t.Fatalf("mismatch error = %v", err)
	}
}

func TestLifecycleOwned_RejectsFilesystemPropertyMismatch(t *testing.T) {
	tests := []struct {
		name string
		edit func(map[string]string, *containLifecycleRecord)
		want string
	}{
		{
			name: "inaccessible paths",
			edit: func(fields map[string]string, _ *containLifecycleRecord) {
				fields["InaccessiblePaths"] = "/etc/pipelock/integrity"
			},
			want: "inaccessible paths",
		},
		{
			name: "temporary filesystem",
			edit: func(fields map[string]string, _ *containLifecycleRecord) {
				fields["TemporaryFileSystem"] = "/run/shm"
			},
			want: "temporary filesystem",
		},
		{
			name: "kernel tunables",
			edit: func(fields map[string]string, _ *containLifecycleRecord) {
				fields["ProtectKernelTunables"] = "no"
			},
			want: "kernel protection",
		},
		{
			name: "kernel modules",
			edit: func(fields map[string]string, _ *containLifecycleRecord) {
				fields["ProtectKernelModules"] = "no"
			},
			want: "kernel protection",
		},
		{
			name: "control groups",
			edit: func(fields map[string]string, _ *containLifecycleRecord) {
				fields["ProtectControlGroups"] = "no"
			},
			want: "kernel protection",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, fields := lifecycleFixture()
			record := enforceLifecycleRecord(fields)
			fields["BindPaths"] = ""
			if err := lifecycleOwned(fields, record, 966); err != nil {
				t.Fatalf("matching profile: %v", err)
			}
			tt.edit(fields, &record)
			err := lifecycleOwned(fields, record, 966)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want substring %q", err, tt.want)
			}
		})
	}
}
