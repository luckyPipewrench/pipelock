// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package contain

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

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

func withFilesystemCanaryRoot(t *testing.T, root string) {
	t.Helper()
	prevRoot := filesystemCanaryRoot
	prevOp := filesystemOperatorCanaryParent
	prevState := filesystemStateCanaryParent
	filesystemCanaryRoot = func() bool { return true }
	filesystemOperatorCanaryParent = root
	filesystemStateCanaryParent = root
	t.Cleanup(func() {
		filesystemCanaryRoot = prevRoot
		filesystemOperatorCanaryParent = prevOp
		filesystemStateCanaryParent = prevState
	})
}

func filesystemCanaryEnv(run func(context.Context, string, ...string) (string, int, error)) *probeEnv {
	return &probeEnv{
		agentUserName: "pipelock-agent",
		agentHome:     "/srv/agent-home",
		lookupUser: func(name string) (*user.User, error) {
			return &user.User{Uid: "966", Gid: "966", Username: name, HomeDir: "/srv/agent-home"}, nil
		},
		groupIDs: func(*user.User) ([]string, error) { return []string{"966"}, nil },
		filesystem: filesystemProfile{
			Mode:       config.ContainmentFilesystemModeEnforce,
			Properties: []string{"ProtectSystem=strict", "InaccessiblePaths=/etc/pipelock/tls"},
			BindPaths:  []string{"/srv/agent-home:/srv/agent-home:norbind"},
		},
		runCmd: run,
	}
}

func TestProbeFilesystemConfinement_OperatorCanaryVisibleFails(t *testing.T) {
	root := t.TempDir()
	withFilesystemCanaryRoot(t, root)
	sawSecretHide := false
	env := filesystemCanaryEnv(func(_ context.Context, _ string, args ...string) (string, int, error) {
		joined := strings.Join(args, "\n")
		if !strings.Contains(joined, "ProtectSystem=strict") {
			return "", 0, nil
		}
		if strings.Contains(joined, "InaccessiblePaths=") && strings.Contains(joined, ".pipelock-fs-secret-") {
			sawSecretHide = true
		}
		return "", 11, nil
	})
	status, detail := probeFilesystemConfinement(context.Background(), env)
	if status != statusFail || !strings.Contains(detail, "operator home canary was visible") {
		t.Fatalf("status=%s detail=%s", status, detail)
	}
	if !sawSecretHide {
		t.Fatal("confined unit did not hide the probe-owned secret directory")
	}
}

func TestOmittedFilesystemCanaryRejectsBaselineFailure(t *testing.T) {
	root := t.TempDir()
	withFilesystemCanaryRoot(t, root)
	calls := 0
	env := filesystemCanaryEnv(func(context.Context, string, ...string) (string, int, error) {
		calls++
		return "", -1, errors.New("baseline service unavailable")
	})
	env.filesystemCanaryOmitProperties = true
	status, detail := probeFilesystemConfinement(context.Background(), env)
	if status != statusFail || calls != 1 || filesystemUnconfinedCanaryFailure(detail) {
		t.Fatalf("status=%s calls=%d detail=%s", status, calls, detail)
	}

	calls = 0
	env = filesystemCanaryEnv(func(_ context.Context, _ string, args ...string) (string, int, error) {
		calls++
		if strings.Contains(strings.Join(args, "\n"), "ProtectSystem=strict") {
			t.Fatal("omitted properties still applied the filesystem profile")
		}
		if calls == 1 {
			return "", 0, nil
		}
		return "", 11, nil
	})
	env.filesystemCanaryOmitProperties = true
	status, detail = probeFilesystemConfinement(context.Background(), env)
	if status != statusFail || calls != 2 || !filesystemUnconfinedCanaryFailure(detail) {
		t.Fatalf("status=%s calls=%d detail=%s", status, calls, detail)
	}
}

func TestProbeFilesystemConfinement_BaselineMustSeeCanaries(t *testing.T) {
	root := t.TempDir()
	withFilesystemCanaryRoot(t, root)
	env := filesystemCanaryEnv(func(_ context.Context, _ string, args ...string) (string, int, error) {
		if !strings.Contains(strings.Join(args, "\n"), "ProtectSystem=strict") {
			return "", 21, nil
		}
		return "", 0, nil
	})
	status, detail := probeFilesystemConfinement(context.Background(), env)
	if status != statusFail || !strings.Contains(detail, "not a valid proof") {
		t.Fatalf("status=%s detail=%s", status, detail)
	}
}

func TestProbeFilesystemConfinement_WorkspaceSymlinkIsNotFollowed(t *testing.T) {
	root := t.TempDir()
	withFilesystemCanaryRoot(t, root)
	victim := filepath.Join(root, "victim")
	if err := os.Mkdir(victim, 0o750); err != nil {
		t.Fatal(err)
	}
	grant := filepath.Join(root, "grant")
	if err := os.Symlink(victim, grant); err != nil {
		t.Fatal(err)
	}
	env := filesystemCanaryEnv(func(context.Context, string, ...string) (string, int, error) {
		t.Fatal("canary ran after a symlink workspace")
		return "", 0, nil
	})
	env.filesystem.BindPaths = append(env.filesystem.BindPaths, grant+":"+grant+":norbind")
	status, detail := probeFilesystemConfinement(context.Background(), env)
	entries, err := os.ReadDir(victim)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("canary followed the workspace symlink: %v", entries)
	}
	if status != statusFail {
		t.Fatalf("status=%s detail=%s", status, detail)
	}
}

func TestProbeFilesystemConfinement_CanaryModeIgnoresUmask(t *testing.T) {
	root := t.TempDir()
	withFilesystemCanaryRoot(t, root)
	old := unix.Umask(0o077)
	t.Cleanup(func() { unix.Umask(old) })
	var sawDir, sawFile bool
	env := filesystemCanaryEnv(func(_ context.Context, _ string, args ...string) (string, int, error) {
		if sawDir && sawFile {
			return "", 0, nil
		}
		entries, err := os.ReadDir(root)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			info, err := entry.Info()
			if err != nil {
				t.Fatal(err)
			}
			name := entry.Name()
			switch {
			case strings.HasPrefix(name, ".pipelock-fs-canary-"), strings.HasPrefix(name, ".pipelock-fs-secret-"):
				if info.Mode().Perm() != 0o755 {
					t.Fatalf("%s mode = %o", name, info.Mode().Perm())
				}
				sawDir = true
				file, err := os.ReadDir(filepath.Join(root, name))
				if err != nil {
					t.Fatal(err)
				}
				if len(file) != 1 {
					t.Fatalf("%s entries = %v", name, file)
				}
				finfo, err := file[0].Info()
				if err != nil {
					t.Fatal(err)
				}
				if finfo.Mode().Perm() != 0o644 {
					t.Fatalf("%s mode = %o", file[0].Name(), finfo.Mode().Perm())
				}
				sawFile = true
			case strings.HasPrefix(name, ".pipelock-fs-write-"):
				if info.Mode().Perm() != 0o777 || info.Mode()&os.ModeSticky == 0 {
					t.Fatalf("write canary mode = %o", info.Mode())
				}
			}
		}
		if !strings.Contains(strings.Join(args, "\n"), "ProtectSystem=strict") {
			return "", 0, nil
		}
		return "", 0, nil
	})
	status, detail := probeFilesystemConfinement(context.Background(), env)
	if !sawDir || !sawFile {
		t.Fatalf("canary modes were not observed, status=%s detail=%s", status, detail)
	}
	if status != statusPass {
		t.Fatalf("status=%s detail=%s", status, detail)
	}
}

func TestFilesystemStateCanaryParentIsVarLib(t *testing.T) {
	if filesystemStateCanaryParent != "/var/lib" {
		t.Fatalf("write canary parent = %s", filesystemStateCanaryParent)
	}
}

func TestDoctorEnforceReachesFilesystemCanary(t *testing.T) {
	root := t.TempDir()
	withFilesystemCanaryRoot(t, root)
	agentHome := t.TempDir()
	configDir := t.TempDir()
	called := 0
	env := &doctorEnv{
		configPath:       filepath.Join(configDir, "pipelock.yaml"),
		configDir:        configDir,
		agentUserName:    "pipelock-agent",
		agentHome:        agentHome,
		operatorUser:     "operator",
		workspaceInvPath: filepath.Join(configDir, "workspaces.json"),
		lookupUser: func(name string) (*user.User, error) {
			home := agentHome
			uid := "966"
			if name == "operator" {
				home = "/home/operator"
				uid = "1000"
			}
			return &user.User{Username: name, Uid: uid, Gid: uid, HomeDir: home}, nil
		},
		groupIDs: func(*user.User) ([]string, error) { return []string{"966"}, nil },
		now:      time.Now,
		readFile: func(path string) ([]byte, error) {
			if strings.HasSuffix(path, "pipelock.yaml") {
				return []byte("containment:\n  filesystem:\n    mode: enforce\n  display:\n    enabled: false\n"), nil
			}
			return nil, os.ErrNotExist
		},
		runCmd: func(context.Context, string, ...string) (string, int, error) {
			called++
			return "", 0, nil
		},
	}
	result := checkFilesystemConfinement(context.Background(), env)
	if called == 0 || strings.Contains(result.detail, "operator home is required") || result.status != statusPass {
		t.Fatalf("called=%d result=%+v", called, result)
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
	if err := os.WriteFile(helper, []byte(script), 0o700); err != nil { //nolint:gosec // G306: this test executes the stub it just wrote
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
	if err := os.WriteFile(path, []byte(body), 0o700); err != nil { //nolint:gosec // G306: this test executes the wrapper it just wrote
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bash, path) //nolint:gosec // G204: bash is LookPath's result and the script is the temp file this test wrote
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
	if err := lifecycleFilesystemOwned(fields, record, nil); err != nil {
		t.Fatal(err)
	}
	fields["BindPaths"] = `/srv/my proj:/srv/my proj:norbind`
	if err := lifecycleFilesystemOwned(fields, record, nil); err != nil {
		t.Fatal(err)
	}
}

func TestLifecycleOwned_RejectsBindMismatch(t *testing.T) {
	_, fields := lifecycleFixture()
	record := enforceLifecycleRecord(fields)
	record.FilesystemBindPaths = []string{"/srv/agent-home:/srv/agent-home:norbind"}
	fields["BindPaths"] = "/srv/agent-home:/srv/agent-home:norbind"
	if err := lifecycleFilesystemOwned(fields, record, nil); err != nil {
		t.Fatalf("matching binds: %v", err)
	}
	record.FilesystemBindPaths = []string{"/srv/other:/srv/other:norbind"}
	if err := lifecycleFilesystemOwned(fields, record, nil); err == nil || !strings.Contains(err.Error(), "bind paths") {
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
			if err := lifecycleFilesystemOwned(fields, record, nil); err != nil {
				t.Fatalf("matching profile: %v", err)
			}
			tt.edit(fields, &record)
			err := lifecycleFilesystemOwned(fields, record, nil)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want substring %q", err, tt.want)
			}
		})
	}
}
