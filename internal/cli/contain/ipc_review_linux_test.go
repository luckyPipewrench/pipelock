// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package contain

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestLifecycleRuntimeMountsInEveryFilesystemMode(t *testing.T) {
	var mounts []string
	for _, property := range runtimeSocketMountProperties() {
		mounts = append(mounts, strings.TrimPrefix(property, "TemporaryFileSystem="))
	}
	for _, mode := range []string{config.ContainmentFilesystemModeOff, config.ContainmentFilesystemModeEnforce} {
		t.Run(mode, func(t *testing.T) {
			_, fields := lifecycleFixture()
			record := enforceLifecycleRecord(fields)
			record.FilesystemMode = mode
			record.FilesystemTemporaryFileSystem = strings.Join(mounts, " ")
			fields["TemporaryFileSystem"] = record.FilesystemTemporaryFileSystem
			l, _ := lifecycleFixture()
			l.record = record
			bindLifecycleFixture(l, fields)
			backend := lifecycleTestBackend(fields)
			backend.binds = func(context.Context, string) ([]systemdBindEntry, []systemdBindEntry, error) { return nil, nil, nil }
			if err := lifecycleFilesystemOwned(fields, record, nil); err != nil {
				t.Fatalf("emitted mounts rejected: %v", err)
			}
			if err := lifecycleFilesystemAdmission(t.Context(), backend, l, 966); err != nil {
				t.Fatalf("emitted mounts failed admission: %v", err)
			}
			for _, changed := range []string{"", "/dev/shm", "/run:rw /dev/shm:rw,nosuid,nodev,noexec", "/run:ro /dev/shm:rw"} {
				fields["TemporaryFileSystem"] = changed
				if err := lifecycleFilesystemOwned(fields, record, nil); err == nil {
					t.Errorf("accepted missing/changed runtime mount %q", changed)
				}
				if err := lifecycleFilesystemAdmission(t.Context(), backend, l, 966); err == nil {
					t.Errorf("consumer admitted missing/changed runtime mount %q", changed)
				}
			}
		})
	}
}

func TestLaunchRecordsRuntimeMountsWithFilesystemOff(t *testing.T) {
	l, fields := lifecycleFixture()
	fields["LoadState"] = "not-found"
	opts := containedAgentCommandOptions{ctx: t.Context(), args: []string{"tool"}, uid: 966, filesystem: filesystemProfile{Mode: config.ContainmentFilesystemModeOff}}
	err := launchContainedAgentLifecycleWithBackend(opts, l, lifecycleTestBackend(fields), func(containedAgentCommandOptions) (*exec.Cmd, string) {
		if l.record.FilesystemTemporaryFileSystem != strings.Join(runtimeSocketTemporaryFileSystems(), " ") {
			t.Fatalf("runtime mounts were not recorded before starting client: %+v", l.record)
		}
		return exec.CommandContext(t.Context(), "/no/such/pipelock-launch-helper"), ""
	})
	if err == nil {
		t.Fatal("missing helper started")
	}
}

func TestDoctorRuntimeSocketUnits(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "pipelock.yaml")
	data := []byte("containment:\n  loopback_services:\n    - host: 127.0.0.1\n      port: 3000\n      owner: operator\n      reason: synthetic service test\n      expires_at: \"" + farFutureExpiry() + "\"\n  display:\n    enabled: true\n    backend: xvnc\n")
	if err := os.WriteFile(configPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	units := []string{containedNamespaceForwarderUnit, loopbackForwarderUnitBase("127.0.0.1", 3000) + "-netns.service", filepath.Base(defaultDisplayUnitPath)}
	for _, stale := range append([]string{""}, units...) {
		t.Run(stale, func(t *testing.T) {
			seen := make(map[string]bool)
			env := &doctorEnv{wrapperDir: root, configPath: configPath, port: defaultProxyPort}
			env.readFile = func(path string) ([]byte, error) {
				if path == filepath.Join(root, "plk-contained-launch") {
					return []byte(renderContainedLaunchWrapper(&installEnv{wrapperDir: root, networkNamespaceUnitPath: containedNetworkNamespaceUnit})), nil
				}
				return os.ReadFile(filepath.Clean(path))
			}
			env.runCmd = func(_ context.Context, name string, args ...string) (string, int, error) {
				if name != "systemctl" || len(args) != 4 || args[0] != "show" || args[2] != "--property=TemporaryFileSystem" || args[3] != "--value" {
					t.Fatalf("unexpected unit probe: %s %v", name, args)
				}
				seen[args[1]] = true
				if args[1] == stale {
					return "/dev/shm", 0, nil
				}
				return strings.Join(runtimeSocketTemporaryFileSystems(), " "), 0, nil
			}
			got := checkRuntimeSocketIsolation(t.Context(), env)
			if stale != "" {
				if got.status != statusFail || !strings.Contains(got.detail, stale) {
					t.Fatalf("stale unit result = %+v", got)
				}
				return
			}
			if got.status != statusPass {
				t.Fatalf("current units result = %+v", got)
			}
			for _, unit := range units {
				if !seen[unit] {
					t.Errorf("did not inspect managed unit %s", unit)
				}
			}
		})
	}
}

func TestDoctorRuntimeSocketIsolation(t *testing.T) {
	var check func(context.Context, *doctorEnv) doctorResult
	for _, candidate := range allDoctorChecks() {
		if candidate.name == "runtime_socket_isolation" {
			check = candidate.fn
		}
	}
	if check == nil {
		t.Fatal("doctor has no runtime socket isolation check")
	}
	wrapper := renderContainedLaunchWrapper(&installEnv{wrapperDir: "/fixture", networkNamespaceUnitPath: containedNetworkNamespaceUnit})
	var mounts []string
	for _, property := range runtimeSocketMountProperties() {
		mounts = append(mounts, strings.TrimPrefix(property, "TemporaryFileSystem="))
	}
	for _, tc := range []struct {
		name, body, mounts, want string
		readErr, showErr         error
		showCode                 int
	}{
		{name: "current", body: wrapper, mounts: strings.Join(mounts, " "), want: statusPass},
		{name: "stale wrapper", body: strings.ReplaceAll(wrapper, "  --property=TemporaryFileSystem=/run:ro", ""), mounts: strings.Join(mounts, " "), want: statusFail},
		{name: "comment only", body: "# --property=TemporaryFileSystem=/run:ro\n", mounts: strings.Join(mounts, " "), want: statusFail},
		{name: "stale unit", body: wrapper, mounts: "/dev/shm", want: statusFail},
		{name: "missing wrapper", readErr: os.ErrNotExist, want: statusFail},
		{name: "unreadable wrapper", readErr: os.ErrPermission, want: statusUnknown},
		{name: "unreadable unit", body: wrapper, showErr: errors.New("manager unavailable"), want: statusUnknown},
		{name: "denied unit without Go error", body: wrapper, mounts: "Access denied", showCode: 1, want: statusUnknown},
		{name: "failed unit with mount output", body: wrapper, mounts: strings.Join(mounts, " "), showCode: 1, want: statusUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := &doctorEnv{wrapperDir: "/fixture", readFile: func(path string) ([]byte, error) {
				if path != "/fixture/plk-contained-launch" {
					return nil, os.ErrNotExist
				}
				return []byte(tc.body), tc.readErr
			}, runCmd: func(context.Context, string, ...string) (string, int, error) {
				return tc.mounts, tc.showCode, tc.showErr
			}}
			got := check(t.Context(), env)
			if got.status != tc.want {
				t.Fatalf("result = %+v, want %s", got, tc.want)
			}
			if (got.status == statusFail || tc.readErr != nil) && !strings.Contains(got.remediation, "contain install") {
				t.Fatalf("unusable remedy: %+v", got)
			}
			if tc.showCode != 0 && (!strings.Contains(got.remediation, "restore access to systemctl") || strings.Contains(got.remediation, "contain install")) {
				t.Fatalf("command failure got reinstall remedy: %+v", got)
			}
		})
	}
}

func TestReviewDoctorUnusedFlagsReproduction(t *testing.T) {
	wrapper := renderContainedLaunchWrapper(&installEnv{wrapperDir: "/fixture", networkNamespaceUnitPath: containedNetworkNamespaceUnit})
	env := &doctorEnv{
		wrapperDir: "/fixture",
		readFile: func(path string) ([]byte, error) {
			if path != "/fixture/plk-contained-launch" {
				return nil, os.ErrNotExist
			}
			return []byte(wrapper), nil
		},
		runCmd: func(context.Context, string, ...string) (string, int, error) {
			return strings.Join(runtimeSocketTemporaryFileSystems(), " "), 0, nil
		},
	}
	if got := probeDoctorRuntimeSockets(t.Context(), env); got.status != statusPass {
		t.Fatalf("generated wrapper positive control = %+v", got)
	}
	// The properties remain in an unused array, but the actual invocation
	// omits them. Their presence alone must not establish runtime isolation.
	wrapper = strings.ReplaceAll(wrapper, `exec /usr/bin/systemd-run "${systemd_args[@]}" "$@"`, `exec /usr/bin/systemd-run --wait --collect -- "$@"`)
	got := probeDoctorRuntimeSockets(t.Context(), env)
	if got.status != statusFail || !strings.Contains(got.remediation, "contain install") {
		t.Fatalf("unused properties result = %+v, want FAIL with install remedy", got)
	}
}

func TestDoctorRuntimeSocketWrapperTemplate(t *testing.T) {
	env := &doctorEnv{
		wrapperDir:     "/fixture",
		pipelockTarget: "/fixture/pipelock",
		agentUserName:  "fixture-agent",
		agentHome:      "/fixture/agent home",
		bashPath:       "/usr/bin/bash",
	}
	installed := &installEnv{
		wrapperDir:               env.wrapperDir,
		networkNamespaceUnitPath: containedNetworkNamespaceUnit,
		pipelockTarget:           env.pipelockTarget,
		agentUserName:            env.agentUserName,
		agentHome:                env.agentHome,
		bashPath:                 env.bashPath,
	}
	legacy := renderContainedLaunchWrapper(installed)
	installed.systemdVersion = systemdExpandEnvironmentMinVersion
	current := renderContainedLaunchWrapper(installed)
	const invocation = `exec /usr/bin/systemd-run "${systemd_args[@]}" "$@"`
	for _, tc := range []struct {
		name, body string
		want       bool
	}{
		{name: "legacy systemd", body: legacy, want: true},
		{name: "current systemd", body: current, want: true},
		{name: "unused properties", body: strings.ReplaceAll(current, invocation, `exec /usr/bin/systemd-run -- "$@"`)},
		{name: "cleared array", body: strings.ReplaceAll(current, invocation, "systemd_args=()\n"+invocation)},
		{name: "unreachable invocation", body: strings.ReplaceAll(current, invocation, "exit 0\n"+invocation)},
		{name: "uninvoked function", body: "#!/usr/bin/bash\nunused() {\n" + current + "\n}\n"},
		{name: "different interpreter", body: strings.ReplaceAll(current, "#!/usr/bin/bash", "#!/usr/bin/false")},
		{name: "different target", body: strings.ReplaceAll(current, "'/fixture/pipelock'", "'/fixture/other'")},
		{name: "different home", body: strings.ReplaceAll(current, "'/fixture/agent home'", "'/fixture/other home'")},
		{name: "missing identity bind", body: strings.ReplaceAll(current, "  --property=BindReadOnlyPaths="+containedNamespaceIdentityPath, "")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := doctorContainedLaunchWrapperMatches([]byte(tc.body), env.wrapperDir, env); got != tc.want {
				t.Fatalf("template match = %v, want %v", got, tc.want)
			}
		})
	}
}
