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
			if got.status == statusFail && !strings.Contains(got.remediation, "contain install") {
				t.Fatalf("unusable remedy: %+v", got)
			}
			if tc.showCode != 0 && (!strings.Contains(got.remediation, "restore access to systemctl") || strings.Contains(got.remediation, "contain install")) {
				t.Fatalf("command failure got reinstall remedy: %+v", got)
			}
		})
	}
}
