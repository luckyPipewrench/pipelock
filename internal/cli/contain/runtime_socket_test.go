// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package contain

import (
	"slices"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestContainedLaunchHidesHostRuntimeSockets(t *testing.T) {
	args := privateTmpSystemdRunArgs(1000, 1000, nil, "/home/agent", "", nil, []string{"true"}, false, true, "")
	for _, property := range []string{
		"--property=TemporaryFileSystem=/run:ro",
		"--property=TemporaryFileSystem=/dev/shm:rw,nosuid,nodev,noexec",
	} {
		if !slices.Contains(args, property) {
			t.Errorf("missing runtime isolation property %q", property)
		}
	}
}

func TestManagedRuntimeSocketProperties(t *testing.T) {
	env := &installEnv{agentUserName: "agent", agentHome: "/home/agent", displayNumber: 99}
	wrapper := renderContainedLaunchWrapper(env)
	for _, property := range runtimeSocketProperties() {
		value := strings.TrimPrefix(property, "BindReadOnlyPaths=")
		if !strings.Contains(wrapper, property) && !strings.Contains(wrapper, "BindReadOnlyPaths='"+value+"'") {
			t.Errorf("installed wrapper missing %s", property)
		}
	}
	units := []string{
		renderContainedNamespaceForwarderUnit("/usr/bin/pipelock", "agent", 8888),
		renderDeclaredLoopbackNamespaceForwarderUnit("/usr/bin/pipelock", "agent", config.ContainmentLoopbackService{Host: "127.0.0.1", Port: 3000}),
		renderAgentDisplayUnit(env),
	}
	for _, unit := range units {
		if !strings.Contains(unit, "TemporaryFileSystem=/run:ro\n") {
			t.Errorf("managed helper lacks runtime isolation:\n%s", unit)
		}
	}
}

func TestRuntimeSocketDirectoriesCannotBeWorkspaceBinds(t *testing.T) {
	for _, path := range []string{"/run", "/run/systemd", "/var/run", "/var/run/service", "/dev/shm", "/dev/shm/service"} {
		if err := refuseFilesystemBind("workspace", path, path); err == nil {
			t.Errorf("runtime directory grant accepted: %s", path)
		}
	}
	for _, path := range []string{"/srv/work", "/runtime-cache", "/var/runtime"} {
		if err := refuseFilesystemBind("workspace", path, path); err != nil {
			t.Errorf("ordinary workspace rejected: %v", err)
		}
	}
}

func TestRuntimeSocketMountsForRunPath(t *testing.T) {
	for _, resolved := range []string{"/run", "/var/run", "/srv/runtime", ""} {
		properties := runtimeSocketMountsForRunPath(resolved)
		if got := slices.Contains(properties, "TemporaryFileSystem=/var/run:ro"); got != (resolved != "/run") {
			t.Errorf("resolved %q: separate runtime mount = %v", resolved, got)
		}
		if !slices.Contains(properties, "TemporaryFileSystem=/run:ro") {
			t.Fatal("primary runtime mount missing")
		}
	}
}
