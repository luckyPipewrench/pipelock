// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package contain

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestDocumentedOperatorUnitRuntimeMountParity(t *testing.T) {
	doc, err := os.ReadFile(filepath.Clean("../../../docs/contain-cli.md"))
	if err != nil {
		t.Fatal(err)
	}
	var unit string
	for _, block := range strings.Split(string(doc), "```") {
		if strings.Contains(block, "ExecStartPre=!/usr/local/bin/pipelock contain service-posture") {
			unit = block
			break
		}
	}
	if unit == "" {
		t.Fatal("documented operator unit was not found")
	}
	for _, property := range runtimeSocketProperties() {
		if property == "TemporaryFileSystem=/var/run:ro" {
			if !strings.Contains(string(doc), "add `"+property+"`") {
				t.Errorf("separate /var/run mount instructions missing: %s", property)
			}
			continue
		}
		if !strings.Contains(unit, "\n"+property+"\n") {
			t.Errorf("operator unit differs from runtime properties: %s", property)
		}
	}
}

func TestDoorwayForwardersBindDedicatedDirectory(t *testing.T) {
	services := []struct{ socket, forwarder, path string }{
		{renderContainedProxySocketUnit("agent"), renderContainedNamespaceForwarderUnit("/usr/bin/pipelock", "agent", 8888), containedDoorwaySocketPath},
	}
	for _, host := range []string{"127.0.0.1", "::1"} {
		service := config.ContainmentLoopbackService{Host: host, Port: 3000}
		services = append(services, struct{ socket, forwarder, path string }{renderDeclaredLoopbackSocketUnit("agent", service), renderDeclaredLoopbackNamespaceForwarderUnit("/usr/bin/pipelock", "agent", service), declaredLoopbackDoorwayPath(host, 3000)})
	}
	parents := make(map[string]bool)
	for _, service := range services {
		parent := filepath.Dir(service.path)
		if parents[parent] {
			t.Errorf("independent doorways share a grant directory: %s", parent)
		}
		parents[parent] = true
		if parent == "/run" {
			t.Errorf("doorway lacks dedicated directory: %s", service.path)
		}
		if !strings.Contains(service.socket, "ListenStream="+service.path+"\n") || !strings.Contains(service.forwarder, "--target "+service.path+"\n") {
			t.Errorf("doorway producers and consumers disagree: %s", service.path)
		}
		if !strings.Contains(service.forwarder, "BindReadOnlyPaths="+parent+"\n") || strings.Contains(service.forwarder, "BindReadOnlyPaths="+service.path+"\n") {
			t.Errorf("forwarder pins replaceable socket inode: %s", service.path)
		}
	}
}

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
