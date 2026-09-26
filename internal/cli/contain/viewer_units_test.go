// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestViewerUnitsAndNestedHomeACL(t *testing.T) {
	yes := true
	env := &installEnv{agentHome: "/srv/agents/current", agentUserName: "agent", proxyUserName: "proxy", pipelockTarget: "/usr/local/bin/pipelock", displayNumber: 99, xvncPath: "/usr/bin/Xvnc", displayUnitPath: "/etc/systemd/system/pipelock-agent-display.service", displayConfig: config.ContainmentDisplay{Viewer: config.ContainmentDisplayViewer{Enabled: &yes, OperatorUser: "operator", PublicOrigin: "https://viewer.example"}}}
	display := renderAgentDisplayUnit(env)
	for _, path := range []string{"/srv/agents/current", "/srv/agents/current/.local", "/srv/agents/current/.local/state", "/srv/agents/current/.local/state/pipelock", "/srv/agents/current/.local/state/pipelock/display"} {
		if !strings.Contains(display, "u:proxy:--x \""+path+"\"") {
			t.Errorf("missing traverse ACL on %s", path)
		}
	}
	if !strings.Contains(display, "u:proxy:rw,g::---,o::---,m::rw \"$2\"") {
		t.Fatal("socket ACL absent from ExecStartPost")
	}
	service := renderViewerServiceUnit(env)
	for _, want := range []string{"User=proxy", "--agent-user agent", "--operator-user operator", "--origin https://viewer.example", "ProtectSystem=strict", "ProtectHome=read-only", "RuntimeDirectory=pipelock-contain-viewer"} {
		if !strings.Contains(service, want) {
			t.Errorf("service missing %q", want)
		}
	}
	socket := renderViewerSocketUnit(env.displayConfig.Viewer)
	for _, want := range []string{"ListenStream=/run/pipelock-contain-published/viewer.sock", "SocketUser=operator", "SocketMode=0600", "RemoveOnStop=true"} {
		if !strings.Contains(socket, want) {
			t.Errorf("socket missing %q", want)
		}
	}
	a, b := viewerUnitPaths(env)
	if filepath.Base(a) != viewerUnitBase+".service" || filepath.Base(b) != viewerUnitBase+".socket" {
		t.Fatal(a, b)
	}
}

func TestViewerInstallAndFailureCleanup(t *testing.T) {
	for _, failStart := range []bool{false, true} {
		t.Run(map[bool]string{false: "enable and disable", true: "failed start"}[failStart], func(t *testing.T) {
			env, runner, out := newFakeEnv(t)
			env.displayUnitPath = filepath.Join(filepath.Dir(env.systemUnitPath), "pipelock-agent-display.service")
			env.agentHome = "/home/agent"
			env.displayNumber = 99
			env.displayEnabled = true
			shown := true
			env.displayConfig = config.ContainmentDisplay{Viewer: config.ContainmentDisplayViewer{Enabled: &shown, OperatorUser: "operator", PublicOrigin: "https://viewer.example"}}
			service, socket := viewerUnitPaths(env)
			if failStart {
				runner.on(argvFor("systemctl", "start", filepath.Base(service)), "failed", 1, nil)
			}
			_, err := runSteps(context.Background(), env, out, []step{stepProvisionViewer()})
			if failStart {
				if err == nil {
					t.Fatal("service start failure accepted")
				}
				for _, path := range []string{service, socket} {
					if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
						t.Fatalf("failed install left %s: %v", path, statErr)
					}
				}
				if !runnerSaw(runner, "systemctl disable --now "+filepath.Base(socket)) {
					t.Fatal("failed install did not stop listening socket")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			for _, path := range []string{service, socket} {
				if _, statErr := os.Stat(path); statErr != nil {
					t.Fatal(statErr)
				}
			}
			env.displayConfig.Viewer.PublicOrigin = "https://updated.example"
			_, err = runSteps(context.Background(), env, out, []step{stepProvisionViewer()})
			if err != nil {
				t.Fatal("rerun: ", err)
			}
			shown = false
			env.displayConfig.Viewer.Enabled = &shown
			_, err = runSteps(context.Background(), env, out, []step{stepProvisionViewer()})
			if err != nil {
				t.Fatal("disable: ", err)
			}
			for _, path := range []string{service, socket} {
				if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
					t.Fatalf("disable left %s: %v", path, statErr)
				}
				if _, statErr := os.Stat(path + ".bak"); !os.IsNotExist(statErr) {
					t.Fatalf("disable left backup %s: %v", path, statErr)
				}
			}
		})
	}
}
