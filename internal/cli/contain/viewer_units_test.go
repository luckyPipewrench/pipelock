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

func TestViewerServiceUnitUsesControlSocket(t *testing.T) {
	yes := true
	env := &installEnv{agentHome: "/srv/agents/current", agentUserName: "agent", proxyUserName: "proxy", pipelockTarget: "/usr/local/bin/pipelock", displayNumber: 99, displayConfig: config.ContainmentDisplay{Viewer: config.ContainmentDisplayViewer{Enabled: &yes, OperatorUser: "operator"}}}
	unit := renderViewerServiceUnit(env)
	for _, want := range []string{"User=proxy", "--agent-user agent", "--operator-user operator", "RuntimeDirectory=pipelock-contain-viewer", "ProtectSystem=strict"} {
		if !strings.Contains(unit, want) {
			t.Errorf("service missing %q", want)
		}
	}
	for _, absent := range []string{"--origin", "Requires=pipelock-contain-viewer.socket", "ListenStream="} {
		if strings.Contains(unit, absent) {
			t.Errorf("service retains %q", absent)
		}
	}
}

func TestViewerInstallRemovesLegacySocketUnit(t *testing.T) {
	env, runner, out := newFakeEnv(t)
	env.displayUnitPath = filepath.Join(filepath.Dir(env.systemUnitPath), "pipelock-agent-display.service")
	env.agentHome = "/home/agent"
	env.displayNumber = 99
	env.displayEnabled = true
	yes := true
	env.displayConfig = config.ContainmentDisplay{Viewer: config.ContainmentDisplayViewer{Enabled: &yes, OperatorUser: "operator"}}
	service, socket := viewerUnitPaths(env)
	legacy := displayUnitMarker + "\n[Socket]\nListenStream=/run/legacy.sock\n"
	if err := os.WriteFile(socket, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := runSteps(context.Background(), env, out, []step{stepProvisionViewer()}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(service); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(socket); !os.IsNotExist(err) {
		t.Fatalf("legacy socket unit remains: %v", err)
	}
	if !runnerSaw(runner, "systemctl disable --now "+filepath.Base(socket)) {
		t.Fatal("legacy socket was not stopped")
	}
	if !runnerSaw(runner, "systemctl enable --now "+filepath.Base(service)) {
		t.Fatal("viewer service was not enabled")
	}
}
