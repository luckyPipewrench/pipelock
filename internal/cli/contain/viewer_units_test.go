// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"errors"
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

func TestViewerProvisionFailuresAndRollback(t *testing.T) {
	for _, tc := range []struct {
		name, command, want             string
		failRead, failWrite, failRemove bool
	}{
		{name: "read service", failRead: true, want: "read failed"},
		{name: "inspect enabled", command: "systemctl is-enabled pipelock-contain-viewer.service", want: "command failed"},
		{name: "inspect active", command: "systemctl is-active pipelock-contain-viewer.service", want: "command failed"},
		{name: "reload", command: "systemctl daemon-reload", want: "command failed"},
		{name: "enable", command: "systemctl enable --now pipelock-contain-viewer.service", want: "command failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env, runner, _ := newFakeEnv(t)
			env.displayUnitPath = filepath.Join(filepath.Dir(env.systemUnitPath), "display.service")
			env.displayEnabled = true
			yes := true
			env.displayConfig = config.ContainmentDisplay{Backend: "xvnc", Viewer: config.ContainmentDisplayViewer{Enabled: &yes, OperatorUser: "operator"}}
			if tc.failRead {
				env.readFile = func(string) ([]byte, error) { return nil, errors.New("read failed") }
			}
			if tc.command != "" {
				runner.on(tc.command, "", 1, errors.New("command failed"))
			}
			_, err := stepProvisionViewer().apply(context.Background(), env)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("provision error = %v, want %q", err, tc.want)
			}
		})
	}

	t.Run("active service restart and restore", func(t *testing.T) {
		env, runner, _ := newFakeEnv(t)
		env.displayUnitPath = filepath.Join(filepath.Dir(env.systemUnitPath), "display.service")
		env.displayEnabled = true
		yes := true
		env.displayConfig = config.ContainmentDisplay{Backend: "xvnc", Viewer: config.ContainmentDisplayViewer{Enabled: &yes, OperatorUser: "operator"}}
		service, socket := viewerUnitPaths(env)
		old := displayUnitMarker + "\n[Service]\nDescription=old\n"
		for _, path := range []string{service, socket} {
			if err := os.WriteFile(path, []byte(old), 0o600); err != nil {
				t.Fatal(err)
			}
			runner.on("systemctl is-enabled "+filepath.Base(path), "enabled\n", 0, nil)
			runner.on("systemctl is-active "+filepath.Base(path), "active\n", 0, nil)
		}
		step := stepProvisionViewer()
		changed, err := step.apply(context.Background(), env)
		if err != nil || !changed {
			t.Fatalf("apply changed=%v err=%v", changed, err)
		}
		if !runnerSaw(runner, "systemctl restart "+filepath.Base(service)) {
			t.Fatal("active viewer was not restarted")
		}
		if err := step.undo(context.Background(), env); err != nil {
			t.Fatal(err)
		}
		for _, path := range []string{service, socket} {
			body, err := os.ReadFile(path)
			if err != nil || string(body) != old {
				t.Fatalf("restored %s = %q, %v", path, body, err)
			}
			if !runnerSaw(runner, "systemctl start "+filepath.Base(path)) {
				t.Fatalf("%s was not restarted", path)
			}
		}
	})
}

func TestViewerRemovalRejectsForeignBackupAndCommandFailure(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	env.displayUnitPath = filepath.Join(filepath.Dir(env.systemUnitPath), "display.service")
	service, _ := viewerUnitPaths(env)
	if err := os.WriteFile(service+".bak", []byte("[Service]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := actionRemoveViewer().undo(context.Background(), env)
	if err == nil || !strings.Contains(err.Error(), "not Pipelock-managed") {
		t.Fatalf("foreign backup error = %v", err)
	}
	if _, err := os.Stat(service + ".bak"); err != nil {
		t.Fatalf("foreign backup was removed: %v", err)
	}
	runner.on("systemctl stop "+filepath.Base(service), "", 1, errors.New("stop failed"))
	err = actionRemoveViewer().undo(context.Background(), env)
	if err == nil || !strings.Contains(err.Error(), "stop failed") {
		t.Fatalf("stop error = %v", err)
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

func TestViewerInstallDisableAndRestore(t *testing.T) {
	for _, tc := range []struct {
		name, priorService, priorSocket string
		wantChanged                     bool
	}{
		{name: "nothing installed"},
		{name: "remove managed service", priorService: displayUnitMarker + "\n[Service]\n", wantChanged: true},
		{name: "remove legacy socket", priorSocket: displayUnitMarker + "\n[Socket]\n", wantChanged: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env, runner, _ := newFakeEnv(t)
			env.displayUnitPath = filepath.Join(filepath.Dir(env.systemUnitPath), "pipelock-agent-display.service")
			service, socket := viewerUnitPaths(env)
			for path, body := range map[string]string{service: tc.priorService, socket: tc.priorSocket} {
				if body != "" {
					if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
						t.Fatal(err)
					}
				}
			}
			step := stepProvisionViewer()
			changed, err := step.apply(context.Background(), env)
			if err != nil || changed != tc.wantChanged {
				t.Fatalf("disable: changed=%v err=%v", changed, err)
			}
			for _, path := range []string{service, socket} {
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Fatalf("%s remains: %v", path, err)
				}
			}
			if tc.wantChanged && !runnerSaw(runner, "systemctl daemon-reload") {
				t.Fatal("manager was not reloaded")
			}
			if err := step.undo(context.Background(), env); err != nil {
				t.Fatal(err)
			}
			for path, body := range map[string]string{service: tc.priorService, socket: tc.priorSocket} {
				got, err := os.ReadFile(filepath.Clean(path))
				if body == "" {
					if !os.IsNotExist(err) {
						t.Fatalf("%s created after rollback: %v", path, err)
					}
				} else if err != nil || string(got) != body {
					t.Fatalf("%s restored as %q: %v", path, got, err)
				}
			}
		})
	}
}

func TestViewerInstallRefusesForeignUnit(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	env.displayUnitPath = filepath.Join(filepath.Dir(env.systemUnitPath), "pipelock-agent-display.service")
	service, _ := viewerUnitPaths(env)
	if err := os.WriteFile(service, []byte("[Service]\nExecStart=/other\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	changed, err := stepProvisionViewer().apply(context.Background(), env)
	if changed || err == nil || !strings.Contains(err.Error(), "not Pipelock-managed") {
		t.Fatalf("foreign unit: changed=%v err=%v", changed, err)
	}
	got, err := os.ReadFile(filepath.Clean(service))
	if err != nil || string(got) != "[Service]\nExecStart=/other\n" {
		t.Fatalf("foreign unit altered: %q, %v", got, err)
	}
}
