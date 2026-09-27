// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestViewerServiceUnitUsesControlSocket(t *testing.T) {
	yes := true
	env := &installEnv{agentHome: "/srv/agents/current", agentUserName: "agent", proxyUserName: "proxy", pipelockTarget: "/usr/local/bin/pipelock", displayNumber: 99, displayConfig: config.ContainmentDisplay{Viewer: config.ContainmentDisplayViewer{Enabled: &yes, OperatorUser: "operator"}}}
	unit := renderViewerServiceUnit(env)
	for _, want := range []string{"User=pipelock-viewer", "Group=pipelock-viewer", "--agent-user agent", "--operator-user operator", "RuntimeDirectory=pipelock-contain-viewer", "ProtectSystem=strict"} {
		if !strings.Contains(unit, want) {
			t.Errorf("service missing %q", want)
		}
	}
	if strings.Contains(unit, "User=proxy") || strings.Contains(unit, "/srv/agents/current/") {
		t.Fatal("viewer still uses proxy identity or an agent-home socket")
	}
	for _, absent := range []string{"--origin", "Requires=pipelock-contain-viewer.socket", "ListenStream="} {
		if strings.Contains(unit, absent) {
			t.Errorf("service retains %q", absent)
		}
	}
}

func TestViewerOperatorIdentityRejectsSharedUID(t *testing.T) {
	yes := true
	for _, name := range []string{"agent", "proxy", viewerUserName} {
		t.Run(name, func(t *testing.T) {
			env := &installEnv{agentUserName: "agent", proxyUserName: "proxy", displayConfig: config.ContainmentDisplay{Viewer: config.ContainmentDisplayViewer{Enabled: &yes, OperatorUser: "operator"}}}
			env.lookupUser = func(got string) (*user.User, error) {
				uid := got
				if got == name {
					uid = "operator"
				}
				return &user.User{Uid: uid}, nil
			}
			if err := checkViewerOperatorIdentity(env); err == nil || !strings.Contains(err.Error(), "distinct identity") {
				t.Fatalf("shared UID with %s accepted: %v", name, err)
			}
		})
	}
}

func TestViewerOperatorIdentityRejectsPrimaryViewerGroup(t *testing.T) {
	yes := true
	env := &installEnv{agentUserName: "agent", proxyUserName: "proxy", displayConfig: config.ContainmentDisplay{Viewer: config.ContainmentDisplayViewer{Enabled: &yes, OperatorUser: "operator"}}}
	env.lookupUser = func(name string) (*user.User, error) {
		if name == viewerUserName {
			return &user.User{Uid: "900", Gid: "901"}, nil
		}
		if name == "operator" {
			return &user.User{Uid: "1000", Gid: "901"}, nil
		}
		return &user.User{Uid: "1001", Gid: "1001"}, nil
	}
	if err := checkViewerOperatorIdentity(env); err == nil || !strings.Contains(err.Error(), "primary group") {
		t.Fatalf("operator primary viewer group accepted: %v", err)
	}
}

func TestViewerIdentityProvisioning(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	env.displayUnitPath = filepath.Join(t.TempDir(), "display.service")
	runner.on("id -nG "+env.proxyUserName, env.proxyUserName+" "+viewerUserName+"\n", 0, nil)
	if _, err := stepCreateViewerUser().apply(context.Background(), env); err == nil || !strings.Contains(err.Error(), "proxy account") {
		t.Fatalf("proxy viewer-group membership accepted: %v", err)
	}
	runner.on("id -nG "+env.proxyUserName, env.proxyUserName+"\n", 0, nil)
	runner.on("id -u "+viewerUserName, "900\n", 0, nil)
	changed, err := stepCreateViewerUser().apply(context.Background(), env)
	if err != nil || !changed || !runnerSaw(runner, "useradd --system --shell "+env.nologinPath+" --home-dir /var/lib/"+viewerUserName+" --no-create-home --user-group "+viewerUserName) {
		t.Fatalf("viewer account provisioning changed=%v err=%v calls=%v", changed, err, runner.calls)
	}
	env.lookupUser = func(name string) (*user.User, error) {
		if name == viewerUserName {
			return &user.User{Uid: "900", Gid: "901"}, nil
		}
		return &user.User{Uid: "1000", Gid: "1000"}, nil
	}
	runner.on("getent group "+viewerUserName, viewerUserName+":x:901:\n", 0, nil)
	changed, err = stepCreateViewerUser().apply(context.Background(), env)
	if err != nil || changed {
		t.Fatalf("existing dedicated account changed=%v err=%v", changed, err)
	}
	runner.on("getent group "+viewerUserName, viewerUserName+":x:902:\n", 0, nil)
	if _, err := stepCreateViewerUser().apply(context.Background(), env); err == nil || !strings.Contains(err.Error(), "unexpected primary group") {
		t.Fatalf("wrong group accepted: %v", err)
	}
	runner.on("getent group "+viewerUserName, viewerUserName+":x:901:other\n", 0, nil)
	if _, err := stepCreateViewerUser().apply(context.Background(), env); err == nil || !strings.Contains(err.Error(), "supplementary members") {
		t.Fatalf("viewer group with extra member accepted: %v", err)
	}
}

// TestViewerCreationMarkerPathIsAbsoluteAndIndependentOfDisplayUnitPath guards
// against deriving the marker location from displayUnitPath's directory: a
// caller that leaves displayUnitPath unset (every full-install test that
// doesn't need the display unit) previously turned the marker into a
// relative path resolved against the process's current working directory,
// which left a stray "pipelock-contain-viewer.user-created" file inside the
// package source tree. The marker must come from its own dedicated,
// injectable field.
func TestViewerCreationMarkerPathIsAbsoluteAndIndependentOfDisplayUnitPath(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	env.displayUnitPath = ""
	if got := viewerCreationMarkerPath(env); !filepath.IsAbs(got) {
		t.Fatalf("viewer creation marker path is not absolute with an empty displayUnitPath: %q", got)
	}
	runner.on("id -nG "+env.proxyUserName, env.proxyUserName+"\n", 0, nil)
	runner.on("id -u "+viewerUserName, "900\n", 0, nil)
	changed, err := stepCreateViewerUser().apply(context.Background(), env)
	if err != nil || !changed {
		t.Fatalf("viewer account provisioning with empty displayUnitPath: changed=%v err=%v", changed, err)
	}
	marker := viewerCreationMarkerPath(env)
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("marker not written at its configured path: %v", err)
	}
	if _, err := os.Stat(viewerUnitBase + ".user-created"); err == nil {
		t.Fatalf("marker leaked into the process working directory: %s", viewerUnitBase+".user-created")
	}
}

func TestViewerCreationMarkerDirFailure(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	runner.on("id -nG "+env.proxyUserName, env.proxyUserName+"\n", 0, nil)
	runner.on("id -u "+viewerUserName, "900\n", 0, nil)
	env.mkdirAll = func(string, os.FileMode) error { return os.ErrPermission }
	changed, err := stepCreateViewerUser().apply(context.Background(), env)
	if !changed || !errors.Is(err, os.ErrPermission) {
		t.Fatalf("marker directory failure: changed=%v err=%v", changed, err)
	}
}

func TestViewerLegacyUnitStateCountsWithoutUnitFile(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(strconv.FormatBool(enabled), func(t *testing.T) {
			env, runner, _ := newFakeEnv(t)
			env.displayUnitPath = filepath.Join(filepath.Dir(env.systemUnitPath), "display.service")
			env.displayEnabled = true
			env.displayConfig = config.ContainmentDisplay{Backend: "xvnc", Viewer: config.ContainmentDisplayViewer{Enabled: &enabled, OperatorUser: "operator"}}
			_, socket := viewerUnitPaths(env)
			runner.on("systemctl is-active "+filepath.Base(socket), "active\n", 0, nil)
			runner.on("systemctl is-enabled "+filepath.Base(socket), "enabled\n", 0, nil)
			changed, err := stepProvisionViewer().apply(context.Background(), env)
			if err != nil || !changed || !runnerSaw(runner, "systemctl disable --now "+filepath.Base(socket)) {
				t.Fatalf("legacy runtime state changed=%v err=%v calls=%v", changed, err, runner.calls)
			}
		})
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
			body, err := os.ReadFile(filepath.Clean(path))
			if err != nil || string(body) != old {
				t.Fatalf("restored %s = %q, %v", path, body, err)
			}
			if !runnerSaw(runner, "systemctl start "+filepath.Base(path)) {
				t.Fatalf("%s was not restarted", path)
			}
		}
	})
}

func TestViewerActiveDisabledRollbackAfterLaterFailure(t *testing.T) {
	env, runner, out := newFakeEnv(t)
	env.displayUnitPath = filepath.Join(filepath.Dir(env.systemUnitPath), "display.service")
	env.displayEnabled = true
	yes := true
	env.displayConfig = config.ContainmentDisplay{Backend: "xvnc", Viewer: config.ContainmentDisplayViewer{Enabled: &yes, OperatorUser: "operator"}}
	service, _ := viewerUnitPaths(env)
	unit := renderViewerServiceUnit(env)
	if err := os.WriteFile(service, []byte(unit), 0o600); err != nil {
		t.Fatal(err)
	}
	runner.on("systemctl is-enabled "+filepath.Base(service), "disabled\n", 1, nil)
	runner.on("systemctl is-active "+filepath.Base(service), "active\n", 0, nil)
	steps := []step{stepProvisionViewer(), {name: "later-failure", apply: func(context.Context, *installEnv) (bool, error) {
		return false, errors.New("later step failed")
	}}}
	outcomes, err := runSteps(context.Background(), env, out, steps)
	if err == nil || !strings.Contains(err.Error(), "later step failed") {
		t.Fatalf("install error = %v", err)
	}
	if !outcomes[0].applied || !strings.Contains(out.String(), "undo provision-display-viewer") {
		t.Fatalf("viewer change skipped rollback: outcomes=%+v output=%s", outcomes, out.String())
	}
	if !runnerSaw(runner, "systemctl enable --now "+filepath.Base(service)) || !runnerSaw(runner, "systemctl disable --now "+filepath.Base(service)) || !runnerSaw(runner, "systemctl start "+filepath.Base(service)) {
		t.Fatalf("viewer enabled state or active state not restored: %+v", runner.calls)
	}
	if runnerSaw(runner, "systemctl enable "+filepath.Base(service)) {
		t.Fatal("rollback enabled a previously disabled viewer")
	}
	got, readErr := os.ReadFile(filepath.Clean(service))
	if readErr != nil || string(got) != unit {
		t.Fatalf("restored unit = %q, %v", got, readErr)
	}
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
	if err := os.Remove(service + ".bak"); err != nil {
		t.Fatal(err)
	}
	runner.on("systemctl disable --now "+filepath.Base(service), "", 1, errors.New("stop failed"))
	err = actionRemoveViewer().undo(context.Background(), env)
	if err == nil || !strings.Contains(err.Error(), "stop failed") {
		t.Fatalf("stop error = %v", err)
	}
}

func TestViewerProvisionRejectsInvalidDisplayAndCleanupFailures(t *testing.T) {
	for _, tc := range []struct {
		name, prior, command, want string
		viewer, failRemove         bool
	}{
		{"invalid backend", "", "", "requires an enabled Xvnc", true, false},
		{"legacy stop", "socket", "systemctl disable --now pipelock-contain-viewer.socket", "socket stop failed", true, false},
		{"legacy removal", "socket", "", "remove failed", true, true},
		{"disabled service stop", "service", "systemctl disable --now pipelock-contain-viewer.service", "service stop failed", false, false},
		{"disabled service removal", "service", "", "remove failed", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env, runner, _ := newFakeEnv(t)
			env.displayUnitPath = filepath.Join(filepath.Dir(env.systemUnitPath), "display.service")
			env.displayEnabled = true
			service, socket := viewerUnitPaths(env)
			yes := tc.viewer
			backend := "xvnc"
			if tc.name == "invalid backend" {
				backend = "xvfb"
			}
			env.displayConfig = config.ContainmentDisplay{Backend: backend, Viewer: config.ContainmentDisplayViewer{Enabled: &yes, OperatorUser: "operator"}}
			path := service
			if tc.prior == "socket" {
				path = socket
			}
			if tc.prior != "" {
				if err := os.WriteFile(path, []byte(displayUnitMarker+"\n[Unit]\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if tc.command != "" {
				runner.on(tc.command, "", 1, errors.New(tc.want))
			}
			if tc.failRemove {
				env.removeFile = func(string) error { return errors.New("remove failed") }
			}
			changed, err := stepProvisionViewer().apply(context.Background(), env)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("changed=%v err=%v, want %q", changed, err, tc.want)
			}
			if tc.prior != "" && !changed {
				t.Fatal("failed cleanup did not report a change requiring rollback")
			}
			if tc.failRemove {
				if _, statErr := os.Stat(path); statErr != nil {
					t.Fatalf("failed removal lost unit: %v", statErr)
				}
			}
		})
	}
}

func TestRemoveManagedViewerUnitChecksEveryCandidate(t *testing.T) {
	for _, tc := range []struct {
		name, want                          string
		failRead, failRemove, foreignBackup bool
	}{
		{"read", "read unavailable", true, false, false},
		{"remove", "remove unavailable", false, true, false},
		{"foreign backup", "not Pipelock-managed", false, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env, _, _ := newFakeEnv(t)
			path := filepath.Join(t.TempDir(), "viewer.service")
			if tc.foreignBackup {
				if err := os.WriteFile(path+".bak", []byte("[Service]\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(path, []byte(displayUnitMarker+"\n[Service]\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if tc.failRead {
				env.readFile = func(string) ([]byte, error) { return nil, errors.New("read unavailable") }
			}
			if tc.failRemove {
				env.removeFile = func(string) error { return errors.New("remove unavailable") }
			}
			err := removeManagedViewerUnit(env, path)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("remove = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestViewerRollbackReportsRestorationFailures(t *testing.T) {
	for _, tc := range []struct {
		name, command, want string
		failWrite           bool
	}{
		{"disable", "systemctl disable --now pipelock-contain-viewer.service", "disable failed", false},
		{"write", "", "write failed", true},
		{"reload", "systemctl daemon-reload", "reload failed", false},
		{"enable", "systemctl enable pipelock-contain-viewer.service", "enable failed", false},
		{"start", "systemctl start pipelock-contain-viewer.service", "start failed", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env, runner, _ := newFakeEnv(t)
			env.displayUnitPath = filepath.Join(filepath.Dir(env.systemUnitPath), "display.service")
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
			if changed, err := step.apply(context.Background(), env); err != nil || !changed {
				t.Fatalf("apply changed=%v err=%v", changed, err)
			}
			if tc.command != "" {
				runner.on(tc.command, "", 1, errors.New(tc.want))
			}
			if tc.failWrite {
				env.writeFile = func(string, []byte, os.FileMode) error { return errors.New("write failed") }
			}
			err := step.undo(context.Background(), env)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("undo = %v, want %q", err, tc.want)
			}
		})
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

func TestViewerUnitOwnershipCheckedBeforeSystemctl(t *testing.T) {
	for _, target := range []string{"service", "service.bak", "socket", "socket.bak"} {
		t.Run(target, func(t *testing.T) {
			env, runner, _ := newFakeEnv(t)
			env.displayUnitPath = filepath.Join(filepath.Dir(env.systemUnitPath), "display.service")
			service, socket := viewerUnitPaths(env)
			paths := map[string]string{"service": service, "service.bak": service + ".bak", "socket": socket, "socket.bak": socket + ".bak"}
			if err := os.WriteFile(paths[target], []byte("[Unit]\nDescription=foreign\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			for _, apply := range []func() error{
				func() error { _, err := stepProvisionViewer().apply(context.Background(), env); return err },
				func() error { return actionRemoveViewer().undo(context.Background(), env) },
			} {
				runner.calls = nil
				if err := apply(); err == nil || !strings.Contains(err.Error(), "not Pipelock-managed") {
					t.Fatalf("ownership rejection = %v", err)
				}
				if len(runner.calls) != 0 {
					t.Fatalf("systemctl called before ownership validation: %+v", runner.calls)
				}
			}
		})
	}
}

func TestViewerInvalidBackendPreservesLegacySocket(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	env.displayUnitPath = filepath.Join(filepath.Dir(env.systemUnitPath), "display.service")
	env.displayEnabled = true
	yes := true
	env.displayConfig = config.ContainmentDisplay{Backend: "xvfb", Viewer: config.ContainmentDisplayViewer{Enabled: &yes}}
	_, socket := viewerUnitPaths(env)
	if err := os.WriteFile(socket, []byte(displayUnitMarker+"\n[Socket]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	changed, err := stepProvisionViewer().apply(context.Background(), env)
	if changed || err == nil || !strings.Contains(err.Error(), "requires an enabled Xvnc") {
		t.Fatalf("invalid backend: changed=%v err=%v", changed, err)
	}
	if _, err := os.Stat(socket); err != nil {
		t.Fatalf("legacy socket removed: %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("systemctl called before backend validation: %+v", runner.calls)
	}
}

func TestStepCreateViewerUserExistingAccountBoundaryErrors(t *testing.T) {
	t.Run("root account rejected", func(t *testing.T) {
		env, _, _ := newFakeEnv(t)
		env.lookupUser = func(string) (*user.User, error) { return &user.User{Uid: "0", Gid: "0"}, nil }
		if _, err := stepCreateViewerUser().apply(context.Background(), env); err == nil || !strings.Contains(err.Error(), "must not be root") {
			t.Fatalf("root viewer account accepted: %v", err)
		}
	})
	t.Run("peer lookup failure", func(t *testing.T) {
		env, _, _ := newFakeEnv(t)
		env.lookupUser = func(name string) (*user.User, error) {
			if name == viewerUserName {
				return &user.User{Uid: "900", Gid: "900"}, nil
			}
			return nil, errors.New("directory unavailable")
		}
		if _, err := stepCreateViewerUser().apply(context.Background(), env); err == nil || !strings.Contains(err.Error(), "inspect viewer identity boundary") {
			t.Fatalf("peer lookup failure not reported: %v", err)
		}
	})
	t.Run("shared uid with a peer identity", func(t *testing.T) {
		env, _, _ := newFakeEnv(t)
		env.lookupUser = func(name string) (*user.User, error) {
			if name == viewerUserName {
				return &user.User{Uid: "987", Gid: "900"}, nil
			}
			return &user.User{Uid: "987"}, nil
		}
		if _, err := stepCreateViewerUser().apply(context.Background(), env); err == nil || !strings.Contains(err.Error(), "shares another containment identity") {
			t.Fatalf("shared uid accepted: %v", err)
		}
	})
	t.Run("empty boundary name is skipped", func(t *testing.T) {
		env, runner, _ := newFakeEnv(t)
		env.operatorUser = ""
		env.lookupUser = func(name string) (*user.User, error) {
			if name == viewerUserName {
				return &user.User{Uid: "900", Gid: "901"}, nil
			}
			return &user.User{Uid: "1000", Gid: "1000"}, nil
		}
		runner.on("getent group "+viewerUserName, viewerUserName+":x:901:\n", 0, nil)
		if _, err := stepCreateViewerUser().apply(context.Background(), env); err != nil {
			t.Fatalf("empty operatorUser boundary: %v", err)
		}
	})
	t.Run("lookup error other than unknown user", func(t *testing.T) {
		env, _, _ := newFakeEnv(t)
		env.lookupUser = func(string) (*user.User, error) { return nil, errors.New("directory unavailable") }
		if _, err := stepCreateViewerUser().apply(context.Background(), env); err == nil || !strings.Contains(err.Error(), "viewer account lookup") {
			t.Fatalf("non-unknown-user lookup error not reported: %v", err)
		}
	})
}

func TestStepCreateViewerUserUndoErrorPaths(t *testing.T) {
	t.Run("marker removal failure on an absent account", func(t *testing.T) {
		env, _, _ := newFakeEnv(t)
		env.lookupUser = func(string) (*user.User, error) { return nil, user.UnknownUserError(viewerUserName) }
		env.removeFile = func(string) error { return os.ErrPermission }
		if err := stepCreateViewerUser().undo(context.Background(), env); !errors.Is(err, os.ErrPermission) {
			t.Fatalf("absent-account marker removal error = %v", err)
		}
	})
	t.Run("lookup error other than unknown user", func(t *testing.T) {
		env, _, _ := newFakeEnv(t)
		env.lookupUser = func(string) (*user.User, error) { return nil, errors.New("directory unavailable") }
		if err := stepCreateViewerUser().undo(context.Background(), env); err == nil || !strings.Contains(err.Error(), "directory unavailable") {
			t.Fatalf("undo lookup error not reported: %v", err)
		}
	})
	t.Run("userdel failure", func(t *testing.T) {
		env, runner, _ := newFakeEnv(t)
		env.lookupUser = func(string) (*user.User, error) { return &user.User{Uid: "900"}, nil }
		runner.on("userdel -r "+viewerUserName, "denied", 1, nil)
		if err := stepCreateViewerUser().undo(context.Background(), env); err == nil || !strings.Contains(err.Error(), "userdel") {
			t.Fatalf("userdel failure not reported: %v", err)
		}
	})
	t.Run("marker removal failure after userdel", func(t *testing.T) {
		env, _, _ := newFakeEnv(t)
		env.lookupUser = func(string) (*user.User, error) { return &user.User{Uid: "900"}, nil }
		env.removeFile = func(string) error { return os.ErrPermission }
		if err := stepCreateViewerUser().undo(context.Background(), env); !errors.Is(err, os.ErrPermission) {
			t.Fatalf("post-userdel marker removal error = %v", err)
		}
	})
}

func TestCheckViewerOperatorIdentityLookupErrors(t *testing.T) {
	yes := true
	t.Run("operator lookup failure", func(t *testing.T) {
		env := &installEnv{displayConfig: config.ContainmentDisplay{Viewer: config.ContainmentDisplayViewer{Enabled: &yes, OperatorUser: "operator"}}}
		env.lookupUser = func(string) (*user.User, error) { return nil, errors.New("directory unavailable") }
		if err := checkViewerOperatorIdentity(env); err == nil || !strings.Contains(err.Error(), "lookup viewer operator") {
			t.Fatalf("operator lookup failure not reported: %v", err)
		}
	})
	t.Run("service account lookup failure", func(t *testing.T) {
		env := &installEnv{agentUserName: "agent", displayConfig: config.ContainmentDisplay{Viewer: config.ContainmentDisplayViewer{Enabled: &yes, OperatorUser: "operator"}}}
		env.lookupUser = func(name string) (*user.User, error) {
			if name == "operator" {
				return &user.User{Uid: "1000"}, nil
			}
			return nil, errors.New("directory unavailable")
		}
		if err := checkViewerOperatorIdentity(env); err == nil || !strings.Contains(err.Error(), "lookup containment service account agent") {
			t.Fatalf("service account lookup failure not reported: %v", err)
		}
	})
}

func TestCheckViewerGroupCommandFailure(t *testing.T) {
	run := func(context.Context, string, ...string) (string, int, error) { return "denied", 1, nil }
	if err := checkViewerGroup(context.Background(), run, "900"); err == nil || !strings.Contains(err.Error(), "inspect viewer group") {
		t.Fatalf("getent failure not reported: %v", err)
	}
}

func TestCheckViewerProxyIsolationEdgeCases(t *testing.T) {
	t.Run("empty proxy name is a no-op", func(t *testing.T) {
		called := false
		run := func(context.Context, string, ...string) (string, int, error) { called = true; return "", 0, nil }
		if err := checkViewerProxyIsolation(context.Background(), run, ""); err != nil || called {
			t.Fatalf("empty proxy name: err=%v called=%v", err, called)
		}
	})
	t.Run("command failure", func(t *testing.T) {
		run := func(context.Context, string, ...string) (string, int, error) { return "denied", 1, nil }
		if err := checkViewerProxyIsolation(context.Background(), run, "proxy"); err == nil || !strings.Contains(err.Error(), "inspect proxy group membership") {
			t.Fatalf("command failure not reported: %v", err)
		}
	})
}

func TestRenderViewerServiceUnitClipboardEnabled(t *testing.T) {
	yes := true
	env := &installEnv{agentUserName: "agent", pipelockTarget: "/usr/local/bin/pipelock", displayNumber: 99, displayConfig: config.ContainmentDisplay{Viewer: config.ContainmentDisplayViewer{Enabled: &yes, OperatorUser: "operator", Clipboard: &yes}}}
	unit := renderViewerServiceUnit(env)
	if !strings.Contains(unit, "--clipboard=true") {
		t.Fatalf("clipboard flag not rendered true: %s", unit)
	}
}

func TestStepProvisionViewerRaceAndFailurePaths(t *testing.T) {
	t.Run("read failure after ownership validation passes", func(t *testing.T) {
		env, _, _ := newFakeEnv(t)
		env.displayUnitPath = filepath.Join(filepath.Dir(env.systemUnitPath), "display.service")
		env.displayEnabled = true
		yes := true
		env.displayConfig = config.ContainmentDisplay{Backend: "xvnc", Viewer: config.ContainmentDisplayViewer{Enabled: &yes, OperatorUser: "operator"}}
		var calls int
		env.readFile = func(string) ([]byte, error) {
			calls++
			if calls <= 4 {
				return nil, os.ErrNotExist
			}
			return nil, os.ErrPermission
		}
		if _, err := stepProvisionViewer().apply(context.Background(), env); !errors.Is(err, os.ErrPermission) {
			t.Fatalf("post-validation read failure = %v", err)
		}
	})
	t.Run("unit becomes foreign between validation and the state read", func(t *testing.T) {
		env, _, _ := newFakeEnv(t)
		env.displayUnitPath = filepath.Join(filepath.Dir(env.systemUnitPath), "display.service")
		env.displayEnabled = true
		yes := true
		env.displayConfig = config.ContainmentDisplay{Backend: "xvnc", Viewer: config.ContainmentDisplayViewer{Enabled: &yes, OperatorUser: "operator"}}
		var calls int
		env.readFile = func(string) ([]byte, error) {
			calls++
			if calls <= 4 {
				return nil, os.ErrNotExist
			}
			return []byte("[Unit]\nDescription=foreign\n"), nil
		}
		if _, err := stepProvisionViewer().apply(context.Background(), env); err == nil || !strings.Contains(err.Error(), "is not Pipelock-managed") {
			t.Fatalf("race-detected foreign unit not reported: %v", err)
		}
	})
	t.Run("ensureContainmentUnit failure", func(t *testing.T) {
		env, _, _ := newFakeEnv(t)
		env.displayUnitPath = filepath.Join(filepath.Dir(env.systemUnitPath), "display.service")
		env.displayEnabled = true
		yes := true
		env.displayConfig = config.ContainmentDisplay{Backend: "xvnc", Viewer: config.ContainmentDisplayViewer{Enabled: &yes, OperatorUser: "operator"}}
		env.mkdirAll = func(string, os.FileMode) error { return os.ErrPermission }
		if _, err := stepProvisionViewer().apply(context.Background(), env); !errors.Is(err, os.ErrPermission) {
			t.Fatalf("ensureContainmentUnit failure not reported: %v", err)
		}
	})
	t.Run("restart failure", func(t *testing.T) {
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
		runner.on("systemctl restart "+filepath.Base(service), "denied", 1, nil)
		if _, err := stepProvisionViewer().apply(context.Background(), env); err == nil || !strings.Contains(err.Error(), "denied") {
			t.Fatalf("restart failure not reported: %v", err)
		}
	})
}

func TestStepProvisionViewerUndoRemovesUnitThatDidNotPreExist(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	env.displayUnitPath = filepath.Join(filepath.Dir(env.systemUnitPath), "display.service")
	service, socket := viewerUnitPaths(env)
	for _, path := range []string{service, socket} {
		if err := os.WriteFile(path, []byte(displayUnitMarker+"\n[Unit]\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	env.removeFile = func(string) error { return os.ErrPermission }
	if err := stepProvisionViewer().undo(context.Background(), env); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("undo removal of a non-preexisting unit = %v", err)
	}
}

func TestActionRemoveViewerCommandFailures(t *testing.T) {
	t.Run("socket disable failure", func(t *testing.T) {
		env, runner, _ := newFakeEnv(t)
		env.displayUnitPath = filepath.Join(filepath.Dir(env.systemUnitPath), "display.service")
		_, socket := viewerUnitPaths(env)
		runner.on("systemctl disable --now "+filepath.Base(socket), "denied", 1, nil)
		if err := actionRemoveViewer().undo(context.Background(), env); err == nil || !strings.Contains(err.Error(), "systemctl disable --now "+filepath.Base(socket)) {
			t.Fatalf("socket disable failure not reported: %v", err)
		}
	})
	t.Run("removal failure", func(t *testing.T) {
		env, _, _ := newFakeEnv(t)
		env.displayUnitPath = filepath.Join(filepath.Dir(env.systemUnitPath), "display.service")
		service, _ := viewerUnitPaths(env)
		if err := os.WriteFile(service, []byte(displayUnitMarker+"\n[Service]\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		env.removeFile = func(string) error { return os.ErrPermission }
		if err := actionRemoveViewer().undo(context.Background(), env); !errors.Is(err, os.ErrPermission) {
			t.Fatalf("removal failure not reported: %v", err)
		}
	})
}
