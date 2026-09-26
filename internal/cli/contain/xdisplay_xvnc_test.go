// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestDisplayUnitOmittedConfigMatchesXvfbGolden(t *testing.T) {
	env := &installEnv{agentUserName: testAgentUser, displayNumber: 99, xvfbPath: "/usr/bin/Xvfb"}
	want := `# Managed by ` + "`pipelock contain install`" + `.
[Unit]
Description=Pipelock contained agent X display
After=systemd-tmpfiles-setup.service

[Service]
Type=simple
User=pipelock-agent
Group=pipelock-agent
UMask=0077
ExecStart=/usr/bin/Xvfb :99 -auth /var/lib/pipelock-agent/Xauthority -screen 0 1280x1024x24 -nolisten tcp -nolisten local -listen unix
ExecStartPost=/usr/bin/bash -c 'for i in {1..200}; do if [ -S "$1" ]; then chmod 0700 "$1"; exit; fi; sleep 0.1; done; exit 1' _ /tmp/.X11-unix/X99
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
`
	if got := renderAgentDisplayUnit(env); got != want {
		t.Fatalf("omitted config Xvfb unit changed:\n%s", got)
	}
}

func TestDisplayGeometryChangesUnit(t *testing.T) {
	for _, backend := range []string{"xvfb", "xvnc"} {
		t.Run(backend, func(t *testing.T) {
			env := &installEnv{agentUserName: testAgentUser, agentHome: "/home/pipelock-agent", displayNumber: 99, xvfbPath: "/usr/bin/Xvfb", xvncPath: "/usr/bin/Xvnc", displayConfig: config.ContainmentDisplay{Backend: backend}}
			original := renderAgentDisplayUnit(env)
			env.displayConfig.Geometry = "1600x900"
			changed := renderAgentDisplayUnit(env)
			if original == changed || !strings.Contains(changed, "1600x900") {
				t.Fatalf("geometry change did not change %s unit", backend)
			}
		})
	}
}

func TestDisplayGeometryVerifyRejectsStaleExecStart(t *testing.T) {
	for _, backend := range []string{"xvfb", "xvnc"} {
		t.Run(backend, func(t *testing.T) {
			cfgPath := filepath.Join(t.TempDir(), "pipelock.yaml")
			configBody := "containment:\n  display:\n    enabled: true\n    backend: " + backend + "\n    geometry: 1600x900\n"
			if err := os.WriteFile(cfgPath, []byte(configBody), 0o600); err != nil {
				t.Fatal(err)
			}
			env := &installEnv{agentUserName: testAgentUser, agentHome: "/home/pipelock-agent", displayNumber: 99, xvfbPath: "/usr/bin/Xvfb", xvncPath: "/usr/bin/Xvnc", displayConfig: config.ContainmentDisplay{Backend: backend}}
			stale := renderAgentDisplayUnit(env)
			env.displayConfig.Geometry = "1600x900"
			current := renderAgentDisplayUnit(env)
			if stale == current {
				t.Fatal("geometry change did not rewrite display unit")
			}
			probe := &probeEnv{configPath: cfgPath, agentUserName: env.agentUserName, agentHome: env.agentHome, displayUnitPath: filepath.Join(t.TempDir(), "display.service"), xvfbPath: env.xvfbPath, xvncPath: env.xvncPath, readFile: func(string) ([]byte, error) { return []byte(stale), nil }}
			status, detail := probeAgentDisplay(context.Background(), probe)
			if status != statusFail || !strings.Contains(detail, "missing exact ExecStart=") || !strings.Contains(detail, "1600x900") {
				t.Fatalf("stale geometry verification = %s: %s", status, detail)
			}
		})
	}
}

func TestViewerDisplayRenderedUnitPassesVerify(t *testing.T) {
	root := t.TempDir()
	cfgPath := filepath.Join(root, "pipelock.yaml")
	if err := os.WriteFile(cfgPath, []byte("containment:\n  display:\n    enabled: true\n    backend: xvnc\n    viewer:\n      enabled: true\n      operator_user: operator\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadForInspection(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	unitPath := filepath.Join(root, "display.service")
	install := &installEnv{agentUserName: testAgentUser, proxyUserName: "proxy", agentHome: filepath.Join(root, "agent"), displayNumber: 99, xvncPath: "/usr/bin/Xvnc", displayConfig: cfg.Containment.Display}
	unit := renderAgentDisplayUnit(install)
	if !strings.Contains(unit, "Group="+viewerUserName) || !strings.Contains(unit, "RuntimeDirectoryMode=0710") || strings.Contains(unit, "setfacl") {
		t.Fatal("viewer unit does not isolate RFB in the dedicated runtime group")
	}
	if err := os.WriteFile(unitPath, []byte(unit), 0o600); err != nil {
		t.Fatal(err)
	}
	probe := &probeEnv{
		configPath: cfgPath, displayUnitPath: unitPath, agentUserName: install.agentUserName, proxyUserName: install.proxyUserName, agentHome: install.agentHome, xvncPath: install.xvncPath, readFile: os.ReadFile,
		stat: func(string) (os.FileInfo, error) {
			return fakeFileInfo{mode: os.ModeSocket | managedXSocketMode, sys: fakeFileSysWithUID(4242)}, nil
		},
		lookupUser: func(string) (*user.User, error) { return &user.User{Uid: "4242"}, nil },
	}
	probe.runCmd = func(_ context.Context, _ string, args ...string) (string, int, error) {
		if len(args) > 0 && args[0] == "is-active" {
			return "active\n", 0, nil
		}
		return "enabled\n", 0, nil
	}
	if status, detail := probeAgentDisplay(context.Background(), probe); status != statusPass {
		t.Fatalf("rendered viewer unit verify = %s: %s", status, detail)
	}
}

func TestXvncUnitClipboardModes(t *testing.T) {
	for _, tc := range []struct {
		name      string
		clipboard *bool
		off       bool
	}{
		{name: "omitted", off: true},
		{name: "off", clipboard: boolPtr(false), off: true},
		{name: "on", clipboard: boolPtr(true)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := &installEnv{agentUserName: testAgentUser, agentHome: "/home/pipelock-agent", displayNumber: 99, xvncPath: "/usr/bin/Xvnc", displayConfig: config.ContainmentDisplay{Backend: "xvnc", Viewer: config.ContainmentDisplayViewer{Clipboard: tc.clipboard}}}
			got := renderAgentDisplayUnit(env)
			for _, arg := range []string{"ExecStart=/usr/bin/Xvnc :99 -auth /var/lib/pipelock-agent/Xauthority -geometry 1280x1024 -depth 24", "-rfbunixpath /run/pipelock-agent-display/rfb.sock", "-rfbunixmode 0600", "-rfbport -1", "-SecurityTypes None", "-AlwaysShared", "-nolisten tcp -nolisten local -listen unix"} {
				if !strings.Contains(got, arg) {
					t.Errorf("Xvnc unit missing %q", arg)
				}
			}
			flags := "-AcceptCutText=0 -SendCutText=0 -SendPrimary=0 -SetPrimary=0"
			if strings.Contains(got, flags) != tc.off {
				t.Errorf("clipboard-off flags mismatch: %s", got)
			}
		})
	}
}

func boolPtr(value bool) *bool { return &value }

func TestDisplayBackendMigrationRestoresActiveXvfbOnFailure(t *testing.T) {
	for _, tc := range []struct {
		name        string
		rfb         bool
		wantFailure bool
	}{
		{name: "success", rfb: true},
		{name: "missing RFB socket", wantFailure: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env, runner, out := newFakeEnv(t)
			prepareMigrationAuthority(t, env)
			env.agentHome = filepath.Join(shortDisplayTestDir(t), "agent")
			env.displayUnitPath = filepath.Join(filepath.Dir(env.systemUnitPath), "pipelock-agent-display.service")
			env.xvfbPath = "/usr/bin/Xvfb"
			env.xvncPath = filepath.Join(t.TempDir(), "Xvnc")
			if err := os.WriteFile(env.xvncPath, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			oldUnit := renderAgentDisplayUnit(&installEnv{agentUserName: env.agentUserName, displayNumber: 99, xvfbPath: env.xvfbPath})
			if err := os.WriteFile(env.displayUnitPath, []byte(oldUnit), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg := "mode: balanced\ncontainment:\n  display:\n    enabled: true\n    backend: xvnc\n"
			if err := os.WriteFile(managedPipelockConfigPath(env), []byte(cfg), 0o600); err != nil {
				t.Fatal(err)
			}
			unitName := filepath.Base(env.displayUnitPath)
			runner.on(argvFor("systemctl", "is-enabled", unitName), "enabled\n", 0, nil)
			runner.on(argvFor("systemctl", "is-active", unitName), "active\n", 0, nil)
			xSocket := filepath.Join(shortDisplayTestDir(t), "X99")
			xListener, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", xSocket)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = xListener.Close() })
			if err := os.Chmod(xSocket, managedXSocketMode); err != nil {
				t.Fatal(err)
			}
			rfbSocket := filepath.Join(env.agentHome, ".local/state/pipelock/display/rfb.sock")
			env.rfbSocketPath = rfbSocket
			runner.on(argvFor("getfacl", "-p", rfbSocket), "user::rw-\ngroup::---\nother::---\n", 0, nil)
			if tc.rfb {
				if err := os.MkdirAll(filepath.Dir(rfbSocket), 0o750); err != nil {
					t.Fatal(err)
				}
				rfbListener, listenErr := (&net.ListenConfig{}).Listen(context.Background(), "unix", rfbSocket)
				if listenErr != nil {
					t.Fatal(listenErr)
				}
				t.Cleanup(func() { _ = rfbListener.Close() })
				if err := os.Chmod(rfbSocket, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			originalStat, originalLstat := env.stat, env.lstat
			env.stat = func(path string) (os.FileInfo, error) {
				if path == displaySocketPath(99) {
					return originalStat(xSocket)
				}
				return originalStat(path)
			}
			env.lstat = func(path string) (os.FileInfo, error) {
				if path == displaySocketPath(99) {
					return originalLstat(xSocket)
				}
				return originalLstat(path)
			}
			env.lookupUser = func(string) (*user.User, error) {
				return &user.User{Uid: strconv.Itoa(os.Getuid()), Gid: strconv.Itoa(os.Getgid())}, nil
			}
			_, err = runSteps(context.Background(), env, out, []step{stepProvisionAgentDisplay()})
			if (err != nil) != tc.wantFailure {
				t.Fatalf("migration error=%v, want failure=%v", err, tc.wantFailure)
			}
			unit, readErr := os.ReadFile(env.displayUnitPath)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if tc.wantFailure && string(unit) != oldUnit {
				t.Fatal("failed migration did not restore prior Xvfb unit")
			}
			if !tc.wantFailure && !strings.Contains(string(unit), "ExecStart="+env.xvncPath) {
				t.Fatal("successful migration did not install Xvnc unit")
			}
			calls := out.String()
			if tc.wantFailure && !strings.Contains(calls, "undo provision-agent-display") {
				t.Fatalf("rollback did not run: %s", calls)
			}
			var restarted bool
			for _, call := range runner.calls {
				if call.name == "systemctl" && strings.Join(call.args, " ") == "restart "+unitName {
					restarted = true
				}
			}
			if !restarted {
				t.Fatal("changed active display unit was not restarted")
			}
			if !tc.wantFailure && runnerSaw(runner, "setfacl -x u:"+env.proxyUserName+" "+env.agentHome) {
				t.Fatal("Xvfb migration touched an unrelated agent-home ACL")
			}
		})
	}
}

func TestRemoveViewerTraverseACLRevokesExistingChainOnly(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	env.agentHome = filepath.Join(shortDisplayTestDir(t), "agent")
	// Only the first two levels exist: the rest must be skipped, not errored.
	if err := os.MkdirAll(filepath.Join(env.agentHome, ".local"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := removeViewerTraverseACL(context.Background(), env); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, call := range runner.calls {
		if call.name == "setfacl" {
			got = append(got, strings.Join(call.args, " "))
		}
	}
	want := []string{
		"-x u:" + env.proxyUserName + " " + env.agentHome,
		"-x u:" + env.proxyUserName + " " + filepath.Join(env.agentHome, ".local"),
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("setfacl calls = %q, want %q", got, want)
	}
	env.stat = func(string) (os.FileInfo, error) { return nil, os.ErrPermission }
	if err := removeViewerTraverseACL(context.Background(), env); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("non-ENOENT stat error = %v", err)
	}
	dirs := viewerTraverseDirs(env.agentHome)
	if last := dirs[len(dirs)-1]; last != filepath.Join(env.agentHome, ".local/state/pipelock/display") {
		t.Fatalf("traverse chain ends at %s, want the socket directory", last)
	}
}

func TestDisplayBackendMigrationRestoresActiveXvncOnFailure(t *testing.T) {
	for _, tc := range []struct {
		name        string
		failRestart bool
	}{
		{name: "success"},
		{name: "restart failure", failRestart: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env, runner, out := newFakeEnv(t)
			prepareMigrationAuthority(t, env)
			env.agentHome = filepath.Join(shortDisplayTestDir(t), "agent")
			if err := os.MkdirAll(env.agentHome, 0o700); err != nil {
				t.Fatal(err)
			}
			env.displayUnitPath = filepath.Join(filepath.Dir(env.systemUnitPath), "pipelock-agent-display.service")
			env.xvfbPath = filepath.Join(shortDisplayTestDir(t), "Xvfb")
			if err := os.WriteFile(env.xvfbPath, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			oldUnit := renderAgentDisplayUnit(&installEnv{agentUserName: env.agentUserName, agentHome: env.agentHome, displayNumber: 99, xvncPath: "/usr/bin/Xvnc", displayConfig: config.ContainmentDisplay{Backend: "xvnc"}})
			oldUnit = strings.ReplaceAll(oldUnit, viewerRFBSocket, filepath.Join(env.agentHome, ".local/state/pipelock/display/rfb.sock"))
			if err := os.WriteFile(env.displayUnitPath, []byte(oldUnit), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg := "mode: balanced\ncontainment:\n  display:\n    enabled: true\n    backend: xvfb\n"
			if err := os.WriteFile(managedPipelockConfigPath(env), []byte(cfg), 0o600); err != nil {
				t.Fatal(err)
			}
			unitName := filepath.Base(env.displayUnitPath)
			runner.on(argvFor("systemctl", "is-enabled", unitName), "enabled\n", 0, nil)
			runner.on(argvFor("systemctl", "is-active", unitName), "active\n", 0, nil)
			if tc.failRestart {
				runner.on(argvFor("systemctl", "restart", unitName), "restart failed", 1, nil)
			}
			_, err := runSteps(context.Background(), env, out, []step{stepProvisionAgentDisplay()})
			if (err != nil) != tc.failRestart {
				t.Fatalf("reverse migration error=%v, failRestart=%t", err, tc.failRestart)
			}
			body, readErr := os.ReadFile(env.displayUnitPath)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if tc.failRestart && string(body) != oldUnit {
				t.Fatal("failed reverse migration did not restore prior Xvnc unit")
			}
			if !tc.failRestart && !strings.Contains(string(body), "ExecStart="+env.xvfbPath) {
				t.Fatal("reverse migration did not install Xvfb unit")
			}
			if !tc.failRestart && !runnerSaw(runner, "setfacl -x u:"+env.proxyUserName+" "+env.agentHome) {
				t.Fatal("legacy proxy traverse grant was not revoked")
			}
		})
	}
}

func prepareMigrationAuthority(t *testing.T, env *installEnv) {
	t.Helper()
	env.displayAuthorityPath = filepath.Join(t.TempDir(), "agent-state", "Xauthority")
	dir := filepath.Dir(env.displayAuthorityPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	realLstat := env.lstat
	trusted := make(map[string]bool)
	for current := dir; ; current = filepath.Dir(current) {
		trusted[current] = true
		if current == string(os.PathSeparator) {
			break
		}
	}
	env.lstat = func(path string) (os.FileInfo, error) {
		info, err := realLstat(path)
		if err == nil && trusted[filepath.Clean(path)] && info.IsDir() {
			return fakeFileInfo{mode: os.ModeDir | 0o755, sys: fakeFileSysWithUID(0)}, nil
		}
		return info, err
	}
}

func TestProbeAgentDisplayRFBRejectsUnsafeSocket(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup string
		want  string
	}{
		{name: "valid", setup: "socket", want: statusPass},
		{name: "missing", setup: "missing", want: statusFail},
		{name: "wrong mode", setup: "wide", want: statusFail},
		{name: "symlink", setup: "symlink", want: statusFail},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := shortDisplayTestDir(t)
			cfgPath := filepath.Join(root, "pipelock.yaml")
			if err := os.WriteFile(cfgPath, []byte("mode: balanced\ncontainment:\n  display:\n    enabled: true\n    backend: xvnc\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			unitPath := filepath.Join(root, "display.service")
			agentHome := filepath.Join(root, "agent")
			rfb := filepath.Join(agentHome, ".local/state/pipelock/display/rfb.sock")
			unit := renderAgentDisplayUnit(&installEnv{agentUserName: testAgentUser, agentHome: agentHome, rfbSocketPath: rfb, displayNumber: 99, xvncPath: "/usr/bin/Xvnc", displayConfig: config.ContainmentDisplay{Backend: "xvnc"}})
			if err := os.WriteFile(unitPath, []byte(unit), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Dir(rfb), 0o750); err != nil {
				t.Fatal(err)
			}
			if tc.setup == "socket" || tc.setup == "wide" {
				listener, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", rfb)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = listener.Close() })
				mode := os.FileMode(0o600)
				if tc.setup == "wide" {
					mode = 0o666
				}
				if err := os.Chmod(rfb, mode); err != nil {
					t.Fatal(err)
				}
			}
			if tc.setup == "symlink" {
				target := filepath.Join(root, "target")
				if err := os.WriteFile(target, nil, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, rfb); err != nil {
					t.Fatal(err)
				}
			}
			env := &probeEnv{configPath: cfgPath, displayUnitPath: unitPath, agentHome: agentHome, rfbSocketPath: rfb, agentUserName: testAgentUser, readFile: os.ReadFile, lstat: os.Lstat, lookupUser: func(string) (*user.User, error) { return &user.User{Uid: strconv.Itoa(os.Getuid())}, nil }, runCmd: func(context.Context, string, ...string) (string, int, error) {
				return "user::rw-\ngroup::---\nother::---\n", 0, nil
			}}
			got, detail := probeAgentDisplayRFB(context.Background(), env)
			if got != tc.want {
				t.Fatalf("agent_display_rfb = %s (%s), want %s", got, detail, tc.want)
			}
			if tc.want == statusFail && !strings.Contains(detail, "RFB socket") {
				t.Fatalf("failure did not name RFB socket check: %s", detail)
			}
		})
	}
}

func TestProbeAgentDisplayRFBReportsFailedControl(t *testing.T) {
	root := shortDisplayTestDir(t)
	cfgPath := filepath.Join(root, "pipelock.yaml")
	configBody := "mode: balanced\ncontainment:\n  display:\n    enabled: true\n    backend: xvnc\n"
	if err := os.WriteFile(cfgPath, []byte(configBody), 0o600); err != nil {
		t.Fatal(err)
	}
	unitPath := filepath.Join(root, "display.service")
	agentHome := filepath.Join(root, "agent")
	rfb := filepath.Join(root, "rfb.sock")
	unit := renderAgentDisplayUnit(&installEnv{agentUserName: testAgentUser, agentHome: agentHome, rfbSocketPath: rfb, displayNumber: 99, xvncPath: "/usr/bin/Xvnc", displayConfig: config.ContainmentDisplay{Backend: "xvnc"}})
	if err := os.WriteFile(unitPath, []byte(unit), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(rfb), 0o750); err != nil {
		t.Fatal(err)
	}
	listener, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", rfb)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	if err := os.Chmod(rfb, 0o600); err != nil {
		t.Fatal(err)
	}
	base := probeEnv{configPath: cfgPath, displayUnitPath: unitPath, agentHome: agentHome, rfbSocketPath: rfb, agentUserName: testAgentUser, readFile: os.ReadFile, lstat: os.Lstat, lookupUser: func(string) (*user.User, error) { return &user.User{Uid: strconv.Itoa(os.Getuid())}, nil }, runCmd: func(context.Context, string, ...string) (string, int, error) {
		return "user::rw-\ngroup::---\nother::---\n", 0, nil
	}}
	for _, tc := range []struct {
		name, want string
		change     func(*probeEnv)
	}{
		{"config read", "read containment display config", func(e *probeEnv) { e.configPath = filepath.Join(root, "missing.yaml") }},
		{"unit read", "read display unit", func(e *probeEnv) { e.readFile = func(string) ([]byte, error) { return nil, os.ErrPermission } }},
		{"unit contract", "disable TCP RFB", func(e *probeEnv) { e.readFile = func(string) ([]byte, error) { return []byte("[Service]\n"), nil } }},
		{"wrong mode", "RFB socket mode", func(e *probeEnv) {
			e.lstat = func(string) (os.FileInfo, error) { return fakeFileInfo{mode: os.ModeSocket | 0o666}, nil }
		}},
		{"owner lookup", "lookup RFB owner", func(e *probeEnv) {
			e.lookupUser = func(string) (*user.User, error) { return nil, errors.New("identity unavailable") }
		}},
		{"owner parse", "parse RFB owner uid", func(e *probeEnv) {
			e.lookupUser = func(string) (*user.User, error) { return &user.User{Uid: "bad"}, nil }
		}},
		{"wrong owner", "not owned", func(e *probeEnv) {
			e.lookupUser = func(string) (*user.User, error) { return &user.User{Uid: strconv.Itoa(os.Getuid() + 1)}, nil }
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := base
			tc.change(&env)
			status, detail := probeAgentDisplayRFB(context.Background(), &env)
			if status != statusFail || !strings.Contains(detail, tc.want) {
				t.Fatalf("probe = %s %q, want %q", status, detail, tc.want)
			}
		})
	}
}

func TestXvncProvisionReportsFailedControl(t *testing.T) {
	const fakeDisplayUID = 4242
	for _, tc := range []struct {
		name, want string
		change     func(*installEnv, *fakeRunner)
	}{
		{"reload", "reload failed", func(_ *installEnv, r *fakeRunner) {
			r.on("systemctl daemon-reload", "", 1, errors.New("reload failed"))
		}},
		{"enable", "enable failed", func(e *installEnv, r *fakeRunner) {
			r.on("systemctl enable --now "+filepath.Base(e.displayUnitPath), "", 1, errors.New("enable failed"))
		}},
		{"lookup owner", "lookup RFB owner", func(e *installEnv, _ *fakeRunner) {
			calls := 0
			e.lookupUser = func(string) (*user.User, error) {
				calls++
				if calls > 1 {
					return nil, errors.New("identity unavailable")
				}
				return &user.User{Uid: strconv.Itoa(fakeDisplayUID), Gid: strconv.Itoa(fakeDisplayUID)}, nil
			}
		}},
		{"parse owner", "parse RFB owner uid", func(e *installEnv, _ *fakeRunner) {
			calls := 0
			e.lookupUser = func(string) (*user.User, error) {
				calls++
				if calls > 1 {
					return &user.User{Uid: "bad"}, nil
				}
				return &user.User{Uid: strconv.Itoa(fakeDisplayUID), Gid: strconv.Itoa(fakeDisplayUID)}, nil
			}
		}},
		{"wrong owner", "not owned by the contained agent", func(e *installEnv, _ *fakeRunner) {
			calls := 0
			e.lookupUser = func(string) (*user.User, error) {
				calls++
				uid := fakeDisplayUID
				if calls > 1 {
					uid++
				}
				return &user.User{Uid: strconv.Itoa(uid), Gid: strconv.Itoa(fakeDisplayUID)}, nil
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env, runner, _ := newFakeEnv(t)
			prepareMigrationAuthority(t, env)
			env.agentHome = filepath.Join(shortDisplayTestDir(t), "agent")
			env.displayUnitPath = filepath.Join(filepath.Dir(env.systemUnitPath), "display.service")
			env.xvncPath = filepath.Join(t.TempDir(), "Xvnc")
			if err := os.WriteFile(env.xvncPath, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			cfg := "mode: balanced\ncontainment:\n  display:\n    enabled: true\n    backend: xvnc\n"
			if err := os.WriteFile(managedPipelockConfigPath(env), []byte(cfg), 0o600); err != nil {
				t.Fatal(err)
			}
			xPath := displaySocketPath(99)
			rfbPath := filepath.Join(env.agentHome, "rfb.sock")
			env.rfbSocketPath = rfbPath
			realStat, realLstat := env.stat, env.lstat
			env.stat = func(path string) (os.FileInfo, error) {
				if path == xPath {
					return fakeFileInfo{mode: os.ModeSocket | managedXSocketMode, sys: fakeFileSysWithUID(fakeDisplayUID)}, nil
				}
				if path == rfbPath {
					return fakeFileInfo{mode: os.ModeSocket | 0o600, sys: fakeFileSysWithUID(fakeDisplayUID)}, nil
				}
				return realStat(path)
			}
			env.lstat = func(path string) (os.FileInfo, error) {
				if path == xPath || path == rfbPath {
					return env.stat(path)
				}
				return realLstat(path)
			}
			runner.on("getfacl -p "+rfbPath, "user::rw-\ngroup::---\nother::---\n", 0, nil)
			env.lookupUser = func(string) (*user.User, error) {
				return &user.User{Uid: strconv.Itoa(fakeDisplayUID), Gid: strconv.Itoa(fakeDisplayUID)}, nil
			}
			tc.change(env, runner)
			changed, err := stepProvisionAgentDisplay().apply(context.Background(), env)
			if !changed || err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("provision changed=%v err=%v, want %q", changed, err, tc.want)
			}
		})
	}
}

func shortDisplayTestDir(t *testing.T) string {
	t.Helper()
	path, err := os.MkdirTemp("/tmp", "xv-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(path) })
	return path
}

func TestDoctorDisplayRFBRemedies(t *testing.T) {
	root := shortDisplayTestDir(t)
	xvnc := filepath.Join(root, "Xvnc")
	if err := os.WriteFile(xvnc, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	env := &doctorEnv{agentHome: root, stat: func(path string) (os.FileInfo, error) {
		if path == defaultXvncPath {
			return os.Stat(xvnc)
		}
		return os.Stat(path)
	}}
	result := checkDoctorDisplayRFB(context.Background(), env)
	if result.status != statusFail || !strings.Contains(result.remediation, "rerun contain install") {
		t.Fatalf("missing RFB remedy: %+v", result)
	}
	env.stat = func(path string) (os.FileInfo, error) { return nil, os.ErrNotExist }
	result = checkDoctorDisplayRFB(context.Background(), env)
	if result.status != statusFail || !strings.Contains(result.remediation, "TigerVNC Xvnc missing; install ") {
		t.Fatalf("missing Xvnc remedy: %+v", result)
	}
}

func TestDoctorDisplayChecksFollowConfiguredViewer(t *testing.T) {
	root := shortDisplayTestDir(t)
	cfgPath := filepath.Join(root, "pipelock.yaml")
	env := &doctorEnv{configPath: cfgPath, agentHome: root, stat: os.Stat, lstat: os.Lstat}
	if got := doctorChecksForEnv(&doctorEnv{}); len(got) != 8 {
		t.Fatalf("unconfigured checks = %d", len(got))
	}
	for _, tc := range []struct {
		name, body string
		want       int
	}{
		{"invalid", "containment: [", 8},
		{"xvfb", "containment:\n  display:\n    enabled: true\n    backend: xvfb\n", 8},
		{"xvnc", "containment:\n  display:\n    enabled: true\n    backend: xvnc\n", 11},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(cfgPath, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			checks := doctorChecksForEnv(env)
			if len(checks) != tc.want {
				t.Fatalf("checks = %d, want %d", len(checks), tc.want)
			}
			if tc.want == 11 && (checks[8].name != "agent_display_rfb" || checks[10].name != "viewer_rfb_access") {
				t.Fatalf("display checks = %+v", checks[8:])
			}
		})
	}
	if err := os.WriteFile(cfgPath, []byte("containment:\n  display:\n    enabled: true\n    backend: xvnc\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	result := checkDoctorViewerService(context.Background(), env)
	if result.status != statusPass || !strings.Contains(result.detail, "viewer disabled") {
		t.Fatalf("disabled viewer: %+v", result)
	}
	if err := os.WriteFile(cfgPath, []byte("containment:\n  display:\n    enabled: true\n    backend: xvnc\n    viewer:\n      enabled: true\n      operator_user: operator\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env.lookPath = func(string) (string, error) { return "", os.ErrNotExist }
	result = checkDoctorViewerService(context.Background(), env)
	if result.status != statusFail || result.detail != "setfacl missing" || result.remediation != "install acl" {
		t.Fatalf("missing ACL tool: %+v", result)
	}
	result = checkDoctorViewerRFBAccess(context.Background(), env)
	if result.status != statusFail || !strings.Contains(result.remediation, "rerun contain install") {
		t.Fatalf("missing RFB ACL: %+v", result)
	}
}

func TestDoctorViewerChecksReportConfiguredRemedies(t *testing.T) {
	root := shortDisplayTestDir(t)
	cfgPath := filepath.Join(root, "pipelock.yaml")
	env := &doctorEnv{configPath: cfgPath, agentHome: root, stat: os.Lstat, lstat: os.Lstat, readFile: os.ReadFile, lookPath: func(string) (string, error) { return "/usr/bin/setfacl", nil }}
	result := checkDoctorViewerService(context.Background(), env)
	if result.status != statusFail || !strings.Contains(result.detail, "viewer config missing") {
		t.Fatalf("missing config: %+v", result)
	}
	if err := os.WriteFile(cfgPath, []byte("mode: balanced\ncontainment:\n  display:\n    enabled: true\n    backend: xvnc\n    viewer:\n      enabled: true\n      operator_user: operator\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	result = checkDoctorViewerService(context.Background(), env)
	if result.status != statusFail || !strings.Contains(result.detail, "viewer unit") || result.remediation != "rerun contain install" {
		t.Fatalf("missing viewer unit: %+v", result)
	}
	rfb := filepath.Join(root, "rfb.sock")
	env.rfbSocketPath = rfb
	if err := os.Chmod(root, 0o710); err != nil { // #nosec G302 -- isolated fixture models the exact runtime-directory mode.
		t.Fatal(err)
	}
	env.lookupUser = func(string) (*user.User, error) {
		return &user.User{Uid: strconv.Itoa(os.Getuid()), Gid: strconv.Itoa(os.Getgid())}, nil
	}
	if err := os.MkdirAll(filepath.Dir(rfb), 0o750); err != nil {
		t.Fatal(err)
	}
	listener, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", rfb)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	realStat := env.stat
	env.stat = func(path string) (os.FileInfo, error) {
		info, err := realStat(path)
		if err != nil || path != rfb {
			return info, err
		}
		return viewerModeInfo{info, info.Mode()&^os.ModePerm | 0o660}, nil
	}
	env.lstat = env.stat
	env.proxyUserName = "proxy"
	env.runCmd = func(context.Context, string, ...string) (string, int, error) {
		return "user::rw-\nuser:proxy:rw-\ngroup::---\nmask::rw-\nother::---\n", 0, nil
	}
	result = checkDoctorViewerRFBAccess(context.Background(), env)
	if result.status != statusPass || !strings.Contains(result.detail, "match") {
		t.Fatalf("viewer RFB group: %+v", result)
	}
}

func TestXvncPackageForOSRelease(t *testing.T) {
	for _, tc := range []struct{ release, want string }{
		{"ID=fedora\nVERSION_ID=43\n", "tigervnc-server-minimal"},
		{"ID=fedora\nVERSION_ID=44\n", "tigervnc-x11-server"},
		{"ID=fedora\nVERSION_ID=unknown\n", "TigerVNC Xvnc"},
		{"ID=rocky\nVERSION_ID=9\n", "TigerVNC Xvnc"},
	} {
		if got := xvncPackageForOSRelease(tc.release); got != tc.want {
			t.Errorf("release %q: got %s, want %s", tc.release, got, tc.want)
		}
	}
	if got := xvncPackage(platformFamilyDebian); got != "tigervnc-standalone-server" {
		t.Fatalf("Debian package = %s", got)
	}
}

func TestXvncViewerUnitAndTraverseRevocation(t *testing.T) {
	yes := true
	env, runner, _ := newFakeEnv(t)
	env.agentHome = filepath.Join(shortDisplayTestDir(t), "agent")
	env.displayNumber = 99
	env.xvncPath = "/usr/bin/Xvnc"
	env.displayConfig = config.ContainmentDisplay{Backend: "xvnc", Viewer: config.ContainmentDisplayViewer{Enabled: &yes, Clipboard: &yes, OperatorUser: "operator"}}
	unit := renderAgentDisplayUnit(env)
	for _, want := range []string{"Group=" + viewerUserName, "RuntimeDirectoryMode=0710", "-rfbunixpath /run/pipelock-agent-display/rfb.sock", "-rfbunixmode 0660"} {
		if !strings.Contains(unit, want) {
			t.Fatalf("viewer unit missing %q: %s", want, unit)
		}
	}
	if strings.Contains(unit, "setfacl") || strings.Contains(unit, env.agentHome+"/.local") {
		t.Fatal("new viewer unit retains agent-home ACL access")
	}
	if strings.Contains(unit, "-AcceptCutText=0") {
		t.Fatal("clipboard enabled but unit disabled it")
	}
	if err := removeViewerTraverseACL(context.Background(), &installEnv{}); err != nil {
		t.Fatalf("unconfigured ACL removal: %v", err)
	}
	if err := os.MkdirAll(env.agentHome, 0o750); err != nil {
		t.Fatal(err)
	}
	runner.on("setfacl -x u:"+env.proxyUserName+" "+env.agentHome, "", 1, errors.New("ACL unavailable"))
	err := removeViewerTraverseACL(context.Background(), env)
	if err == nil || !strings.Contains(err.Error(), "revoke viewer traverse ACL") || !strings.Contains(err.Error(), env.agentHome) {
		t.Fatalf("ACL revocation error = %v", err)
	}
}

func TestViewerTraverseACLRestoresGroupAccess(t *testing.T) {
	if _, err := exec.LookPath("setfacl"); err != nil {
		t.Skip("setfacl unavailable")
	}
	if _, err := exec.LookPath("getfacl"); err != nil {
		t.Skip("getfacl unavailable")
	}
	dir := t.TempDir()
	// #nosec G302 -- the fixture needs a group entry to catch permission drift.
	if err := os.Chmod(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	// #nosec G204 -- the command targets this test's temporary directory.
	if output, err := exec.CommandContext(context.Background(), "setfacl", "-m", "g::r-x", dir).CombinedOutput(); err != nil {
		t.Fatalf("seed group ACL: %v: %s", err, output)
	}
	// #nosec G204 -- the command reads this test's temporary directory.
	before, err := exec.CommandContext(context.Background(), "getfacl", "-cp", dir).Output()
	if err != nil {
		t.Fatal(err)
	}
	proxyUID := "65534"
	if os.Getuid() == 65534 {
		proxyUID = "65533"
	}
	// #nosec G204 -- the command targets this test's temporary directory.
	if output, err := exec.CommandContext(context.Background(), "setfacl", "-m", "u:"+proxyUID+":--x", dir).CombinedOutput(); err != nil {
		t.Fatalf("grant ACL: %v: %s", err, output)
	}
	env, _, _ := newFakeEnv(t)
	proxyUser, err := user.LookupId(proxyUID)
	if err != nil {
		t.Fatal(err)
	}
	env.proxyUserName = proxyUser.Username
	env.runCmd = func(ctx context.Context, name string, args ...string) (string, int, error) {
		// #nosec G204 -- production passes only getfacl/setfacl and the test directory.
		output, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
		if err != nil {
			return string(output), 1, err
		}
		return string(output), 0, nil
	}
	if err := revokeViewerTraverseDir(context.Background(), env, dir); err != nil {
		t.Fatal(err)
	}
	// #nosec G204 -- the command reads this test's temporary directory.
	after, err := exec.CommandContext(context.Background(), "getfacl", "-cp", dir).Output()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(after), "user:"+proxyUID+":") || !strings.Contains(string(after), "group::r-x") || !strings.Contains(string(before), "group::r-x") {
		t.Fatalf("legacy grant not safely revoked:\nbefore: %s\nafter: %s", before, after)
	}
}

func TestProbeAgentDisplayRFBViewerModeAndBackend(t *testing.T) {
	const fakeDisplayUID = 4242
	root := shortDisplayTestDir(t)
	cfgPath := filepath.Join(root, "pipelock.yaml")
	if err := os.WriteFile(cfgPath, []byte("mode: balanced\ncontainment:\n  display:\n    enabled: true\n    backend: xvfb\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := &probeEnv{configPath: cfgPath}
	if status, detail := probeAgentDisplayRFB(context.Background(), env); status != statusPass || detail != "RFB display is not configured" {
		t.Fatalf("Xvfb = %s %q", status, detail)
	}
	if err := os.WriteFile(cfgPath, []byte("mode: balanced\ncontainment:\n  display:\n    enabled: true\n    backend: xvnc\n    viewer:\n      enabled: true\n      operator_user: operator\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env.agentHome = filepath.Join(root, "agent")
	env.displayUnitPath = filepath.Join(root, "display.service")
	env.proxyUserName = "proxy"
	env.agentUserName = testAgentUser
	yes := true
	unit := renderAgentDisplayUnit(&installEnv{agentHome: env.agentHome, agentUserName: env.agentUserName, displayNumber: 99, displayConfig: config.ContainmentDisplay{Backend: "xvnc", Viewer: config.ContainmentDisplayViewer{Enabled: &yes}}})
	if err := os.WriteFile(env.displayUnitPath, []byte(unit), 0o600); err != nil {
		t.Fatal(err)
	}
	env.readFile = os.ReadFile
	env.lstat = func(string) (os.FileInfo, error) {
		return fakeFileInfo{mode: os.ModeSocket | 0o660, sys: fakeFileSysWithUID(fakeDisplayUID)}, nil
	}
	env.stat = func(string) (os.FileInfo, error) { return nil, errors.New("RFB probe must use lstat") }
	env.runCmd = func(context.Context, string, ...string) (string, int, error) {
		return "user::rw-\nuser:proxy:rw-\ngroup::---\nmask::rw-\nother::---\n", 0, nil
	}
	env.lookupUser = func(string) (*user.User, error) {
		return &user.User{Uid: strconv.Itoa(fakeDisplayUID), Gid: strconv.Itoa(fakeDisplayUID)}, nil
	}
	status, detail := probeAgentDisplayRFB(context.Background(), env)
	if status != statusPass || !strings.Contains(detail, "private") {
		t.Fatalf("viewer RFB probe = %s %q", status, detail)
	}
	if err := os.Remove(env.displayUnitPath); err != nil {
		t.Fatal(err)
	}
	if status, detail := probeAgentDisplayRFB(context.Background(), env); status != statusFail || !strings.Contains(detail, "read display unit") {
		t.Fatalf("missing Xvnc unit = %s %q", status, detail)
	}
}

func TestXvncResolutionIgnoresPATHAndMatchesVerify(t *testing.T) {
	present := func(paths ...string) func(string) (os.FileInfo, error) {
		return func(path string) (os.FileInfo, error) {
			for _, p := range paths {
				if p == path {
					return os.Stat(os.TempDir())
				}
			}
			return nil, os.ErrNotExist
		}
	}
	for _, tc := range []struct {
		name      string
		installed []string
		want      string
	}{
		{"fedora", []string{"/usr/bin/Xvnc"}, "/usr/bin/Xvnc"},
		{"debian without alternative", []string{"/usr/bin/Xtigervnc"}, "/usr/bin/Xtigervnc"},
		{"system binary wins over local", []string{"/usr/local/bin/Xvnc", "/usr/bin/Xvnc"}, "/usr/bin/Xvnc"},
		{"local only", []string{"/usr/local/bin/Xvnc"}, "/usr/local/bin/Xvnc"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stat := present(tc.installed...)
			env := &installEnv{stat: stat, lookPath: func(string) (string, error) { return "/opt/elsewhere/Xvnc", nil }}
			got, err := findXvnc(env)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("install resolved %q, want %q", got, tc.want)
			}
			if v := xvncPathForVerify(stat); v != got {
				t.Fatalf("verify expects %q but install rendered %q", v, got)
			}
		})
	}
}

func TestDisabledDisplayWithoutUnitRevokesViewerTraverseACL(t *testing.T) {
	env, runner, out := newFakeEnv(t)
	env.agentHome = filepath.Join(shortDisplayTestDir(t), "agent")
	if err := os.MkdirAll(env.agentHome, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(managedPipelockConfigPath(env), []byte("containment:\n  display:\n    enabled: false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := runSteps(context.Background(), env, out, []step{stepProvisionAgentDisplay()}); err != nil {
		t.Fatal(err)
	}
	for _, call := range runner.calls {
		if call.name == "setfacl" && strings.Join(call.args, " ") == "-x u:"+env.proxyUserName+" "+env.agentHome {
			return
		}
	}
	t.Fatal("disabled display without a unit retained the viewer traverse ACL")
}

func TestXvncRuntimeSocketDoesNotGrantProxyACL(t *testing.T) {
	yes := true
	unit := renderAgentDisplayUnit(&installEnv{agentHome: "/home/agent", agentUserName: "agent", proxyUserName: "proxy", displayNumber: 99, xvncPath: "/usr/bin/Xvnc", displayConfig: config.ContainmentDisplay{Backend: "xvnc", Viewer: config.ContainmentDisplayViewer{Enabled: &yes}}})
	for _, want := range []string{"Group=" + viewerUserName, "RuntimeDirectory=pipelock-agent-display", "RuntimeDirectoryMode=0710", "-rfbunixpath /run/pipelock-agent-display/rfb.sock", "-rfbunixmode 0660"} {
		if !strings.Contains(unit, want) {
			t.Fatalf("runtime socket unit missing %q", want)
		}
	}
	for _, absent := range []string{"setfacl", "getfacl", "/home/agent/.local/state/pipelock/display", "Group=proxy"} {
		if strings.Contains(unit, absent) {
			t.Fatalf("runtime socket unit retains %q", absent)
		}
	}
}
