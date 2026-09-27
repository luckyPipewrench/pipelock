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
	if !strings.Contains(unit, "Group="+viewerUserName) || !strings.Contains(unit, "ExecStartPre=+/usr/bin/install -d -o root -g "+viewerUserName+" -m 0730 /run/pipelock-agent-display") || strings.Contains(unit, "setfacl") {
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
			if err := os.MkdirAll(env.agentHome, 0o750); err != nil {
				t.Fatal(err)
			}
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
			rfbSocket := filepath.Join(shortDisplayTestDir(t), "rfb.sock")
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
				if path == filepath.Dir(rfbSocket) {
					return fakeFileInfo{mode: os.ModeDir | 0o730, sys: fakeFileSysWithUID(0)}, nil
				}
				return originalLstat(path)
			}
			env.lookupUser = func(string) (*user.User, error) {
				return &user.User{Uid: strconv.Itoa(os.Getuid()), Gid: "0"}, nil
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
			if !tc.wantFailure && !runnerSaw(runner, "setfacl -x u:"+env.proxyUserName+" "+env.agentHome) {
				t.Fatal("migration did not retry legacy viewer ACL cleanup")
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
		"--mask -m g::r-x " + env.agentHome,
		"-x u:" + env.proxyUserName + " " + filepath.Join(env.agentHome, ".local"),
		"--mask -m g::r-x " + filepath.Join(env.agentHome, ".local"),
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("setfacl calls = %q, want %q", got, want)
	}
	env.lstat = func(string) (os.FileInfo, error) { return nil, os.ErrPermission }
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
		// The first two lookupUser calls belong to writeDisplayAuthority's
		// chown (agent) and checkRFBRuntimeDirectory's group check (viewer);
		// both must keep succeeding so the failure below is isolated to the
		// "lookup RFB owner" check's own, third, call.
		{"lookup owner", "lookup RFB owner", func(e *installEnv, _ *fakeRunner) {
			calls := 0
			e.lookupUser = func(string) (*user.User, error) {
				calls++
				if calls > 2 {
					return nil, errors.New("identity unavailable")
				}
				return &user.User{Uid: strconv.Itoa(fakeDisplayUID), Gid: "0"}, nil
			}
		}},
		{"parse owner", "parse RFB owner uid", func(e *installEnv, _ *fakeRunner) {
			calls := 0
			e.lookupUser = func(string) (*user.User, error) {
				calls++
				if calls > 2 {
					return &user.User{Uid: "bad"}, nil
				}
				return &user.User{Uid: strconv.Itoa(fakeDisplayUID), Gid: "0"}, nil
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
				return &user.User{Uid: strconv.Itoa(uid), Gid: "0"}, nil
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
			rfbPath := filepath.Join(shortDisplayTestDir(t), "rfb.sock")
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
				if path == filepath.Dir(rfbPath) {
					return fakeFileInfo{mode: os.ModeDir | 0o730, sys: fakeFileSysWithUID(0)}, nil
				}
				if path == xPath || path == rfbPath {
					return env.stat(path)
				}
				return realLstat(path)
			}
			runner.on("getfacl -p "+rfbPath, "user::rw-\ngroup::---\nother::---\n", 0, nil)
			env.lookupUser = func(string) (*user.User, error) {
				return &user.User{Uid: strconv.Itoa(fakeDisplayUID), Gid: "0"}, nil
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

func TestDoctorDisplayRFBPassesWithViewerEnabled(t *testing.T) {
	root := shortDisplayTestDir(t)
	xvnc := filepath.Join(root, "Xvnc")
	if err := os.WriteFile(xvnc, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(root, "pipelock.yaml")
	if err := os.WriteFile(cfgPath, []byte("containment:\n  display:\n    enabled: true\n    backend: xvnc\n    viewer:\n      enabled: true\n      operator_user: operator\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rfb := viewerRFBSocket
	env := &doctorEnv{configPath: cfgPath, agentHome: root, agentUserName: testAgentUser, lookupUser: func(string) (*user.User, error) {
		return &user.User{Uid: strconv.Itoa(os.Getuid()), Gid: strconv.Itoa(os.Getgid())}, nil
	}, stat: func(path string) (os.FileInfo, error) {
		switch path {
		case defaultXvncPath:
			return os.Stat(xvnc)
		case rfb:
			return fakeFileInfo{mode: os.ModeSocket | 0o660}, nil
		default:
			return os.Stat(path)
		}
	}, lstat: func(path string) (os.FileInfo, error) {
		if path == rfb {
			return fakeFileInfo{mode: os.ModeSocket | 0o660, sys: fakeFileSysWithOwner(testUID(), testGID())}, nil
		}
		if path == filepath.Dir(rfb) {
			return fakeFileInfo{mode: os.ModeDir | 0o730, sys: fakeFileSysWithOwner(0, testGID())}, nil
		}
		return os.Lstat(path)
	}}
	result := checkDoctorDisplayRFB(context.Background(), env)
	if result.status != statusPass || !strings.Contains(result.detail, "0660") {
		t.Fatalf("viewer-enabled RFB socket should pass at 0660: %+v", result)
	}
	originalLstat := env.lstat
	for _, tc := range []struct {
		name string
		mode os.FileMode
		uid  uint32
	}{
		{name: "symlink", mode: os.ModeSymlink | 0o660, uid: testUID()},
		{name: "foreign owner", mode: os.ModeSocket | 0o660, uid: testUID() + 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env.lstat = func(path string) (os.FileInfo, error) {
				if path == rfb {
					return fakeFileInfo{mode: tc.mode, sys: fakeFileSysWithOwner(tc.uid, testGID())}, nil
				}
				return originalLstat(path)
			}
			if got := checkDoctorDisplayRFB(context.Background(), env); got.status != statusFail {
				t.Fatalf("unsafe RFB socket accepted: %+v", got)
			}
		})
	}
}

func TestDoctorDisplayChecksFollowConfiguredViewer(t *testing.T) {
	root := shortDisplayTestDir(t)
	cfgPath := filepath.Join(root, "pipelock.yaml")
	env := &doctorEnv{configPath: cfgPath, agentHome: root, stat: os.Stat, lstat: os.Lstat, runCmd: func(context.Context, string, ...string) (string, int, error) {
		return "user::rwx\ngroup::r-x\nother::---\n", 0, nil
	}}
	if got := doctorChecksForEnv(&doctorEnv{}); len(got) != 8 {
		t.Fatalf("unconfigured checks = %d", len(got))
	}
	for _, tc := range []struct {
		name, body string
		want       int
	}{
		{"invalid", "containment: [", 8},
		{"xvfb", "containment:\n  display:\n    enabled: true\n    backend: xvfb\n", 9},
		{"xvnc", "containment:\n  display:\n    enabled: true\n    backend: xvnc\n", 12},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(cfgPath, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			checks := doctorChecksForEnv(env)
			if len(checks) != tc.want {
				t.Fatalf("checks = %d, want %d", len(checks), tc.want)
			}
			if tc.want == 12 && (checks[8].name != "agent_display_rfb" || checks[10].name != "viewer_rfb_access" || checks[11].name != "legacy_viewer_acl") {
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
	env := &doctorEnv{configPath: cfgPath, agentHome: root, stat: os.Lstat, lstat: os.Lstat, readFile: os.ReadFile, lookPath: func(string) (string, error) { return "/usr/bin/setfacl", nil }, runCmd: func(context.Context, string, ...string) (string, int, error) {
		return "user::rwx\ngroup::r-x\nother::---\n", 0, nil
	}}
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
	if err := os.Chmod(root, 0o730); err != nil { // #nosec G302 -- isolated fixture models the exact runtime-directory mode.
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
		if err != nil {
			return info, err
		}
		if path == root {
			return viewerRuntimeInfo{viewerModeInfo{info, info.Mode()}, fakeFileSysWithOwner(0, testGID())}, nil
		}
		if path != rfb {
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
	for _, want := range []string{"Group=" + viewerUserName, "ExecStartPre=+/usr/bin/install -d -o root -g " + viewerUserName + " -m 0730 /run/pipelock-agent-display", "-rfbunixpath /run/pipelock-agent-display/rfb.sock", "-rfbunixmode 0660"} {
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

func TestLegacyViewerACLRetryAfterMigratedUnit(t *testing.T) {
	env, runner, out := newFakeEnv(t)
	env.agentHome = filepath.Join(shortDisplayTestDir(t), "agent")
	env.displayUnitPath = filepath.Join(t.TempDir(), "display.service")
	legacySocket := legacyViewerSocketPath(env.agentHome)
	if err := os.MkdirAll(filepath.Dir(legacySocket), 0o750); err != nil {
		t.Fatal(err)
	}
	listener, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", legacySocket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	if err := os.WriteFile(env.displayUnitPath, []byte(renderAgentDisplayUnit(&installEnv{agentUserName: env.agentUserName, xvfbPath: "/usr/bin/Xvfb"})), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(managedPipelockConfigPath(env), []byte("containment:\n  display:\n    enabled: false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runner.on(argvFor("getfacl", "-p", env.agentHome), "user::rwx\nuser:"+env.proxyUserName+":--x\nuser:other:--x\ngroup::---\nmask::--x\nother::---\n", 0, nil)
	revoke := "setfacl -x u:" + env.proxyUserName + " " + env.agentHome
	runner.on(revoke, "denied", 1, nil)
	if _, err := stepProvisionAgentDisplay().apply(context.Background(), env); err == nil {
		t.Fatal("first revoke failure accepted")
	}
	if _, err := os.Stat(env.displayUnitPath); err != nil {
		t.Fatalf("failed revoke changed migrated unit: %v", err)
	}
	runner.on(revoke, "", 0, nil)
	if _, err := stepProvisionAgentDisplay().apply(context.Background(), env); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{revoke, "setfacl -x u:other " + env.agentHome, "setfacl --mask -m g::--- " + env.agentHome, "setfacl -x u:" + env.proxyUserName + " " + legacySocket} {
		if !runnerSaw(runner, want) {
			t.Fatalf("cleanup did not issue %q", want)
		}
	}
	if _, err := os.Lstat(legacySocket); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("legacy socket remains: %v", err)
	}
	if err := actionRemoveAgentDisplay().undo(context.Background(), env); err != nil {
		t.Fatalf("idempotent rollback cleanup: %v", err)
	}
	_ = out
}

func TestLegacyViewerACLFailsVerifyAndDoctor(t *testing.T) {
	home := filepath.Join(shortDisplayTestDir(t), "agent")
	if err := os.MkdirAll(home, 0o750); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(t.TempDir(), "pipelock.yaml")
	if err := os.WriteFile(cfg, []byte("containment:\n  display:\n    enabled: false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	run := func(_ context.Context, name string, _ ...string) (string, int, error) {
		if name == "getfacl" {
			return "user::rwx\nuser:proxy:--x\ngroup::---\nmask::--x\nother::---\n", 0, nil
		}
		return "", 0, nil
	}
	probe := &probeEnv{configPath: cfg, displayUnitPath: filepath.Join(t.TempDir(), "display.service"), agentHome: home, lstat: os.Lstat, runCmd: run}
	if status, detail := probeViewerService(context.Background(), probe); status != statusFail || !strings.Contains(detail, "non-operator") {
		t.Fatalf("verify accepted old ACL: %s %s", status, detail)
	}
	doctor := &doctorEnv{configPath: cfg, agentHome: home, lstat: os.Lstat, runCmd: run}
	if result := checkDoctorLegacyViewerACL(context.Background(), doctor); result.status != statusFail {
		t.Fatalf("doctor accepted old ACL: %+v", result)
	}
}

func TestRemoveViewerTraverseACLErrorPaths(t *testing.T) {
	t.Run("no stat hook available", func(t *testing.T) {
		env, _, _ := newFakeEnv(t)
		env.agentHome = filepath.Join(shortDisplayTestDir(t), "agent")
		env.stat, env.lstat = nil, nil
		if err := removeViewerTraverseACL(context.Background(), env); err == nil || !strings.Contains(err.Error(), "stat unavailable") {
			t.Fatalf("nil stat/lstat = %v", err)
		}
	})
	t.Run("falls back to stat when lstat is nil", func(t *testing.T) {
		env, runner, _ := newFakeEnv(t)
		env.agentHome = filepath.Join(shortDisplayTestDir(t), "agent")
		if err := os.MkdirAll(env.agentHome, 0o750); err != nil {
			t.Fatal(err)
		}
		env.lstat = nil
		runner.on(argvFor("getfacl", "-p", env.agentHome), "user::rwx\ngroup::r-x\nother::---\n", 0, nil)
		if err := removeViewerTraverseACL(context.Background(), env); err != nil {
			t.Fatalf("stat fallback: %v", err)
		}
		if !runnerSaw(runner, "setfacl -x u:"+env.proxyUserName+" "+env.agentHome) {
			t.Fatal("stat fallback did not reach the ACL revoke")
		}
	})
	t.Run("traverse path is not a real directory", func(t *testing.T) {
		env, _, _ := newFakeEnv(t)
		env.agentHome = filepath.Join(shortDisplayTestDir(t), "agent")
		if err := os.MkdirAll(filepath.Dir(env.agentHome), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(env.agentHome, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := removeViewerTraverseACL(context.Background(), env); err == nil || !strings.Contains(err.Error(), "not a real directory") {
			t.Fatalf("regular file traverse path = %v", err)
		}
	})
	t.Run("socket stat non-ENOENT error", func(t *testing.T) {
		env, runner, _ := newFakeEnv(t)
		env.agentHome = filepath.Join(shortDisplayTestDir(t), "agent")
		if err := os.MkdirAll(env.agentHome, 0o750); err != nil {
			t.Fatal(err)
		}
		runner.on(argvFor("getfacl", "-p", env.agentHome), "user::rwx\ngroup::r-x\nother::---\n", 0, nil)
		socket := legacyViewerSocketPath(env.agentHome)
		realLstat := env.lstat
		env.lstat = func(path string) (os.FileInfo, error) {
			if path == socket {
				return nil, os.ErrPermission
			}
			return realLstat(path)
		}
		if err := removeViewerTraverseACL(context.Background(), env); !errors.Is(err, os.ErrPermission) {
			t.Fatalf("socket stat error = %v", err)
		}
	})
	t.Run("legacy path is not a socket", func(t *testing.T) {
		env, runner, _ := newFakeEnv(t)
		env.agentHome = filepath.Join(shortDisplayTestDir(t), "agent")
		socket := legacyViewerSocketPath(env.agentHome)
		if err := os.MkdirAll(filepath.Dir(socket), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(socket, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		runner.on(argvFor("getfacl", "-p", env.agentHome), "user::rwx\ngroup::r-x\nother::---\n", 0, nil)
		if err := removeViewerTraverseACL(context.Background(), env); err == nil || !strings.Contains(err.Error(), "is not a socket") {
			t.Fatalf("regular file at legacy socket path = %v", err)
		}
	})
	t.Run("socket revoke failure propagates", func(t *testing.T) {
		env, runner, _ := newFakeEnv(t)
		env.agentHome = filepath.Join(shortDisplayTestDir(t), "agent")
		socket := legacyViewerSocketPath(env.agentHome)
		if err := os.MkdirAll(filepath.Dir(socket), 0o750); err != nil {
			t.Fatal(err)
		}
		listener, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", socket)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = listener.Close() })
		runner.on(argvFor("getfacl", "-p", env.agentHome), "user::rwx\ngroup::r-x\nother::---\n", 0, nil)
		runner.on(argvFor("getfacl", "-p", socket), "user::rwx\ngroup::r-x\nother::---\n", 0, nil)
		runner.on(argvFor("setfacl", "-x", "u:"+env.proxyUserName, socket), "denied", 1, nil)
		if err := removeViewerTraverseACL(context.Background(), env); err == nil || !strings.Contains(err.Error(), "revoke viewer traverse ACL on "+socket) {
			t.Fatalf("failed socket revoke = %v", err)
		}
	})
	t.Run("socket removal failure", func(t *testing.T) {
		env, runner, _ := newFakeEnv(t)
		env.agentHome = filepath.Join(shortDisplayTestDir(t), "agent")
		socket := legacyViewerSocketPath(env.agentHome)
		if err := os.MkdirAll(filepath.Dir(socket), 0o750); err != nil {
			t.Fatal(err)
		}
		listener, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", socket)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = listener.Close() })
		runner.on(argvFor("getfacl", "-p", env.agentHome), "user::rwx\ngroup::r-x\nother::---\n", 0, nil)
		runner.on(argvFor("getfacl", "-p", socket), "user::rwx\ngroup::r-x\nother::---\n", 0, nil)
		env.removeFile = func(string) error { return os.ErrPermission }
		if err := removeViewerTraverseACL(context.Background(), env); !errors.Is(err, os.ErrPermission) {
			t.Fatalf("socket removal error = %v", err)
		}
	})
}

func TestRevokeViewerTraverseDirErrorPaths(t *testing.T) {
	t.Run("readAccessACL failure", func(t *testing.T) {
		env, runner, _ := newFakeEnv(t)
		dir := shortDisplayTestDir(t)
		runner.on(argvFor("getfacl", "-p", dir), "", 1, nil)
		if err := revokeViewerTraverseDir(context.Background(), env, dir); err == nil || !strings.Contains(err.Error(), "read legacy viewer ACL") {
			t.Fatalf("getfacl failure = %v", err)
		}
	})
	t.Run("revokes a default-scoped named entry and a non-operator entry, keeps the operator", func(t *testing.T) {
		env, runner, _ := newFakeEnv(t)
		env.operatorUser = "operator"
		dir := shortDisplayTestDir(t)
		runner.on(argvFor("getfacl", "-p", dir), "user::rwx\ndefault:user:other:rwx\nuser:extra:--x\nuser:operator:--x\ngroup::r-x\nother::---\n", 0, nil)
		if err := revokeViewerTraverseDir(context.Background(), env, dir); err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"setfacl -x u:" + env.proxyUserName + " " + dir, "setfacl -x d:u:other " + dir, "setfacl -x u:extra " + dir} {
			if !runnerSaw(runner, want) {
				t.Fatalf("missing revoke call %q in %v", want, runner.calls)
			}
		}
		if runnerSaw(runner, "setfacl -x u:operator "+dir) {
			t.Fatal("revoke removed the operator's own entry")
		}
	})
	t.Run("named entry revoke failure", func(t *testing.T) {
		env, runner, _ := newFakeEnv(t)
		dir := shortDisplayTestDir(t)
		runner.on(argvFor("getfacl", "-p", dir), "user::rwx\nuser:extra:--x\ngroup::r-x\nother::---\n", 0, nil)
		runner.on(argvFor("setfacl", "-x", "u:extra", dir), "denied", 1, nil)
		if err := revokeViewerTraverseDir(context.Background(), env, dir); err == nil || !strings.Contains(err.Error(), "revoke viewer traverse ACL on "+dir) {
			t.Fatalf("named entry revoke failure = %v", err)
		}
	})
	t.Run("missing group permissions", func(t *testing.T) {
		env, runner, _ := newFakeEnv(t)
		dir := shortDisplayTestDir(t)
		runner.on(argvFor("getfacl", "-p", dir), "user::rwx\nother::---\n", 0, nil)
		if err := revokeViewerTraverseDir(context.Background(), env, dir); err == nil || !strings.Contains(err.Error(), "lacks group permissions") {
			t.Fatalf("missing group perms = %v", err)
		}
	})
	t.Run("mask restore failure", func(t *testing.T) {
		env, runner, _ := newFakeEnv(t)
		dir := shortDisplayTestDir(t)
		runner.on(argvFor("getfacl", "-p", dir), "user::rwx\ngroup::r-x\nother::---\n", 0, nil)
		runner.on(argvFor("setfacl", "--mask", "-m", "g::r-x", dir), "denied", 1, nil)
		if err := revokeViewerTraverseDir(context.Background(), env, dir); err == nil || !strings.Contains(err.Error(), "restore legacy viewer ACL mask") {
			t.Fatalf("mask restore failure = %v", err)
		}
	})
}

func TestCheckLegacyViewerACLErrorPaths(t *testing.T) {
	t.Run("stat unavailable", func(t *testing.T) {
		if err := checkLegacyViewerACL(context.Background(), nil, nil, shortDisplayTestDir(t), "operator"); err == nil || !strings.Contains(err.Error(), "stat unavailable") {
			t.Fatalf("nil stat = %v", err)
		}
	})
	t.Run("dir stat non-ENOENT error", func(t *testing.T) {
		home := shortDisplayTestDir(t)
		stat := func(string) (os.FileInfo, error) { return nil, os.ErrPermission }
		if err := checkLegacyViewerACL(context.Background(), nil, stat, home, "operator"); !errors.Is(err, os.ErrPermission) {
			t.Fatalf("dir stat error = %v", err)
		}
	})
	t.Run("traverse path is not a real directory", func(t *testing.T) {
		home := filepath.Join(shortDisplayTestDir(t), "agent")
		if err := os.MkdirAll(filepath.Dir(home), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(home, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := checkLegacyViewerACL(context.Background(), nil, os.Lstat, home, "operator"); err == nil || !strings.Contains(err.Error(), "not a real directory") {
			t.Fatalf("regular file home = %v", err)
		}
	})
	t.Run("readAccessACL failure", func(t *testing.T) {
		home := shortDisplayTestDir(t)
		run := func(context.Context, string, ...string) (string, int, error) { return "", 1, nil }
		if err := checkLegacyViewerACL(context.Background(), run, os.Lstat, home, "operator"); err == nil || !strings.Contains(err.Error(), "read legacy viewer ACL") {
			t.Fatalf("getfacl failure = %v", err)
		}
	})
	t.Run("retains a default named entry", func(t *testing.T) {
		home := shortDisplayTestDir(t)
		run := func(context.Context, string, ...string) (string, int, error) {
			return "user::rwx\ndefault:user:other:rwx\ngroup::r-x\nother::---\n", 0, nil
		}
		if err := checkLegacyViewerACL(context.Background(), run, os.Lstat, home, "operator"); err == nil || !strings.Contains(err.Error(), "retains default named entry") {
			t.Fatalf("default entry retained = %v", err)
		}
	})
	t.Run("retains a non-operator named entry", func(t *testing.T) {
		home := shortDisplayTestDir(t)
		run := func(context.Context, string, ...string) (string, int, error) {
			return "user::rwx\nuser:extra:--x\ngroup::r-x\nother::---\n", 0, nil
		}
		if err := checkLegacyViewerACL(context.Background(), run, os.Lstat, home, "operator"); err == nil || !strings.Contains(err.Error(), "retains non-operator entry") {
			t.Fatalf("non-operator entry retained = %v", err)
		}
	})
	t.Run("mask not restored", func(t *testing.T) {
		home := shortDisplayTestDir(t)
		run := func(context.Context, string, ...string) (string, int, error) {
			return "user::rwx\ngroup::r-x\nmask::rwx\nother::---\n", 0, nil
		}
		if err := checkLegacyViewerACL(context.Background(), run, os.Lstat, home, "operator"); err == nil || !strings.Contains(err.Error(), "mask is not restored") {
			t.Fatalf("stale mask = %v", err)
		}
	})
	t.Run("operator entry tolerates a wider mask", func(t *testing.T) {
		home := shortDisplayTestDir(t)
		run := func(context.Context, string, ...string) (string, int, error) {
			return "user::rwx\nuser:operator:--x\ngroup::r-x\nmask::rwx\nother::---\n", 0, nil
		}
		if err := checkLegacyViewerACL(context.Background(), run, os.Lstat, home, "operator"); err != nil {
			t.Fatalf("operator entry should tolerate its own mask: %v", err)
		}
	})
	t.Run("legacy socket remains", func(t *testing.T) {
		home := filepath.Join(shortDisplayTestDir(t), "agent")
		socket := legacyViewerSocketPath(home)
		if err := os.MkdirAll(filepath.Dir(socket), 0o750); err != nil {
			t.Fatal(err)
		}
		listener, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", socket)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = listener.Close() })
		run := func(context.Context, string, ...string) (string, int, error) {
			return "user::rwx\ngroup::r-x\nother::---\n", 0, nil
		}
		if err := checkLegacyViewerACL(context.Background(), run, os.Lstat, home, "operator"); err == nil || !strings.Contains(err.Error(), "legacy RFB socket remains") {
			t.Fatalf("leftover socket = %v", err)
		}
	})
	t.Run("legacy socket inspect error", func(t *testing.T) {
		home := shortDisplayTestDir(t)
		run := func(context.Context, string, ...string) (string, int, error) {
			return "user::rwx\ngroup::r-x\nother::---\n", 0, nil
		}
		socket := legacyViewerSocketPath(home)
		stat := func(path string) (os.FileInfo, error) {
			if path == socket {
				return nil, os.ErrPermission
			}
			return os.Lstat(path)
		}
		if err := checkLegacyViewerACL(context.Background(), run, stat, home, "operator"); !errors.Is(err, os.ErrPermission) {
			t.Fatalf("socket inspect error = %v", err)
		}
	})
}

func TestProbeLegacyViewerACL(t *testing.T) {
	t.Run("passes on a clean install", func(t *testing.T) {
		root := shortDisplayTestDir(t)
		cfgPath := filepath.Join(root, "pipelock.yaml")
		if err := os.WriteFile(cfgPath, []byte("containment:\n  display:\n    viewer:\n      operator_user: operator\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		home := filepath.Join(root, "agent")
		if err := os.MkdirAll(home, 0o750); err != nil {
			t.Fatal(err)
		}
		env := &probeEnv{configPath: cfgPath, agentHome: home, lstat: os.Lstat, runCmd: func(context.Context, string, ...string) (string, int, error) {
			return "user::rwx\nuser:operator:--x\ngroup::---\nmask::--x\nother::---\n", 0, nil
		}}
		if status, detail := probeLegacyViewerACL(context.Background(), env); status != statusPass || !strings.Contains(detail, "absent") {
			t.Fatalf("clean install = %s %s", status, detail)
		}
	})
	t.Run("missing config treats operator as empty", func(t *testing.T) {
		root := shortDisplayTestDir(t)
		env := &probeEnv{configPath: filepath.Join(root, "missing.yaml"), agentHome: root, lstat: os.Lstat, runCmd: func(context.Context, string, ...string) (string, int, error) {
			return "user::rwx\ngroup::---\nother::---\n", 0, nil
		}}
		if status, _ := probeLegacyViewerACL(context.Background(), env); status != statusPass {
			t.Fatalf("missing config with a clean directory should pass: %s", status)
		}
	})
	t.Run("other config load error fails closed", func(t *testing.T) {
		root := shortDisplayTestDir(t)
		cfgPath := filepath.Join(root, "pipelock.yaml")
		if err := os.WriteFile(cfgPath, []byte("containment: ["), 0o600); err != nil {
			t.Fatal(err)
		}
		env := &probeEnv{configPath: cfgPath, agentHome: root, lstat: os.Lstat}
		if status, detail := probeLegacyViewerACL(context.Background(), env); status != statusFail || !strings.Contains(detail, "viewer config") {
			t.Fatalf("invalid config = %s %s", status, detail)
		}
	})
	t.Run("falls back to stat when lstat is nil", func(t *testing.T) {
		root := shortDisplayTestDir(t)
		env := &probeEnv{configPath: filepath.Join(root, "missing.yaml"), agentHome: root, stat: os.Lstat, runCmd: func(context.Context, string, ...string) (string, int, error) {
			return "user::rwx\ngroup::---\nother::---\n", 0, nil
		}}
		if status, _ := probeLegacyViewerACL(context.Background(), env); status != statusPass {
			t.Fatalf("stat fallback = %s", status)
		}
	})
	t.Run("fails when the legacy grant remains", func(t *testing.T) {
		root := shortDisplayTestDir(t)
		env := &probeEnv{configPath: filepath.Join(root, "missing.yaml"), agentHome: root, lstat: os.Lstat, runCmd: func(context.Context, string, ...string) (string, int, error) {
			return "user::rwx\nuser:extra:--x\ngroup::---\nother::---\n", 0, nil
		}}
		if status, detail := probeLegacyViewerACL(context.Background(), env); status != statusFail || !strings.Contains(detail, "non-operator") {
			t.Fatalf("dirty ACL = %s %s", status, detail)
		}
	})
}

func TestCheckDisplaySocketWrongMode(t *testing.T) {
	dir := t.TempDir()
	socket := filepath.Join(dir, "x.sock")
	if err := os.WriteFile(socket, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := checkDisplaySocket(os.Lstat, socket, managedXSocketMode); err == nil || !strings.Contains(err.Error(), "want socket") {
		t.Fatalf("regular file accepted as socket: %v", err)
	}
}

func TestCheckRFBRuntimeDirectoryLookupUnavailableAndErrors(t *testing.T) {
	dir := t.TempDir()
	stat := func(string) (os.FileInfo, error) {
		return fakeFileInfo{mode: os.ModeDir | 0o730, sys: fakeFileSysWithOwner(0, 0)}, nil
	}
	socket := filepath.Join(dir, "rfb.sock")
	t.Run("nil lookup", func(t *testing.T) {
		if err := checkRFBRuntimeDirectory(stat, nil, socket); err == nil || !strings.Contains(err.Error(), "identity lookup unavailable") {
			t.Fatalf("nil lookup = %v", err)
		}
	})
	t.Run("lookup failure", func(t *testing.T) {
		lookup := func(string) (*user.User, error) { return nil, errors.New("directory unavailable") }
		if err := checkRFBRuntimeDirectory(stat, lookup, socket); err == nil || !strings.Contains(err.Error(), "RFB runtime group") {
			t.Fatalf("lookup failure = %v", err)
		}
	})
	t.Run("gid parse failure", func(t *testing.T) {
		lookup := func(string) (*user.User, error) { return &user.User{Gid: "not-a-number"}, nil }
		if err := checkRFBRuntimeDirectory(stat, lookup, socket); err == nil || !strings.Contains(err.Error(), "RFB runtime group") {
			t.Fatalf("gid parse failure = %v", err)
		}
	})
}

func TestCheckDoctorLegacyViewerACL(t *testing.T) {
	t.Run("config load error fails closed", func(t *testing.T) {
		root := shortDisplayTestDir(t)
		cfgPath := filepath.Join(root, "pipelock.yaml")
		if err := os.WriteFile(cfgPath, []byte("containment: ["), 0o600); err != nil {
			t.Fatal(err)
		}
		env := &doctorEnv{configPath: cfgPath, agentHome: root, lstat: os.Lstat}
		if result := checkDoctorLegacyViewerACL(context.Background(), env); result.status != statusFail || !strings.Contains(result.detail, "viewer config") {
			t.Fatalf("invalid config = %+v", result)
		}
	})
	t.Run("falls back to stat when lstat is nil", func(t *testing.T) {
		root := shortDisplayTestDir(t)
		env := &doctorEnv{configPath: filepath.Join(root, "missing.yaml"), agentHome: root, stat: os.Lstat, runCmd: func(context.Context, string, ...string) (string, int, error) {
			return "user::rwx\ngroup::---\nother::---\n", 0, nil
		}}
		if result := checkDoctorLegacyViewerACL(context.Background(), env); result.status != statusPass {
			t.Fatalf("stat fallback = %+v", result)
		}
	})
	t.Run("passes on a clean install", func(t *testing.T) {
		root := shortDisplayTestDir(t)
		cfgPath := filepath.Join(root, "pipelock.yaml")
		if err := os.WriteFile(cfgPath, []byte("containment:\n  display:\n    viewer:\n      operator_user: operator\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		env := &doctorEnv{configPath: cfgPath, agentHome: root, lstat: os.Lstat, runCmd: func(context.Context, string, ...string) (string, int, error) {
			return "user::rwx\nuser:operator:--x\ngroup::---\nmask::--x\nother::---\n", 0, nil
		}}
		if result := checkDoctorLegacyViewerACL(context.Background(), env); result.status != statusPass || !strings.Contains(result.detail, "absent") {
			t.Fatalf("clean install = %+v", result)
		}
	})
}

func TestXvncRuntimeSocketDoesNotGrantProxyACL(t *testing.T) {
	yes := true
	unit := renderAgentDisplayUnit(&installEnv{agentHome: "/home/agent", agentUserName: "agent", proxyUserName: "proxy", displayNumber: 99, xvncPath: "/usr/bin/Xvnc", displayConfig: config.ContainmentDisplay{Backend: "xvnc", Viewer: config.ContainmentDisplayViewer{Enabled: &yes}}})
	for _, want := range []string{"Group=" + viewerUserName, "ExecStartPre=+/usr/bin/install -d -o root -g " + viewerUserName + " -m 0730 /run/pipelock-agent-display", "-rfbunixpath /run/pipelock-agent-display/rfb.sock", "-rfbunixmode 0660"} {
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
