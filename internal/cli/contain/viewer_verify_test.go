// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"errors"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

type viewerModeInfo struct {
	os.FileInfo
	mode os.FileMode
}

func (v viewerModeInfo) Mode() os.FileMode { return v.mode }

type viewerRuntimeInfo struct {
	viewerModeInfo
	owner any
}

func (v viewerRuntimeInfo) Sys() any { return v.owner }

func TestProbeViewerServiceFallsBackToStatWhenLstatIsNil(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "agent")
	if err := os.MkdirAll(home, 0o750); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(root, "pipelock.yaml")
	if err := os.WriteFile(cfgPath, []byte("containment:\n  display:\n    enabled: true\n    backend: xvnc\n    viewer:\n      enabled: true\n      operator_user: operator\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := &probeEnv{configPath: cfgPath, agentHome: home, stat: os.Lstat, readFile: os.ReadFile, displayUnitPath: filepath.Join(root, "display.service"), runCmd: func(context.Context, string, ...string) (string, int, error) {
		return "user::rwx\ngroup::---\nother::---\n", 0, nil
	}}
	if status, detail := probeViewerService(context.Background(), env); status != statusFail || !strings.Contains(detail, "viewer unit") {
		t.Fatalf("lstat fallback did not reach the unit check: %s %s", status, detail)
	}
}

func TestViewerServiceProbe(t *testing.T) {
	root := t.TempDir()
	configuredSocket := viewerControlSocket
	actualSocket := filepath.Join(root, "viewer.sock")
	listener, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", actualSocket)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	if err := os.Chmod(actualSocket, 0o660); err != nil { // #nosec G302 -- fixture models a named-operator ACL mask.
		t.Fatal(err)
	}
	yes := true
	display := config.ContainmentDisplay{Viewer: config.ContainmentDisplayViewer{Enabled: &yes, OperatorUser: "operator"}}
	cfgPath := filepath.Join(root, "pipelock.yaml")
	if err := os.WriteFile(cfgPath, []byte("mode: balanced\ncontainment:\n  display:\n    enabled: true\n    viewer:\n      enabled: true\n      operator_user: operator\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	displayPath := filepath.Join(root, "pipelock-agent-display.service")
	install := &installEnv{displayUnitPath: displayPath, agentHome: "/home/agent", agentUserName: "agent", proxyUserName: "proxy", pipelockTarget: "/usr/local/bin/pipelock", displayNumber: 99, displayConfig: display}
	service, _ := viewerUnitPaths(install)
	if err := os.WriteFile(service, []byte(renderViewerServiceUnit(install)), 0o600); err != nil {
		t.Fatal(err)
	}
	wideSocket := false
	statSocket := func(path string) (os.FileInfo, error) {
		if path == configuredSocket {
			info, err := os.Lstat(actualSocket)
			if err != nil {
				return nil, err
			}
			if wideSocket {
				return viewerModeInfo{info, info.Mode()&^os.ModePerm | 0o666}, nil
			}
			return info, nil
		}
		return os.Lstat(path)
	}
	env := &probeEnv{configPath: cfgPath, displayUnitPath: displayPath, agentHome: install.agentHome, agentUserName: install.agentUserName, proxyUserName: install.proxyUserName, pipelockTarget: install.pipelockTarget, readFile: os.ReadFile, stat: statSocket, lstat: statSocket, lookupUser: func(string) (*user.User, error) {
		return &user.User{Uid: strconv.Itoa(os.Getuid()), Gid: strconv.Itoa(os.Getgid())}, nil
	}, runCmd: func(context.Context, string, ...string) (string, int, error) { return "active\n", 0, nil }}
	env.runCmd = func(_ context.Context, name string, _ ...string) (string, int, error) {
		if name == "getfacl" {
			return "user::rw-\nuser:operator:rw-\ngroup::---\nmask::rw-\nother::---\n", 0, nil
		}
		if name == "getent" {
			return viewerUserName + ":x:" + strconv.Itoa(os.Getgid()) + ":\n", 0, nil
		}
		return "active\n", 0, nil
	}
	if status, detail := probeViewerService(context.Background(), env); status != statusPass {
		t.Fatalf("valid service: %s %s", status, detail)
	}
	env.runCmd = func(_ context.Context, name string, _ ...string) (string, int, error) {
		if name == "getfacl" {
			return "user::rw-\ngroup::---\nother::---\n", 0, nil
		}
		if name == "getent" {
			return viewerUserName + ":x:" + strconv.Itoa(os.Getgid()) + ":\n", 0, nil
		}
		return "active\n", 0, nil
	}
	if status, detail := probeViewerService(context.Background(), env); status != statusFail || !strings.Contains(detail, "ACL") {
		t.Fatalf("missing operator ACL: %s %s", status, detail)
	}
	env.runCmd = func(_ context.Context, name string, _ ...string) (string, int, error) {
		if name == "getfacl" {
			return "user::rw-\nuser:operator:rw-\ngroup::---\nmask::rw-\nother::---\n", 0, nil
		}
		if name == "getent" {
			return viewerUserName + ":x:" + strconv.Itoa(os.Getgid()) + ":\n", 0, nil
		}
		return "active\n", 0, nil
	}
	wideSocket = true
	if status, detail := probeViewerService(context.Background(), env); status != statusFail || !strings.Contains(detail, "socket mode") {
		t.Fatalf("wide socket: %s %s", status, detail)
	}
	wideSocket = false
	if err := os.Chmod(actualSocket, 0o600); err != nil {
		t.Fatal(err)
	}
	if status, detail := probeViewerService(context.Background(), env); status != statusFail || !strings.Contains(detail, "0660") {
		t.Fatalf("0600 socket: %s %s", status, detail)
	}
	if err := os.Chmod(actualSocket, 0o660); err != nil { // #nosec G302 -- fixture models a named-operator ACL mask.
		t.Fatal(err)
	}
	env.lookupUser = func(string) (*user.User, error) { return &user.User{Uid: strconv.Itoa(os.Getuid() + 1)}, nil }
	if status, detail := probeViewerService(context.Background(), env); status != statusFail || !strings.Contains(detail, "wrong user") {
		t.Fatalf("wrong owner: %s %s", status, detail)
	}
	env.lookupUser = func(string) (*user.User, error) { return &user.User{Uid: strconv.Itoa(os.Getuid())}, nil }
	if err := os.WriteFile(service, []byte("drift"), 0o600); err != nil {
		t.Fatal(err)
	}
	if status, detail := probeViewerService(context.Background(), env); status != statusFail || !strings.Contains(detail, "unit drift") {
		t.Fatalf("unit drift: %s %s", status, detail)
	}
}

func TestViewerServiceProbeFailureDirections(t *testing.T) {
	root := t.TempDir()
	cfgPath := filepath.Join(root, "pipelock.yaml")
	servicePath := filepath.Join(root, "pipelock-agent-display.service")
	service, socket := viewerUnitPaths(&installEnv{displayUnitPath: servicePath})
	writeConfig := func(enabled bool) {
		t.Helper()
		body := "mode: balanced\ncontainment:\n  display:\n    enabled: true\n    viewer:\n      enabled: false\n"
		if enabled {
			body = strings.Replace(body, "enabled: false", "enabled: true\n      operator_user: operator", 1)
		}
		if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeConfig(false)
	base := probeEnv{configPath: cfgPath, displayUnitPath: servicePath, stat: os.Lstat, lstat: os.Lstat, readFile: os.ReadFile}
	if status, detail := probeViewerService(context.Background(), &base); status != statusPass || detail != "viewer disabled" {
		t.Fatalf("disabled: %s %s", status, detail)
	}
	if err := os.WriteFile(socket, []byte(displayUnitMarker+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if status, detail := probeViewerService(context.Background(), &base); status != statusFail || !strings.Contains(detail, "disabled but unit remains") {
		t.Fatalf("disabled stale socket: %s %s", status, detail)
	}
	writeConfig(true)
	if status, detail := probeViewerService(context.Background(), &base); status != statusFail || !strings.Contains(detail, "legacy viewer HTTP socket") {
		t.Fatalf("enabled stale socket: %s %s", status, detail)
	}
	if err := os.Remove(socket); err != nil {
		t.Fatal(err)
	}
	if status, detail := probeViewerService(context.Background(), &base); status != statusFail || !strings.Contains(detail, "viewer unit") {
		t.Fatalf("missing unit: %s %s", status, detail)
	}
	base.stat = func(path string) (os.FileInfo, error) {
		if path == socket {
			return nil, os.ErrPermission
		}
		return os.Lstat(path)
	}
	if status, detail := probeViewerService(context.Background(), &base); status != statusFail || !strings.Contains(detail, "permission denied") {
		t.Fatalf("inaccessible socket unit: %s %s", status, detail)
	}
	base.stat = os.Lstat
	yes := true
	unit := renderViewerServiceUnit(&installEnv{displayUnitPath: servicePath, displayNumber: 99, displayConfig: config.ContainmentDisplay{Viewer: config.ContainmentDisplayViewer{Enabled: &yes, OperatorUser: "operator"}}})
	if err := os.WriteFile(service, []byte(unit), 0o600); err != nil {
		t.Fatal(err)
	}
	base.runCmd = func(context.Context, string, ...string) (string, int, error) { return "inactive", 3, nil }
	if status, detail := probeViewerService(context.Background(), &base); status != statusFail || !strings.Contains(detail, "inactive") {
		t.Fatalf("inactive service: %s %s", status, detail)
	}
	base.runCmd = func(context.Context, string, ...string) (string, int, error) {
		return "", 0, errors.New("manager unavailable")
	}
	if status, detail := probeViewerService(context.Background(), &base); status != statusFail || !strings.Contains(detail, "inactive") {
		t.Fatalf("manager error: %s %s", status, detail)
	}
}

func TestProbeViewerServiceConfigAndDisabledUnitErrors(t *testing.T) {
	t.Run("invalid config", func(t *testing.T) {
		root := t.TempDir()
		cfgPath := filepath.Join(root, "pipelock.yaml")
		if err := os.WriteFile(cfgPath, []byte("containment: ["), 0o600); err != nil {
			t.Fatal(err)
		}
		env := &probeEnv{configPath: cfgPath, lstat: os.Lstat}
		if status, detail := probeViewerService(context.Background(), env); status != statusFail || !strings.Contains(detail, "viewer config") {
			t.Fatalf("invalid config = %s %s", status, detail)
		}
	})
	t.Run("disabled viewer unit stat error", func(t *testing.T) {
		root := t.TempDir()
		cfgPath := filepath.Join(root, "pipelock.yaml")
		if err := os.WriteFile(cfgPath, []byte("containment:\n  display:\n    enabled: true\n    backend: xvnc\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		env := &probeEnv{configPath: cfgPath, displayUnitPath: filepath.Join(root, "display.service"), lstat: os.Lstat, stat: func(string) (os.FileInfo, error) { return nil, os.ErrPermission }}
		if status, detail := probeViewerService(context.Background(), env); status != statusFail || !strings.Contains(detail, "permission denied") {
			t.Fatalf("disabled unit stat error = %s %s", status, detail)
		}
	})
}

func TestProbeViewerServiceGroupAndProxyIsolationFailures(t *testing.T) {
	root := t.TempDir()
	cfgPath := filepath.Join(root, "pipelock.yaml")
	if err := os.WriteFile(cfgPath, []byte("mode: balanced\ncontainment:\n  display:\n    enabled: true\n    viewer:\n      enabled: true\n      operator_user: operator\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	displayPath := filepath.Join(root, "display.service")
	install := &installEnv{displayUnitPath: displayPath, proxyUserName: "proxy", displayNumber: 99, displayConfig: config.ContainmentDisplay{Viewer: config.ContainmentDisplayViewer{Enabled: new(bool), OperatorUser: "operator"}}}
	*install.displayConfig.Viewer.Enabled = true
	service, _ := viewerUnitPaths(install)
	if err := os.WriteFile(service, []byte(renderViewerServiceUnit(install)), 0o600); err != nil {
		t.Fatal(err)
	}
	actual := filepath.Join(root, "control.sock")
	listener, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", actual)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	if err := os.Chmod(actual, 0o660); err != nil { // #nosec G302 -- fixture models a named-operator ACL mask.
		t.Fatal(err)
	}
	base := probeEnv{configPath: cfgPath, displayUnitPath: displayPath, proxyUserName: "proxy", readFile: os.ReadFile, stat: os.Lstat, lstat: func(path string) (os.FileInfo, error) {
		if path == viewerControlSocket {
			return os.Lstat(actual)
		}
		return os.Lstat(path)
	}, lookupUser: func(string) (*user.User, error) {
		return &user.User{Uid: strconv.Itoa(os.Getuid()), Gid: strconv.Itoa(os.Getgid())}, nil
	}, runCmd: func(_ context.Context, name string, _ ...string) (string, int, error) {
		if name == "getfacl" {
			return "user::rw-\nuser:operator:rw-\ngroup::---\nmask::rw-\nother::---\n", 0, nil
		}
		return "active", 0, nil
	}}
	t.Run("viewer group mismatch", func(t *testing.T) {
		env := base
		env.runCmd = func(_ context.Context, name string, _ ...string) (string, int, error) {
			if name == "getfacl" {
				return "user::rw-\nuser:operator:rw-\ngroup::---\nmask::rw-\nother::---\n", 0, nil
			}
			if name == "getent" {
				return "", 1, nil
			}
			return "active", 0, nil
		}
		if status, detail := probeViewerService(context.Background(), &env); status != statusFail || !strings.Contains(detail, "inspect viewer group") {
			t.Fatalf("viewer group failure = %s %s", status, detail)
		}
	})
	t.Run("proxy isolation failure", func(t *testing.T) {
		env := base
		env.runCmd = func(_ context.Context, name string, _ ...string) (string, int, error) {
			if name == "getfacl" {
				return "user::rw-\nuser:operator:rw-\ngroup::---\nmask::rw-\nother::---\n", 0, nil
			}
			if name == "getent" {
				return viewerUserName + ":x:" + strconv.Itoa(os.Getgid()) + ":\n", 0, nil
			}
			if name == "id" {
				return viewerUserName, 0, nil
			}
			return "active", 0, nil
		}
		if status, detail := probeViewerService(context.Background(), &env); status != statusFail || !strings.Contains(detail, "must not be in the viewer group") {
			t.Fatalf("proxy isolation failure = %s %s", status, detail)
		}
	})
}

func TestViewerServiceProbeControlSocketFailureDirections(t *testing.T) {
	root := t.TempDir()
	cfgPath := filepath.Join(root, "pipelock.yaml")
	if err := os.WriteFile(cfgPath, []byte("mode: balanced\ncontainment:\n  display:\n    enabled: true\n    viewer:\n      enabled: true\n      operator_user: operator\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	displayPath := filepath.Join(root, "display.service")
	install := &installEnv{displayUnitPath: displayPath, displayNumber: 99, displayConfig: config.ContainmentDisplay{Viewer: config.ContainmentDisplayViewer{Enabled: new(bool), OperatorUser: "operator"}}}
	*install.displayConfig.Viewer.Enabled = true
	service, _ := viewerUnitPaths(install)
	if err := os.WriteFile(service, []byte(renderViewerServiceUnit(install)), 0o600); err != nil {
		t.Fatal(err)
	}
	actual := filepath.Join(root, "control.sock")
	listener, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", actual)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	if err := os.Chmod(actual, 0o660); err != nil { // #nosec G302 -- fixture models a named-operator ACL mask.
		t.Fatal(err)
	}
	base := probeEnv{configPath: cfgPath, displayUnitPath: displayPath, readFile: os.ReadFile, stat: os.Lstat, lstat: func(path string) (os.FileInfo, error) {
		if path == viewerControlSocket {
			return os.Lstat(actual)
		}
		return os.Lstat(path)
	}, runCmd: func(context.Context, string, ...string) (string, int, error) { return "active", 0, nil }, lookupUser: func(string) (*user.User, error) { return &user.User{Uid: strconv.Itoa(os.Getuid())}, nil }}
	for _, tc := range []struct {
		name, want string
		change     func(*probeEnv)
	}{
		{"missing socket", "viewer socket missing", func(e *probeEnv) { e.lstat = func(string) (os.FileInfo, error) { return nil, os.ErrNotExist } }},
		{"owner lookup", "owner lookup", func(e *probeEnv) {
			e.lookupUser = func(string) (*user.User, error) { return nil, errors.New("lookup unavailable") }
		}},
		{"invalid owner uid", "invalid syntax", func(e *probeEnv) {
			e.lookupUser = func(string) (*user.User, error) { return &user.User{Uid: "invalid"}, nil }
		}},
		{"wrong active text", "inactive", func(e *probeEnv) {
			e.runCmd = func(context.Context, string, ...string) (string, int, error) { return "activating", 0, nil }
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := base
			tc.change(&env)
			status, detail := probeViewerService(context.Background(), &env)
			if status != statusFail || !strings.Contains(detail, tc.want) {
				t.Fatalf("probe = %s %q, want %q", status, detail, tc.want)
			}
		})
	}
}

func TestViewerRFBAccessProbeReportsExactFailure(t *testing.T) {
	root := shortDisplayTestDir(t)
	cfgPath := filepath.Join(root, "pipelock.yaml")
	configBody := "mode: balanced\ncontainment:\n  display:\n    enabled: true\n    backend: xvnc\n    viewer:\n      enabled: true\n      operator_user: operator\n"
	if err := os.WriteFile(cfgPath, []byte(configBody), 0o600); err != nil {
		t.Fatal(err)
	}
	rfbPath := filepath.Join(root, "agent", ".local/state/pipelock/display/rfb.sock")
	if err := os.MkdirAll(filepath.Dir(rfbPath), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Dir(rfbPath), 0o710); err != nil { // #nosec G302 -- isolated fixture models the exact runtime-directory mode.
		t.Fatal(err)
	}
	listener, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", rfbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	wideStat := func(path string) (os.FileInfo, error) {
		info, err := os.Lstat(path)
		if err != nil {
			return info, err
		}
		if path == filepath.Dir(rfbPath) {
			return viewerRuntimeInfo{viewerModeInfo{info, info.Mode()&^os.ModePerm | 0o730}, fakeFileSysWithOwner(0, uint32(os.Getgid()))}, nil //nolint:gosec // G115: os.Getgid() fits in uint32.
		}
		if path != rfbPath {
			return info, nil
		}
		return viewerModeInfo{info, info.Mode()&^os.ModePerm | 0o660}, nil
	}
	base := probeEnv{configPath: cfgPath, agentHome: filepath.Join(root, "agent"), rfbSocketPath: rfbPath, agentUserName: "agent", proxyUserName: "proxy", lstat: wideStat, lookupUser: func(string) (*user.User, error) {
		return &user.User{Uid: strconv.Itoa(os.Getuid()), Gid: strconv.Itoa(os.Getgid())}, nil
	}, runCmd: func(context.Context, string, ...string) (string, int, error) {
		return "user::rw-\nuser:proxy:rw-\ngroup::---\nmask::rw-\nother::---\n", 0, nil
	}}
	if status, detail := probeViewerRFBAccess(context.Background(), &base); status != statusPass || !strings.Contains(detail, "match") {
		t.Fatalf("valid RFB access = %s %q", status, detail)
	}
	for _, tc := range []struct {
		name, want string
		change     func(*probeEnv)
	}{
		{"config", "viewer config", func(e *probeEnv) { e.configPath = filepath.Join(root, "missing.yaml") }},
		{"socket", "RFB socket", func(e *probeEnv) { e.lstat = func(string) (os.FileInfo, error) { return nil, os.ErrPermission } }},
		{"runtime mode", "runtime directory mode", func(e *probeEnv) {
			e.lstat = func(path string) (os.FileInfo, error) {
				info, err := wideStat(path)
				if err != nil || path != filepath.Dir(rfbPath) {
					return info, err
				}
				return viewerModeInfo{info, info.Mode()&^os.ModePerm | 0o770}, nil
			}
		}},
		{"agent owned runtime directory", "wrong owner or group", func(e *probeEnv) {
			e.lstat = func(path string) (os.FileInfo, error) {
				info, err := wideStat(path)
				if err != nil || path != filepath.Dir(rfbPath) {
					return info, err
				}
				return viewerRuntimeInfo{viewerModeInfo{info, info.Mode()}, fakeFileSysWithOwner(4242, uint32(os.Getgid()))}, nil //nolint:gosec // G115: os.Getgid() fits in uint32.
			}
		}},
		{"mode", "want 0660", func(e *probeEnv) {
			e.lstat = func(path string) (os.FileInfo, error) {
				info, err := os.Lstat(path)
				if err != nil {
					return nil, err
				}
				return viewerModeInfo{info, info.Mode()&^os.ModePerm | 0o666}, nil
			}
		}},
		{"wrong group", "wrong owner or group", func(e *probeEnv) {
			e.lookupUser = func(string) (*user.User, error) {
				return &user.User{Uid: strconv.Itoa(os.Getuid()), Gid: strconv.Itoa(os.Getgid() + 1)}, nil
			}
		}},
		{"socket group mismatch, directory group still correct", "not owned by the " + viewerUserName + " group", func(e *probeEnv) {
			e.lstat = func(path string) (os.FileInfo, error) {
				info, err := wideStat(path)
				if err != nil || path != rfbPath {
					return info, err
				}
				return viewerRuntimeInfo{viewerModeInfo{info, info.Mode()}, fakeFileSysWithOwner(uint32(os.Getuid()), 4242)}, nil //nolint:gosec // G115: os.Getuid() fits in uint32.
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := base
			tc.change(&env)
			status, detail := probeViewerRFBAccess(context.Background(), &env)
			if status != statusFail || !strings.Contains(detail, tc.want) {
				t.Fatalf("probe = %s %q, want %q", status, detail, tc.want)
			}
		})
	}
	if err := os.WriteFile(cfgPath, []byte(strings.Replace(configBody, "enabled: true\n      operator_user", "enabled: false\n      operator_user", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	disabled := base
	disabled.lstat = func(path string) (os.FileInfo, error) {
		info, err := os.Lstat(path)
		if err != nil {
			return nil, err
		}
		if path == rfbPath {
			return viewerModeInfo{info, info.Mode()&^os.ModePerm | 0o600}, nil
		}
		if path == filepath.Dir(rfbPath) {
			return viewerRuntimeInfo{viewerModeInfo{info, info.Mode()&^os.ModePerm | 0o730}, fakeFileSysWithOwner(0, uint32(os.Getgid()))}, nil //nolint:gosec // G115: os.Getgid() fits in uint32.
		}
		return info, nil
	}
	if status, detail := probeViewerRFBAccess(context.Background(), &disabled); status != statusPass {
		t.Fatalf("disabled RFB access = %s %q", status, detail)
	}
	disabled.lookupUser = func(string) (*user.User, error) {
		return &user.User{Uid: strconv.Itoa(os.Getuid()), Gid: strconv.Itoa(os.Getgid() + 1)}, nil
	}
	if status, detail := probeViewerRFBAccess(context.Background(), &disabled); status != statusFail || !strings.Contains(detail, "wrong owner or group") {
		t.Fatalf("disabled RFB wrong group = %s %q", status, detail)
	}
}
