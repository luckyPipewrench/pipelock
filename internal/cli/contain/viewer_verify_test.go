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

func TestViewerServiceProbe(t *testing.T) {
	root := t.TempDir()
	configuredSocket := viewerControlSocket
	actualSocket := filepath.Join(root, "viewer.sock")
	listener, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", actualSocket)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	if err := os.Chmod(actualSocket, 0o600); err != nil {
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
	env := &probeEnv{configPath: cfgPath, displayUnitPath: displayPath, agentHome: install.agentHome, agentUserName: install.agentUserName, proxyUserName: install.proxyUserName, pipelockTarget: install.pipelockTarget, readFile: os.ReadFile, stat: statSocket, lstat: statSocket, lookupUser: func(string) (*user.User, error) { return &user.User{Uid: strconv.Itoa(os.Getuid())}, nil }, runCmd: func(context.Context, string, ...string) (string, int, error) { return "active\n", 0, nil }}
	if status, detail := probeViewerService(context.Background(), env); status != statusPass {
		t.Fatalf("valid service: %s %s", status, detail)
	}
	wideSocket = true
	if status, detail := probeViewerService(context.Background(), env); status != statusFail || !strings.Contains(detail, "socket mode") {
		t.Fatalf("wide socket: %s %s", status, detail)
	}
	wideSocket = false
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
	if err := os.Chmod(actual, 0o600); err != nil {
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
	listener, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", rfbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	if err := os.Chmod(rfbPath, 0o660); err != nil {
		t.Fatal(err)
	}
	base := probeEnv{configPath: cfgPath, agentHome: filepath.Join(root, "agent"), proxyUserName: "proxy", lstat: os.Lstat, runCmd: func(context.Context, string, ...string) (string, int, error) {
		return "user::rw-\nuser:proxy:rw-\ngroup::---\nmask::rw-\nother::---\n", 0, nil
	}}
	if status, detail := probeViewerRFBAccess(context.Background(), &base); status != statusPass || !strings.Contains(detail, "matches") {
		t.Fatalf("valid RFB access = %s %q", status, detail)
	}
	for _, tc := range []struct {
		name, want string
		change     func(*probeEnv)
	}{
		{"config", "viewer config", func(e *probeEnv) { e.configPath = filepath.Join(root, "missing.yaml") }},
		{"socket", "RFB socket", func(e *probeEnv) { e.lstat = func(string) (os.FileInfo, error) { return nil, os.ErrPermission } }},
		{"mode", "want 0660", func(e *probeEnv) {
			e.lstat = func(path string) (os.FileInfo, error) {
				info, err := os.Lstat(path)
				if err != nil {
					return nil, err
				}
				return viewerModeInfo{info, info.Mode()&^os.ModePerm | 0o666}, nil
			}
		}},
		{"ACL", "RFB ACL", func(e *probeEnv) {
			e.runCmd = func(context.Context, string, ...string) (string, int, error) {
				return "", 1, errors.New("ACL unavailable")
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
}
