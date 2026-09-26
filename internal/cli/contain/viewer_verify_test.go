// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
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
