// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package contain

import (
	"bufio"
	"context"
	"errors"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/cli/contain/viewer"
)

func TestViewerControlProtocolAndPeer(t *testing.T) {
	for _, tc := range []struct {
		name, mode, response string
		uid                  uint32
	}{
		{"view", "view\n", "ok\n", currentViewerUID()},
		{"control", "control\n", "ok\n", currentViewerUID()},
		{"unknown mode", "other\n", "denied\n", currentViewerUID()},
		{"wrong peer", "view\n", "denied\n", currentViewerUID() + 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "control.sock")
			ln, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", path)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			upstream, server := net.Pipe()
			defer func() { _ = server.Close() }()
			v, err := viewer.New(viewer.Config{Display: ":99", ExpectedUID: 4242, Dial: func() (net.Conn, error) { return upstream, nil }, PeerUID: func(net.Conn) (uint32, error) { return 4242, nil }})
			if err != nil {
				t.Fatal(err)
			}
			go serveViewerControl(ctx, ln, tc.uid, v)
			conn, err := (&net.Dialer{}).DialContext(ctx, "unix", path)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close() }()
			if _, err := conn.Write([]byte(tc.mode)); err != nil {
				t.Fatal(err)
			}
			line, err := bufio.NewReader(conn).ReadString('\n')
			if err != nil || line != tc.response {
				t.Fatalf("response = %q: %v", line, err)
			}
		})
	}
}

func TestViewerServeDependencies(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "control.sock")
	opts := serveOptions{display: ":99", rfbSocket: filepath.Join(root, "rfb.sock"), operator: "operator", agentUser: "agent"}
	base := realServeDeps()
	base.path = path
	base.lookup = func(string) (*user.User, error) { return &user.User{Uid: "1000"}, nil }
	base.run = func(context.Context, string, ...string) (string, int, error) { return "", 0, nil }
	for _, tc := range []struct {
		name, want string
		change     func(*serveDeps)
		opts       serveOptions
	}{
		{"required", "requires operator", func(*serveDeps) {}, serveOptions{}},
		{"lookup", "viewer operator", func(d *serveDeps) { d.lookup = func(string) (*user.User, error) { return nil, errors.New("missing") } }, opts},
		{"invalid uid", "viewer operator uid", func(d *serveDeps) { d.lookup = func(string) (*user.User, error) { return &user.User{Uid: "bad"}, nil } }, opts},
		{"listen", "viewer control socket", func(d *serveDeps) {
			d.listen = func(context.Context, string, string) (net.Listener, error) { return nil, errors.New("unavailable") }
		}, opts},
		{"setfacl exit", "exit 1", func(d *serveDeps) {
			d.run = func(context.Context, string, ...string) (string, int, error) { return "denied", 1, nil }
		}, opts},
		{"setfacl exec", "grant viewer control socket to operator", func(d *serveDeps) {
			d.run = func(context.Context, string, ...string) (string, int, error) {
				return "", 0, errors.New("missing setfacl")
			}
		}, opts},
	} {
		t.Run(tc.name, func(t *testing.T) {
			deps := base
			tc.change(&deps)
			if err := runViewerServe(context.Background(), deps, tc.opts); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
			_ = os.Remove(path)
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runViewerServe(ctx, base, opts) }()
	deadline := time.After(time.Second)
	for {
		if _, err := os.Lstat(path); err == nil {
			break
		}
		select {
		case <-deadline:
			t.Fatal("positive control did not listen")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("socket cleanup: %v", err)
	}
}

func TestReadViewerModeDoesNotConsumeRFB(t *testing.T) {
	server, client := net.Pipe()
	defer func() { _ = server.Close(); _ = client.Close() }()
	go func() { _, _ = client.Write([]byte("view\nRFB 003.008\n")) }()
	mode, err := readViewerMode(server)
	if err != nil || mode != "view\n" {
		t.Fatalf("mode = %q: %v", mode, err)
	}
	buf := make([]byte, 12)
	if _, err := server.Read(buf); err != nil || !strings.HasPrefix(string(buf), "RFB") {
		t.Fatalf("RFB prefix = %q: %v", buf, err)
	}
}
