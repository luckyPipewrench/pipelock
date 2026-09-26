// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package contain

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type viewSignalWriter struct{ lines chan string }

func (w viewSignalWriter) Write(p []byte) (int, error) {
	select {
	case w.lines <- string(p):
	default:
	}
	return len(p), nil
}

func TestContainViewRelayAndBusy(t *testing.T) {
	for _, tc := range []struct{ mode, response string }{{"view", "ok\n"}, {"control", "busy\n"}} {
		t.Run(tc.mode, func(t *testing.T) {
			root := t.TempDir()
			controlPath := filepath.Join(root, "control.sock")
			localPath := filepath.Join(root, "view.sock")
			control, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", controlPath)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = control.Close() }()
			modeSeen := make(chan string, 1)
			go func() {
				conn, acceptErr := control.Accept()
				if acceptErr != nil {
					return
				}
				defer func() { _ = conn.Close() }()
				line, _ := readViewerMode(conn)
				modeSeen <- line
				_, _ = io.WriteString(conn, tc.response)
				if tc.response == "ok\n" {
					_, _ = io.Copy(conn, conn)
				}
			}()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			stdout := viewSignalWriter{lines: make(chan string, 4)}
			stderr := viewSignalWriter{lines: make(chan string, 4)}
			done := make(chan error, 1)
			go func() {
				done <- runContainView(ctx, localPath, controlPath, tc.mode, currentViewerUID(), stdout, stderr)
			}()
			select {
			case path := <-stdout.lines:
				if !strings.Contains(path, localPath) {
					t.Fatalf("printed path = %q", path)
				}
			case <-time.After(time.Second):
				t.Fatal("viewer listener did not start")
			}
			client, err := (&net.Dialer{}).DialContext(ctx, "unix", localPath)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = client.Close() }()
			if seen := <-modeSeen; seen != tc.mode+"\n" {
				t.Fatalf("mode = %q", seen)
			}
			if tc.response == "ok\n" {
				if _, err := client.Write([]byte("RFB")); err != nil {
					t.Fatal(err)
				}
				got := make([]byte, 3)
				_ = client.SetReadDeadline(time.Now().Add(time.Second))
				if _, err := io.ReadFull(client, got); err != nil || string(got) != "RFB" {
					t.Fatalf("relay = %q: %v", got, err)
				}
			} else {
				_ = client.SetReadDeadline(time.Now().Add(time.Second))
				if _, err := bufio.NewReader(client).ReadByte(); err == nil {
					t.Fatal("busy connection remained open")
				}
				select {
				case detail := <-stderr.lines:
					if !strings.Contains(detail, "busy") {
						t.Fatalf("busy reason = %q", detail)
					}
				case <-time.After(time.Second):
					t.Fatal("busy was not reported")
				}
			}
			cancel()
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if _, err := os.Lstat(localPath); !os.IsNotExist(err) {
				t.Fatalf("socket cleanup: %v", err)
			}
		})
	}
}

func TestContainViewRejectsWrongLocalPeer(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "view.sock")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := viewSignalWriter{lines: make(chan string, 4)}
	errors := viewSignalWriter{lines: make(chan string, 4)}
	done := make(chan error, 1)
	go func() {
		done <- runContainView(ctx, path, filepath.Join(root, "absent.sock"), "view", currentViewerUID()+1, out, errors)
	}()
	<-out.lines
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", path)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("wrong peer remained connected")
	}
	_ = conn.Close()
	select {
	case detail := <-errors.lines:
		if !strings.Contains(detail, "peer uid") {
			t.Fatalf("wrong peer reason = %q", detail)
		}
	case <-time.After(time.Second):
		t.Fatal("wrong peer was not reported")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestContainViewStaleSocketAndSymlink(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "view.sock")
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", path)
	if err != nil {
		t.Fatal(err)
	}
	ln.(*net.UnixListener).SetUnlinkOnClose(false)
	if err := removeStaleViewSocket(path, currentViewerUID()); err == nil || !strings.Contains(err.Error(), "already active") {
		t.Fatalf("active socket = %v", err)
	}
	_ = ln.Close()
	if err := removeStaleViewSocket(path, currentViewerUID()+1); err == nil || !strings.Contains(err.Error(), "not owned") {
		t.Fatalf("wrong owner = %v", err)
	}
	if err := removeStaleViewSocket(path, currentViewerUID()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("stale socket remains: %v", err)
	}
	if err := os.Symlink(filepath.Join(root, "target"), path); err != nil {
		t.Fatal(err)
	}
	if err := removeStaleViewSocket(path, currentViewerUID()); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlink = %v", err)
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("symlink changed: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("file"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := removeStaleViewSocket(path, currentViewerUID()); err == nil || !strings.Contains(err.Error(), "not a socket") {
		t.Fatalf("regular file = %v", err)
	}
}

func TestViewCommandDefaultRequiresRuntimeDir(t *testing.T) {
	var out bytes.Buffer
	cmd := viewCmd()
	cmd.SetOut(&out)
	if cmd.Flag("control") == nil || cmd.Flag("socket") == nil {
		t.Fatal("view flags missing")
	}
}

type failingViewWriter struct{}

func (failingViewWriter) Write([]byte) (int, error) { return 0, errors.New("terminal closed") }

func TestContainViewRefusesUnsafePathsAndReportsOutputFailure(t *testing.T) {
	root := t.TempDir()
	for _, tc := range []struct{ name, path, mode, want string }{
		{"relative path", "view.sock", "view", "clean and absolute"},
		{"unclean path", root + "/../view.sock", "view", "clean and absolute"},
		{"bad mode", filepath.Join(root, "view.sock"), "edit", "invalid viewer mode"},
		{"missing parent", filepath.Join(root, "absent", "view.sock"), "view", "listen for VNC client"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := runContainView(context.Background(), tc.path, "unused", tc.mode, currentViewerUID(), io.Discard, io.Discard)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error=%v, want %q", err, tc.want)
			}
		})
	}
	path := filepath.Join(root, "view.sock")
	err := runContainView(context.Background(), path, "unused", "view", currentViewerUID(), failingViewWriter{}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "print VNC socket: terminal closed") {
		t.Fatalf("terminal failure=%v", err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("socket left after output failure: %v", err)
	}
}
