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
	"syscall"
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

func TestViewCommandDependencies(t *testing.T) {
	root := t.TempDir()
	base := realViewDeps(io.Discard, io.Discard)
	base.access = func(string) error { return nil }
	base.getenv = func(string) string { return root }
	base.geteuid = func() int { return os.Geteuid() }
	for _, tc := range []struct {
		name, want string
		change     func(*viewDeps)
		opts       viewOptions
	}{
		{"viewer not running", "viewer is not running", func(d *viewDeps) {
			d.access = func(string) error { return &os.PathError{Op: "access", Path: d.controlPath, Err: syscall.ENOENT} }
		}, viewOptions{}},
		{"permission denied", "rerun pipelock contain install", func(d *viewDeps) {
			d.access = func(string) error { return &os.PathError{Op: "access", Path: d.controlPath, Err: syscall.EACCES} }
		}, viewOptions{}},
		{"socket check error", "check viewer control socket", func(d *viewDeps) {
			d.access = func(string) error { return syscall.EIO }
		}, viewOptions{}},
		{"runtime", "XDG_RUNTIME_DIR is unset", func(d *viewDeps) { d.getenv = func(string) string { return "" } }, viewOptions{}},
		{"listen", "listen for VNC client", func(d *viewDeps) {
			d.listen = func(context.Context, string, string) (net.Listener, error) { return nil, errors.New("unavailable") }
		}, viewOptions{socket: filepath.Join(root, "view.sock")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			deps := base
			tc.change(&deps)
			err := runContainViewCommand(context.Background(), deps, tc.opts)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
			// A permission error is also what the configured operator sees on
			// a host whose viewer unit predates the traverse grant, so the
			// message must name both causes.
			if tc.name == "permission denied" && !strings.Contains(err.Error(), "operator_user") {
				t.Fatalf("error = %v, want it to name the operator_user cause too", err)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := viewSignalWriter{lines: make(chan string, 4)}
	base.out = ready
	done := make(chan error, 1)
	go func() { done <- runContainViewCommand(ctx, base, viewOptions{}) }()
	select {
	case <-ready.lines:
	case <-time.After(time.Second):
		t.Fatal("positive control did not listen")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestViewCommandControlModeAndFailurePaths(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "view.sock")
	deps := realViewDeps(io.Discard, io.Discard)
	deps.access = func(string) error { return nil }
	deps.getenv = func(string) string { return root }
	deps.geteuid = os.Geteuid
	deps.listen = func(_ context.Context, network, address string) (net.Listener, error) {
		if network != "unix" || address != path {
			t.Fatalf("listener = %s %s", network, address)
		}
		return nil, errors.New("listener refused")
	}
	if err := runContainViewCommand(context.Background(), deps, viewOptions{socket: path, control: true}); err == nil || !strings.Contains(err.Error(), "listen for VNC client: listener refused") {
		t.Fatalf("control listener error = %v", err)
	}
	for _, uid := range []int{-1, int(^uint32(0))} {
		if got := viewerUID(uid); got != ^uint32(0) {
			t.Fatalf("viewerUID(%d) = %d, want rejected UID", uid, got)
		}
	}
	if err := os.WriteFile(path, []byte("occupied"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runContainViewWithDeps(context.Background(), path, "", "view", currentViewerUID(), deps); err == nil || !strings.Contains(err.Error(), "not a socket") {
		t.Fatalf("occupied path error = %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	deps.listen = func(context.Context, string, string) (net.Listener, error) {
		return (&net.ListenConfig{}).Listen(context.Background(), "unix", filepath.Join(root, "other.sock"))
	}
	if err := runContainViewWithDeps(context.Background(), path, "", "view", currentViewerUID(), deps); err == nil || !strings.Contains(err.Error(), "inspect VNC socket") {
		t.Fatalf("missing listener socket error = %v", err)
	}
}

func TestViewCommandControlSendsRequestedMode(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "view.sock")
	ready := viewSignalWriter{lines: make(chan string, 4)}
	deps := realViewDeps(ready, io.Discard)
	deps.access = func(string) error { return nil }
	deps.geteuid = os.Geteuid
	modeSeen := make(chan string, 1)
	deps.dial = func(context.Context, string, string) (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			defer func() { _ = server.Close() }()
			mode, err := readViewerMode(server)
			if err == nil {
				modeSeen <- mode
				_, _ = io.WriteString(server, "busy\n")
			}
		}()
		return client, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- runContainViewCommand(ctx, deps, viewOptions{socket: path, control: true}) }()
	select {
	case printed := <-ready.lines:
		if printed != path+"\n" {
			t.Fatalf("printed socket = %q", printed)
		}
	case <-time.After(time.Second):
		t.Fatal("viewer socket did not become ready")
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	select {
	case mode := <-modeSeen:
		if mode != "control\n" {
			t.Fatalf("requested mode = %q, want control", mode)
		}
	case <-time.After(time.Second):
		t.Fatal("viewer did not send control mode")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestContainViewControlDialFailure(t *testing.T) {
	root := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	deps := realViewDeps(viewSignalWriter{lines: make(chan string, 4)}, viewSignalWriter{lines: make(chan string, 4)})
	deps.dial = func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("control unavailable") }
	stdout := deps.out.(viewSignalWriter)
	stderr := deps.errOut.(viewSignalWriter)
	path := filepath.Join(root, "view.sock")
	done := make(chan error, 1)
	go func() {
		done <- runContainViewWithDeps(ctx, path, filepath.Join(root, "control.sock"), "view", currentViewerUID(), deps)
	}()
	select {
	case <-stdout.lines:
	case <-time.After(time.Second):
		t.Fatal("listener did not start")
	}
	client, err := (&net.Dialer{}).DialContext(ctx, "unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	select {
	case detail := <-stderr.lines:
		if !strings.Contains(detail, "connect viewer control socket: control unavailable") {
			t.Fatalf("error = %q", detail)
		}
	case <-time.After(time.Second):
		t.Fatal("dial error not reported")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
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
	select {
	case <-out.lines:
	case err := <-done:
		t.Fatalf("listener exited before ready: %v", err)
	case <-time.After(time.Second):
		t.Fatal("listener did not start")
	}
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

type failingViewWriter struct{}

func (failingViewWriter) Write([]byte) (int, error) { return 0, errors.New("terminal closed") }

type failNthViewWriter struct {
	writes, failAt int
	output         bytes.Buffer
}

func (w *failNthViewWriter) Write(p []byte) (int, error) {
	w.writes++
	if w.writes == w.failAt {
		return 0, errors.New("terminal closed")
	}
	return w.output.Write(p)
}

type rejectViewListener struct{ net.Listener }

func (rejectViewListener) Accept() (net.Conn, error) { return nil, errors.New("listener failed") }

type failViewModeWriteConn struct{ net.Conn }

func (failViewModeWriteConn) Write([]byte) (int, error) { return 0, errors.New("send failed") }

func TestContainViewControlHandshakeFailures(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		failWrite  bool
	}{
		{"request", "request viewer mode: send failed", true},
		{"response", "read viewer response", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(shortDisplayTestDir(t), "local.sock")
			listener, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", path)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = listener.Close() }()
			client, err := (&net.Dialer{}).DialContext(context.Background(), "unix", path)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = client.Close() }()
			local, err := listener.Accept()
			if err != nil {
				t.Fatal(err)
			}
			dial := func(context.Context, string, string) (net.Conn, error) {
				remote, server := net.Pipe()
				if tc.failWrite {
					_ = server.Close()
					return failViewModeWriteConn{remote}, nil
				}
				go func() { _, _ = io.ReadFull(server, make([]byte, len("view\n"))); _ = server.Close() }()
				return remote, nil
			}
			err = bridgeViewClientWithDial(context.Background(), local, "control.sock", "view", currentViewerUID(), dial)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("bridge = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestContainViewReportsTerminalAndAcceptFailures(t *testing.T) {
	for _, tc := range []struct {
		name   string
		failAt int
		want   string
	}{
		{"ssh example", 2, "print SSH forwarding example"},
		{"client example", 3, "print VNC connection example"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(shortDisplayTestDir(t), "view.sock")
			writer := &failNthViewWriter{failAt: tc.failAt}
			err := runContainView(context.Background(), path, "unused", "view", currentViewerUID(), writer, io.Discard)
			if err == nil || !strings.Contains(err.Error(), tc.want+": terminal closed") {
				t.Fatalf("error = %v", err)
			}
			if !strings.Contains(writer.output.String(), path) {
				t.Fatalf("socket path was not printed: %q", writer.output.String())
			}
			if _, err := os.Lstat(path); !os.IsNotExist(err) {
				t.Fatalf("socket remains: %v", err)
			}
		})
	}
	path := filepath.Join(shortDisplayTestDir(t), "view.sock")
	deps := realViewDeps(io.Discard, io.Discard)
	deps.listen = func(ctx context.Context, network, address string) (net.Listener, error) {
		ln, err := (&net.ListenConfig{}).Listen(ctx, network, address)
		if err != nil {
			return nil, err
		}
		return rejectViewListener{ln}, nil
	}
	err := runContainViewWithDeps(context.Background(), path, "unused", "view", currentViewerUID(), deps)
	if err == nil || !strings.Contains(err.Error(), "accept VNC client: listener failed") {
		t.Fatalf("accept error = %v", err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("socket remains after accept failure: %v", err)
	}
}

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

func TestContainViewCancellationClosesActiveBridge(t *testing.T) {
	root := t.TempDir()
	localPath := filepath.Join(root, "view.sock")
	controlPath := filepath.Join(root, "control.sock")
	control, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", controlPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = control.Close() }()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	remoteReady := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := control.Accept()
		if acceptErr != nil {
			return
		}
		var request [5]byte
		_, _ = io.ReadFull(conn, request[:])
		_, _ = conn.Write([]byte("ok\n"))
		remoteReady <- conn
	}()
	out := viewSignalWriter{lines: make(chan string, 4)}
	done := make(chan error, 1)
	go func() {
		done <- runContainView(ctx, localPath, controlPath, "view", currentViewerUID(), out, io.Discard)
	}()
	select {
	case <-out.lines:
	case <-time.After(time.Second):
		t.Fatal("view listener did not start")
	}
	client, err := (&net.Dialer{}).DialContext(ctx, "unix", localPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	var remote net.Conn
	select {
	case remote = <-remoteReady:
	case <-time.After(time.Second):
		t.Fatal("bridge did not connect")
	}
	defer func() { _ = remote.Close() }()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("view did not wait for active bridge shutdown")
	}
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Fatal("client bridge remained open")
	}
	_ = remote.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := remote.Read(make([]byte, 1)); err == nil {
		t.Fatal("control bridge remained open")
	}
}
