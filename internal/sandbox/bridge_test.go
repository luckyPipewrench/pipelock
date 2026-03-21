// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestBridgeProxy_ForwardsToUnixSocket(t *testing.T) {
	// Set up a mock "parent proxy" on a Unix socket.
	dir := t.TempDir()
	socketPath := ProxySocketPath(dir)

	parentLn, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", socketPath)
	if err != nil {
		t.Fatalf("parent listen: %v", err)
	}
	defer func() { _ = parentLn.Close() }()

	// Parent: echo back whatever it receives.
	go func() {
		for {
			conn, err := parentLn.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				buf := make([]byte, 4096)
				n, _ := conn.Read(buf)
				_, _ = conn.Write(buf[:n])
			}()
		}
	}()

	// Create bridge proxy pointing to the Unix socket.
	bp, err := NewBridgeProxy(socketPath, "127.0.0.1:0")
	if err != nil {
		t.Fatalf("NewBridgeProxy: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go bp.Serve(ctx)
	defer bp.Close()

	// Connect to the bridge proxy on loopback.
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", bp.Addr())
	if err != nil {
		t.Fatalf("dial bridge: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// Send data through the bridge.
	msg := "hello through bridge"
	_, _ = fmt.Fprint(conn, msg)

	// Read response (echoed by parent).
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got := string(buf[:n]); got != msg {
		t.Errorf("got %q, want %q", got, msg)
	}
}

func TestNewBridgeProxy_ListenError(t *testing.T) {
	// Invalid address should return an error.
	_, err := NewBridgeProxy("/nonexistent/socket", "invalid-not-an-address")
	if err == nil {
		t.Error("expected error for invalid listen address")
	}
}

func TestBridgeProxy_Addr(t *testing.T) {
	dir := t.TempDir()
	socketPath := ProxySocketPath(dir)

	// Need a listener for the socket path (even if unused).
	parentLn, lnErr := (&net.ListenConfig{}).Listen(context.Background(), "unix", socketPath)
	if lnErr != nil {
		t.Fatalf("listen unix: %v", lnErr)
	}
	defer func() { _ = parentLn.Close() }()

	bp, err := NewBridgeProxy(socketPath, "127.0.0.1:0")
	if err != nil {
		t.Fatalf("NewBridgeProxy: %v", err)
	}
	defer bp.Close()

	addr := bp.Addr()
	if !strings.Contains(addr, "127.0.0.1") {
		t.Errorf("expected loopback addr, got %s", addr)
	}
}

func TestBridgeProxy_HandleConnFailsGracefully(t *testing.T) {
	// Bridge proxy with a nonexistent socket path — connections should
	// fail gracefully (log error, close conn) not panic.
	bp, err := NewBridgeProxy("/tmp/nonexistent-socket-path-xyz.sock", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("NewBridgeProxy: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go bp.Serve(ctx)
	defer bp.Close()

	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", bp.Addr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	// Write something — bridge will try to connect to nonexistent socket.
	_, _ = fmt.Fprint(conn, "test")

	// Read should get EOF or error (parent connection failed).
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	_, err = io.ReadAll(conn)
	// We just verify no panic — error or EOF is fine.
	_ = err
	_ = conn.Close()
}

func TestProxySocketPath(t *testing.T) {
	path := ProxySocketPath("/tmp/sandbox-123")
	if !strings.Contains(path, "proxy.sock") {
		t.Errorf("expected proxy.sock in path, got %s", path)
	}
	if !strings.HasPrefix(path, "/tmp/sandbox-123") {
		t.Errorf("expected /tmp/sandbox-123 prefix, got %s", path)
	}
}
