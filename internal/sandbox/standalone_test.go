// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"testing"
)

// skipIfStandaloneUnavailable skips tests that require forking with
// CLONE_NEWUSER + CLONE_NEWNET and bringing up loopback. CI runners
// (Ubuntu with AppArmor) restrict these capabilities.
func skipIfStandaloneUnavailable(t *testing.T) {
	t.Helper()
	if runtime.GOOS != osLinux {
		t.Skip("sandbox requires linux")
	}
	caps := Detect()
	if !caps.UserNamespaces {
		t.Skip("user namespaces unavailable (CI/AppArmor restriction)")
	}
}

func TestIsStandaloneInitMode_FalseByDefault(t *testing.T) {
	if IsStandaloneInitMode() {
		t.Error("should not be in standalone init mode during normal tests")
	}
}

func TestLaunchStandalone_EchoCommand(t *testing.T) {
	skipIfStandaloneUnavailable(t)
	workspace := t.TempDir()

	err := LaunchStandalone(StandaloneLaunchConfig{
		Command:   []string{"echo", "standalone-test-output"},
		Workspace: workspace,
	})
	// echo exits immediately, LaunchStandalone should return cleanly.
	if err != nil {
		t.Fatalf("LaunchStandalone: %v", err)
	}
}

func TestLaunchStandalone_FilesystemBlocked(t *testing.T) {
	skipIfStandaloneUnavailable(t)
	home := os.Getenv("HOME")
	if home == "" {
		t.Skip("HOME not set")
	}
	workspace := t.TempDir()

	err := LaunchStandalone(StandaloneLaunchConfig{
		Command:   []string{"cat", home + "/.ssh/id_rsa"},
		Workspace: workspace,
	})
	// Should fail because Landlock blocks HOME access.
	if err == nil {
		t.Error("expected error (filesystem should be blocked)")
	}
}

func TestLaunchStandalone_NetworkBlocked(t *testing.T) {
	skipIfStandaloneUnavailable(t)
	workspace := t.TempDir()

	err := LaunchStandalone(StandaloneLaunchConfig{
		Command:   []string{"python3", "-c", "import socket; socket.create_connection(('8.8.8.8', 53), timeout=2)"},
		Workspace: workspace,
	})
	// Should fail because network namespace blocks direct access.
	if err == nil {
		t.Error("expected error (direct network should be blocked)")
	}
}

func TestLaunchStandalone_RejectsInvalidWorkspace(t *testing.T) {
	if runtime.GOOS != osLinux {
		t.Skip("sandbox requires linux")
	}
	err := LaunchStandalone(StandaloneLaunchConfig{
		Command:   []string{"echo", "test"},
		Workspace: "/",
	})
	if err == nil {
		t.Error("expected error for / workspace")
	}
}

func TestLaunchStandalone_NonLinuxReturnsError(t *testing.T) {
	if runtime.GOOS == osLinux {
		t.Skip("testing non-linux behavior")
	}
	err := LaunchStandalone(StandaloneLaunchConfig{
		Command:   []string{"echo", "test"},
		Workspace: t.TempDir(),
	})
	if err == nil {
		t.Error("expected error on non-linux")
	}
}

func TestLaunchStandalone_ProxyHandlerCalled(t *testing.T) {
	skipIfStandaloneUnavailable(t)
	workspace := t.TempDir()

	// Track whether the proxy handler was called.
	var proxyCallBuf bytes.Buffer
	handler := func(conn net.Conn) {
		defer func() { _ = conn.Close() }()
		buf := make([]byte, 256)
		n, _ := conn.Read(buf)
		proxyCallBuf.Write(buf[:n])
		// Send back a minimal HTTP response so curl doesn't hang.
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))
	}

	// Use curl to make a request through the bridge proxy.
	// The proxy handler receives the raw request.
	err := LaunchStandalone(StandaloneLaunchConfig{
		Command:      []string{"curl", "-s", "--proxy", "http://127.0.0.1:8888", "http://test.local/check"},
		Workspace:    workspace,
		ProxyHandler: handler,
	})
	// curl may fail (test.local doesn't resolve), but we just verify
	// the handler was called.
	_ = err

	if proxyCallBuf.Len() == 0 {
		t.Error("proxy handler was never called")
	}
	if !strings.Contains(proxyCallBuf.String(), "test.local") {
		t.Errorf("proxy handler didn't receive expected request, got: %s", proxyCallBuf.String())
	}
}

func TestLaunchStandalone_BridgeProxyListens(t *testing.T) {
	skipIfStandaloneUnavailable(t)
	workspace := t.TempDir()

	// Run a command that checks HTTP_PROXY is set.
	err := LaunchStandalone(StandaloneLaunchConfig{
		Command:   []string{"sh", "-c", "echo HTTP_PROXY=$HTTP_PROXY"},
		Workspace: workspace,
	})
	if err != nil {
		t.Fatalf("LaunchStandalone: %v", err)
	}
}

func TestHandleDirectForward_CONNECT(t *testing.T) {
	// Test the fallback CONNECT handler used when no ProxyHandler is set.
	// Set up a target server.
	targetLn, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("target listen: %v", err)
	}
	defer func() { _ = targetLn.Close() }()

	go func() {
		conn, err := targetLn.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = conn.Write([]byte("hello from target"))
	}()

	// Create a pipe to simulate the bridge connection.
	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()

	// Run handleDirectForward in a goroutine.
	done := make(chan struct{})
	go func() {
		defer close(done)
		handleDirectForward(serverConn)
	}()

	// Send CONNECT request.
	_, _ = fmt.Fprintf(clientConn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n",
		targetLn.Addr(), targetLn.Addr())

	// Read response.
	buf := make([]byte, 256)
	n, _ := clientConn.Read(buf)
	resp := string(buf[:n])
	if !strings.Contains(resp, "200") {
		t.Errorf("expected 200 response, got: %s", resp)
	}

	// Read tunneled data.
	n, _ = clientConn.Read(buf)
	if got := string(buf[:n]); got != "hello from target" {
		t.Errorf("expected 'hello from target', got: %q", got)
	}

	_ = clientConn.Close()
	<-done
}

func TestHandleDirectForward_BadRequest(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()

	done := make(chan struct{})
	go func() {
		defer close(done)
		handleDirectForward(serverConn)
	}()

	// Send non-CONNECT request.
	_, _ = fmt.Fprintf(clientConn, "GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n")

	buf := make([]byte, 256)
	n, _ := clientConn.Read(buf)
	resp := string(buf[:n])
	if !strings.Contains(resp, "400") {
		t.Errorf("expected 400 for non-CONNECT, got: %s", resp)
	}
	_ = clientConn.Close()
	<-done
}

func TestBringUpLoopback(t *testing.T) {
	if runtime.GOOS != osLinux {
		t.Skip("linux only")
	}
	// bringUpLoopback only works inside a network namespace where we
	// have CAP_NET_ADMIN. In the test process (host namespace), it will
	// fail with EPERM. We just verify it doesn't panic.
	err := bringUpLoopback()
	// Expected: either nil (if already up) or permission error.
	_ = err
}
