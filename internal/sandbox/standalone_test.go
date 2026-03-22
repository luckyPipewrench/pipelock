// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sandbox

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// skipIfStandaloneUnavailable skips tests that require full standalone
// sandbox (CLONE_NEWUSER + CLONE_NEWNET + loopback setup). CI runners
// (Ubuntu with AppArmor) may allow namespace creation but restrict
// network capabilities inside the namespace.
func skipIfStandaloneUnavailable(t *testing.T) {
	t.Helper()
	if runtime.GOOS != osLinux {
		t.Skip("sandbox requires linux")
	}
	// Probe: try launching a minimal standalone sandbox. If loopback setup
	// fails (AppArmor restricts CAP_NET_ADMIN in user namespaces), skip.
	err := LaunchStandalone(StandaloneLaunchConfig{
		Command:   []string{"true"},
		Workspace: t.TempDir(),
	})
	if err != nil {
		t.Skipf("standalone sandbox unavailable: %v", err)
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

	// Create a test file in HOME so ENOENT isn't the failure reason.
	testFile := filepath.Join(home, ".pipelock-sandbox-test-marker")
	if err := os.WriteFile(testFile, []byte("test"), 0o600); err != nil {
		t.Skipf("cannot create test file in HOME: %v", err)
	}
	defer func() { _ = os.Remove(testFile) }()

	err := LaunchStandalone(StandaloneLaunchConfig{
		Command:   []string{"cat", testFile},
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

	// Verify network isolation: count network interfaces in /proc/self/net/dev.
	// In a network namespace, only "lo" exists. Skip the 2 header lines,
	// then count non-lo interfaces.
	err := LaunchStandalone(StandaloneLaunchConfig{
		Command:   []string{"sh", "-c", "awk 'NR>2 && !/^\\s*lo:/' /proc/self/net/dev | grep -q . && exit 1; exit 0"},
		Workspace: workspace,
	})
	if err != nil {
		t.Errorf("network isolation check failed (non-lo interface found): %v", err)
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
	// Use mutex for thread safety since handler runs in a goroutine.
	var mu sync.Mutex
	var proxyData string
	handler := func(conn net.Conn) {
		defer func() { _ = conn.Close() }()
		buf := make([]byte, 256)
		n, _ := conn.Read(buf)
		mu.Lock()
		proxyData = string(buf[:n])
		mu.Unlock()
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))
	}

	// Use curl to make a request through the bridge proxy.
	err := LaunchStandalone(StandaloneLaunchConfig{
		Command:      []string{"curl", "-s", "--max-time", "3", "--proxy", "http://127.0.0.1:8888", "http://test.local/check"},
		Workspace:    workspace,
		ProxyHandler: handler,
	})
	_ = err

	mu.Lock()
	defer mu.Unlock()
	if proxyData == "" {
		t.Error("proxy handler was never called")
	}
	if !strings.Contains(proxyData, "test.local") {
		t.Errorf("proxy handler didn't receive expected request, got: %s", proxyData)
	}
}

func TestLaunchStandalone_BridgeProxyListens(t *testing.T) {
	skipIfStandaloneUnavailable(t)
	workspace := t.TempDir()

	// Verify HTTP_PROXY is set and non-empty (bridge proxy address).
	err := LaunchStandalone(StandaloneLaunchConfig{
		Command:   []string{"sh", "-c", "test -n \"$HTTP_PROXY\" || exit 1"},
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

	// Read response with deadline to prevent hang on regression.
	_ = clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 256)
	n, _ := clientConn.Read(buf)
	resp := string(buf[:n])
	if !strings.Contains(resp, "200") {
		t.Errorf("expected 200 response, got: %s", resp)
	}

	// Read tunneled data.
	_ = clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))
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

	_ = clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))
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
