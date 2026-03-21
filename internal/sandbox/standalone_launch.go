// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
)

// StandaloneLaunchConfig configures the standalone sandbox launcher.
type StandaloneLaunchConfig struct {
	// Ctx controls the child's lifetime.
	Ctx context.Context

	// Command is the command and arguments to execute inside the sandbox.
	Command []string

	// Workspace is the resolved absolute workspace path.
	Workspace string

	// Policy overrides the default sandbox policy.
	Policy *Policy

	// ExtraEnv contains additional KEY=VALUE pairs to pass to the child.
	ExtraEnv []string

	// ProxyHandler is called for each connection from the sandboxed agent.
	// It receives the connection from the bridge proxy and should handle
	// it as an HTTP forward proxy (CONNECT tunneling, DLP scanning, etc.).
	// If nil, connections are forwarded directly (no scanning).
	ProxyHandler func(conn net.Conn)
}

// LaunchStandalone runs a command in a full sandbox with network traffic
// routed through pipelock's scanner via a Unix domain socket bridge.
//
// Architecture:
//  1. Parent creates Unix socket proxy at /tmp/pipelock-sandbox-<pid>/proxy.sock
//  2. Parent forks child in new user+net namespace
//  3. Child applies Landlock + seccomp + rlimits
//  4. Child starts bridge proxy on loopback (127.0.0.1:8888)
//  5. Child runs agent command with HTTP_PROXY pointing to bridge
//  6. Agent traffic: loopback → bridge → Unix socket → parent proxy → scanner → internet
//
// Returns when the agent command exits.
func LaunchStandalone(cfg StandaloneLaunchConfig) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("%w: sandbox requires Linux", ErrUnavailable)
	}

	if err := ValidateWorkspace(cfg.Workspace); err != nil {
		return fmt.Errorf("workspace validation: %w", err)
	}

	// Validate policy doesn't re-authorize secret directories.
	policy := DefaultPolicy(cfg.Workspace)
	if cfg.Policy != nil {
		policy = *cfg.Policy
	}
	if err := ValidatePolicy(policy); err != nil {
		return err
	}

	ctx := cfg.Ctx
	if ctx == nil {
		ctx = context.Background()
	}

	// Create sandbox temp directory for the Unix socket.
	sandboxDir := fmt.Sprintf("/tmp/pipelock-sandbox-%d", os.Getpid())
	if err := os.MkdirAll(sandboxDir, 0o750); err != nil {
		return fmt.Errorf("creating sandbox dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(sandboxDir) }()

	socketPath := ProxySocketPath(sandboxDir)

	// Start Unix socket proxy listener.
	_ = os.Remove(socketPath) // clean up stale socket
	unixLn, err := (&net.ListenConfig{}).Listen(ctx, "unix", socketPath)
	if err != nil {
		return fmt.Errorf("unix proxy listen: %w", err)
	}
	defer func() { _ = unixLn.Close() }()

	// Chmod the socket so the sandboxed child can connect.
	if err := os.Chmod(socketPath, 0o600); err != nil {
		return fmt.Errorf("chmod socket: %w", err)
	}

	// Accept connections from the bridge proxy in the child.
	var proxyWg sync.WaitGroup
	go func() {
		for {
			conn, err := unixLn.Accept()
			if err != nil {
				return // listener closed
			}
			proxyWg.Add(1)
			go func() {
				defer proxyWg.Done()
				if cfg.ProxyHandler != nil {
					cfg.ProxyHandler(conn)
				} else {
					// Default: direct forwarding (no scanning).
					handleDirectForward(conn)
				}
			}()
		}
	}()

	// Fork child in sandbox with standalone init mode.
	selfExe, err := os.Readlink("/proc/self/exe")
	if err != nil {
		return fmt.Errorf("reading /proc/self/exe: %w", err)
	}

	cmd := exec.CommandContext(ctx, selfExe) //nolint:gosec // G204: re-exec of self
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	cmd.Env = []string{
		standaloneInitEnv + "=1",
		"__PIPELOCK_SANDBOX_WORKSPACE=" + cfg.Workspace,
		"__PIPELOCK_SANDBOX_COMMAND=" + strings.Join(cfg.Command, "\x1f"),
		"__PIPELOCK_SANDBOX_SOCKET=" + socketPath,
	}
	if len(cfg.ExtraEnv) > 0 {
		cmd.Env = append(cmd.Env, "__PIPELOCK_SANDBOX_EXTRA_ENV="+strings.Join(cfg.ExtraEnv, "\x1f"))
	}
	if cfg.Policy != nil {
		policyJSON, jsonErr := encodePolicyJSON(cfg.Policy)
		if jsonErr != nil {
			return fmt.Errorf("encoding sandbox policy: %w", jsonErr)
		}
		cmd.Env = append(cmd.Env, "__PIPELOCK_SANDBOX_POLICY="+policyJSON)
	}

	uid := os.Getuid()
	gid := os.Getgid()
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET,
		UidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: uid, Size: 1},
		},
		GidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: gid, Size: 1},
		},
		Pdeathsig: syscall.SIGTERM,
		Setpgid:   true,
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting sandbox child: %w", err)
	}

	// Wait for child to exit.
	waitErr := cmd.Wait()

	// Kill process group — terminate descendants that may still hold bridge
	// proxy connections open.
	if cmd.Process != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
	}

	// Close listener to prevent new connections.
	_ = unixLn.Close()

	// Wait for proxy goroutines to drain with a timeout. Detached
	// grandchildren (setsid) escape process group kill and can hold
	// bridge connections open indefinitely. The timeout prevents a hang.
	const proxyDrainTimeout = 5 * time.Second
	done := make(chan struct{})
	go func() {
		proxyWg.Wait()
		close(done)
	}()
	select {
	case <-done:
		// Clean drain.
	case <-time.After(proxyDrainTimeout):
		// Detached descendants holding connections. Force exit — the OS
		// will clean up the TCP connections when the process exits.
	}

	// Clean up child's sandbox temp dir.
	if cmd.Process != nil {
		CleanupChildSandboxDir(cmd.Process.Pid)
	}

	return waitErr
}

// handleDirectForward bridges a Unix socket connection to a direct TCP
// connection. DEBUG ONLY — no scanning, no SSRF protection. Production
// code paths always use cfg.ProxyHandler which routes through pipelock's
// full scanner pipeline.
func handleDirectForward(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	// Read the first line to get the CONNECT target.
	// For now, just close — the real handler is provided by the CLI.
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return
	}

	// Parse CONNECT host:port from the HTTP request.
	line := string(buf[:n])
	if !strings.HasPrefix(line, "CONNECT ") {
		_, _ = fmt.Fprintf(conn, "HTTP/1.1 400 Bad Request\r\n\r\nOnly CONNECT supported\r\n")
		return
	}
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return
	}
	target := parts[1]

	// Direct connect (no scanning).
	upstream, err := (&net.Dialer{}).DialContext(context.Background(), "tcp", target)
	if err != nil {
		_, _ = fmt.Fprintf(conn, "HTTP/1.1 502 Bad Gateway\r\n\r\n%v\r\n", err)
		return
	}
	defer func() { _ = upstream.Close() }()

	_, _ = fmt.Fprintf(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")

	// Bridge.
	var wg sync.WaitGroup
	wg.Add(2) //nolint:mnd // two copy directions
	go func() { defer wg.Done(); _, _ = io.Copy(upstream, conn) }()
	go func() { defer wg.Done(); _, _ = io.Copy(conn, upstream) }()
	wg.Wait()
}
