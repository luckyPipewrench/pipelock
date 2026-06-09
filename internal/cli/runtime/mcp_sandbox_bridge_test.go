// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
	"github.com/luckyPipewrench/pipelock/internal/sandbox"
)

func TestSetupMCPSandboxBridge_LinuxStartsBridge(t *testing.T) {
	t.Parallel()

	cfg := config.Defaults()
	ks := killswitch.New(cfg)
	var stderr bytes.Buffer
	launchCfg := sandbox.LaunchConfig{}
	started := false

	closeBridge, err := setupMCPSandboxBridge(
		mcpSandboxBridgeSetupOptions{
			Context:      context.Background(),
			GOOS:         "linux",
			Config:       cfg,
			KillSwitch:   ks,
			AuditLogger:  audit.NewNop(),
			Stderr:       &stderr,
			LaunchConfig: &launchCfg,
			StartBridge: func(opts mcpSandboxBridgeStartOptions) (*mcpSandboxBridge, error) {
				if opts.Config != cfg || opts.KillSwitch != ks {
					t.Fatal("bridge start options did not preserve config and kill switch")
				}
				started = true
				return &mcpSandboxBridge{socketPath: "/tmp/pl-mcp-test/proxy.sock"}, nil
			},
		},
	)
	if err != nil {
		t.Fatalf("setupMCPSandboxBridge: %v", err)
	}
	if !started {
		t.Fatal("bridge starter was not called")
	}
	if launchCfg.BridgeSocketPath != "/tmp/pl-mcp-test/proxy.sock" {
		t.Fatalf("BridgeSocketPath = %q", launchCfg.BridgeSocketPath)
	}
	if got := stderr.String(); !strings.Contains(got, "MCP sandbox egress bridge enabled") {
		t.Fatalf("stderr = %q, want bridge enabled message", got)
	}
	closeBridge()
}

func TestSetupMCPSandboxBridge_StartError(t *testing.T) {
	t.Parallel()

	cfg := config.Defaults()
	wantErr := errors.New("bridge unavailable")
	launchCfg := sandbox.LaunchConfig{}

	closeBridge, err := setupMCPSandboxBridge(
		mcpSandboxBridgeSetupOptions{
			Context:      context.Background(),
			GOOS:         "linux",
			Config:       cfg,
			KillSwitch:   killswitch.New(cfg),
			AuditLogger:  audit.NewNop(),
			Stderr:       io.Discard,
			LaunchConfig: &launchCfg,
			StartBridge: func(mcpSandboxBridgeStartOptions) (*mcpSandboxBridge, error) {
				return nil, wantErr
			},
		},
	)
	if !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want %v", err, wantErr)
	}
	if closeBridge != nil {
		t.Fatal("closeBridge should be nil on start error")
	}
	if launchCfg.BridgeSocketPath != "" {
		t.Fatalf("BridgeSocketPath = %q, want empty", launchCfg.BridgeSocketPath)
	}
}

func TestSetupMCPSandboxBridge_NonLinuxWarns(t *testing.T) {
	t.Parallel()

	cfg := config.Defaults()
	var stderr bytes.Buffer
	launchCfg := sandbox.LaunchConfig{}
	started := false

	closeBridge, err := setupMCPSandboxBridge(
		mcpSandboxBridgeSetupOptions{
			Context:      context.Background(),
			GOOS:         "darwin",
			Config:       cfg,
			KillSwitch:   killswitch.New(cfg),
			AuditLogger:  audit.NewNop(),
			Stderr:       &stderr,
			LaunchConfig: &launchCfg,
			StartBridge: func(mcpSandboxBridgeStartOptions) (*mcpSandboxBridge, error) {
				started = true
				return nil, nil
			},
		},
	)
	if err != nil {
		t.Fatalf("setupMCPSandboxBridge: %v", err)
	}
	if started {
		t.Fatal("bridge starter should not run on non-Linux")
	}
	if launchCfg.BridgeSocketPath != "" {
		t.Fatalf("BridgeSocketPath = %q, want empty", launchCfg.BridgeSocketPath)
	}
	got := stderr.String()
	if !strings.Contains(got, "Linux-only") || !strings.Contains(got, "HTTPS_PROXY") {
		t.Fatalf("stderr = %q, want actionable non-Linux warning", got)
	}
	closeBridge()
}

func TestMCPSandboxBridgeHelpers_NilAndClosed(t *testing.T) {
	t.Parallel()

	var nilBridge *mcpSandboxBridge
	if nilBridge.SocketPath() != "" {
		t.Fatal("nil bridge SocketPath should be empty")
	}
	nilBridge.Close()

	trackedConn, peerConn := net.Pipe()
	t.Cleanup(func() { _ = peerConn.Close() })

	bridge := &mcpSandboxBridge{
		conns: map[net.Conn]struct{}{
			trackedConn: {},
		},
	}
	conns := bridge.markClosed()
	if len(conns) != 1 || conns[0] != trackedConn {
		t.Fatalf("markClosed tracked %d conn(s), want original tracked conn", len(conns))
	}
	if bridge.trackConn(peerConn) {
		t.Fatal("trackConn succeeded after bridge was marked closed")
	}
	bridge.Close()
}

func TestStartMCPSandboxBridge_ForcesForwardProxyIntoScanner(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "bridge-ok")
	}))
	t.Cleanup(upstream.Close)

	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.ForwardProxy.Enabled = false

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	bridge, err := startMCPSandboxBridge(mcpSandboxBridgeStartOptions{
		Context:     ctx,
		Config:      cfg,
		KillSwitch:  killswitch.New(cfg),
		AuditLogger: audit.NewNop(),
	})
	if err != nil {
		t.Fatalf("startMCPSandboxBridge: %v", err)
	}
	t.Cleanup(bridge.Close)

	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", bridge.SocketPath())
	if err != nil {
		t.Fatalf("dial bridge socket: %v", err)
	}
	defer func() { _ = conn.Close() }()

	_, _ = fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: ignored.invalid\r\nConnection: close\r\n\r\n", upstream.URL)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want scanner block 403; body=%q", resp.StatusCode, string(body))
	}
	if got := string(body); !strings.Contains(got, "SSRF") {
		t.Fatalf("body = %q, want scanner SSRF block", got)
	}
	if cfg.ForwardProxy.Enabled {
		t.Fatal("startMCPSandboxBridge mutated caller config")
	}
}

func TestStartMCPSandboxBridge_CONNECTThroughScanner(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	targetLn, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen target: %v", err)
	}
	t.Cleanup(func() { _ = targetLn.Close() })

	go func() {
		conn, acceptErr := targetLn.Accept()
		if acceptErr != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		buf := make([]byte, 4)
		if _, readErr := io.ReadFull(conn, buf); readErr != nil {
			return
		}
		_, _ = conn.Write([]byte("pong"))
	}()

	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8"}
	cfg.ForwardProxy.Enabled = false

	bridge, err := startMCPSandboxBridge(mcpSandboxBridgeStartOptions{
		Context:     ctx,
		Config:      cfg,
		KillSwitch:  killswitch.New(cfg),
		AuditLogger: audit.NewNop(),
	})
	if err != nil {
		t.Fatalf("startMCPSandboxBridge: %v", err)
	}
	t.Cleanup(bridge.Close)

	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", bridge.SocketPath())
	if err != nil {
		t.Fatalf("dial bridge socket: %v", err)
	}
	defer func() { _ = conn.Close() }()

	target := targetLn.Addr().String()
	_, _ = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("CONNECT status = %d, want 200; body=%q", resp.StatusCode, string(body))
	}

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write tunnel payload: %v", err)
	}
	got := make([]byte, 4)
	if _, err := io.ReadFull(br, got); err != nil {
		t.Fatalf("read tunnel payload: %v", err)
	}
	if string(got) != "pong" {
		t.Fatalf("tunnel echo = %q, want pong", string(got))
	}
}

func TestStartMCPSandboxBridge_ContextCancelClosesTunnel(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	targetLn, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen target: %v", err)
	}
	t.Cleanup(func() { _ = targetLn.Close() })

	targetSeen := make(chan struct{})
	go func() {
		conn, acceptErr := targetLn.Accept()
		if acceptErr != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		buf := make([]byte, 4)
		if _, readErr := io.ReadFull(conn, buf); readErr == nil {
			close(targetSeen)
		}
		_, _ = io.Copy(io.Discard, conn)
	}()

	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8"}
	cfg.ForwardProxy.Enabled = false

	bridge, err := startMCPSandboxBridge(mcpSandboxBridgeStartOptions{
		Context:     ctx,
		Config:      cfg,
		KillSwitch:  killswitch.New(cfg),
		AuditLogger: audit.NewNop(),
	})
	if err != nil {
		t.Fatalf("startMCPSandboxBridge: %v", err)
	}
	t.Cleanup(bridge.Close)

	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", bridge.SocketPath())
	if err != nil {
		t.Fatalf("dial bridge socket: %v", err)
	}
	defer func() { _ = conn.Close() }()

	target := targetLn.Addr().String()
	_, _ = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("CONNECT status = %d, want 200; body=%q", resp.StatusCode, string(body))
	}

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write tunnel payload: %v", err)
	}
	select {
	case <-targetSeen:
	case <-time.After(2 * time.Second):
		t.Fatal("target did not receive tunnel payload before cancel")
	}

	cancel()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	if n, err := br.Read(buf); err == nil {
		t.Fatalf("read after cancel succeeded with %d byte(s), want closed tunnel", n)
	}
}

func TestStartMCPSandboxBridge_KillSwitchBlocks(t *testing.T) {
	t.Parallel()

	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.KillSwitch.Enabled = true
	cfg.KillSwitch.Message = "bridge denied"
	cfg.ForwardProxy.Enabled = false

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	bridge, err := startMCPSandboxBridge(mcpSandboxBridgeStartOptions{
		Context:     ctx,
		Config:      cfg,
		KillSwitch:  killswitch.New(cfg),
		AuditLogger: audit.NewNop(),
	})
	if err != nil {
		t.Fatalf("startMCPSandboxBridge: %v", err)
	}
	t.Cleanup(bridge.Close)

	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", bridge.SocketPath())
	if err != nil {
		t.Fatalf("dial bridge socket: %v", err)
	}
	defer func() { _ = conn.Close() }()

	_, _ = fmt.Fprint(conn, "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%q", resp.StatusCode, string(body))
	}
	if got := string(body); !strings.Contains(got, "kill_switch_active") {
		t.Fatalf("body = %q, want kill_switch_active", got)
	}
}
