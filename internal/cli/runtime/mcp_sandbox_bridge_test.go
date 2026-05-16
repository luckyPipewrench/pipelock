// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"bufio"
	"context"
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
)

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

	bridge, err := startMCPSandboxBridge(ctx, cfg, killswitch.New(cfg), audit.NewNop(), nil, nil, nil)
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

	bridge, err := startMCPSandboxBridge(ctx, cfg, killswitch.New(cfg), audit.NewNop(), nil, nil, nil)
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

	bridge, err := startMCPSandboxBridge(ctx, cfg, killswitch.New(cfg), audit.NewNop(), nil, nil, nil)
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
	cfg.KillSwitch.Enabled = true
	cfg.KillSwitch.Message = "bridge denied"
	cfg.ForwardProxy.Enabled = false

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	bridge, err := startMCPSandboxBridge(ctx, cfg, killswitch.New(cfg), audit.NewNop(), nil, nil, nil)
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
