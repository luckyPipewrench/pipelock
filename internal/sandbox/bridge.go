// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
)

// bridgeListenAddr is the address the child-side bridge proxy listens on
// inside the sandbox network namespace. Agent processes use this as
// HTTP_PROXY/HTTPS_PROXY to route traffic through pipelock's scanner.
const bridgeListenAddr = "127.0.0.1:8888"

// BridgeProxy runs inside the sandboxed child process. It listens on
// loopback and bridges each TCP connection to the parent's Unix domain
// socket proxy. The parent runs pipelock's scanner on the traffic.
//
// Architecture:
//
//	Agent (HTTP_PROXY=127.0.0.1:8888)
//	  → BridgeProxy (loopback, inside sandbox)
//	  → Unix socket (/tmp/pipelock-sandbox-<pid>/proxy.sock)
//	  → Parent (pipelock proxy + scanner, host namespace)
//	  → Internet
type BridgeProxy struct {
	listener   net.Listener
	socketPath string // parent's Unix domain socket path
	wg         sync.WaitGroup
}

// NewBridgeProxy creates a bridge proxy inside the sandbox namespace.
// socketPath is the Unix domain socket where the parent's proxy listens.
// listenAddr overrides the default listen address if non-empty.
func NewBridgeProxy(socketPath string, listenAddr ...string) (*BridgeProxy, error) {
	addr := bridgeListenAddr
	if len(listenAddr) > 0 && listenAddr[0] != "" {
		addr = listenAddr[0]
	}
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("bridge proxy listen: %w", err)
	}
	return &BridgeProxy{
		listener:   ln,
		socketPath: socketPath,
	}, nil
}

// Addr returns the proxy's listen address.
func (bp *BridgeProxy) Addr() string {
	return bp.listener.Addr().String()
}

// Serve accepts connections and bridges them to the parent's Unix socket.
// Blocks until ctx is cancelled or the listener is closed.
func (bp *BridgeProxy) Serve(ctx context.Context) {
	go func() {
		<-ctx.Done()
		_ = bp.listener.Close()
	}()

	for {
		conn, err := bp.listener.Accept()
		if err != nil {
			return // listener closed
		}
		bp.wg.Add(1)
		go func() {
			defer bp.wg.Done()
			bp.handleConn(conn)
		}()
	}
}

// Close shuts down the proxy and waits for active connections.
func (bp *BridgeProxy) Close() {
	_ = bp.listener.Close()
	bp.wg.Wait()
}

// handleConn bridges a single TCP connection from the sandbox to the
// parent's Unix domain socket proxy. Raw TCP forwarding — the parent's
// proxy handles HTTP CONNECT, DLP scanning, etc.
func (bp *BridgeProxy) handleConn(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	// Connect to parent's proxy via Unix socket.
	parentConn, err := (&net.Dialer{}).DialContext(context.Background(), "unix", bp.socketPath)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "[bridge] connect to parent proxy: %v\n", err)
		return
	}
	defer func() { _ = parentConn.Close() }()

	// Bridge data bidirectionally.
	var wg sync.WaitGroup
	wg.Add(2) //nolint:mnd // two copy directions

	go func() {
		defer wg.Done()
		_, _ = io.Copy(parentConn, conn) // agent → parent
		// Signal parent that agent is done sending.
		if uc, ok := parentConn.(*net.UnixConn); ok {
			_ = uc.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(conn, parentConn) // parent → agent
		// Signal agent that parent is done sending.
		if tc, ok := conn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()

	wg.Wait()
}
