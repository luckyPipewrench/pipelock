// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/proxy"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/sandbox"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

type mcpSandboxBridge struct {
	dir        string
	socketPath string
	listener   net.Listener
	scanner    *scanner.Scanner
	acceptDone chan struct{}
	connWg     sync.WaitGroup
	closeOnce  sync.Once
	mu         sync.Mutex
	conns      map[net.Conn]struct{}
	closed     bool
}

func startMCPSandboxBridge(
	ctx context.Context,
	cfg *config.Config,
	ks *killswitch.Controller,
	log *audit.Logger,
	m *metrics.Metrics,
	receiptEmitter *receipt.Emitter,
	envEmitter *envelope.Emitter,
) (*mcpSandboxBridge, error) {
	dir, err := os.MkdirTemp("", "pl-mcp-*")
	if err != nil {
		return nil, fmt.Errorf("creating MCP sandbox bridge dir: %w", err)
	}

	bridge := &mcpSandboxBridge{dir: dir}
	bridge.socketPath = sandbox.ProxySocketPath(dir)

	ln, err := (&net.ListenConfig{}).Listen(ctx, "unix", bridge.socketPath)
	if err != nil {
		bridge.Close()
		return nil, fmt.Errorf("MCP sandbox bridge listen: %w", err)
	}
	bridge.listener = ln

	if err := os.Chmod(bridge.socketPath, 0o600); err != nil {
		bridge.Close()
		return nil, fmt.Errorf("MCP sandbox bridge socket permissions: %w", err)
	}

	egressCfg := cfg.Clone()
	egressCfg.ForwardProxy.Enabled = true
	bridge.scanner = scanner.New(egressCfg)
	if m == nil {
		m = metrics.New()
	}
	bridge.scanner.SetDLPWarnHook(func(ctx context.Context, patternName, severity string) {
		emitDLPWarn(log, m, receiptEmitter, ctx, patternName, severity)
	})

	p, err := proxy.New(
		egressCfg,
		log,
		bridge.scanner,
		m,
		proxy.WithKillSwitch(ks),
		proxy.WithReceiptEmitter(receiptEmitter),
		proxy.WithEnvelopeEmitter(envEmitter),
	)
	if err != nil {
		bridge.Close()
		return nil, fmt.Errorf("MCP sandbox bridge proxy init: %w", err)
	}
	handler := p.Handler()
	bridge.conns = make(map[net.Conn]struct{})

	bridge.acceptDone = make(chan struct{})
	go func() {
		<-ctx.Done()
		bridge.Close()
	}()
	go func() {
		defer close(bridge.acceptDone)
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			if !bridge.trackConn(conn) {
				_ = conn.Close()
				return
			}
			bridge.connWg.Add(1)
			go func() {
				defer bridge.connWg.Done()
				defer bridge.untrackConn(conn)
				srv := &http.Server{
					Handler:           handler,
					ReadHeaderTimeout: 30 * time.Second,
					IdleTimeout:       30 * time.Second,
				}
				_ = srv.Serve(&singleConnListener{conn: conn})
			}()
		}
	}()

	return bridge, nil
}

func (b *mcpSandboxBridge) SocketPath() string {
	if b == nil {
		return ""
	}
	return b.socketPath
}

func (b *mcpSandboxBridge) Close() {
	if b == nil {
		return
	}
	b.closeOnce.Do(func() {
		conns := b.markClosed()
		if b.listener != nil {
			_ = b.listener.Close()
		}
		for _, conn := range conns {
			_ = conn.Close()
		}
		if b.acceptDone != nil {
			<-b.acceptDone
		}
		b.connWg.Wait()
		if b.scanner != nil {
			b.scanner.Close()
		}
		if b.dir != "" {
			_ = os.RemoveAll(b.dir)
		}
	})
}

func (b *mcpSandboxBridge) trackConn(conn net.Conn) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return false
	}
	if b.conns != nil {
		b.conns[conn] = struct{}{}
	}
	return true
}

func (b *mcpSandboxBridge) untrackConn(conn net.Conn) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.conns != nil {
		delete(b.conns, conn)
	}
}

func (b *mcpSandboxBridge) markClosed() []net.Conn {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
	conns := make([]net.Conn, 0, len(b.conns))
	for conn := range b.conns {
		conns = append(conns, conn)
	}
	return conns
}
