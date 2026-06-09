// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/contract/proxydecision"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/proxy"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/sandbox"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

type mcpSandboxBridgeStartOptions struct {
	Context          context.Context
	Config           *config.Config
	KillSwitch       *killswitch.Controller
	AuditLogger      *audit.Logger
	Metrics          *metrics.Metrics
	ReceiptEmitter   *receipt.Emitter
	V2ReceiptEmitter *proxydecision.Emitter
	EnvelopeEmitter  *envelope.Emitter
}

type startMCPSandboxBridgeFunc func(mcpSandboxBridgeStartOptions) (*mcpSandboxBridge, error)

type mcpSandboxBridgeSetupOptions struct {
	Context          context.Context
	GOOS             string
	Config           *config.Config
	KillSwitch       *killswitch.Controller
	AuditLogger      *audit.Logger
	Metrics          *metrics.Metrics
	ReceiptEmitter   *receipt.Emitter
	V2ReceiptEmitter *proxydecision.Emitter
	EnvelopeEmitter  *envelope.Emitter
	Stderr           io.Writer
	LaunchConfig     *sandbox.LaunchConfig
	StartBridge      startMCPSandboxBridgeFunc
}

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

func setupMCPSandboxBridge(opts mcpSandboxBridgeSetupOptions) (func(), error) {
	if opts.GOOS != "linux" {
		_, _ = fmt.Fprintf(opts.Stderr,
			"pipelock: WARNING: MCP sandbox egress bridge is Linux-only; bridge-style MCP servers on %s may need separate egress controls to ensure upstream HTTP(S) traverses pipelock. "+
				"Configure the MCP server to use pipelock's forward proxy listener via HTTPS_PROXY and disable any built-in proxy bypass.\n",
			opts.GOOS)
		return func() {}, nil
	}

	bridge, err := opts.StartBridge(mcpSandboxBridgeStartOptions{
		Context:          opts.Context,
		Config:           opts.Config,
		KillSwitch:       opts.KillSwitch,
		AuditLogger:      opts.AuditLogger,
		Metrics:          opts.Metrics,
		ReceiptEmitter:   opts.ReceiptEmitter,
		V2ReceiptEmitter: opts.V2ReceiptEmitter,
		EnvelopeEmitter:  opts.EnvelopeEmitter,
	})
	if err != nil {
		return nil, err
	}
	opts.LaunchConfig.BridgeSocketPath = bridge.SocketPath()
	_, _ = fmt.Fprintf(opts.Stderr,
		"pipelock: MCP sandbox egress bridge enabled; forward_proxy forced on for sandboxed MCP egress (child loopback -> parent scanner)\n")
	return bridge.Close, nil
}

func startMCPSandboxBridge(opts mcpSandboxBridgeStartOptions) (*mcpSandboxBridge, error) {
	dir, err := os.MkdirTemp("", "pl-mcp-*")
	if err != nil {
		return nil, fmt.Errorf("creating MCP sandbox bridge dir: %w", err)
	}

	bridge := &mcpSandboxBridge{dir: dir}
	bridge.socketPath = sandbox.ProxySocketPath(dir)

	ln, err := (&net.ListenConfig{}).Listen(opts.Context, "unix", bridge.socketPath)
	if err != nil {
		bridge.Close()
		return nil, fmt.Errorf("MCP sandbox bridge listen: %w", err)
	}
	bridge.listener = ln

	if err := os.Chmod(bridge.socketPath, 0o600); err != nil {
		bridge.Close()
		return nil, fmt.Errorf("MCP sandbox bridge socket permissions: %w", err)
	}

	egressCfg := opts.Config.Clone()
	egressCfg.ForwardProxy.Enabled = true
	bridge.scanner = scanner.New(egressCfg)
	if opts.Metrics == nil {
		opts.Metrics = metrics.New()
	}
	bridge.scanner.SetDLPWarnHook(func(ctx context.Context, patternName, severity string) {
		emitDLPWarn(opts.AuditLogger, opts.Metrics, opts.ReceiptEmitter, ctx, patternName, severity)
	})

	p, err := proxy.New(
		egressCfg,
		opts.AuditLogger,
		bridge.scanner,
		opts.Metrics,
		proxy.WithKillSwitch(opts.KillSwitch),
		proxy.WithReceiptEmitter(opts.ReceiptEmitter),
		proxy.WithV2ReceiptEmitter(opts.V2ReceiptEmitter),
		proxy.WithEnvelopeEmitter(opts.EnvelopeEmitter),
	)
	if err != nil {
		bridge.Close()
		return nil, fmt.Errorf("MCP sandbox bridge proxy init: %w", err)
	}
	handler := p.Handler()
	bridge.conns = make(map[net.Conn]struct{})

	bridge.acceptDone = make(chan struct{})
	go func() {
		<-opts.Context.Done()
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
			go func(conn net.Conn) {
				defer bridge.connWg.Done()
				defer bridge.untrackConn(conn)
				srv := &http.Server{
					Handler:           handler,
					ReadHeaderTimeout: 30 * time.Second,
					IdleTimeout:       30 * time.Second,
				}
				_ = srv.Serve(&singleConnListener{conn: conn})
			}(conn)
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
