// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build mcp_hardening_test

package runtime

import (
	"context"
	"errors"
	"io"
	"os"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/contract/proxydecision"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/sandbox"
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

type mcpSandboxBridge struct{}

// setupMCPSandboxBridge deliberately leaves BridgeSocketPath empty in the
// hardening proof build. sandbox-init then direct-execs the fixture, making
// the target a direct child of the real Pipelock proxy for the proc check.
func setupMCPSandboxBridge(opts mcpSandboxBridgeSetupOptions) (func(), error) {
	if os.Getenv("PIPELOCK_SANDBOX_HARDENING_PROOF_MARKER") == "" {
		return nil, errors.New("mcp hardening proof build refuses non-test sandbox use")
	}
	if opts.LaunchConfig == nil {
		return nil, errors.New("MCP sandbox hardening proof missing launch config")
	}
	return func() {}, nil
}

func startMCPSandboxBridge(mcpSandboxBridgeStartOptions) (*mcpSandboxBridge, error) {
	return nil, errors.New("MCP sandbox bridge disabled in hardening proof build")
}
