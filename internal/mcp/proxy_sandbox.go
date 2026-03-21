// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/hitl"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
	"github.com/luckyPipewrench/pipelock/internal/mcp/chains"
	"github.com/luckyPipewrench/pipelock/internal/mcp/policy"
	"github.com/luckyPipewrench/pipelock/internal/mcp/tools"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/sandbox"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	session "github.com/luckyPipewrench/pipelock/internal/session"
)

// RunProxyWithSandbox is like RunProxy but uses a pre-built (unstarted)
// sandbox exec.Cmd from sandbox.PrepareSandboxCmd(). Sets up stdio pipes
// for MCP scanning, then starts the sandboxed child.
//
// This function requires Linux kernel primitives (user namespaces) and is
// integration-tested via subprocess tests. It cannot be unit-tested without
// a real sandbox environment.
func RunProxyWithSandbox(ctx context.Context, sandboxCmd *exec.Cmd, clientIn io.Reader, clientOut io.Writer, logW io.Writer, sc *scanner.Scanner, approver *hitl.Approver, inputCfg *InputScanConfig, toolCfg *tools.ToolScanConfig, policyCfg *policy.Config, ks *killswitch.Controller, chainMatcher *chains.Matcher, auditLogger *audit.Logger, cee *CEEDeps, store session.Store, adaptiveCfg *config.AdaptiveEnforcement, m *metrics.Metrics) error {
	var rec session.Recorder
	if store != nil {
		rec = store.GetOrCreate(session.NextInvocationKey("mcp-stdio"))
	}

	safeClientOut := &syncWriter{w: clientOut}
	safeLogW := &syncWriter{w: logW}

	serverIn, err := sandboxCmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("creating stdin pipe: %w", err)
	}
	serverOut, err := sandboxCmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("creating stdout pipe: %w", err)
	}
	sandboxCmd.Stderr = safeLogW

	if err := sandboxCmd.Start(); err != nil {
		return fmt.Errorf("starting sandboxed MCP server %q: %w", sandboxCmd.Path, err)
	}

	blockedCh := make(chan BlockedRequest, 16)

	var fwdToolCfg *tools.ToolScanConfig
	if toolCfg != nil && toolCfg.Action != "" {
		fwdToolCfg = &tools.ToolScanConfig{
			Baseline:                tools.NewToolBaseline(),
			Action:                  toolCfg.Action,
			DetectDrift:             toolCfg.DetectDrift,
			BindingUnknownAction:    toolCfg.BindingUnknownAction,
			BindingNoBaselineAction: toolCfg.BindingNoBaselineAction,
			ExtraPoison:             toolCfg.ExtraPoison,
		}
	}

	var bindingCfg *SessionBindingConfig
	if fwdToolCfg != nil && fwdToolCfg.BindingUnknownAction != "" {
		bindingCfg = &SessionBindingConfig{
			Baseline:          fwdToolCfg.Baseline,
			UnknownToolAction: fwdToolCfg.BindingUnknownAction,
			NoBaselineAction:  fwdToolCfg.BindingNoBaselineAction,
		}
	}

	tracker := NewRequestTracker()

	// Guard against nil inputCfg (when input scanning is disabled).
	inputAction := config.ActionForward
	inputOnParseError := config.ActionBlock
	if inputCfg != nil {
		inputAction = inputCfg.Action
		inputOnParseError = inputCfg.OnParseError
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer func() { _ = serverIn.Close() }()
		clientReader := transport.NewStdioReader(clientIn)
		serverWriter := transport.NewStdioWriter(serverIn)
		ForwardScannedInput(clientReader, serverWriter, safeLogW, sc,
			inputAction, inputOnParseError, blockedCh,
			policyCfg, bindingCfg, ks, chainMatcher, tracker,
			auditLogger, cee, rec, adaptiveCfg, m)
	}()

	var wgBlocked sync.WaitGroup
	wgBlocked.Add(1)
	go func() {
		defer wgBlocked.Done()
		for blocked := range blockedCh {
			if blocked.IsNotification {
				continue
			}
			resp := blockRequestResponse(blocked)
			if wErr := safeClientOut.WriteMessage(resp); wErr != nil {
				_, _ = fmt.Fprintf(safeLogW, "pipelock: failed to send block response: %v\n", wErr)
			}
		}
	}()

	serverReader := transport.NewStdioReader(serverOut)
	_, scanErr := ForwardScanned(serverReader, safeClientOut, safeLogW, sc, approver, fwdToolCfg, tracker, rec, adaptiveCfg, m)

	waitErr := sandboxCmd.Wait()

	// Clean up sandbox child and temp dir.
	if sandboxCmd.Process != nil {
		_ = sandboxCmd.Process.Signal(os.Kill)
		sandbox.CleanupChildSandboxDir(sandboxCmd.Process.Pid)
	}

	// Drain with timeout — detached descendants can hold pipes open.
	const drainTimeout = 5 * time.Second
	done := make(chan struct{})
	go func() {
		wg.Wait()
		wgBlocked.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(drainTimeout):
	}

	if scanErr != nil {
		return fmt.Errorf("scanning: %w", scanErr)
	}
	return waitErr
}
