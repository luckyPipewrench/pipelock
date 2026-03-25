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

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/tools"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
	"github.com/luckyPipewrench/pipelock/internal/sandbox"
	session "github.com/luckyPipewrench/pipelock/internal/session"
)

// RunProxyWithSandbox is like RunProxy but uses a pre-built (unstarted)
// sandbox exec.Cmd from sandbox.PrepareSandboxCmd(). Sets up stdio pipes
// for MCP scanning, then starts the sandboxed child.
//
// This function requires Linux kernel primitives (user namespaces) and is
// integration-tested via subprocess tests. It cannot be unit-tested without
// a real sandbox environment.
// RunProxyWithSandbox runs an MCP proxy with a sandboxed child process.
// The optional strict parameter enables subreaper for orphan cleanup.
func RunProxyWithSandbox(ctx context.Context, sandboxCmd *exec.Cmd, clientIn io.Reader, clientOut io.Writer, logW io.Writer, opts MCPProxyOpts, strict ...bool) error {
	isStrict := len(strict) > 0 && strict[0]
	if isStrict {
		if err := sandbox.SetChildSubreaper(); err != nil {
			return fmt.Errorf("strict mode: failed to set child subreaper: %w", err)
		}
	}
	var rec session.Recorder
	if opts.Store != nil {
		rec = opts.Store.GetOrCreate(session.NextInvocationKey("mcp-stdio"))
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
	if opts.ToolCfg != nil && opts.ToolCfg.Action != "" {
		fwdToolCfg = &tools.ToolScanConfig{
			Baseline:                tools.NewToolBaseline(),
			Action:                  opts.ToolCfg.Action,
			DetectDrift:             opts.ToolCfg.DetectDrift,
			BindingUnknownAction:    opts.ToolCfg.BindingUnknownAction,
			BindingNoBaselineAction: opts.ToolCfg.BindingNoBaselineAction,
			ExtraPoison:             opts.ToolCfg.ExtraPoison,
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
	if opts.InputCfg != nil {
		inputAction = opts.InputCfg.Action
		inputOnParseError = opts.InputCfg.OnParseError
	}

	// Build per-invocation opts with session-specific recorder.
	inputOpts := opts
	inputOpts.Rec = rec

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer func() { _ = serverIn.Close() }()
		clientReader := transport.NewStdioReader(clientIn)
		serverWriter := transport.NewStdioWriter(serverIn)
		ForwardScannedInput(clientReader, serverWriter, safeLogW,
			inputAction, inputOnParseError, blockedCh,
			bindingCfg, tracker, inputOpts)
	}()

	var wgBlocked sync.WaitGroup
	wgBlocked.Add(1)
	go func() {
		defer wgBlocked.Done()
		for blocked := range blockedCh {
			if blocked.IsNotification {
				continue
			}
			var resp []byte
			if blocked.SyntheticResponse != nil {
				resp = blocked.SyntheticResponse
			} else {
				resp = blockRequestResponse(blocked)
			}
			if wErr := safeClientOut.WriteMessage(resp); wErr != nil {
				_, _ = fmt.Fprintf(safeLogW, "pipelock: failed to send block response: %v\n", wErr)
			}
		}
	}()

	serverReader := transport.NewStdioReader(serverOut)
	fwdOpts := inputOpts
	fwdOpts.ToolCfg = fwdToolCfg // session-specific baseline
	_, scanErr := ForwardScanned(serverReader, safeClientOut, safeLogW, tracker, fwdOpts)

	waitErr := sandboxCmd.Wait()

	// Clean up sandbox child and temp dir.
	if sandboxCmd.Process != nil {
		_ = sandboxCmd.Process.Signal(os.Kill)
	}
	sandbox.CleanupSandboxCmd(sandboxCmd)

	// Strict: reap orphaned descendants adopted by subreaper.
	if isStrict {
		sandbox.ReapOrphans()
	}

	// Drain with timeout — detached descendants can hold pipes open.
	// Use ctx for cancellation so the caller can control shutdown.
	drainCtx, drainCancel := context.WithTimeout(ctx, 5*time.Second)
	defer drainCancel()
	done := make(chan struct{})
	go func() {
		wg.Wait()
		wgBlocked.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-drainCtx.Done():
	}

	if scanErr != nil {
		return fmt.Errorf("scanning: %w", scanErr)
	}
	return waitErr
}
