// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"errors"
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

// RunProxyWithSandbox runs an MCP proxy with a sandboxed child process.
// It retains the legacy plain-command entry point for tests and callers that
// do not have a UID/GID map phase. Mapped sandbox launches must use
// RunProxyWithSandboxLaunch so target start is gated on parent hardening.
// The optional strict parameter enables subreaper for orphan cleanup.
func RunProxyWithSandbox(ctx context.Context, sandboxCmd *exec.Cmd, clientIn io.Reader, clientOut io.Writer, logW io.Writer, opts MCPProxyOpts, strict ...bool) error {
	// Refuse a mapped command here rather than starting it ungated. This entry
	// point calls Start directly, so a mapped launch would get neither the map
	// ordering nor the parent hardening, and would get them missing silently.
	// A gate with an unguarded door beside it is not a gate.
	if sandbox.CmdNeedsHardeningGate(sandboxCmd) {
		return fmt.Errorf("mapped sandbox command must start through RunProxyWithSandboxLaunch so target start is gated on parent hardening")
	}
	return runProxyWithSandbox(ctx, sandboxCmd, sandboxCmd.Start, clientIn, clientOut, logW, opts, strict...)
}

// RunProxyWithSandboxLaunch runs a prepared sandbox launch with the explicit
// parent-hardening ordering selected by sandbox.PrepareSandboxLaunch.
func RunProxyWithSandboxLaunch(ctx context.Context, launch *sandbox.PreparedSandboxCmd, clientIn io.Reader, clientOut io.Writer, logW io.Writer, opts MCPProxyOpts, strict ...bool) error {
	if launch == nil || launch.Cmd == nil {
		return fmt.Errorf("sandbox launch is nil")
	}
	defer launch.Close()
	return runProxyWithSandbox(ctx, launch.Cmd, func() error {
		return launch.StartWithParentHardening(HardenProxyProcess)
	}, clientIn, clientOut, logW, opts, strict...)
}

func runProxyWithSandbox(ctx context.Context, sandboxCmd *exec.Cmd, start func() error, clientIn io.Reader, clientOut io.Writer, logW io.Writer, opts MCPProxyOpts, strict ...bool) error {
	if opts.Transport == "" {
		opts.Transport = "mcp_stdio"
	}
	if opts.ContractServer == "" {
		opts.ContractServer = mcpContractServerFromCommand([]string{sandboxCmd.Path})
	}
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
	defer recordMCPBaselineSample(opts, rec)

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

	if err := start(); err != nil {
		return fmt.Errorf("starting sandboxed MCP server %q: %w", sandboxCmd.Path, err)
	}

	blockedCh := make(chan BlockedRequest, 16)

	toolCfg := opts.toolCfg()
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
	if opts.InputCfg != nil {
		inputAction = opts.InputCfg.Action
		inputOnParseError = opts.InputCfg.OnParseError
	}

	// Build per-invocation opts with session-specific recorder.
	inputOpts := opts
	inputOpts.Rec = rec
	inputOpts.WarnContext = ctx

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

	fwdOpts := inputOpts
	fwdOpts.ToolCfg = fwdToolCfg // session-specific baseline
	fwdOpts.ToolCfgFn = nil
	// Apply the optional per-read response timeout (no-op when disabled) so a
	// hung sandboxed upstream fails closed instead of hanging the agent.
	serverReader := fwdOpts.withResponseTimeout(transport.NewStdioReader(serverOut))
	_, scanErr := ForwardScanned(serverReader, safeClientOut, safeLogW, tracker, fwdOpts)
	timedOut := errors.Is(scanErr, transport.ErrResponseTimeout)

	// On an upstream response timeout the sandboxed child is still alive; kill
	// it before Wait() so Wait() returns instead of blocking forever, then fall
	// through to the existing sandbox teardown below.
	if timedOut && sandboxCmd.Process != nil {
		_, _ = fmt.Fprintf(safeLogW, "pipelock: terminating sandboxed MCP subprocess after upstream response timeout\n")
		if c, ok := clientIn.(io.Closer); ok {
			_ = c.Close()
		}
		_ = serverIn.Close()
		_ = sandboxCmd.Process.Signal(os.Kill)
	}

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

	// Drain with timeout - detached descendants can hold pipes open.
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
	if timedOut {
		emitPendingTimeoutResponses(safeClientOut, safeLogW, tracker, fwdOpts)
	} else {
		emitPendingIncompleteOutcomes(safeLogW, tracker, fwdOpts, "upstream_closed")
	}

	if scanErr != nil {
		return fmt.Errorf("scanning: %w", scanErr)
	}

	var exitErr *exec.ExitError
	if errors.As(waitErr, &exitErr) {
		return fmt.Errorf("%w: %w", ErrSubprocessExit, waitErr)
	}

	return waitErr
}
