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
// Strict mode fails closed if orphan cleanup cannot be enabled. Every sandbox
// proxy attempts the same cleanup so a detached child cannot outlive its
// spawning session merely because the sandbox uses best-effort containment.
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
	// Capture before pipe setup and sandbox startup. The sandbox command
	// re-execs pipelock, then either execs the wrapped server or supervises it
	// for bridge mode, so this proxy process still owns the spawning session.
	startupParentWatch := parentWatchOpts{startPPID: os.Getppid()}
	if opts.Transport == "" {
		opts.Transport = "mcp_stdio"
	}
	if opts.ContractServer == "" {
		opts.ContractServer = mcpContractServerFromCommand([]string{sandboxCmd.Path})
	}
	isStrict := len(strict) > 0 && strict[0]
	subreaperEnabled := true
	enable := enableSubreaper
	if opts.enableSubreaperForTest != nil {
		enable = opts.enableSubreaperForTest
	}
	if err := enable(); err != nil {
		subreaperEnabled = false
		if isStrict {
			return fmt.Errorf("strict mode: failed to set child subreaper: %w", err)
		}
		// Name the consequence, not just the failed call. An operator reading
		// "teardown will be incomplete" cannot tell what they are now exposed
		// to; degraded cleanup here means a detached descendant can outlive
		// the session and can wedge proxy shutdown by holding inherited I/O.
		// Use strict mode to refuse the launch instead of accepting that.
		_, _ = fmt.Fprintf(logW, "pipelock: warning: session descendant cleanup degraded: PR_SET_CHILD_SUBREAPER failed (%v). Detached descendants can survive session exit and can block proxy shutdown by retaining inherited I/O. Run with strict mode to fail closed instead.\n", err)
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
	// The sandbox launch preserves other SysProcAttr settings, but it must run
	// in its own process group before session teardown can safely signal its
	// subprocess tree.
	setupChildProcessGroup(sandboxCmd)

	// Start and claim as one step. Between fork and the claim the child is a
	// live process no session has registered, which is exactly what a sibling
	// session's sweep is entitled to reap.
	unlockStart := lockChildStart()
	if err := start(); err != nil {
		unlockStart()
		return fmt.Errorf("starting sandboxed MCP server %q: %w", sandboxCmd.Path, err)
	}
	releaseChild := protectDirectChild(sandboxCmd.Process.Pid)
	unlockStart()
	defer releaseChild()
	childPgid := captureChildPgid(sandboxCmd.Process.Pid)
	processExit := &processExitHandoff{}
	killDirectChild := func() bool {
		if sandboxCmd.Process == nil {
			return false
		}
		return sandboxCmd.Process.Kill() == nil
	}
	// The claim itself is made above, atomically with the start, and holds
	// whether or not this session's subreaper setup succeeded. The reaper
	// below registers the same claim again; the registry is counted, so both
	// releases are safe.
	if subreaperEnabled {
		reaperDone := make(chan struct{})
		defer close(reaperDone)
		startAdoptedReaper(sandboxCmd.Process.Pid, reaperDone)
	}

	// Proactive teardown on context cancellation, mirroring the plain stdio
	// path. exec.CommandContext delivers SIGKILL to the direct child's PID
	// only. That is enough when sandbox-init execs the server in place, and it
	// is not enough for a bridge supervisor or any descendant that inherited
	// stdout: the reader below never sees EOF, so this call cannot reach its
	// own teardown and cancellation hangs until the caller gives up.
	//
	// Closing our read end is the half that unblocks the scanner. Signalling
	// the group is the half that lets cooperative descendants exit. This is
	// not the ordinary exit path, where a group teardown would kill a server
	// that is still finishing; reaching here means the caller asked to stop.
	cancelDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			processExit.terminate(func() { signalProcessGroupTerm(childPgid) }, killDirectChild)
			_ = serverOut.Close()
		case <-cancelDone:
		}
	}()
	defer close(cancelDone)

	// The sandbox command is a subprocess tree just like the plain stdio
	// command. In normal mode sandbox-init execs the server in place; with the
	// bridge it remains a supervisor for the server. Either way, parent death
	// needs the full drain and process-group teardown rather than a context-only
	// cancellation.
	waitDone := make(chan struct{})
	sessionExit := &sessionExitState{}
	sessionCtx, stopSession := context.WithCancel(ctx)
	defer stopSession()
	sessionOpts := startupParentWatch
	sessionGrace := defaultParentExitGrace
	if h := opts.sessionExitForTest; h != nil {
		sessionOpts = h.watch
		sessionGrace = h.grace
	}
	if sessionOpts.startPPID > orphanedPPID {
		go runSessionBoundExit(sessionCtx, sessionOpts, sessionExitActions{
			onSessionExit: sessionExit.begin,
			stopIntake: func() {
				if c, ok := clientIn.(io.Closer); ok {
					_ = c.Close()
				}
			},
			closeServerStdin: func() { _ = serverIn.Close() },
			terminateTree: func() bool {
				// A descendant can retain stdout after it leaves the direct
				// process. Releasing our read end lets ForwardScanned return so
				// Wait and the post-exit orphan cleanup can run.
				_ = serverOut.Close()
				return processExit.terminate(func() {
					terminateProcessGroup(childPgid)
					_ = killDirectChild()
				}, killDirectChild)
			},
			waitDone: waitDone,
			grace:    sessionGrace,
			logW:     safeLogW,
		})
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
	inputOpts.WarnContext = sessionCtx
	inputOpts.sessionExit = sessionExit

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
		_ = sandboxCmd.Process.Kill()
	}

	// Do not signal the process group on the ordinary EOF path. The response
	// reader can observe EOF just before the direct child finishes exiting; a
	// teardown here turns that clean exit into SIGTERM. Cancellation and parent
	// death already own process-group termination through processExit above.
	// A sandbox child can detach from the process group while retaining the
	// stderr pipe. Once the direct command has been signalled, it is adopted by
	// the subreaper; sweep it before Wait so inherited descriptors cannot keep
	// the direct command's pipe copy loop alive forever.
	if subreaperEnabled {
		killAdoptedDescendants()
	}
	waitErr := processExit.wait(sandboxCmd.Wait)
	close(waitDone)

	// Clean up the sandbox temp dir. No kill belongs here: Wait has already
	// reaped the direct child, so a Kill at this point can only return
	// os.ErrProcessDone, and once the PID is retired signaling it risks landing
	// on whatever the kernel assigns next. Termination happens before Wait,
	// above.
	sandbox.CleanupSandboxCmd(sandboxCmd)

	// Sweep once more after Wait for a descendant that exited or reparented in
	// the narrow interval around the first sweep.
	if subreaperEnabled {
		killAdoptedDescendants()
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
