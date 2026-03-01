package mcp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/luckyPipewrench/pipelock/internal/hitl"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
	"github.com/luckyPipewrench/pipelock/internal/mcp/chains"
	"github.com/luckyPipewrench/pipelock/internal/mcp/policy"
	"github.com/luckyPipewrench/pipelock/internal/mcp/tools"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// RunWSProxy proxies MCP JSON-RPC between stdin/stdout and a WebSocket upstream.
// Messages from stdin are scanned and forwarded as WS text frames to the upstream.
// Messages from the upstream WS connection are scanned and written to stdout.
// Returns when stdin reaches EOF or the upstream connection closes.
func RunWSProxy(
	ctx context.Context,
	clientIn io.Reader,
	clientOut io.Writer,
	logW io.Writer,
	upstreamURL string,
	sc *scanner.Scanner,
	approver *hitl.Approver,
	inputCfg *InputScanConfig,
	toolCfg *tools.ToolScanConfig,
	policyCfg *policy.Config,
	ks *killswitch.Controller,
	chainMatcher *chains.Matcher,
) error {
	// Separate parent and inner context. The parent context comes from
	// signal handling (SIGINT/SIGTERM). The inner context is cancelled
	// when either direction finishes (stdin EOF or upstream close).
	innerCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	safeClientOut := &syncWriter{w: clientOut}
	safeLogW := &syncWriter{w: logW}

	wsClient, err := transport.NewWSClient(innerCtx, upstreamURL)
	if err != nil {
		return fmt.Errorf("connecting to upstream: %w", err)
	}

	// Force-close connection on external cancellation (SIGINT, SIGTERM, parent
	// timeout). This unblocks ForwardScanned's ReadMessage which blocks on raw
	// TCP reads that don't respect context cancellation. WSClient.Close is safe
	// to call multiple times (sync.Once guard).
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = wsClient.Close()
		case <-done:
		}
	}()

	// Tool scanning baseline for this session.
	var fwdToolCfg *tools.ToolScanConfig
	if toolCfg != nil && toolCfg.Action != "" {
		fwdToolCfg = &tools.ToolScanConfig{
			Baseline:                tools.NewToolBaseline(),
			Action:                  toolCfg.Action,
			DetectDrift:             toolCfg.DetectDrift,
			BindingUnknownAction:    toolCfg.BindingUnknownAction,
			BindingNoBaselineAction: toolCfg.BindingNoBaselineAction,
		}
	}

	const sessionKey = "ws-stdio"

	clientReader := transport.NewStdioReader(clientIn)

	var wg sync.WaitGroup
	var lastScanErr error

	// Upstream -> stdout goroutine: scan responses via ForwardScanned.
	// WSClient implements MessageReader; ForwardScanned loops until EOF.
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel() // Signal main goroutine if upstream closes first.
		_, scanErr := ForwardScanned(wsClient, safeClientOut, safeLogW, sc, approver, fwdToolCfg)
		if scanErr != nil {
			_, _ = fmt.Fprintf(safeLogW, "pipelock: upstream scan error: %v\n", scanErr)
			lastScanErr = scanErr
		}
	}()

	// Stdin -> upstream loop (runs on main goroutine).
	var stdinErr error
	for {
		msg, readErr := clientReader.ReadMessage()
		if readErr != nil {
			if !errors.Is(readErr, io.EOF) {
				stdinErr = fmt.Errorf("reading stdin: %w", readErr)
			}
			break
		}

		select {
		case <-innerCtx.Done():
			// Upstream closed or external cancellation.
			_ = wsClient.Close()
			wg.Wait()
			if stdinErr != nil {
				return stdinErr
			}
			if lastScanErr != nil {
				return lastScanErr
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			return nil
		default:
		}

		// Kill switch: deny all messages when active.
		if ks != nil {
			if d := ks.IsActiveMCP(msg); d.Active {
				if d.IsNotification {
					_, _ = fmt.Fprintf(safeLogW, "pipelock: kill switch dropped notification (source=%s)\n", d.Source)
					continue
				}
				rpcID := extractRPCID(msg)
				resp := killswitch.ErrorResponse(rpcID, d.Message)
				if wErr := safeClientOut.WriteMessage(resp); wErr != nil {
					_, _ = fmt.Fprintf(safeLogW, "pipelock: stdout write error: %v\n", wErr)
				}
				continue
			}
		}

		// Input scanning: DLP, injection, policy, chain detection.
		if blocked := scanHTTPInput(msg, sc, safeLogW, inputCfg, policyCfg, chainMatcher, sessionKey); blocked != nil {
			if !blocked.IsNotification {
				resp := blockRequestResponse(*blocked)
				if wErr := safeClientOut.WriteMessage(resp); wErr != nil {
					_, _ = fmt.Fprintf(safeLogW, "pipelock: stdout write error: %v\n", wErr)
				}
			}
			continue
		}

		// Forward to upstream.
		if writeErr := wsClient.WriteMessage(msg); writeErr != nil {
			stdinErr = fmt.Errorf("upstream write: %w", writeErr)
			break
		}
	}

	// Close the WS connection to unblock ForwardScanned's ReadMessage.
	// WSClient.ReadMessage maps "use of closed network connection" to io.EOF
	// via IsExpectedCloseErr, so ForwardScanned exits cleanly.
	cancel()
	_ = wsClient.Close()
	wg.Wait()

	if stdinErr != nil {
		return stdinErr
	}
	if lastScanErr != nil {
		return lastScanErr
	}
	return nil
}
