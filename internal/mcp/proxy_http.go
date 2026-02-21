package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/hitl"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// RunHTTPProxy bridges stdio (client) to an upstream HTTP MCP server with
// bidirectional scanning. Reads JSON-RPC from clientIn, POSTs to upstreamURL,
// scans responses via ForwardScanned, writes to clientOut.
func RunHTTPProxy(
	ctx context.Context,
	clientIn io.Reader,
	clientOut io.Writer,
	logW io.Writer,
	upstreamURL string,
	sc *scanner.Scanner,
	approver *hitl.Approver,
	extraHeaders http.Header,
	inputCfg *InputScanConfig,
	toolCfg *ToolScanConfig,
	policyCfg *PolicyConfig,
) error {
	// Create a child context so we can stop the GET stream when stdin EOF is reached.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	safeClientOut := &syncWriter{w: clientOut}
	safeLogW := &syncWriter{w: logW}

	httpClient := NewHTTPClient(upstreamURL, extraHeaders)

	// Tool scanning baseline for this session.
	var fwdToolCfg *ToolScanConfig
	if toolCfg != nil && toolCfg.Action != "" {
		fwdToolCfg = &ToolScanConfig{
			Baseline:    NewToolBaseline(),
			Action:      toolCfg.Action,
			DetectDrift: toolCfg.DetectDrift,
		}
	}

	clientReader := NewStdioReader(clientIn)

	var wg sync.WaitGroup
	var getStreamOnce sync.Once
	var lastScanErr error

	for {
		msg, err := clientReader.ReadMessage()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return fmt.Errorf("reading stdin: %w", err)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Input scanning — call ScanRequest and CheckRequest directly.
		// The sequential (non-concurrent) architecture means no channel needed.
		if blocked := scanHTTPInput(msg, sc, safeLogW, inputCfg, policyCfg); blocked != nil {
			if !blocked.IsNotification {
				resp := blockRequestResponse(*blocked)
				if wErr := safeClientOut.WriteMessage(resp); wErr != nil {
					_, _ = fmt.Fprintf(safeLogW, "pipelock: failed to send block response: %v\n", wErr)
				}
			}
			continue
		}

		// POST to upstream.
		respReader, err := httpClient.SendMessage(ctx, msg)
		if err != nil {
			// Log full upstream error details to stderr for debugging.
			_, _ = fmt.Fprintf(safeLogW, "pipelock: upstream error: %v\n", err)
			// Send sanitized error to client — don't include upstream body content
			// which could contain prompt injection payloads.
			rpcID := extractRPCID(msg)
			errResp := upstreamErrorResponse(rpcID, fmt.Errorf("upstream HTTP request failed"))
			if wErr := safeClientOut.WriteMessage(errResp); wErr != nil {
				_, _ = fmt.Fprintf(safeLogW, "pipelock: failed to send error response: %v\n", wErr)
			}
			continue
		}

		// Scan and forward response.
		_, scanErr := ForwardScanned(respReader, safeClientOut, safeLogW, sc, approver, fwdToolCfg)
		if scanErr != nil {
			_, _ = fmt.Fprintf(safeLogW, "pipelock: scan error: %v\n", scanErr)
			lastScanErr = scanErr
		}

		// After first successful response with a session ID, start GET stream
		// for server-initiated messages. Check session ID OUTSIDE the Once so
		// that early responses without a session ID (e.g. 202) don't consume
		// the Once and permanently prevent the GET stream.
		if httpClient.SessionID() != "" {
			getStreamOnce.Do(func() {
				startGETStream(ctx, httpClient, safeClientOut, safeLogW, sc, approver, fwdToolCfg, &wg)
			})
		}
	}

	// Terminate session if established.
	if httpClient.SessionID() != "" {
		httpClient.DeleteSession(safeLogW)
	}

	// Stop GET stream and wait for it to finish.
	cancel()
	wg.Wait()

	return lastScanErr
}

// scanHTTPInput checks a single input message for DLP/injection/policy.
// Returns a *BlockedRequest if the message should be blocked, nil if clean.
// This is the HTTP proxy equivalent of ForwardScannedInput's per-message logic,
// but returns a verdict instead of writing to a channel.
func scanHTTPInput(msg []byte, sc *scanner.Scanner, logW io.Writer, inputCfg *InputScanConfig, policyCfg *PolicyConfig) *BlockedRequest {
	// Determine input scanning parameters.
	action := config.ActionWarn
	onParseError := config.ActionBlock
	if inputCfg != nil && inputCfg.Enabled {
		action = inputCfg.Action
		onParseError = inputCfg.OnParseError
	}

	// Content scan.
	var verdict InputVerdict
	scanEnabled := inputCfg != nil && inputCfg.Enabled
	if scanEnabled {
		verdict = ScanRequest(msg, sc, action, onParseError)
	} else {
		verdict = InputVerdict{Clean: true}
	}

	// Policy check.
	policyVerdict := PolicyVerdict{}
	if policyCfg != nil {
		policyVerdict = policyCfg.CheckRequest(msg)
	}

	// Parse error — always block.
	if verdict.Error != "" {
		_, _ = fmt.Fprintf(logW, "pipelock: input: %s\n", verdict.Error)
		isNotification := len(verdict.ID) == 0
		return &BlockedRequest{
			ID:             verdict.ID,
			IsNotification: isNotification,
			LogMessage:     "blocked (parse error)",
		}
	}

	// Both clean — proceed.
	if verdict.Clean && !policyVerdict.Matched {
		return nil
	}

	// Build reasons.
	var reasons []string
	for _, m := range verdict.Matches {
		reasons = append(reasons, m.PatternName)
	}
	for _, m := range verdict.Inject {
		reasons = append(reasons, m.PatternName)
	}
	for _, r := range policyVerdict.Rules {
		reasons = append(reasons, "policy:"+r)
	}

	// Determine effective action (strictest wins).
	effectiveAction := ""
	if !verdict.Clean {
		effectiveAction = action
	}
	if policyVerdict.Matched {
		effectiveAction = stricterAction(effectiveAction, policyVerdict.Action)
	}

	isNotification := len(verdict.ID) == 0

	// Error code/message based on what triggered.
	errCode := 0
	errMsg := ""
	if verdict.Clean && policyVerdict.Matched {
		errCode = -32002
		errMsg = "pipelock: request blocked by tool call policy" //nolint:goconst // shared error message with input.go
	}

	switch effectiveAction {
	case config.ActionBlock:
		_, _ = fmt.Fprintf(logW, "pipelock: input: blocked (%s)\n", joinStrings(reasons))
		return &BlockedRequest{
			ID:             verdict.ID,
			IsNotification: isNotification,
			LogMessage:     "blocked",
			ErrorCode:      errCode,
			ErrorMessage:   errMsg,
		}
	case config.ActionAsk:
		// HITL for input scanning is impractical — fall back to block (same as stdio proxy).
		_, _ = fmt.Fprintf(logW, "pipelock: input: blocked (%s) [ask not supported for input scanning]\n", joinStrings(reasons))
		return &BlockedRequest{
			ID:             verdict.ID,
			IsNotification: isNotification,
			LogMessage:     "blocked (ask fallback)",
			ErrorCode:      errCode,
			ErrorMessage:   errMsg,
		}
	default: // warn
		if len(reasons) > 0 {
			_, _ = fmt.Fprintf(logW, "pipelock: input: warning (%s)\n", joinStrings(reasons))
		}
		return nil // forward
	}
}

// extractRPCID extracts the "id" field from a JSON-RPC message.
// Returns nil for notifications (no id field) or parse failures.
func extractRPCID(msg []byte) json.RawMessage {
	var rpc struct {
		ID json.RawMessage `json:"id"`
	}
	if json.Unmarshal(msg, &rpc) != nil {
		return nil
	}
	if string(rpc.ID) == jsonNull || len(rpc.ID) == 0 {
		return nil
	}
	return rpc.ID
}

// upstreamErrorResponse creates a JSON-RPC error for HTTP transport failures.
// If id is nil, the response uses a JSON null id (valid for unidentifiable requests).
func upstreamErrorResponse(id json.RawMessage, upstreamErr error) []byte {
	resp := rpcError{
		JSONRPC: jsonRPCVersion,
		ID:      id,
		Error: rpcErrorDetail{
			Code:    -32003,
			Message: fmt.Sprintf("pipelock: upstream error: %v", upstreamErr),
		},
	}
	data, _ := json.Marshal(resp) //nolint:errcheck // marshaling known-good struct
	return data
}

// startGETStream maintains a background GET SSE connection for server-initiated
// messages. Called after the initialize handshake establishes a session ID.
// Reconnects with exponential backoff (1s base, 30s cap) on stream end or
// transient errors. Exits permanently only on ErrStreamNotSupported (HTTP 405)
// or context cancellation.
func startGETStream(
	ctx context.Context,
	httpClient *HTTPClient,
	safeClientOut *syncWriter,
	safeLogW *syncWriter,
	sc *scanner.Scanner,
	approver *hitl.Approver,
	toolCfg *ToolScanConfig,
	wg *sync.WaitGroup,
) {
	wg.Add(1)
	go func() {
		defer wg.Done()

		backoff := time.Second
		const maxBackoff = 30 * time.Second

		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			reader, err := httpClient.OpenGETStream(ctx)
			if err != nil {
				_, _ = fmt.Fprintf(safeLogW, "pipelock: GET stream: %v\n", err)
				// Permanent error — server does not support GET streams.
				if errors.Is(err, ErrStreamNotSupported) {
					return
				}
				// Transient error — backoff and retry.
				select {
				case <-ctx.Done():
					return
				case <-time.After(backoff):
				}
				backoff *= 2
				if backoff > maxBackoff {
					backoff = maxBackoff
				}
				continue
			}

			// Reset backoff on successful connection.
			backoff = time.Second

			_, scanErr := ForwardScanned(reader, safeClientOut, safeLogW, sc, approver, toolCfg)
			if scanErr != nil {
				_, _ = fmt.Fprintf(safeLogW, "pipelock: GET stream scan error: %v\n", scanErr)
			}

			// Stream ended — reconnect with backoff unless cancelled.
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	}()
}
