package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"

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
				_ = safeClientOut.WriteMessage(resp) //nolint:errcheck // best-effort
			}
			continue
		}

		// POST to upstream.
		respReader, err := httpClient.SendMessage(msg)
		if err != nil {
			_, _ = fmt.Fprintf(safeLogW, "pipelock: upstream error: %v\n", err)
			rpcID := extractRPCID(msg)
			if rpcID != nil {
				errResp := upstreamErrorResponse(rpcID, err)
				_ = safeClientOut.WriteMessage(errResp) //nolint:errcheck // best-effort
			}
			continue
		}

		// Scan and forward response.
		_, scanErr := ForwardScanned(respReader, safeClientOut, safeLogW, sc, approver, fwdToolCfg)
		if scanErr != nil {
			_, _ = fmt.Fprintf(safeLogW, "pipelock: scan error: %v\n", scanErr)
		}

		// After first successful response, start GET stream for server-initiated messages.
		getStreamOnce.Do(func() {
			if sid := httpClient.SessionID(); sid != "" {
				startGETStream(ctx, httpClient, safeClientOut, safeLogW, sc, approver, fwdToolCfg, &wg)
			}
		})
	}

	// Terminate session if established.
	if httpClient.SessionID() != "" {
		httpClient.DeleteSession()
	}

	// Stop GET stream and wait for it to finish.
	cancel()
	wg.Wait()

	return nil
}

// scanHTTPInput checks a single input message for DLP/injection/policy.
// Returns a *BlockedRequest if the message should be blocked, nil if clean.
// This is the HTTP proxy equivalent of ForwardScannedInput's per-message logic,
// but returns a verdict instead of writing to a channel.
func scanHTTPInput(msg []byte, sc *scanner.Scanner, logW io.Writer, inputCfg *InputScanConfig, policyCfg *PolicyConfig) *BlockedRequest {
	// Determine input scanning parameters.
	action := "warn"        //nolint:goconst // config action value
	onParseError := "block" //nolint:goconst // config action value
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
	case "block": //nolint:goconst // config action value
		_, _ = fmt.Fprintf(logW, "pipelock: input: blocked (%s)\n", joinStrings(reasons))
		return &BlockedRequest{
			ID:             verdict.ID,
			IsNotification: isNotification,
			LogMessage:     "blocked",
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
	if string(rpc.ID) == "null" || len(rpc.ID) == 0 {
		return nil
	}
	return rpc.ID
}

// upstreamErrorResponse creates a JSON-RPC error for HTTP transport failures.
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
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			reader, err := httpClient.OpenGETStream()
			if err != nil {
				_, _ = fmt.Fprintf(safeLogW, "pipelock: GET stream: %v\n", err)
				return
			}

			_, _ = ForwardScanned(reader, safeClientOut, safeLogW, sc, approver, toolCfg)
			// Stream ended — reconnect unless cancelled.
		}
	}()
}
