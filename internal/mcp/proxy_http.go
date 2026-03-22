// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/decide"
	"github.com/luckyPipewrench/pipelock/internal/hitl"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
	"github.com/luckyPipewrench/pipelock/internal/mcp/chains"
	"github.com/luckyPipewrench/pipelock/internal/mcp/jsonrpc"
	"github.com/luckyPipewrench/pipelock/internal/mcp/policy"
	"github.com/luckyPipewrench/pipelock/internal/mcp/tools"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	session "github.com/luckyPipewrench/pipelock/internal/session"
)

// RunHTTPProxy bridges stdio (client) to an upstream HTTP MCP server with
// bidirectional scanning. Reads JSON-RPC from clientIn, POSTs to upstreamURL,
// scans responses via ForwardScanned, writes to clientOut.
// When store is non-nil, a per-invocation session recorder is created and used
// for adaptive enforcement signal recording across both input and response scanning.
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
	toolCfg *tools.ToolScanConfig,
	policyCfg *policy.Config,
	ks *killswitch.Controller,
	chainMatcher *chains.Matcher,
	auditLogger *audit.Logger,
	cee *CEEDeps,
	store session.Store,
	adaptiveCfg *config.AdaptiveEnforcement,
	m *metrics.Metrics,
) error {
	// Create a child context so we can stop the GET stream when stdin EOF is reached.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Per-invocation adaptive enforcement recorder.
	var rec session.Recorder
	if store != nil {
		rec = store.GetOrCreate(session.NextInvocationKey("mcp-http"))
	}

	safeClientOut := &syncWriter{w: clientOut}
	safeLogW := &syncWriter{w: logW}

	httpClient := transport.NewHTTPClient(upstreamURL, extraHeaders)

	// Tool scanning baseline for this session.
	var fwdToolCfg *tools.ToolScanConfig
	if toolCfg != nil && toolCfg.Action != "" {
		fwdToolCfg = &tools.ToolScanConfig{
			Baseline:    tools.NewToolBaseline(),
			Action:      toolCfg.Action,
			DetectDrift: toolCfg.DetectDrift,
			ExtraPoison: toolCfg.ExtraPoison,
		}
	}

	// Request tracker for confused deputy protection.
	tracker := NewRequestTracker()

	clientReader := transport.NewStdioReader(clientIn)

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
					_, _ = fmt.Fprintf(safeLogW, "pipelock: failed to send kill switch response: %v\n", wErr)
				}
				continue
			}
		}

		// Input scanning — call ScanRequest and CheckRequest directly.
		// The sequential (non-concurrent) architecture means no channel needed.
		if blocked := scanHTTPInput(msg, sc, safeLogW, inputCfg, policyCfg, chainMatcher, "default", "default", auditLogger, cee, rec, adaptiveCfg, m); blocked != nil {
			if !blocked.IsNotification {
				var resp []byte
				if blocked.SyntheticResponse != nil {
					resp = blocked.SyntheticResponse
				} else {
					resp = blockRequestResponse(*blocked)
				}
				if wErr := safeClientOut.WriteMessage(resp); wErr != nil {
					_, _ = fmt.Fprintf(safeLogW, "pipelock: failed to send block response: %v\n", wErr)
				}
			}
			continue
		}

		// Track request ID before sending to upstream for confused deputy protection.
		// Only track requests (have "method"), not client responses to
		// server-initiated calls, to prevent tracker pollution.
		if isRequest(msg) {
			tracker.Track(extractRPCID(msg))
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
		_, scanErr := ForwardScanned(respReader, safeClientOut, safeLogW, sc, approver, fwdToolCfg, tracker, ks, rec, adaptiveCfg, m)
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
				startGETStream(ctx, httpClient, safeClientOut, safeLogW, sc, approver, fwdToolCfg, ks, rec, adaptiveCfg, &wg, m)
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

// scanHTTPInput checks a single input message for DLP/injection/policy/CEE.
// Returns a *BlockedRequest if the message should be blocked, nil if clean.
// This is the HTTP proxy equivalent of ForwardScannedInput's per-message logic,
// but returns a verdict instead of writing to a channel.
// When cee is non-nil, outbound payloads are recorded for cross-request
// exfiltration detection after content scanning passes.
func scanHTTPInput(msg []byte, sc *scanner.Scanner, logW io.Writer, inputCfg *InputScanConfig, policyCfg *policy.Config, chainMatcher *chains.Matcher, sessionKey, auditSessionKey string, auditLogger *audit.Logger, cee *CEEDeps, rec session.Recorder, adaptiveCfg *config.AdaptiveEnforcement, m *metrics.Metrics) *BlockedRequest {
	// Helper: record an adaptive signal and handle escalation side-effects.
	// Eliminates repeated nil/enabled guards at every call site.
	recordAdaptiveSignal := func(sig session.SignalType) {
		if rec != nil && adaptiveCfg != nil && adaptiveCfg.Enabled {
			recordSignalWithEscalation(rec, sig, adaptiveCfg.EscalationThreshold, logW, auditLogger, m, auditSessionKey, "", "")
		}
	}

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
		// When input scanning is disabled, extract enough metadata from the
		// raw message so policy and chain detection still work.
		if policyCfg != nil || chainMatcher != nil {
			verdict.ID = extractRPCID(msg)
			// Extract method for chain detection even when content scanning is off.
			var env struct {
				Method string `json:"method"`
			}
			if json.Unmarshal(msg, &env) == nil {
				verdict.Method = env.Method
			}
		}
	}

	// Policy check.
	policyVerdict := policy.Verdict{}
	if policyCfg != nil {
		policyVerdict = policyCfg.CheckRequest(msg)
	}

	// Chain detection: check if this tool call matches an attack pattern.
	chainAction := ""
	chainReason := ""
	if chainMatcher != nil && verdict.Method == methodToolsCall {
		toolName := extractToolCallName(msg)
		if toolName != "" {
			cv := chainMatcher.Record(sessionKey, toolName, string(msg))
			if cv.Matched {
				_, _ = fmt.Fprintf(logW, "pipelock: chain detected: %s (severity=%s, action=%s)\n",
					cv.PatternName, cv.Severity, cv.Action)
				if auditLogger != nil {
					auditLogger.LogChainDetection(cv.PatternName, cv.Severity, cv.Action, toolName, auditSessionKey)
				}
				if cv.Action == config.ActionBlock {
					recordAdaptiveSignal(session.SignalBlock)
					return &BlockedRequest{
						ID:             verdict.ID,
						IsNotification: isRPCNotification(verdict.ID),
						LogMessage:     fmt.Sprintf("chain pattern %q blocked", cv.PatternName),
						ErrorCode:      -32004,
						ErrorMessage:   fmt.Sprintf("tool call blocked: chain pattern %q detected", cv.PatternName),
					}
				}
				chainAction = cv.Action
				chainReason = "chain:" + cv.PatternName
			}
		}
	}

	// Parse error — always block.
	if verdict.Error != "" {
		_, _ = fmt.Fprintf(logW, "pipelock: input: %s\n", verdict.Error)
		return &BlockedRequest{
			ID:             verdict.ID,
			IsNotification: isRPCNotification(verdict.ID),
			LogMessage:     "blocked (parse error)",
		}
	}

	// All clean — proceed (with block_all and CEE checks).
	if verdict.Clean && !policyVerdict.Matched && chainAction == "" {
		// block_all enforcement: deny ALL traffic (including clean) when the
		// session is at an escalation level with block_all=true.
		if rec != nil && decide.UpgradeAction("", rec.EscalationLevel(), adaptiveCfg) == config.ActionBlock {
			_, _ = fmt.Fprintf(logW, "pipelock: adaptive upgrade (clean) -> block (level %s)\n", session.EscalationLabel(rec.EscalationLevel()))
			if m != nil {
				m.RecordAdaptiveUpgrade("", config.ActionBlock, session.EscalationLabel(rec.EscalationLevel()))
			}
			return &BlockedRequest{
				ID:             verdict.ID,
				IsNotification: isRPCNotification(verdict.ID),
				LogMessage:     "blocked (session deny)",
				ErrorCode:      -32001,
				ErrorMessage:   "pipelock: session escalation level critical",
			}
		}
		// Cross-request exfiltration check on clean outbound messages.
		ceeKey := ceeSessionKeyMCP("", sessionKey)
		if reason := ceeRecordMCP(ceeKey, msg, cee, sc, logW, auditLogger); reason != "" {
			return &BlockedRequest{
				ID:             verdict.ID,
				IsNotification: isRPCNotification(verdict.ID),
				LogMessage:     "CEE blocked",
				ErrorCode:      -32005,
				ErrorMessage:   fmt.Sprintf("pipelock: %s", reason),
			}
		}
		if rec != nil && adaptiveCfg != nil && adaptiveCfg.Enabled {
			rec.RecordClean(adaptiveCfg.DecayPerCleanRequest)
		}
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
	if chainReason != "" {
		reasons = append(reasons, chainReason)
	}

	// Determine effective action (strictest wins).
	// mergeAction sets effectiveAction to the stricter of cur and next,
	// handling the initial empty state correctly (empty = no action yet).
	effectiveAction := ""
	mergeAction := func(cur, next string) string {
		if cur == "" {
			return next
		}
		return policy.StricterAction(cur, next)
	}
	if !verdict.Clean {
		effectiveAction = action
	}
	if policyVerdict.Matched {
		effectiveAction = mergeAction(effectiveAction, policyVerdict.Action)
	}
	if chainAction != "" {
		effectiveAction = mergeAction(effectiveAction, chainAction)
	}

	isNotification := isRPCNotification(verdict.ID)

	// Error code/message based on what triggered.
	errCode := 0
	errMsg := ""
	if verdict.Clean && policyVerdict.Matched {
		errCode = -32002
		errMsg = errPolicyBlocked
	}

	// Escalation upgrade: may promote warn/ask to block for elevated sessions.
	originalAction := effectiveAction
	if rec != nil {
		effectiveAction = decide.UpgradeAction(effectiveAction, rec.EscalationLevel(), adaptiveCfg)
	}
	if effectiveAction != originalAction {
		levelLabel := session.EscalationLabel(rec.EscalationLevel())
		_, _ = fmt.Fprintf(logW, "pipelock: adaptive upgrade %s -> %s (level %s)\n", originalAction, effectiveAction, levelLabel)
		if auditLogger != nil {
			auditLogger.LogAdaptiveUpgrade(auditSessionKey, levelLabel, originalAction, effectiveAction, "mcp_input", "", "")
		}
		if m != nil {
			m.RecordAdaptiveUpgrade(originalAction, effectiveAction, levelLabel)
		}
	}

	switch effectiveAction {
	case config.ActionBlock:
		_, _ = fmt.Fprintf(logW, "pipelock: input: blocked (%s)\n", joinStrings(reasons))
		recordAdaptiveSignal(session.SignalBlock)
		return &BlockedRequest{
			ID:             verdict.ID,
			IsNotification: isNotification,
			LogMessage:     "blocked",
			ErrorCode:      errCode,
			ErrorMessage:   errMsg,
		}
	case config.ActionRedirect:
		// Batch requests cannot be redirected element-by-element. Fail closed.
		trimmedMsg := bytes.TrimSpace(msg)
		if len(trimmedMsg) > 0 && trimmedMsg[0] == '[' {
			_, _ = fmt.Fprintf(logW, "pipelock: input: blocked batch (%s) [redirect not supported for batches]\n", joinStrings(reasons))
			recordAdaptiveSignal(session.SignalBlock)
			return &BlockedRequest{
				ID: verdict.ID, IsNotification: isNotification,
				LogMessage: "blocked (batch redirect)", ErrorCode: -32002, ErrorMessage: errPolicyBlocked,
			}
		}
		if policyCfg == nil {
			// No policy config — fail closed.
			_, _ = fmt.Fprintf(logW, "pipelock: input: blocked (%s) [redirect without policy config]\n", joinStrings(reasons))
			recordAdaptiveSignal(session.SignalBlock)
			return &BlockedRequest{
				ID: verdict.ID, IsNotification: isNotification,
				LogMessage: "blocked (no policy config)", ErrorCode: -32002, ErrorMessage: errPolicyBlocked,
			}
		}
		profile, ok := policyCfg.RedirectProfiles[policyVerdict.RedirectProfile]
		if !ok {
			_, _ = fmt.Fprintf(logW, "pipelock: input: blocked (%s) [redirect profile %q not found]\n", joinStrings(reasons), policyVerdict.RedirectProfile)
			recordAdaptiveSignal(session.SignalBlock)
			return &BlockedRequest{
				ID: verdict.ID, IsNotification: isNotification,
				LogMessage: "blocked (redirect profile missing)", ErrorCode: -32002, ErrorMessage: errPolicyBlocked,
			}
		}
		toolName, toolArgs := extractToolCallFields(msg)
		policyRuleName := ""
		if len(policyVerdict.Rules) > 0 {
			policyRuleName = policyVerdict.Rules[0]
		}
		result := executeRedirect(profile, policyVerdict.RedirectProfile, verdict.ID, toolArgs, policyRuleName)
		// Determine final outcome before audit logging so the event
		// reflects the actual result delivered to the client.
		var br *BlockedRequest
		finalResult := "blocked"
		if result.Success {
			// Scan redirect handler output for prompt injection before
			// sending to client. Untrusted handler output is attack surface.
			scanVerdict := ScanResponse(result.Response, sc)
			if !scanVerdict.Clean {
				_, _ = fmt.Fprintf(logW, "pipelock: input: blocked redirect response (injection detected in handler output)\n")
				recordAdaptiveSignal(session.SignalBlock)
				br = &BlockedRequest{
					ID: verdict.ID, IsNotification: isNotification,
					LogMessage: "blocked (redirect output injection)", ErrorCode: -32001,
					ErrorMessage: "pipelock: redirect handler output blocked by response scanning",
				}
			} else {
				finalResult = "redirected"
				_, _ = fmt.Fprintf(logW, "pipelock: input: redirected via profile %q (%dms)\n", policyVerdict.RedirectProfile, result.LatencyMs)
				br = &BlockedRequest{
					ID: verdict.ID, IsNotification: isNotification,
					LogMessage: "redirected", SyntheticResponse: result.Response,
				}
			}
		} else {
			// Redirect handler failed — fall through to block (fail-closed).
			_, _ = fmt.Fprintf(logW, "pipelock: input: blocked (%s) [redirect failed: %s]\n", joinStrings(reasons), result.Error)
			recordAdaptiveSignal(session.SignalBlock)
			br = &BlockedRequest{
				ID: verdict.ID, IsNotification: isNotification,
				LogMessage: "blocked (redirect failed)", ErrorCode: -32002, ErrorMessage: errPolicyBlocked,
			}
		}
		if auditLogger != nil {
			auditLogger.LogToolRedirect(auditSessionKey, toolName, argsDigest(toolArgs), policyVerdict.RedirectProfile, profile.Reason, policyRuleName, finalResult, result.LatencyMs)
		}
		return br
	case config.ActionAsk:
		// HITL for input scanning is impractical — fall back to block (same as stdio proxy).
		_, _ = fmt.Fprintf(logW, "pipelock: input: blocked (%s) [ask not supported for input scanning]\n", joinStrings(reasons))
		recordAdaptiveSignal(session.SignalBlock)
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
			recordAdaptiveSignal(session.SignalNearMiss)
		}
		// Cross-request exfiltration check even in warn mode.
		ceeKey := ceeSessionKeyMCP("", sessionKey)
		if reason := ceeRecordMCP(ceeKey, msg, cee, sc, logW, auditLogger); reason != "" {
			return &BlockedRequest{
				ID:             verdict.ID,
				IsNotification: isRPCNotification(verdict.ID),
				LogMessage:     "CEE blocked",
				ErrorCode:      -32005,
				ErrorMessage:   fmt.Sprintf("pipelock: %s", reason),
			}
		}
		return nil // forward
	}
}

// hashSessionKey produces a short, non-reversible identifier from a raw IP
// for use in audit logs, so client IPs don't leak through the session field.
func hashSessionKey(ip string) string {
	h := sha256.Sum256([]byte(ip))
	return "ip:" + hex.EncodeToString(h[:8]) // 16 hex chars, enough to correlate
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
	if string(rpc.ID) == jsonrpc.Null || len(rpc.ID) == 0 {
		return nil
	}
	return rpc.ID
}

// validateRPCStructure checks JSON-RPC 2.0 structural requirements that
// json.Valid() cannot catch: version field, method presence, and method type.
// Returns an error message if invalid, empty string if ok.
func validateRPCStructure(msg []byte) string {
	var env struct {
		JSONRPC string          `json:"jsonrpc"`
		Method  json.RawMessage `json:"method"`
	}
	if json.Unmarshal(msg, &env) != nil {
		return "invalid JSON structure"
	}
	// jsonrpc field must be exactly "2.0".
	if env.JSONRPC != jsonrpc.Version {
		return "jsonrpc field must be \"2.0\""
	}
	// method field is required for client requests.
	if len(env.Method) == 0 {
		return "missing required field: method"
	}
	// Method must be a JSON string (starts with quote).
	if env.Method[0] != '"' {
		return "method must be a string"
	}
	return ""
}

// upstreamErrorResponse creates a JSON-RPC error for HTTP transport failures.
// If id is nil, the response uses a JSON null id (valid for unidentifiable requests).
func upstreamErrorResponse(id json.RawMessage, upstreamErr error) []byte {
	resp := rpcError{
		JSONRPC: jsonrpc.Version,
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
// transient errors. Exits permanently only on transport.ErrStreamNotSupported (HTTP 405)
// or context cancellation.
// rec and adaptiveCfg are passed through to ForwardScanned for adaptive enforcement.
func startGETStream(
	ctx context.Context,
	httpClient *transport.HTTPClient,
	safeClientOut *syncWriter,
	safeLogW *syncWriter,
	sc *scanner.Scanner,
	approver *hitl.Approver,
	toolCfg *tools.ToolScanConfig,
	ks *killswitch.Controller,
	rec session.Recorder,
	adaptiveCfg *config.AdaptiveEnforcement,
	wg *sync.WaitGroup,
	m *metrics.Metrics,
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

			// Kill switch: pause reconnecting while active. Without this,
			// the retry loop keeps establishing outbound connections even
			// though ForwardScanned blocks every message. Wait here instead
			// of returning so the goroutine resumes when the switch clears.
			if ks != nil && ks.IsActive() {
				_, _ = fmt.Fprintf(safeLogW, "pipelock: GET stream paused: kill switch active\n")
				for ks.IsActive() {
					select {
					case <-ctx.Done():
						return
					case <-time.After(time.Second):
					}
				}
				_, _ = fmt.Fprintf(safeLogW, "pipelock: GET stream resuming: kill switch cleared\n")
			}

			reader, err := httpClient.OpenGETStream(ctx)
			if err != nil {
				_, _ = fmt.Fprintf(safeLogW, "pipelock: GET stream: %v\n", err)
				// Permanent error — server does not support GET streams.
				if errors.Is(err, transport.ErrStreamNotSupported) {
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

			// nil tracker: GET stream carries server-initiated messages,
			// not responses to client requests.
			_, scanErr := ForwardScanned(reader, safeClientOut, safeLogW, sc, approver, toolCfg, nil, ks, rec, adaptiveCfg, m)
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

// RunHTTPListenerProxy starts an HTTP server that reverse-proxies MCP requests
// to an upstream server with bidirectional scanning. Each inbound POST is
// independently scanned and forwarded. Mcp-Session-Id and Authorization headers
// pass through transparently; the upstream owns session lifecycle.
//
// The caller is responsible for creating the net.Listener (via net.Listen or
// net.ListenConfig). This separates the bind step from serving, so callers
// detect port conflicts synchronously instead of losing them inside a goroutine.
//
// When store is non-nil, per-request session recorders are created using the
// Mcp-Session-Id header (or RemoteAddr fallback) as the session key, enabling
// adaptive enforcement signal tracking per logical MCP session.
//
// Endpoints:
//   - POST / : scan and forward JSON-RPC requests to upstream
//   - GET /health : returns 200 OK for liveness probes
func RunHTTPListenerProxy(
	ctx context.Context,
	ln net.Listener,
	upstreamURL string,
	logW io.Writer,
	sc *scanner.Scanner,
	approver *hitl.Approver,
	inputCfg *InputScanConfig,
	toolCfg *tools.ToolScanConfig,
	policyCfg *policy.Config,
	ks *killswitch.Controller,
	chainMatcher *chains.Matcher,
	auditLogger *audit.Logger,
	cee *CEEDeps,
	store session.Store,
	adaptiveCfgFn AdaptiveConfigFunc,
	m *metrics.Metrics,
) error {
	safeLogW := &syncWriter{w: logW}

	// Shared tool baseline across all requests for drift detection.
	var fwdToolCfg *tools.ToolScanConfig
	if toolCfg != nil && toolCfg.Action != "" {
		fwdToolCfg = &tools.ToolScanConfig{
			Baseline:    tools.NewToolBaseline(),
			Action:      toolCfg.Action,
			DetectDrift: toolCfg.DetectDrift,
			ExtraPoison: toolCfg.ExtraPoison,
		}
	}

	// Shared HTTP client for upstream requests. Redirect-following is disabled
	// to prevent SSRF via crafted Location headers from the upstream.
	// 30s timeout prevents hanging on unresponsive upstreams.
	upstreamClient := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"status":"ok"}`)
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Resolve adaptive config per-request so hot-reloads take effect
		// without restarting the long-lived listener.
		var adaptiveCfg *config.AdaptiveEnforcement
		if adaptiveCfgFn != nil {
			adaptiveCfg = adaptiveCfgFn()
		}

		// Cap request body to prevent memory exhaustion.
		r.Body = http.MaxBytesReader(w, r.Body, int64(transport.MaxLineSize))
		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			_, _ = w.Write(upstreamErrorResponse(nil, fmt.Errorf("request body too large")))
			return
		}

		body = bytes.TrimSpace(body)
		if len(body) == 0 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write(upstreamErrorResponse(nil, fmt.Errorf("empty request body")))
			return
		}

		// Reject malformed JSON early. Without this, invalid payloads
		// reach scanHTTPInput where parse errors may be treated as
		// notifications (202 with no body), silently dropping the error.
		// Uses JSON-RPC 2.0 standard code -32700 (Parse error).
		if !json.Valid(body) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			parseErr, _ := json.Marshal(rpcError{
				JSONRPC: jsonrpc.Version,
				Error:   rpcErrorDetail{Code: -32700, Message: "pipelock: parse error: invalid JSON"},
			})
			_, _ = w.Write(parseErr)
			return
		}

		// Validate JSON-RPC 2.0 structure for single requests: version
		// must be "2.0", method must be present and a string. Batch
		// requests (JSON arrays) are validated per-element by scanHTTPInput.
		// Uses JSON-RPC 2.0 standard code -32600 (Invalid Request).
		if body[0] != '[' {
			if reason := validateRPCStructure(body); reason != "" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				rpcID := extractRPCID(body)
				invalidReq, _ := json.Marshal(rpcError{
					JSONRPC: jsonrpc.Version,
					ID:      rpcID,
					Error:   rpcErrorDetail{Code: -32600, Message: "pipelock: invalid request: " + reason},
				})
				_, _ = w.Write(invalidReq)
				return
			}
		}

		// Kill switch: deny all requests when active.
		if ks != nil {
			if d := ks.IsActiveMCP(body); d.Active {
				w.Header().Set("Content-Type", "application/json")
				if d.IsNotification {
					w.WriteHeader(http.StatusAccepted)
					_, _ = fmt.Fprintf(safeLogW, "pipelock: kill switch dropped notification (source=%s)\n", d.Source)
					return
				}
				rpcID := extractRPCID(body)
				_, _ = w.Write(killswitch.ErrorResponse(rpcID, d.Message))
				return
			}
		}

		// Use Mcp-Session-Id header as chain detection session key so
		// concurrent clients don't share tool call history. When no
		// session ID is present, fall back to the client IP (without
		// port) so all requests from the same agent share chain history
		// even across separate TCP connections.
		chainSessionKey := r.Header.Get("Mcp-Session-Id")
		auditSessionKey := chainSessionKey
		if chainSessionKey == "" {
			host, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				host = r.RemoteAddr
			}
			chainSessionKey = host
			// Hash the IP for audit logs to avoid persisting raw client
			// addresses in a field that bypasses report IP redaction.
			auditSessionKey = hashSessionKey(host)
		}

		// Per-request adaptive enforcement recorder. Uses RemoteAddr (without
		// port) as a stable session key: the first request has no Mcp-Session-Id
		// yet, so using the chain key would split signals across two keys (IP
		// for first request, session ID for subsequent ones).
		var reqRec session.Recorder
		if store != nil {
			adaptiveHost, _, adaptiveErr := net.SplitHostPort(r.RemoteAddr)
			if adaptiveErr != nil {
				adaptiveHost = r.RemoteAddr
			}
			reqRec = store.GetOrCreate(adaptiveHost)
		}

		// Scan Authorization header for DLP patterns. The body scanner
		// doesn't see HTTP headers, so an agent could leak credentials
		// via the Authorization header without triggering DLP.
		if auth := r.Header.Get("Authorization"); auth != "" {
			dlpResult := sc.ScanTextForDLP(r.Context(), auth)
			if !dlpResult.Clean {
				_, _ = fmt.Fprintf(safeLogW, "pipelock: DLP match in Authorization header: %s\n", dlpResult.Matches[0].PatternName)
				if reqRec != nil && adaptiveCfg != nil && adaptiveCfg.Enabled {
					recordSignalWithEscalation(reqRec, session.SignalBlock, adaptiveCfg.EscalationThreshold, safeLogW, auditLogger, m, auditSessionKey, "", "")
				}
				w.Header().Set("Content-Type", "application/json")
				rpcID := extractRPCID(body)
				resp, _ := json.Marshal(rpcError{
					JSONRPC: jsonrpc.Version,
					ID:      rpcID,
					Error:   rpcErrorDetail{Code: -32001, Message: "pipelock: request blocked by MCP input scanning"},
				})
				_, _ = w.Write(resp)
				return
			}
		}

		// Input scanning: DLP, injection, policy, chain detection.
		if blocked := scanHTTPInput(body, sc, safeLogW, inputCfg, policyCfg, chainMatcher, chainSessionKey, auditSessionKey, auditLogger, cee, reqRec, adaptiveCfg, m); blocked != nil {
			w.Header().Set("Content-Type", "application/json")
			if blocked.IsNotification {
				w.WriteHeader(http.StatusAccepted)
				return
			}
			if blocked.SyntheticResponse != nil {
				_, _ = w.Write(blocked.SyntheticResponse)
			} else {
				_, _ = w.Write(blockRequestResponse(*blocked))
			}
			return
		}

		// Build upstream request with passthrough headers.
		upReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, upstreamURL, bytes.NewReader(body))
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write(upstreamErrorResponse(extractRPCID(body), fmt.Errorf("upstream HTTP request failed")))
			return
		}
		upReq.Header.Set("Content-Type", "application/json")
		upReq.Header.Set("Accept", "application/json, text/event-stream")

		if auth := r.Header.Get("Authorization"); auth != "" {
			upReq.Header.Set("Authorization", auth)
		}
		if sid := r.Header.Get("Mcp-Session-Id"); sid != "" {
			upReq.Header.Set("Mcp-Session-Id", sid)
		}

		upResp, err := upstreamClient.Do(upReq)
		if err != nil {
			_, _ = fmt.Fprintf(safeLogW, "pipelock: upstream error: %v\n", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write(upstreamErrorResponse(extractRPCID(body), fmt.Errorf("upstream HTTP request failed")))
			return
		}
		defer upResp.Body.Close() //nolint:errcheck // best-effort cleanup

		// 202 Accepted: notification acknowledged, no body.
		if upResp.StatusCode == http.StatusAccepted {
			w.WriteHeader(http.StatusAccepted)
			return
		}

		// Upstream error: sanitize before forwarding (don't leak body content
		// that could contain injection payloads).
		if upResp.StatusCode >= 400 {
			_, _ = fmt.Fprintf(safeLogW, "pipelock: upstream HTTP %d\n", upResp.StatusCode)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write(upstreamErrorResponse(extractRPCID(body), fmt.Errorf("upstream HTTP request failed")))
			return
		}

		// Read upstream response body and scan it.
		// nil tracker: HTTP reverse proxy pairs each request/response via HTTP
		// semantics, so confused deputy tracking is handled at the transport level.
		reader := &transport.SingleMessageReader{Body: upResp.Body}
		var buf bytes.Buffer
		bufWriter := &syncWriter{w: &buf}
		_, scanErr := ForwardScanned(reader, bufWriter, safeLogW, sc, approver, fwdToolCfg, nil, ks, reqRec, adaptiveCfg, m)
		if scanErr != nil {
			_, _ = fmt.Fprintf(safeLogW, "pipelock: scan error: %v\n", scanErr)
		}

		// Pass Mcp-Session-Id from upstream back to client.
		if sid := upResp.Header.Get("Mcp-Session-Id"); sid != "" {
			w.Header().Set("Mcp-Session-Id", sid)
		}

		w.Header().Set("Content-Type", "application/json")
		output := bytes.TrimSpace(buf.Bytes())
		if len(output) == 0 {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		_, _ = w.Write(output)
	})

	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// Graceful shutdown on context cancellation.
	go func() {
		<-ctx.Done()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		_ = srv.Shutdown(shutdownCtx) //nolint:errcheck // best-effort shutdown
	}()

	_, _ = fmt.Fprintf(safeLogW, "pipelock: MCP reverse proxy listening on %s\n", ln.Addr())

	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("HTTP listener: %w", err)
	}
	return nil
}
