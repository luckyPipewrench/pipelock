package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/hitl"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// syncWriter wraps an io.Writer with a mutex to make concurrent writes safe.
// Used in RunProxy where multiple goroutines write to clientOut and logW.
type syncWriter struct {
	mu sync.Mutex
	w  io.Writer
}

// Compile-time assertion: syncWriter implements MessageWriter.
var _ MessageWriter = (*syncWriter)(nil)

func (sw *syncWriter) Write(p []byte) (int, error) {
	sw.mu.Lock()
	defer sw.mu.Unlock()
	return sw.w.Write(p)
}

// WriteMessage writes a JSON-RPC message followed by a newline in a single
// Write call under the mutex, preventing interleaving between concurrent
// goroutines (e.g., the blocked request drainer and ForwardScanned).
func (sw *syncWriter) WriteMessage(msg []byte) error {
	sw.mu.Lock()
	defer sw.mu.Unlock()
	if len(msg) > maxLineSize {
		return fmt.Errorf("message too large: %d bytes", len(msg))
	}
	buf := make([]byte, len(msg)+1)
	copy(buf, msg)
	buf[len(msg)] = '\n'
	if _, err := sw.w.Write(buf); err != nil {
		return fmt.Errorf("writing message: %w", err)
	}
	return nil
}

// ForwardScanned reads JSON-RPC 2.0 messages from reader, scans each for prompt
// injection, and forwards to writer based on the scanner's configured action
// (warn, block, strip). Scan verdicts are logged to logW.
// When toolCfg is non-nil, tool descriptions in tools/list responses are scanned
// for poisoning and tracked for drift (rug pull) detection. Tool scanning runs
// independently of general response scanning so a "block" tool action is never
// bypassed by a "warn" general action.
// Returns true if any injection was detected.
func ForwardScanned(reader MessageReader, writer MessageWriter, logW io.Writer, sc *scanner.Scanner, approver *hitl.Approver, toolCfg *ToolScanConfig) (bool, error) {
	foundInjection := false
	// lineNum counts non-empty messages, not raw lines. StdioReader skips
	// empty lines internally, so this is a message index. ScanStream (scan.go)
	// preserves raw line counting for user-facing diagnostics.
	lineNum := 0

	for {
		line, err := reader.ReadMessage()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return foundInjection, fmt.Errorf("reading input: %w", err)
		}
		lineNum++

		verdict := ScanResponse(line, sc)

		// Tool scanning runs on every response, independent of general scan
		// verdict. A general scan "warn" must not bypass a tool scan "block".
		if toolCfg != nil {
			toolResult := ScanTools(line, sc, toolCfg)
			if toolResult.IsToolsList && !toolResult.Clean {
				foundInjection = true
				logToolFindings(logW, lineNum, toolResult)

				if toolCfg.Action == config.ActionBlock {
					resp := blockResponse(toolResult.RPCID)
					if err := writer.WriteMessage(resp); err != nil {
						return foundInjection, fmt.Errorf("writing tool block: %w", err)
					}
					continue
				}
				// warn: logged above, fall through to general handling
			}
		}

		if verdict.Clean {
			if err := writer.WriteMessage(line); err != nil {
				return foundInjection, fmt.Errorf("writing line: %w", err)
			}
			continue
		}

		// Parse error: always fail-closed regardless of action setting.
		// Unparseable responses could hide injection in malformed content.
		if verdict.Error != "" {
			_, _ = fmt.Fprintf(logW, "pipelock: line %d: %s\n", lineNum, verdict.Error)
			// Scan raw text for injection even when not valid JSON-RPC.
			rawResult := sc.ScanResponse(string(line))
			if !rawResult.Clean {
				foundInjection = true
				names := matchNames(rawResult.Matches)
				_, _ = fmt.Fprintf(logW, "pipelock: line %d: injection in non-JSON content (%s)\n",
					lineNum, strings.Join(names, ", "))
			}
			_, _ = fmt.Fprintf(logW, "pipelock: line %d: blocking unparseable response\n", lineNum)
			resp := blockResponse(nil)
			if err := writer.WriteMessage(resp); err != nil {
				return foundInjection, fmt.Errorf("writing block response: %w", err)
			}
			continue
		}

		// Injection detected.
		foundInjection = true
		action := sc.ResponseAction()
		names := matchNames(verdict.Matches)
		_, _ = fmt.Fprintf(logW, "pipelock: line %d: injection detected (%s), action=%s\n",
			lineNum, strings.Join(names, ", "), action)

		switch action {
		case config.ActionBlock:
			resp := blockResponse(verdict.ID)
			if err := writer.WriteMessage(resp); err != nil {
				return foundInjection, fmt.Errorf("writing block response: %w", err)
			}
		case config.ActionAsk:
			if approver == nil {
				_, _ = fmt.Fprintf(logW, "pipelock: line %d: no HITL approver configured, blocking\n", lineNum)
				resp := blockResponse(verdict.ID)
				if err := writer.WriteMessage(resp); err != nil {
					return foundInjection, fmt.Errorf("writing block response: %w", err)
				}
			} else {
				preview := ""
				if len(verdict.Matches) > 0 {
					preview = verdict.Matches[0].MatchText
				}
				d := approver.Ask(&hitl.Request{
					URL:      "mcp-response",
					Reason:   fmt.Sprintf("prompt injection detected: %s", strings.Join(names, ", ")),
					Patterns: names,
					Preview:  preview,
				})
				switch d {
				case hitl.DecisionAllow:
					_, _ = fmt.Fprintf(logW, "pipelock: line %d: operator allowed\n", lineNum)
					if err := writer.WriteMessage(line); err != nil {
						return foundInjection, fmt.Errorf("writing line: %w", err)
					}
				case hitl.DecisionStrip:
					_, _ = fmt.Fprintf(logW, "pipelock: line %d: operator chose strip\n", lineNum)
					if err := stripOrBlock(line, sc, writer, logW, verdict.ID); err != nil {
						return foundInjection, fmt.Errorf("writing strip/block response: %w", err)
					}
				default: // DecisionBlock
					_, _ = fmt.Fprintf(logW, "pipelock: line %d: operator blocked\n", lineNum)
					resp := blockResponse(verdict.ID)
					if err := writer.WriteMessage(resp); err != nil {
						return foundInjection, fmt.Errorf("writing block response: %w", err)
					}
				}
			}
		case config.ActionStrip:
			if err := stripOrBlock(line, sc, writer, logW, verdict.ID); err != nil {
				return foundInjection, fmt.Errorf("writing strip/block response: %w", err)
			}
		default: // warn
			if err := writer.WriteMessage(line); err != nil {
				return foundInjection, fmt.Errorf("writing line: %w", err)
			}
		}
	}

	return foundInjection, nil
}

// stripOrBlock tries to strip injection from the response. If stripping fails,
// it falls back to blocking (fail-closed). Returns a write error if the writer fails.
func stripOrBlock(line []byte, sc *scanner.Scanner, writer MessageWriter, logW io.Writer, rpcID json.RawMessage) error {
	stripped, sErr := stripResponse(line, sc)
	if sErr != nil {
		_, _ = fmt.Fprintf(logW, "pipelock: strip failed (%v), blocking instead\n", sErr)
		return writer.WriteMessage(blockResponse(rpcID))
	}
	return writer.WriteMessage(stripped)
}

// rpcError is a JSON-RPC 2.0 error response sent when a response is blocked.
type rpcError struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Error   rpcErrorDetail  `json:"error"`
}

type rpcErrorDetail struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// blockResponse generates a JSON-RPC 2.0 error response for a blocked message.
// Code -32000 is in the implementation-defined error range.
func blockResponse(id json.RawMessage) []byte {
	resp := rpcError{
		JSONRPC: jsonRPCVersion,
		ID:      id,
		Error: rpcErrorDetail{
			Code:    -32000,
			Message: "pipelock: prompt injection detected in MCP response",
		},
	}
	data, _ := json.Marshal(resp) //nolint:errcheck // marshaling known-good struct
	return data
}

// stripRPCResponse is used only by stripResponse for typed result manipulation.
// The main RPCResponse uses json.RawMessage for flexible scanning.
type stripRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  *ToolResult     `json:"result,omitempty"`
	Error   json.RawMessage `json:"error,omitempty"`
}

// maxStripDepth limits recursion between stripResponseDepth and stripBatchDepth
// to prevent stack overflow from maliciously nested JSON arrays.
const maxStripDepth = 4

// stripResponse re-parses a JSON-RPC response, redacts matched injection
// patterns in content blocks and error fields, and returns the re-marshaled JSON.
func stripResponse(line []byte, sc *scanner.Scanner) ([]byte, error) {
	return stripResponseDepth(line, sc, 0)
}

func stripResponseDepth(line []byte, sc *scanner.Scanner, depth int) ([]byte, error) {
	// Handle batch responses (JSON array).
	if len(line) > 0 && line[0] == '[' {
		if depth >= maxStripDepth {
			return nil, fmt.Errorf("batch nesting too deep (max %d)", maxStripDepth)
		}
		return stripBatchDepth(line, sc, depth+1)
	}

	var rpc stripRPCResponse
	if err := json.Unmarshal(line, &rpc); err != nil {
		return nil, fmt.Errorf("parsing response for strip: %w", err)
	}

	if rpc.Result != nil {
		for i, block := range rpc.Result.Content {
			if block.Text == "" {
				continue
			}
			result := sc.ScanResponse(block.Text)
			if !result.Clean {
				if result.TransformedContent != "" {
					rpc.Result.Content[i].Text = result.TransformedContent
				} else {
					// Detection from non-redactable pass (vowel-fold/decoded).
					// Can't strip, fail-closed to block.
					return nil, fmt.Errorf("injection detected but not redactable in content block %d", i)
				}
			}
		}
	}

	// Scan error.message and error.data for injection content.
	if len(rpc.Error) > 0 {
		var errObj struct {
			Code    int             `json:"code"`
			Message string          `json:"message"`
			Data    json.RawMessage `json:"data,omitempty"`
		}
		if json.Unmarshal(rpc.Error, &errObj) == nil {
			changed := false
			if errObj.Message != "" {
				result := sc.ScanResponse(errObj.Message)
				if !result.Clean {
					if result.TransformedContent != "" {
						errObj.Message = result.TransformedContent
						changed = true
					} else {
						return nil, fmt.Errorf("injection detected but not redactable in error message")
					}
				}
			}
			if len(errObj.Data) > 0 {
				var dataStr string
				if json.Unmarshal(errObj.Data, &dataStr) == nil && dataStr != "" {
					result := sc.ScanResponse(dataStr)
					if !result.Clean {
						if result.TransformedContent != "" {
							if newData, mErr := json.Marshal(result.TransformedContent); mErr == nil {
								errObj.Data = newData
								changed = true
							}
						} else {
							return nil, fmt.Errorf("injection detected but not redactable in error data")
						}
					}
				}
			}
			if changed {
				if newErr, mErr := json.Marshal(errObj); mErr == nil {
					rpc.Error = newErr
				}
			}
		}
	}

	return json.Marshal(rpc)
}

// stripBatchDepth handles stripping injection from batch (array) JSON-RPC responses.
func stripBatchDepth(line []byte, sc *scanner.Scanner, depth int) ([]byte, error) {
	var batch []json.RawMessage
	if err := json.Unmarshal(line, &batch); err != nil {
		return nil, fmt.Errorf("parsing batch for strip: %w", err)
	}
	result := make([]json.RawMessage, len(batch))
	for i, elem := range batch {
		stripped, err := stripResponseDepth(elem, sc, depth)
		if err != nil {
			// Never forward unstripped injection — block the element instead.
			result[i] = json.RawMessage(blockResponse(nil))
		} else {
			result[i] = json.RawMessage(stripped)
		}
	}
	return json.Marshal(result)
}

// matchNames extracts pattern names from a list of response matches.
func matchNames(matches []scanner.ResponseMatch) []string {
	names := make([]string, 0, len(matches))
	for _, m := range matches {
		names = append(names, m.PatternName)
	}
	return names
}

// InputScanConfig holds the settings for MCP input scanning.
// Passed to RunProxy to control request scanning behavior.
type InputScanConfig struct {
	Enabled      bool
	Action       string // warn, block
	OnParseError string // block, forward
}

// RunProxy launches an MCP server subprocess and proxies stdio through
// the scanner. Client input is scanned for DLP/injection (if enabled) before
// forwarding to the server's stdin. Server stdout is scanned and forwarded
// to the client. Server stderr is forwarded to logW.
// When toolCfg is non-nil with a non-empty Action, tool description scanning
// and drift detection are enabled for this proxy session.
// Both clientOut and logW are wrapped in mutex adapters to prevent concurrent
// write races between the input scanning goroutine, blocked request drainer,
// child process stderr, and the main goroutine's response scanning.
func RunProxy(ctx context.Context, clientIn io.Reader, clientOut io.Writer, logW io.Writer, command []string, sc *scanner.Scanner, approver *hitl.Approver, inputCfg *InputScanConfig, toolCfg *ToolScanConfig, policyCfg *PolicyConfig, extraEnv ...string) error {
	cmd := exec.CommandContext(ctx, command[0], command[1:]...) //nolint:gosec // command comes from user CLI args

	// Wrap shared writers in mutex adapters. Multiple goroutines write to
	// clientOut (blocked request drainer + response scanner) and logW
	// (input scanner + response scanner + child stderr).
	safeClientOut := &syncWriter{w: clientOut}
	safeLogW := &syncWriter{w: logW}

	// Restrict child process environment to safe variables only.
	// Prevents leaking secrets from the proxy's environment to the MCP server.
	// Extra env vars from --env flags are appended (user explicitly opted in).
	cmd.Env = append(safeEnv(), extraEnv...)

	serverIn, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("creating stdin pipe: %w", err)
	}

	serverOut, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("creating stdout pipe: %w", err)
	}

	cmd.Stderr = safeLogW

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting MCP server %q: %w", command[0], err)
	}

	// Channel for blocked request IDs from input scanning goroutine.
	// Blocked drainer goroutine writes error responses to safeClientOut,
	// which is mutex-protected against concurrent writes from ForwardScanned.
	blockedCh := make(chan BlockedRequest, 16)

	// Forward client input to server stdin (with optional input scanning).
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer serverIn.Close() //nolint:errcheck // best-effort close on stdin forward
		if inputCfg != nil && inputCfg.Enabled {
			clientReader := NewStdioReader(clientIn)
			serverWriter := NewStdioWriter(serverIn)
			ForwardScannedInput(clientReader, serverWriter, safeLogW, sc, inputCfg.Action, inputCfg.OnParseError, blockedCh, policyCfg)
		} else if policyCfg != nil {
			// Policy checking enabled but content scanning disabled.
			// Route through ForwardScannedInput with pass-through content scanning.
			// Use onParseError="block" (fail-closed) so malformed JSON can't bypass policy.
			clientReader := NewStdioReader(clientIn)
			serverWriter := NewStdioWriter(serverIn)
			ForwardScannedInput(clientReader, serverWriter, safeLogW, sc, config.ActionWarn, config.ActionBlock, blockedCh, policyCfg)
		} else {
			close(blockedCh)                   // No input scanning — close channel immediately.
			_, _ = io.Copy(serverIn, clientIn) //nolint:errcheck // broken pipe on server exit is expected
		}
	}()

	// Drain blocked request channel and write error responses to client.
	// Runs in a separate goroutine so ForwardScanned can proceed concurrently.
	var wgBlocked sync.WaitGroup
	wgBlocked.Add(1)
	go func() {
		defer wgBlocked.Done()
		for blocked := range blockedCh {
			if blocked.IsNotification {
				// Notifications have no ID — silently drop (no error response).
				continue
			}
			resp := blockRequestResponse(blocked)
			_ = safeClientOut.WriteMessage(resp) //nolint:errcheck // best-effort
		}
	}()

	// Set up tool scanning with a fresh baseline for this proxy session.
	var fwdToolCfg *ToolScanConfig
	if toolCfg != nil && toolCfg.Action != "" {
		fwdToolCfg = &ToolScanConfig{
			Baseline:    NewToolBaseline(),
			Action:      toolCfg.Action,
			DetectDrift: toolCfg.DetectDrift,
		}
	}

	// Scan and forward server output to client.
	serverReader := NewStdioReader(serverOut)
	_, scanErr := ForwardScanned(serverReader, safeClientOut, safeLogW, sc, approver, fwdToolCfg)

	// Wait for subprocess to exit.
	waitErr := cmd.Wait()

	// Wait for stdin goroutine to finish (server exit closes pipe, unblocking scanner).
	wg.Wait()

	// Wait for blocked channel drain to complete.
	wgBlocked.Wait()

	if scanErr != nil {
		return fmt.Errorf("scanning: %w", scanErr)
	}

	return waitErr
}

// safeEnvKeys are environment variables safe to pass to child MCP server processes.
// These cannot be overridden via --env to prevent footgun scenarios (e.g. --env PATH=/evil).
var safeEnvKeys = []string{"PATH", "HOME", "USER", "LANG", "TERM", "TZ", "TMPDIR", "SHELL"}

// safeEnvKeySet mirrors safeEnvKeys as a set for O(1) lookup in IsSafeEnvKey.
var safeEnvKeySet = func() map[string]bool {
	m := make(map[string]bool, len(safeEnvKeys))
	for _, k := range safeEnvKeys {
		m[k] = true
	}
	return m
}()

// dangerousEnvKeys are environment variable names that can inject code or libraries
// into child processes. These are blocked even when explicitly requested via --env.
var dangerousEnvKeys = map[string]bool{
	// Dynamic linker injection (Linux/macOS).
	"LD_PRELOAD":            true,
	"LD_LIBRARY_PATH":       true,
	"DYLD_INSERT_LIBRARIES": true,
	"DYLD_LIBRARY_PATH":     true,
	// Runtime code injection.
	"NODE_OPTIONS":      true,
	"PYTHONSTARTUP":     true,
	"PYTHONPATH":        true,
	"PERL5OPT":          true,
	"RUBYOPT":           true,
	"BASH_ENV":          true,
	"JAVA_TOOL_OPTIONS": true,
	"_JAVA_OPTIONS":     true,
	"JDK_JAVA_OPTIONS":  true,
	// Credential helper injection — causes git to execute arbitrary programs.
	"GIT_ASKPASS": true,
	// Proxy redirection — the MCP proxy IS the controlled network path.
	// Both cases listed because Go checks HTTP_PROXY/http_proxy, Node.js
	// checks case-insensitively, etc. Mixed-case caught by IsDangerousEnvKey.
	"HTTP_PROXY":  true,
	"HTTPS_PROXY": true,
	"ALL_PROXY":   true,
	"FTP_PROXY":   true,
	"NO_PROXY":    true,
	"http_proxy":  true,
	"https_proxy": true,
	"all_proxy":   true,
	"ftp_proxy":   true,
	"no_proxy":    true,
}

// IsSafeEnvKey reports whether the given key is one of the system variables
// already provided by safeEnv(). These cannot be overridden via --env.
func IsSafeEnvKey(key string) bool {
	return safeEnvKeySet[key]
}

// IsDangerousEnvKey reports whether the given environment variable name is
// blocked from passthrough because it can inject code or redirect traffic.
// Proxy-related vars are checked case-insensitively since different runtimes
// (Go, Node.js, Python, curl) honor different casings.
func IsDangerousEnvKey(key string) bool {
	if dangerousEnvKeys[key] {
		return true
	}
	// Case-insensitive catch-all for proxy vars. Covers mixed-case forms
	// like Http_Proxy that some runtimes (notably Node.js) honor.
	upper := strings.ToUpper(key)
	return strings.HasSuffix(upper, "_PROXY")
}

// safeEnv builds a filtered environment from the current process, keeping only
// variables in safeEnvKeys. This prevents accidental secret leakage to MCP servers.
func safeEnv() []string {
	var env []string
	for _, key := range safeEnvKeys {
		if val, ok := os.LookupEnv(key); ok {
			env = append(env, key+"="+val)
		}
	}
	return env
}
