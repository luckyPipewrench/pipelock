package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/luckyPipewrench/pipelock/internal/hitl"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// ForwardScanned reads newline-delimited JSON-RPC 2.0 messages from r, scans
// each for prompt injection, and forwards to w based on the scanner's configured
// action (warn, block, strip). Scan verdicts are logged to logW.
// Returns true if any injection was detected.
func ForwardScanned(r io.Reader, w io.Writer, logW io.Writer, sc *scanner.Scanner, approver *hitl.Approver) (bool, error) {
	lineScanner := bufio.NewScanner(r)
	lineScanner.Buffer(make([]byte, 0, 64*1024), maxLineSize)

	foundInjection := false
	lineNum := 0

	for lineScanner.Scan() {
		lineNum++
		line := bytes.TrimSpace(lineScanner.Bytes())
		if len(line) == 0 {
			continue
		}

		verdict := ScanResponse(line, sc)

		if verdict.Clean {
			if _, err := w.Write(line); err != nil {
				return foundInjection, fmt.Errorf("writing line: %w", err)
			}
			if _, err := w.Write([]byte("\n")); err != nil {
				return foundInjection, fmt.Errorf("writing newline: %w", err)
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
			if _, err := w.Write(resp); err != nil {
				return foundInjection, fmt.Errorf("writing block response: %w", err)
			}
			if _, err := w.Write([]byte("\n")); err != nil {
				return foundInjection, fmt.Errorf("writing newline: %w", err)
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
		case "block":
			resp := blockResponse(verdict.ID)
			if _, err := w.Write(resp); err != nil {
				return foundInjection, fmt.Errorf("writing block response: %w", err)
			}
			if _, err := w.Write([]byte("\n")); err != nil {
				return foundInjection, fmt.Errorf("writing newline: %w", err)
			}
		case "ask":
			if approver == nil {
				_, _ = fmt.Fprintf(logW, "pipelock: line %d: no HITL approver configured, blocking\n", lineNum)
				resp := blockResponse(verdict.ID)
				if _, err := w.Write(resp); err != nil {
					return foundInjection, fmt.Errorf("writing block response: %w", err)
				}
				if _, err := w.Write([]byte("\n")); err != nil {
					return foundInjection, fmt.Errorf("writing newline: %w", err)
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
					if _, err := w.Write(line); err != nil {
						return foundInjection, fmt.Errorf("writing line: %w", err)
					}
					if _, err := w.Write([]byte("\n")); err != nil {
						return foundInjection, fmt.Errorf("writing newline: %w", err)
					}
				case hitl.DecisionStrip:
					_, _ = fmt.Fprintf(logW, "pipelock: line %d: operator chose strip\n", lineNum)
					stripped, err := stripResponse(line, sc)
					if err != nil {
						_, _ = fmt.Fprintf(logW, "pipelock: strip failed (%v), blocking instead\n", err)
						resp := blockResponse(verdict.ID)
						if _, err := w.Write(resp); err != nil {
							return foundInjection, fmt.Errorf("writing block response: %w", err)
						}
						if _, err := w.Write([]byte("\n")); err != nil {
							return foundInjection, fmt.Errorf("writing newline: %w", err)
						}
					} else {
						if _, err := w.Write(stripped); err != nil {
							return foundInjection, fmt.Errorf("writing stripped response: %w", err)
						}
						if _, err := w.Write([]byte("\n")); err != nil {
							return foundInjection, fmt.Errorf("writing newline: %w", err)
						}
					}
				default: // DecisionBlock
					_, _ = fmt.Fprintf(logW, "pipelock: line %d: operator blocked\n", lineNum)
					resp := blockResponse(verdict.ID)
					if _, err := w.Write(resp); err != nil {
						return foundInjection, fmt.Errorf("writing block response: %w", err)
					}
					if _, err := w.Write([]byte("\n")); err != nil {
						return foundInjection, fmt.Errorf("writing newline: %w", err)
					}
				}
			}
		case "strip":
			stripped, err := stripResponse(line, sc)
			if err != nil {
				_, _ = fmt.Fprintf(logW, "pipelock: strip failed (%v), blocking instead\n", err)
				resp := blockResponse(verdict.ID)
				if _, err := w.Write(resp); err != nil {
					return foundInjection, fmt.Errorf("writing block response: %w", err)
				}
				if _, err := w.Write([]byte("\n")); err != nil {
					return foundInjection, fmt.Errorf("writing newline: %w", err)
				}
			} else {
				if _, err := w.Write(stripped); err != nil {
					return foundInjection, fmt.Errorf("writing stripped response: %w", err)
				}
				if _, err := w.Write([]byte("\n")); err != nil {
					return foundInjection, fmt.Errorf("writing newline: %w", err)
				}
			}
		default: // warn
			if _, err := w.Write(line); err != nil {
				return foundInjection, fmt.Errorf("writing line: %w", err)
			}
			if _, err := w.Write([]byte("\n")); err != nil {
				return foundInjection, fmt.Errorf("writing newline: %w", err)
			}
		}
	}

	if err := lineScanner.Err(); err != nil {
		return foundInjection, fmt.Errorf("reading input: %w", err)
	}

	return foundInjection, nil
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
			if !result.Clean && result.TransformedContent != "" {
				rpc.Result.Content[i].Text = result.TransformedContent
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
				if !result.Clean && result.TransformedContent != "" {
					errObj.Message = result.TransformedContent
					changed = true
				}
			}
			if len(errObj.Data) > 0 {
				var dataStr string
				if json.Unmarshal(errObj.Data, &dataStr) == nil && dataStr != "" {
					result := sc.ScanResponse(dataStr)
					if !result.Clean && result.TransformedContent != "" {
						if newData, mErr := json.Marshal(result.TransformedContent); mErr == nil {
							errObj.Data = newData
							changed = true
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
			result[i] = elem // keep original if strip fails for one element
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

// RunProxy launches an MCP server subprocess and proxies stdio through
// the scanner. Client input is forwarded to the server's stdin, server
// stdout is scanned and forwarded to the client, and server stderr is
// forwarded to logW. Returns when the subprocess exits or ctx is cancelled.
func RunProxy(ctx context.Context, clientIn io.Reader, clientOut io.Writer, logW io.Writer, command []string, sc *scanner.Scanner, approver *hitl.Approver) error {
	cmd := exec.CommandContext(ctx, command[0], command[1:]...) //nolint:gosec // command comes from user CLI args

	// Restrict child process environment to safe variables only.
	// Prevents leaking secrets from the proxy's environment to the MCP server.
	cmd.Env = safeEnv()

	serverIn, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("creating stdin pipe: %w", err)
	}

	serverOut, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("creating stdout pipe: %w", err)
	}

	cmd.Stderr = logW

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting MCP server %q: %w", command[0], err)
	}

	// Forward client input to server stdin.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer serverIn.Close()             //nolint:errcheck // best-effort close on stdin forward
		_, _ = io.Copy(serverIn, clientIn) //nolint:errcheck // broken pipe on server exit is expected
	}()

	// Scan and forward server output to client.
	_, scanErr := ForwardScanned(serverOut, clientOut, logW, sc, approver)

	// Wait for subprocess to exit.
	waitErr := cmd.Wait()

	// Wait for stdin goroutine to finish (server exit closes pipe, unblocking io.Copy).
	wg.Wait()

	if scanErr != nil {
		return fmt.Errorf("scanning: %w", scanErr)
	}

	return waitErr
}

// safeEnvKeys are environment variables safe to pass to child MCP server processes.
var safeEnvKeys = []string{"PATH", "HOME", "USER", "LANG", "TERM", "TZ", "TMPDIR", "SHELL"}

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
