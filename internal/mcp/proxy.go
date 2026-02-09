package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"

	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// ForwardScanned reads newline-delimited JSON-RPC 2.0 messages from r, scans
// each for prompt injection, and forwards to w based on the scanner's configured
// action (warn, block, strip). Scan verdicts are logged to logW.
// Returns true if any injection was detected.
func ForwardScanned(r io.Reader, w io.Writer, logW io.Writer, sc *scanner.Scanner) (bool, error) {
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

		// Clean or parse error: forward as-is.
		// Parse errors are the server's problem — we pass them through.
		if verdict.Clean || verdict.Error != "" {
			if _, err := w.Write(line); err != nil {
				return foundInjection, fmt.Errorf("writing line: %w", err)
			}
			if _, err := w.Write([]byte("\n")); err != nil {
				return foundInjection, fmt.Errorf("writing newline: %w", err)
			}
			if verdict.Error != "" {
				_, _ = fmt.Fprintf(logW, "pipelock: line %d: %s\n", lineNum, verdict.Error)
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

// stripResponse re-parses a JSON-RPC response, redacts matched injection
// patterns in each text content block, and returns the re-marshaled JSON.
func stripResponse(line []byte, sc *scanner.Scanner) ([]byte, error) {
	var rpc RPCResponse
	if err := json.Unmarshal(line, &rpc); err != nil {
		return nil, fmt.Errorf("parsing response for strip: %w", err)
	}

	if rpc.Result != nil {
		for i, block := range rpc.Result.Content {
			if block.Type != "text" {
				continue
			}
			result := sc.ScanResponse(block.Text)
			if !result.Clean && result.TransformedContent != "" {
				rpc.Result.Content[i].Text = result.TransformedContent
			}
		}
	}

	return json.Marshal(rpc)
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
func RunProxy(ctx context.Context, clientIn io.Reader, clientOut io.Writer, logW io.Writer, command []string, sc *scanner.Scanner) error {
	cmd := exec.CommandContext(ctx, command[0], command[1:]...) //nolint:gosec // command comes from user CLI args

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
	_, scanErr := ForwardScanned(serverOut, clientOut, logW, sc)

	// Wait for subprocess to exit.
	waitErr := cmd.Wait()

	// Wait for stdin goroutine to finish (server exit closes pipe, unblocking io.Copy).
	wg.Wait()

	if scanErr != nil {
		return fmt.Errorf("scanning: %w", scanErr)
	}

	return waitErr
}
