// Command mcpstdio is a deterministic MCP stdio server used by the egress
// benchmark. It implements just enough of the MCP protocol (initialize,
// tools/list, tools/call) to be wrapped by `pipelock mcp proxy --` and also
// to be driven directly for baseline measurement.
//
// All responses are canned and constant-size so the harness measures pipelock
// overhead and not backend variance.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
)

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func main() {
	if err := run(os.Stdin, os.Stdout); err != nil && !errors.Is(err, io.EOF) {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(in io.Reader, out io.Writer) error {
	scanner := bufio.NewScanner(in)
	// MCP messages can exceed bufio.Scanner's default 64 KiB line buffer when
	// tool definitions are large; raise to 4 MiB.
	scanner.Buffer(make([]byte, 0, 1<<20), 4<<20)
	enc := json.NewEncoder(out)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var req rpcRequest
		if err := json.Unmarshal(line, &req); err != nil {
			// Malformed input is benign for the bench — skip and keep reading.
			continue
		}
		resp := handle(&req)
		if resp == nil {
			// Notification, no reply expected.
			continue
		}
		if err := enc.Encode(resp); err != nil {
			return err
		}
	}
	return scanner.Err()
}

func handle(req *rpcRequest) *rpcResponse {
	if len(req.ID) == 0 {
		// JSON-RPC notification.
		return nil
	}
	switch req.Method {
	case "initialize":
		return &rpcResponse{
			JSONRPC: "2.0", ID: req.ID,
			Result: map[string]any{
				"protocolVersion": "2024-11-05",
				"capabilities":    map[string]any{"tools": map[string]any{}},
				"serverInfo":      map[string]any{"name": "bench-mcpstdio", "version": "0.1.0"},
			},
		}
	case "tools/list":
		return &rpcResponse{
			JSONRPC: "2.0", ID: req.ID,
			Result: map[string]any{
				"tools": []map[string]any{{
					"name":        "echo",
					"description": "Returns the input string. Used by the egress benchmark harness.",
					"inputSchema": map[string]any{
						"type": "object",
						"properties": map[string]any{
							"value": map[string]any{"type": "string"},
						},
						"required": []string{"value"},
					},
				}},
			},
		}
	case "tools/call":
		return &rpcResponse{
			JSONRPC: "2.0", ID: req.ID,
			Result: map[string]any{
				"content": []map[string]any{{"type": "text", "text": "ok"}},
			},
		}
	default:
		return &rpcResponse{
			JSONRPC: "2.0", ID: req.ID,
			Error: &rpcError{Code: -32601, Message: "method not found"},
		}
	}
}
