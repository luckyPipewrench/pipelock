// Package toolchain is a deterministic LLM-shape mock for benchmarking
// tool-use sequences. It returns Claude-shaped responses with tool_use blocks
// so the harness can drive an N-step tool-call chain through pipelock without
// hitting a real LLM provider.
package toolchain

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

// Server returns canned tool_use responses, advancing through a fixed chain.
type Server struct {
	httpServer *http.Server
	listener   net.Listener
	step       atomic.Uint32
	chainLen   int
}

// Start binds on a random port. chainLen controls how many tool_use rounds
// before the mock returns end_turn.
func Start(ctx context.Context, chainLen int) (*Server, string, error) {
	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		return nil, "", fmt.Errorf("listen: %w", err)
	}
	s := &Server{listener: ln, chainLen: chainLen}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/messages", s.handle)
	s.httpServer = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		_ = s.httpServer.Serve(ln)
	}()
	return s, ln.Addr().String(), nil
}

// Close shuts down the server.
func (s *Server) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return s.httpServer.Shutdown(ctx)
}

// Reset returns the chain position to zero. Call between benchmark iterations
// so each iteration walks the full chain.
func (s *Server) Reset() {
	s.step.Store(0)
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	// Drain request body (best effort; mock doesn't inspect contents).
	if r.Body != nil {
		_ = r.Body.Close()
	}
	step := int(s.step.Add(1))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if step > s.chainLen {
		_, _ = w.Write([]byte(endTurnResponse))
		return
	}
	resp := strings.ReplaceAll(toolUseResponseTpl, "{{TOOL_USE_ID}}",
		fmt.Sprintf("toolu_%d", step))
	resp = strings.ReplaceAll(resp, "{{TOOL_NAME}}", "echo")
	resp = strings.ReplaceAll(resp, "{{TOOL_INPUT}}",
		jsonEscape(fmt.Sprintf("step %d", step)))
	_, _ = w.Write([]byte(resp))
}

// jsonEscape escapes a string for embedding in a JSON template.
func jsonEscape(s string) string {
	b, _ := json.Marshal(s)
	return strings.Trim(string(b), `"`)
}

const toolUseResponseTpl = `{
  "id": "msg_test",
  "type": "message",
  "role": "assistant",
  "model": "mock",
  "content": [
    {"type": "text", "text": "ok"},
    {"type": "tool_use", "id": "{{TOOL_USE_ID}}", "name": "{{TOOL_NAME}}", "input": {"value": "{{TOOL_INPUT}}"}}
  ],
  "stop_reason": "tool_use"
}`

const endTurnResponse = `{
  "id": "msg_test",
  "type": "message",
  "role": "assistant",
  "model": "mock",
  "content": [{"type": "text", "text": "done"}],
  "stop_reason": "end_turn"
}`
