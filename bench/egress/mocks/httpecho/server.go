// Package httpecho is a deterministic HTTP mock server used by the egress
// benchmark harness. It returns a fixed 1 KiB body so that latency
// measurements reflect pipelock's overhead rather than backend variance.
package httpecho

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"
)

// bodySize is the canned response size in bytes.
const bodySize = 1024

// Server is an in-process HTTP responder.
type Server struct {
	httpServer *http.Server
	listener   net.Listener
	body       []byte
}

// Start binds 127.0.0.1 on a random port and serves until ctx is canceled or
// Close is called. The returned address is "127.0.0.1:PORT".
func Start(ctx context.Context) (*Server, string, error) {
	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		return nil, "", fmt.Errorf("listen: %w", err)
	}
	body := make([]byte, bodySize)
	for i := range body {
		body[i] = 'a' + byte(i%26)
	}
	s := &Server{listener: ln, body: body}
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handle)
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

func (s *Server) handle(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", bodySize))
	_, _ = w.Write(s.body)
}
