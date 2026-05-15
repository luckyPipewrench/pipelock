// Package sse is a deterministic Server-Sent Events mock used by the egress
// benchmark. It streams a fixed number of chunks at a fixed cadence so that
// TTFB (time to first byte) and full-stream duration can be measured.
package sse

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"
)

const (
	// numChunks is how many "tokens" the mock streams.
	numChunks = 100
	// chunkInterval is the simulated inter-token delay.
	chunkInterval = 100 * time.Microsecond
	// chunkPayload is each chunk's data line (~100 bytes -> 10 KiB total).
	chunkPayload = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGH"
)

// Server streams SSE responses.
type Server struct {
	httpServer *http.Server
	listener   net.Listener
}

// Start binds 127.0.0.1 on a random port and streams SSE until ctx is canceled.
func Start(ctx context.Context) (*Server, string, error) {
	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		return nil, "", fmt.Errorf("listen: %w", err)
	}
	s := &Server{listener: ln}
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

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	flusher, ok := w.(http.Flusher)
	if !ok {
		return
	}
	// First chunk immediately so TTFB is measurable.
	_, _ = fmt.Fprintf(w, "data: %s\n\n", chunkPayload)
	flusher.Flush()
	t := time.NewTicker(chunkInterval)
	defer t.Stop()
	for i := 1; i < numChunks; i++ {
		select {
		case <-r.Context().Done():
			return
		case <-t.C:
			_, _ = fmt.Fprintf(w, "data: %s\n\n", chunkPayload)
			flusher.Flush()
		}
	}
	_, _ = fmt.Fprint(w, "data: [DONE]\n\n")
	flusher.Flush()
}
