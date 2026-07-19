// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
)

// sseMessageWriter writes each scanned JSON-RPC message as one SSE event.
// It is used by the HTTP listener when the upstream POST response is
// text/event-stream so clean messages reach the downstream client as soon as
// ForwardScanned accepts them, instead of buffering the whole stream to EOF.
type sseMessageWriter struct {
	mu      sync.Mutex
	w       io.Writer
	flusher http.Flusher
	wrote   bool
}

var _ transport.MessageWriter = (*sseMessageWriter)(nil)

func (sw *sseMessageWriter) WriteMessage(msg []byte) error {
	sw.mu.Lock()
	defer sw.mu.Unlock()
	if len(msg) > transport.MaxLineSize {
		return fmt.Errorf("message too large: %d bytes", len(msg))
	}
	lines := bytes.Split(msg, []byte("\n"))
	for _, line := range lines {
		if _, err := sw.w.Write([]byte("data: ")); err != nil {
			return fmt.Errorf("writing sse data prefix: %w", err)
		}
		if _, err := sw.w.Write(line); err != nil {
			return fmt.Errorf("writing sse data: %w", err)
		}
		if _, err := sw.w.Write([]byte("\n")); err != nil {
			return fmt.Errorf("writing sse line terminator: %w", err)
		}
	}
	if _, err := sw.w.Write([]byte("\n")); err != nil {
		return fmt.Errorf("writing sse event terminator: %w", err)
	}
	sw.wrote = true
	if sw.flusher != nil {
		sw.flusher.Flush()
	}
	return nil
}

func (sw *sseMessageWriter) Wrote() bool {
	sw.mu.Lock()
	defer sw.mu.Unlock()
	return sw.wrote
}

// startGETStream maintains a background GET SSE connection for server-initiated
// messages. Called after the initialize handshake establishes a session ID.
// Reconnects with exponential backoff (1s base, 30s cap) on stream end or
// transient errors. Exits permanently only on transport.ErrStreamNotSupported (HTTP 405)
// or context cancellation.
// opts carries Scanner, Approver, ToolCfg, KillSwitch, Rec, AdaptiveCfg, and
// Metrics through to ForwardScanned for adaptive enforcement.
func startGETStream(
	ctx context.Context,
	httpClient *transport.HTTPClient,
	safeClientOut *syncWriter,
	safeLogW *syncWriter,
	opts MCPProxyOpts,
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

			// Kill switch: pause reconnecting while active. Without this,
			// the retry loop keeps establishing outbound connections even
			// though ForwardScanned blocks every message. Wait here instead
			// of returning so the goroutine resumes when the switch clears.
			if opts.KillSwitch != nil && opts.KillSwitch.IsActive() {
				_, _ = fmt.Fprintf(safeLogW, "pipelock: GET stream paused: kill switch active\n")
				for opts.KillSwitch.IsActive() {
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
				// Permanent error - server does not support GET streams.
				if errors.Is(err, transport.ErrStreamNotSupported) {
					return
				}
				// Transient error - backoff and retry.
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
			_, scanErr := ForwardScanned(reader, safeClientOut, safeLogW, nil, opts)
			if scanErr != nil {
				_, _ = fmt.Fprintf(safeLogW, "pipelock: GET stream scan error: %v\n", scanErr)
			}

			// Stream ended - reconnect with backoff unless cancelled.
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
