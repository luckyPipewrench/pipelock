// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// ErrSSEResponseCompressed signals that an SSE response carries a
// non-identity Content-Encoding. The streaming scanners cannot operate
// on compressed bytes, so the caller MUST close the upstream and emit a
// fail-closed block receipt rather than forward the response.
var ErrSSEResponseCompressed = errors.New("compressed sse response cannot be scanned")

// IsSSEContentType reports whether the response Content-Type header
// indicates a Server-Sent Events stream. Match is prefix-based so the
// optional charset parameter ("text/event-stream; charset=utf-8") still
// counts.
func IsSSEContentType(contentType string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(contentType)), "text/event-stream")
}

// IsSSECompressed mirrors hasNonIdentityEncoding for the SSE path so call
// sites in forward.go, intercept.go, and reverse.go all reach the same
// conclusion about what counts as compressed.
func IsSSECompressed(h http.Header) bool {
	return hasNonIdentityEncoding(h.Get("Content-Encoding"))
}

// SSEDispatchOptions selects which streaming scanner runs for an SSE
// response. Exactly one of A2A and Generic is consulted at a time:
// IsA2A=true picks the A2A field-aware scanner, otherwise the generic
// LLM SSE scanner runs (still flushing pass-through when GenericSSE
// is nil or disabled).
type SSEDispatchOptions struct {
	IsA2A      bool
	A2A        *config.A2AScanning
	GenericSSE *config.GenericSSEScanning
	Generic    mcp.GenericSSEScanOptions
}

// DispatchSSEScan picks the appropriate streaming scanner and runs it.
// Returns nil on clean EOF, a wrapped ErrA2AStreamFinding or
// ErrSSEStreamFinding on detection, or a wrapped IO error otherwise.
//
// Caller MUST:
//   - confirm the response is NOT compressed (use IsSSECompressed first);
//   - copy response headers to w BEFORE calling so flush ordering stays correct;
//   - inspect the returned error and emit transport-appropriate receipts.
//
// The function does not own the response body and does not close it.
func DispatchSSEScan(
	ctx context.Context,
	body io.Reader,
	w io.Writer,
	flusher http.Flusher,
	sc *scanner.Scanner,
	opts SSEDispatchOptions,
) error {
	if opts.IsA2A {
		return mcp.ScanA2AStream(ctx, body, w, flusher, sc, opts.A2A)
	}
	return mcp.ScanGenericSSEStreamWithOptions(ctx, body, w, flusher, sc, opts.GenericSSE, opts.Generic)
}

// IsSSEStreamFinding reports whether err originated from a streaming
// scanner detection (A2A or generic). Use this on the caller side to
// distinguish content findings from IO/scanner errors so warn-mode and
// block-mode behave correctly.
func IsSSEStreamFinding(err error) bool {
	return errors.Is(err, mcp.ErrA2AStreamFinding) || errors.Is(err, mcp.ErrSSEStreamFinding)
}

// LayerA2AStream is the receipt layer label used for A2A streaming
// findings on the forward proxy. Dashboards and alerts pivot on this
// label; do not change without coordinating downstream consumers.
const LayerA2AStream = "a2a_stream"

// LayerSSEStream is the receipt layer label used for generic (non-A2A)
// SSE streaming findings on every transport.
const LayerSSEStream = "sse_stream"

// LayerReverseResponseBlocked is the receipt layer label used for
// reverse-proxy fail-closed response blocks that are not finding-driven:
// compressed bodies the regex pipeline cannot inspect, oversize bodies
// that exceed the scanning limit, and read errors. The Pattern field
// carries the specific reason. Forward and intercept currently emit the
// equivalent shape under "tls_response_blocked" / inline pattern strings;
// "reverse" is split out so dashboards can pivot per transport.
const LayerReverseResponseBlocked = "reverse_response_blocked"

// SSEStreamLayer returns the layer label to use when emitting receipts
// for a given dispatch outcome. A2A findings keep the existing
// LayerA2AStream label so dashboards and alerts stay continuous; generic
// findings use LayerSSEStream so they can be tracked independently.
func SSEStreamLayer(opts SSEDispatchOptions) string {
	if opts.IsA2A {
		return LayerA2AStream
	}
	return LayerSSEStream
}

// HijackResponseForSSE rewrites resp.Body to a streaming scanner that
// runs in a background goroutine. Used by reverse.go where there is no
// directly accessible http.ResponseWriter; httputil.ReverseProxy detects
// text/event-stream and auto-flushes per write to the client. The pipe
// here gives the scanner somewhere to write per-event without buffering.
//
// The onComplete callback fires after the scanner finishes (clean EOF,
// finding, or IO error) and is intended for receipt emission. It runs in
// the streaming goroutine; implementations must be goroutine-safe and
// must not block the caller's request lifecycle.
//
// Returns the new resp.Body so callers can assign it back. The original
// upstream body is closed by the goroutine when scanning ends.
//
// Pre-condition: the response Content-Type is text/event-stream and the
// response is NOT compressed (callers should check both first).
func HijackResponseForSSE(
	ctx context.Context,
	resp *http.Response,
	sc *scanner.Scanner,
	opts SSEDispatchOptions,
	onComplete func(error),
) io.ReadCloser {
	pr, pw := io.Pipe()
	upstream := resp.Body

	// Ctx-cancel watcher: DispatchSSEScan only checks ctx.Done() between
	// SSE events. If the upstream is slow or hung, the scanner sits inside
	// transport.SSEReader.ReadMessage() (which calls body.Read) until
	// upstream sends bytes or closes. Without this watcher, ctx
	// cancellation does not propagate through the blocked read and the
	// goroutine + connection leak. Closing the upstream body forces the
	// read to error out promptly so the scanner returns and onComplete
	// fires. The done channel keeps the watcher from outliving the
	// streaming goroutine when the stream finishes naturally.
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = upstream.Close()
		case <-done:
		}
	}()

	go func() {
		defer close(done)
		// nil flusher: httputil.ReverseProxy detects text/event-stream and
		// flushes per write to the client, so the per-event flush behavior
		// happens downstream of this pipe write.
		scanErr := DispatchSSEScan(ctx, upstream, pw, nil, sc, opts)
		if scanErr != nil {
			_ = pw.CloseWithError(scanErr)
		} else {
			_ = pw.Close()
		}
		_ = upstream.Close()
		if onComplete != nil {
			onComplete(scanErr)
		}
	}()

	return pr
}
