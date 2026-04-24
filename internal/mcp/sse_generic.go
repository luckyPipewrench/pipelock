// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// ErrSSEStreamFinding is returned by ScanGenericSSEStream when scanning
// detects a DLP or injection finding inside a generic SSE event payload.
// Callers distinguish findings from IO errors via errors.Is so warn-mode
// behavior can mirror the A2A path (log only) while block-mode terminates
// with a receipt.
var ErrSSEStreamFinding = errors.New("sse stream finding")

// ErrSSEEventTooLarge is wrapped inside ErrSSEStreamFinding when a single
// event's joined data: payload exceeds cfg.MaxEventBytes. Treated as a
// finding so oversize events fail closed without distinguishing from
// content-based detections.
var ErrSSEEventTooLarge = errors.New("sse event exceeds max_event_bytes")

// DefaultGenericSSEMaxEventBytes caps per-event scanning to 64 KB. LLM
// streaming events are typically a few hundred bytes; 64 KB carries
// about 16k tokens, far above any realistic single-event payload.
const DefaultGenericSSEMaxEventBytes = 64 * 1024

// passthroughChunkSize is the buffer size used when scanning is disabled
// and the function falls through to flushing pass-through. Small enough
// to keep latency low, large enough to avoid syscall pressure.
const passthroughChunkSize = 4096

// GenericSSEScanOptions carries transport-level policy context for generic
// SSE scanning. It lets proxy transports preserve the existing response
// scanning contract for exempt domains and suppress rules without coupling
// this package to proxy logging or receipt emission.
type GenericSSEScanOptions struct {
	// Target is the URL/path used to evaluate suppress rules.
	Target string
	// Suppress contains global suppress rules from pipelock.yaml.
	Suppress []config.SuppressEntry
	// ResponseScanExempt means prompt-injection findings should be treated
	// as visibility-only for this target. DLP findings still apply.
	ResponseScanExempt bool
	// OnFinding is called for warn-mode findings that are forwarded rather
	// than returned. It must be safe to call inline from the stream loop.
	OnFinding func(error)
}

// ScanGenericSSEStream handles non-A2A text/event-stream responses with
// per-event DLP and injection scanning. Used for OpenAI, Anthropic,
// Kilo Gateway, and any other LLM SSE traffic the proxy intercepts.
//
// Contract:
//   - Caller copies response headers to w BEFORE calling this function.
//   - Caller has already verified the response is NOT compressed.
//   - Clean events are flushed immediately when flusher is non-nil.
//   - Block-mode detection returns an error wrapping ErrSSEStreamFinding;
//     caller closes the connection.
//   - Warn-mode detection calls opts.OnFinding and keeps forwarding.
//   - IO or scanner errors return the underlying error wrapped with
//     "sse stream read:"; caller closes the connection.
//   - End of stream returns nil.
//
// When cfg is nil or cfg.Enabled is false the function falls through to
// flushing pass-through so the disabled mode preserves token-by-token UX
// instead of silently buffering a streaming protocol it recognizes.
//
// The scanner intentionally does NOT field-walk JSON (that's the A2A
// scanner's job). Generic SSE data: payloads can be non-JSON: OpenAI
// emits "[DONE]" as a literal sentinel and some providers send raw text
// deltas. Treating the joined data: payload as text is the lowest-common
// denominator that catches DLP and injection patterns across providers.
func ScanGenericSSEStream(
	ctx context.Context,
	body io.Reader,
	w io.Writer,
	flusher http.Flusher,
	sc *scanner.Scanner,
	cfg *config.GenericSSEScanning,
) error {
	return ScanGenericSSEStreamWithOptions(ctx, body, w, flusher, sc, cfg, GenericSSEScanOptions{})
}

// ScanGenericSSEStreamWithOptions is ScanGenericSSEStream with transport-level
// policy context for suppress rules, response-scan exemptions, and warn-mode
// finding callbacks.
func ScanGenericSSEStreamWithOptions(
	ctx context.Context,
	body io.Reader,
	w io.Writer,
	flusher http.Flusher,
	sc *scanner.Scanner,
	cfg *config.GenericSSEScanning,
	opts GenericSSEScanOptions,
) error {
	if cfg == nil || !cfg.Enabled {
		return passthroughGenericSSE(ctx, body, w, flusher)
	}

	maxEventBytes := cfg.MaxEventBytes
	if maxEventBytes <= 0 {
		maxEventBytes = DefaultGenericSSEMaxEventBytes
	}

	reader := transport.NewSSEReader(body)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		event, err := reader.ReadMessage()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("sse stream read: %w", err)
		}

		if len(event) > maxEventBytes {
			findingErr := fmt.Errorf("%w: %w (size=%d, limit=%d)",
				ErrSSEStreamFinding, ErrSSEEventTooLarge, len(event), maxEventBytes)
			if cfg.Action == config.ActionWarn {
				// Warn-mode parity with injection + DLP: surface the finding
				// to the caller via OnFinding, drop this oversize event so
				// unscanned bytes never reach the client, and keep streaming
				// subsequent events. Block mode terminates the stream.
				if opts.OnFinding != nil {
					opts.OnFinding(findingErr)
				}
				continue
			}
			return findingErr
		}

		if len(event) > 0 {
			text := string(event)

			injectResult := sc.ScanResponse(ctx, text)
			if !injectResult.Clean && len(opts.Suppress) > 0 {
				var kept []scanner.ResponseMatch
				for _, match := range injectResult.Matches {
					if !config.IsSuppressed(match.PatternName, opts.Target, opts.Suppress) {
						kept = append(kept, match)
					}
				}
				injectResult.Matches = kept
				injectResult.Clean = len(kept) == 0
			}
			if !injectResult.Clean {
				findingErr := fmt.Errorf("%w: injection: %s",
					ErrSSEStreamFinding, sseInjectionNames(injectResult.Matches))
				if opts.ResponseScanExempt || cfg.Action == config.ActionWarn {
					if opts.OnFinding != nil {
						opts.OnFinding(findingErr)
					}
				} else {
					return findingErr
				}
			}

			dlpResult := sc.ScanTextForDLP(ctx, text)
			if !dlpResult.Clean && len(opts.Suppress) > 0 {
				var kept []scanner.TextDLPMatch
				for _, match := range dlpResult.Matches {
					if !config.IsSuppressed(match.PatternName, opts.Target, opts.Suppress) {
						kept = append(kept, match)
					}
				}
				dlpResult.Matches = kept
				dlpResult.Clean = len(kept) == 0
			}
			if !dlpResult.Clean {
				findingErr := fmt.Errorf("%w: dlp: %s",
					ErrSSEStreamFinding, sseDLPMatchNames(dlpResult.Matches))
				if cfg.Action == config.ActionWarn {
					if opts.OnFinding != nil {
						opts.OnFinding(findingErr)
					}
				} else {
					return findingErr
				}
			}
		}

		if werr := writeSSEEvent(w, event, reader.LastEventID(), reader.LastEventType(), reader.LastRetry()); werr != nil {
			// Downstream consumer went away (e.g. the io.Pipe in the
			// reverse-proxy hijack was closed by the client). Returning
			// here breaks the loop and lets the goroutine close the
			// upstream body via its own deferred cleanup, instead of
			// reading more events into a sink that no longer exists.
			return fmt.Errorf("sse stream write: %w", werr)
		}
		if flusher != nil {
			flusher.Flush()
		}
	}
}

// passthroughGenericSSE forwards body to w in small chunks, flushing
// after every successful read so the client sees bytes as soon as they
// arrive even when scanning is opt-out.
func passthroughGenericSSE(ctx context.Context, body io.Reader, w io.Writer, flusher http.Flusher) error {
	buf := make([]byte, passthroughChunkSize)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		n, err := body.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return werr
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

func sseInjectionNames(matches []scanner.ResponseMatch) string {
	if len(matches) == 0 {
		return patternUnknown
	}
	names := make([]string, 0, len(matches))
	for _, m := range matches {
		names = append(names, m.PatternName)
	}
	return strings.Join(names, ", ")
}

func sseDLPMatchNames(matches []scanner.TextDLPMatch) string {
	if len(matches) == 0 {
		return patternUnknown
	}
	names := make([]string, 0, len(matches))
	for _, m := range matches {
		names = append(names, m.PatternName)
	}
	return strings.Join(names, ", ")
}
