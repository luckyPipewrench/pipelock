// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package redact

import "errors"

// BlockReason classifies a fail-closed outcome. Every redaction failure
// mode is a separate constant so operators and telemetry can distinguish
// them without parsing error messages.
type BlockReason string

const (
	// ReasonBodyTooLarge — the request body exceeds the configured byte cap.
	ReasonBodyTooLarge BlockReason = "body_too_large"
	// ReasonBodyUnparseable — the body was expected to be JSON but did not
	// parse.
	ReasonBodyUnparseable BlockReason = "body_unparseable"
	// ReasonNonJSONBody — Content-Type signaled non-JSON and the host is not
	// on the operator's `allowlist_unparseable` list.
	ReasonNonJSONBody BlockReason = "non_json_body"
	// ReasonStreamingRequest — request used chunked or streaming transfer
	// encoding which cannot be buffered safely.
	ReasonStreamingRequest BlockReason = "streaming_request_unsupported"
	// ReasonMultipart — request was multipart/form-data which v1 does not
	// scan.
	ReasonMultipart BlockReason = "multipart_unsupported"
	// ReasonWebSocketFragmented — WebSocket message arrived with
	// continuation frames.
	ReasonWebSocketFragmented BlockReason = "ws_message_fragmented"
	// ReasonOverflow — match count exceeded the per-request cap.
	ReasonOverflow BlockReason = "redaction_overflow"
	// ReasonDepthExceeded — JSON structure exceeded the configured nesting
	// depth cap (defensive against resource-exhaustion JSON).
	ReasonDepthExceeded BlockReason = "json_depth_exceeded"
	// ReasonKeyCollision — rewriting two different object keys produced
	// the same placeholder. Silently letting one key overwrite another
	// changes the forwarded object's structure, so we fail closed.
	ReasonKeyCollision BlockReason = "key_collision"
)

// BlockError is returned by Rewrite when redaction cannot safely proceed.
// Callers should treat it as a signal to refuse the request upstream.
type BlockError struct {
	Reason BlockReason
	// MatchesBeforeBlock reports how many unique redactions were applied
	// before the failure (0 when the failure prevents any scanning).
	MatchesBeforeBlock int
	// Detail is an optional human-readable hint. Not stable API — telemetry
	// and receipts should key off Reason.
	Detail string
}

// Error implements the error interface. The format is compact and safe for
// logs: it never includes originals, only the block reason and count.
func (e *BlockError) Error() string {
	if e == nil {
		return ""
	}
	if e.Detail != "" {
		return "redact: blocked (" + string(e.Reason) + "): " + e.Detail
	}
	return "redact: blocked (" + string(e.Reason) + ")"
}

// Is makes BlockError comparable with errors.Is for a specific reason.
// Callers can check `errors.Is(err, &redact.BlockError{Reason: ...})`.
func (e *BlockError) Is(target error) bool {
	if e == nil {
		return false
	}
	var other *BlockError
	if !errors.As(target, &other) {
		return false
	}
	// Match on reason; empty reason in target matches any reason.
	return other.Reason == "" || e.Reason == other.Reason
}

// newBlock is a shorthand for constructing a BlockError.
func newBlock(reason BlockReason, matches int, detail string) *BlockError {
	return &BlockError{Reason: reason, MatchesBeforeBlock: matches, Detail: detail}
}
