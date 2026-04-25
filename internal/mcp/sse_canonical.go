// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
)

// canonicalSSEEventText builds the full scannable representation of an SSE
// event by combining metadata fields (event:, id:, retry:) with the joined
// data: payload. Both the generic SSE scanner (ScanGenericSSEStream) and
// the A2A SSE scanner (ScanA2AStream) previously scanned only the data:
// payload and then wrote the metadata fields through to the client via
// writeSSEEvent without inspection. That let DLP content and prompt
// injection ride through in the metadata fields, which Rook confirmed as a
// tag-blocker finding:
//
//	event: sk-ant-FAKEKEY...
//	id: ignore all previous instructions
//	data: ok
//
// Feeding a canonical text form to the scanner closes the bypass without
// changing wire-level behavior: the clean event still flushes downstream
// unchanged; only the FINDING step inspects the full field set.
//
// The returned string is purely for scanner input. Field ordering matches
// what writeSSEEvent emits on the wire so operator-visible audit snippets
// correspond to the bytes the client would have seen.
func canonicalSSEEventText(eventData []byte, reader *transport.SSEReader) string {
	var b strings.Builder
	// Rough upper bound to avoid re-alloc: metadata fields + data payload
	// plus newline/field-label overhead.
	b.Grow(len(eventData) + 64)

	if reader != nil {
		if et := reader.LastEventType(); et != "" {
			b.WriteString("event: ")
			b.WriteString(et)
			b.WriteByte('\n')
		}
		if id := reader.LastEventID(); id != "" {
			b.WriteString("id: ")
			b.WriteString(id)
			b.WriteByte('\n')
		}
		if retry := reader.LastRetry(); retry != "" {
			b.WriteString("retry: ")
			b.WriteString(retry)
			b.WriteByte('\n')
		}
	}
	if len(eventData) > 0 {
		b.WriteString("data: ")
		b.Write(eventData)
	}
	return b.String()
}
