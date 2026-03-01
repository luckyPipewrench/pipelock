package wsutil

import (
	"bytes"

	"github.com/gobwas/ws"
)

const (
	// ReasonMessageTooLarge is the close reason for oversized messages.
	ReasonMessageTooLarge = "message too large" //nolint:gosec // not a credential

	// MaxControlPayload is the RFC 6455 §5.5 limit for control frame payloads.
	MaxControlPayload = 125
)

// FragmentState tracks WebSocket message fragment reassembly.
type FragmentState struct {
	Opcode   ws.OpCode
	buf      bytes.Buffer
	MaxBytes int
	Active   bool
}

// Process handles fragment reassembly. Returns (complete, message, closeCode, closeReason).
// When closeCode is non-zero, the connection should be terminated.
func (f *FragmentState) Process(hdr ws.Header, payload []byte) (complete bool, msg []byte, closeCode ws.StatusCode, closeReason string) {
	switch {
	case hdr.OpCode == ws.OpContinuation && !f.Active:
		// Unexpected continuation without a started fragment.
		return false, nil, ws.StatusProtocolError, "unexpected continuation frame"

	case hdr.OpCode != ws.OpContinuation && !hdr.OpCode.IsControl() && f.Active:
		// New data frame while fragmentation is in progress.
		return false, nil, ws.StatusProtocolError, "new data frame during fragmentation"

	case !hdr.Fin && hdr.OpCode != ws.OpContinuation && !hdr.OpCode.IsControl():
		// Start of a new fragmented message.
		f.Active = true
		f.Opcode = hdr.OpCode
		f.buf.Reset()
		if int(hdr.Length) > f.MaxBytes {
			return false, nil, ws.StatusMessageTooBig, ReasonMessageTooLarge
		}
		_, _ = f.buf.Write(payload)
		return false, nil, 0, ""

	case hdr.OpCode == ws.OpContinuation && f.Active:
		// Continuation of a fragmented message.
		if f.buf.Len()+len(payload) > f.MaxBytes {
			return false, nil, ws.StatusMessageTooBig, ReasonMessageTooLarge
		}
		_, _ = f.buf.Write(payload)
		if hdr.Fin {
			msg := make([]byte, f.buf.Len())
			copy(msg, f.buf.Bytes())
			return true, msg, 0, ""
		}
		return false, nil, 0, ""

	default:
		// Single-frame message (Fin=true, non-continuation, non-control).
		if len(payload) > f.MaxBytes {
			return false, nil, ws.StatusMessageTooBig, ReasonMessageTooLarge
		}
		f.Opcode = hdr.OpCode
		return true, payload, 0, ""
	}
}

// Reset clears fragment state after a complete message.
func (f *FragmentState) Reset() {
	f.Active = false
	f.Opcode = 0
	f.buf.Reset()
}
