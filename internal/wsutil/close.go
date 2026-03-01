package wsutil

import (
	"bytes"
	"crypto/rand"
	"net"
	"time"
	"unicode/utf8"

	"github.com/gobwas/ws"
)

// WriteCloseFrame sends a WebSocket close frame with the given status code and reason.
func WriteCloseFrame(conn net.Conn, code ws.StatusCode, reason string) {
	// Close frame payload: 2-byte status code + optional UTF-8 reason.
	// Truncate reason to fit in control frame (125 bytes max payload).
	reasonBytes := []byte(reason)
	if len(reasonBytes) > 123 { // 125 - 2 bytes for status code
		reasonBytes = reasonBytes[:123]
		// Back up to a valid UTF-8 boundary so we don't split a multi-byte
		// codepoint (RFC 6455 requires close reasons to be valid UTF-8).
		for len(reasonBytes) > 0 && !utf8.Valid(reasonBytes) {
			reasonBytes = reasonBytes[:len(reasonBytes)-1]
		}
	}
	payload := make([]byte, 2+len(reasonBytes))
	payload[0] = byte(code >> 8) //nolint:gosec // StatusCode is uint16, high byte extraction is safe
	payload[1] = byte(code & 0xFF)
	copy(payload[2:], reasonBytes)

	// Build the complete frame (header + payload) in a single buffer so the
	// conn.Write is one syscall. Both relay goroutines may call WriteCloseFrame
	// on the same conn concurrently; a single write prevents interleaved bytes.
	var buf bytes.Buffer
	_ = ws.WriteHeader(&buf, ws.Header{
		Fin:    true,
		OpCode: ws.OpClose,
		Length: int64(len(payload)),
	})
	buf.Write(payload)

	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, _ = conn.Write(buf.Bytes())
}

// WriteClientCloseFrame sends a masked close frame (client-to-server per RFC 6455).
func WriteClientCloseFrame(conn net.Conn, code ws.StatusCode, reason string) {
	reasonBytes := []byte(reason)
	if len(reasonBytes) > 123 {
		reasonBytes = reasonBytes[:123]
		for len(reasonBytes) > 0 && !utf8.Valid(reasonBytes) {
			reasonBytes = reasonBytes[:len(reasonBytes)-1]
		}
	}
	payload := make([]byte, 2+len(reasonBytes))
	payload[0] = byte(code >> 8) //nolint:gosec // StatusCode is uint16, high byte extraction is safe
	payload[1] = byte(code & 0xFF)
	copy(payload[2:], reasonBytes)

	var mask [4]byte
	_, _ = rand.Read(mask[:])
	ws.Cipher(payload, mask, 0)

	var buf bytes.Buffer
	_ = ws.WriteHeader(&buf, ws.Header{
		Fin:    true,
		OpCode: ws.OpClose,
		Masked: true,
		Mask:   mask,
		Length: int64(len(payload)),
	})
	buf.Write(payload)

	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, _ = conn.Write(buf.Bytes())
}
