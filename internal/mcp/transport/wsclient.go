package transport

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"unicode/utf8"

	"github.com/gobwas/ws"
	gobwasutil "github.com/gobwas/ws/wsutil"

	plwsutil "github.com/luckyPipewrench/pipelock/internal/wsutil"
)

// WSClient implements MessageReader and MessageWriter over a WebSocket connection
// to an upstream MCP server. MCP is JSON-RPC over text frames only; binary frames
// are rejected (fail-closed). Fragment reassembly uses the shared wsutil package.
type WSClient struct {
	conn net.Conn
	frag plwsutil.FragmentState

	// writeMu serializes writes. Reads are expected from a single goroutine.
	writeMu   sync.Mutex
	closeOnce sync.Once
}

// NewWSClient establishes a WebSocket connection to the given URL and returns
// a WSClient. The connection is established using gobwas/ws.Dial with the
// provided context for timeout/cancellation.
func NewWSClient(ctx context.Context, rawURL string) (*WSClient, error) {
	conn, _, _, err := ws.Dial(ctx, rawURL)
	if err != nil {
		return nil, fmt.Errorf("ws dial %s: %w", rawURL, err)
	}
	return &WSClient{
		conn: conn,
		frag: plwsutil.FragmentState{MaxBytes: MaxLineSize},
	}, nil
}

// NewWSClientFromConn wraps an existing net.Conn as a WSClient.
// Used for listener mode where the connection is already established.
func NewWSClientFromConn(conn net.Conn) *WSClient {
	return &WSClient{
		conn: conn,
		frag: plwsutil.FragmentState{MaxBytes: MaxLineSize},
	}
}

// ReadMessage reads the next complete text message from the WebSocket connection.
// Handles fragment reassembly, rejects binary frames, and validates UTF-8.
// Returns io.EOF on clean close.
func (c *WSClient) ReadMessage() ([]byte, error) {
	for {
		hdr, err := ws.ReadHeader(c.conn)
		if err != nil {
			if plwsutil.IsExpectedCloseErr(err) {
				return nil, io.EOF
			}
			return nil, fmt.Errorf("reading ws header: %w", err)
		}

		// Enforce size limit before allocation to prevent memory DoS.
		// A malicious upstream could send a header claiming a huge payload.
		if hdr.Length > int64(MaxLineSize) {
			plwsutil.WriteClientCloseFrame(c.conn, ws.StatusMessageTooBig, "frame too large")
			return nil, fmt.Errorf("frame too large: %d bytes (max %d)", hdr.Length, MaxLineSize)
		}

		payload := make([]byte, hdr.Length)
		if hdr.Length > 0 {
			if _, err := io.ReadFull(c.conn, payload); err != nil {
				return nil, fmt.Errorf("reading ws payload: %w", err)
			}
		}

		// Unmask if needed (server-to-client frames are unmasked per RFC 6455,
		// but handle masked frames defensively).
		if hdr.Masked {
			ws.Cipher(payload, hdr.Mask, 0)
		}

		// Control frames: handle inline (they can appear between fragments).
		if hdr.OpCode.IsControl() {
			if hdr.Length > plwsutil.MaxControlPayload {
				plwsutil.WriteClientCloseFrame(c.conn, ws.StatusProtocolError, "control frame too large")
				return nil, fmt.Errorf("control frame too large: %d bytes", hdr.Length)
			}
			switch hdr.OpCode {
			case ws.OpClose:
				// Echo close frame back, then signal EOF.
				plwsutil.WriteClientCloseFrame(c.conn, ws.StatusNormalClosure, "")
				return nil, io.EOF
			case ws.OpPing:
				c.writeMu.Lock()
				_ = gobwasutil.WriteClientMessage(c.conn, ws.OpPong, payload)
				c.writeMu.Unlock()
			case ws.OpPong:
				// Ignore unsolicited pongs.
			}
			continue
		}

		// Reject binary frames. MCP is JSON-RPC text only.
		isBinary := hdr.OpCode == ws.OpBinary ||
			(hdr.OpCode == ws.OpContinuation && c.frag.Active && c.frag.Opcode == ws.OpBinary)
		if isBinary {
			plwsutil.WriteClientCloseFrame(c.conn, ws.StatusPolicyViolation, "binary frames not allowed")
			return nil, fmt.Errorf("binary frame rejected")
		}

		complete, msg, closeCode, closeReason := c.frag.Process(hdr, payload)
		if closeCode != 0 {
			plwsutil.WriteClientCloseFrame(c.conn, closeCode, closeReason)
			return nil, fmt.Errorf("fragment error: %s", closeReason)
		}
		if !complete {
			continue
		}

		// Validate UTF-8 (RFC 6455 requirement for text frames).
		if !utf8.Valid(msg) {
			plwsutil.WriteClientCloseFrame(c.conn, ws.StatusInvalidFramePayloadData, "invalid UTF-8")
			return nil, fmt.Errorf("invalid UTF-8 in text frame")
		}

		c.frag.Reset()

		// Return a copy to match the MessageReader contract.
		result := make([]byte, len(msg))
		copy(result, msg)
		return result, nil
	}
}

// WriteMessage sends a complete JSON-RPC message as a single text frame.
func (c *WSClient) WriteMessage(msg []byte) error {
	if len(msg) > MaxLineSize {
		return fmt.Errorf("message too large: %d bytes", len(msg))
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	// Write as client (masked) per RFC 6455.
	return gobwasutil.WriteClientMessage(c.conn, ws.OpText, msg)
}

// Close sends a close frame and closes the underlying connection.
// Safe to call from multiple goroutines; the close frame is sent at most once.
func (c *WSClient) Close() error {
	c.closeOnce.Do(func() {
		c.writeMu.Lock()
		plwsutil.WriteClientCloseFrame(c.conn, ws.StatusNormalClosure, "")
		c.writeMu.Unlock()
	})
	return c.conn.Close()
}
