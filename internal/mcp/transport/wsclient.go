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
	conn     net.Conn
	r        io.Reader // reader for frames (may differ from conn when Dial returns a buffered reader)
	isServer bool      // true = unmasked writes (server side), false = masked writes (client side)
	frag     plwsutil.FragmentState

	// writeMu serializes writes. Reads are expected from a single goroutine.
	writeMu   sync.Mutex
	closeOnce sync.Once
}

// NewWSClient establishes a WebSocket connection to the given URL and returns
// a WSClient. The connection is established using gobwas/ws.Dial with the
// provided context for timeout/cancellation.
func NewWSClient(ctx context.Context, rawURL string) (*WSClient, error) {
	conn, br, _, err := ws.Dial(ctx, rawURL)
	if err != nil {
		return nil, fmt.Errorf("ws dial %s: %w", rawURL, err)
	}
	var reader io.Reader = conn
	if br != nil {
		reader = br
	}
	return &WSClient{
		conn: conn,
		r:    reader,
		frag: plwsutil.FragmentState{MaxBytes: MaxLineSize},
	}, nil
}

// NewWSClientFromConn wraps an existing net.Conn as a WSClient.
// Set server=true for connections accepted via UpgradeHTTP (sends unmasked frames).
// Set server=false for connections established via Dial (sends masked frames).
func NewWSClientFromConn(conn net.Conn, server bool) *WSClient {
	return &WSClient{
		conn:     conn,
		r:        conn,
		isServer: server,
		frag:     plwsutil.FragmentState{MaxBytes: MaxLineSize},
	}
}

// ReadMessage reads the next complete text message from the WebSocket connection.
// Handles fragment reassembly, rejects binary frames, and validates UTF-8.
// Returns io.EOF on clean close.
func (c *WSClient) ReadMessage() ([]byte, error) {
	for {
		hdr, err := ws.ReadHeader(c.r)
		if err != nil {
			if plwsutil.IsExpectedCloseErr(err) {
				return nil, io.EOF
			}
			return nil, fmt.Errorf("reading ws header: %w", err)
		}

		// Enforce size limits before allocation to prevent memory DoS.
		// Control frames: RFC 6455 caps at 125 bytes.
		if hdr.OpCode.IsControl() && hdr.Length > plwsutil.MaxControlPayload {
			c.writeCloseFrame(ws.StatusProtocolError, "control frame too large")
			return nil, fmt.Errorf("control frame too large: %d bytes", hdr.Length)
		}
		// Data frames: reject headers claiming payloads larger than MaxLineSize.
		if !hdr.OpCode.IsControl() && hdr.Length > int64(MaxLineSize) {
			c.writeCloseFrame(ws.StatusMessageTooBig, "frame too large")
			return nil, fmt.Errorf("frame too large: %d bytes (max %d)", hdr.Length, MaxLineSize)
		}

		// Redundant bounds check at the allocation site. The guards above
		// already reject oversized frames, but CodeQL's taint analysis
		// needs a comparison against a constant on the direct path to make().
		n := int(hdr.Length) //nolint:gosec // overflow impossible: hdr.Length <= MaxLineSize (10MB) after guards above
		if n < 0 || n > MaxLineSize {
			c.writeCloseFrame(ws.StatusMessageTooBig, "frame too large")
			return nil, fmt.Errorf("frame too large: %d bytes (max %d)", hdr.Length, MaxLineSize)
		}
		payload := make([]byte, n)
		if n > 0 {
			if _, err := io.ReadFull(c.r, payload); err != nil {
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
			switch hdr.OpCode {
			case ws.OpClose:
				// Echo close frame back, then signal EOF.
				c.writeCloseFrame(ws.StatusNormalClosure, "")
				return nil, io.EOF
			case ws.OpPing:
				c.writeMu.Lock()
				pongErr := c.writeMsg(ws.OpPong, payload)
				c.writeMu.Unlock()
				if pongErr != nil {
					return nil, fmt.Errorf("writing pong: %w", pongErr)
				}
			case ws.OpPong:
				// Ignore unsolicited pongs.
			}
			continue
		}

		// Reject binary frames. MCP is JSON-RPC text only.
		isBinary := hdr.OpCode == ws.OpBinary ||
			(hdr.OpCode == ws.OpContinuation && c.frag.Active && c.frag.Opcode == ws.OpBinary)
		if isBinary {
			c.writeCloseFrame(ws.StatusPolicyViolation, "binary frames not allowed")
			return nil, fmt.Errorf("binary frame rejected")
		}

		complete, msg, closeCode, closeReason := c.frag.Process(hdr, payload)
		if closeCode != 0 {
			c.writeCloseFrame(closeCode, closeReason)
			return nil, fmt.Errorf("fragment error: %s", closeReason)
		}
		if !complete {
			continue
		}

		// Validate UTF-8 (RFC 6455 requirement for text frames).
		if !utf8.Valid(msg) {
			c.writeCloseFrame(ws.StatusInvalidFramePayloadData, "invalid UTF-8")
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
	return c.writeMsg(ws.OpText, msg)
}

// Close sends a close frame and closes the underlying connection.
// Safe to call from multiple goroutines; the close frame is sent at most once.
func (c *WSClient) Close() error {
	c.closeOnce.Do(func() {
		c.writeCloseFrame(ws.StatusNormalClosure, "")
	})
	return c.conn.Close()
}

// writeCloseFrame sends a close frame under writeMu.
func (c *WSClient) writeCloseFrame(code ws.StatusCode, reason string) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.isServer {
		plwsutil.WriteCloseFrame(c.conn, code, reason)
	} else {
		plwsutil.WriteClientCloseFrame(c.conn, code, reason)
	}
}

// writeMsg sends a data/control frame with the correct masking for the role.
// Caller must hold writeMu.
func (c *WSClient) writeMsg(op ws.OpCode, payload []byte) error {
	if c.isServer {
		return gobwasutil.WriteServerMessage(c.conn, op, payload)
	}
	return gobwasutil.WriteClientMessage(c.conn, op, payload)
}
