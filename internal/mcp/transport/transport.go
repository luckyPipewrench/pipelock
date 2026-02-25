// Package transport provides message framing for MCP JSON-RPC 2.0 transports.
// It includes stdio (newline-delimited), SSE (Server-Sent Events), and HTTP
// client implementations.
package transport

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
)

// MaxLineSize is the maximum line length for MCP responses (10 MB).
const MaxLineSize = 10 * 1024 * 1024

// MessageReader reads framed messages from a transport.
// Each call to ReadMessage returns one complete JSON-RPC message.
// The returned byte slice is owned by the caller and will not be
// modified or reused by subsequent calls.
// Returns io.EOF when no more messages are available.
type MessageReader interface {
	ReadMessage() ([]byte, error)
}

// MessageWriter writes framed messages to a transport.
// Each call to WriteMessage sends one complete JSON-RPC message
// with appropriate framing for the transport (e.g., newline for stdio).
type MessageWriter interface {
	WriteMessage(msg []byte) error
}

// StdioReader reads newline-delimited JSON-RPC messages from an io.Reader.
// Each line is one message, matching the MCP stdio transport specification.
type StdioReader struct {
	scanner *bufio.Scanner
}

// NewStdioReader creates a StdioReader that reads newline-delimited messages.
func NewStdioReader(r io.Reader) *StdioReader {
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 0, 64*1024), MaxLineSize)
	return &StdioReader{scanner: s}
}

// ReadMessage returns the next non-empty line as a message.
// Returns io.EOF when the underlying reader is exhausted.
func (sr *StdioReader) ReadMessage() ([]byte, error) {
	for sr.scanner.Scan() {
		line := bytes.TrimSpace(sr.scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		// Return a copy — bufio.Scanner reuses the backing array.
		msg := make([]byte, len(line))
		copy(msg, line)
		return msg, nil
	}
	if err := sr.scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading message: %w", err)
	}
	return nil, io.EOF
}

// StdioWriter writes newline-delimited JSON-RPC messages to an io.Writer.
type StdioWriter struct {
	w io.Writer
}

// NewStdioWriter creates a StdioWriter that appends a newline after each message.
func NewStdioWriter(w io.Writer) *StdioWriter {
	return &StdioWriter{w: w}
}

// WriteMessage writes msg followed by a newline in a single Write call.
// The single-call approach avoids partial writes from interleaving.
func (sw *StdioWriter) WriteMessage(msg []byte) error {
	if len(msg) > MaxLineSize {
		return fmt.Errorf("message too large: %d bytes", len(msg))
	}
	buf := make([]byte, len(msg)+1)
	copy(buf, msg)
	buf[len(msg)] = '\n'
	if _, err := sw.w.Write(buf); err != nil {
		return fmt.Errorf("writing message: %w", err)
	}
	return nil
}
