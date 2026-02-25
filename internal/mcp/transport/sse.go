package transport

import (
	"bufio"
	"io"
	"strings"
)

// SSEReader reads Server-Sent Events from an io.Reader and implements
// MessageReader. Each ReadMessage call returns the data payload of the
// next SSE event. Multi-line data: fields are concatenated with newlines
// per the SSE specification.
type SSEReader struct {
	scanner     *bufio.Scanner
	lastEventID string
}

// NewSSEReader creates an SSEReader that parses SSE events from r.
// The scanner buffer matches StdioReader's sizing (64KB initial, MaxLineSize max).
func NewSSEReader(r io.Reader) *SSEReader {
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 0, 64*1024), MaxLineSize)
	return &SSEReader{scanner: s}
}

// LastEventID returns the most recently seen SSE id: field value.
// This can be used for reconnection with the Last-Event-ID header.
func (sr *SSEReader) LastEventID() string {
	return sr.lastEventID
}

// ReadMessage returns the data payload of the next SSE event.
// Multiple data: lines within a single event are concatenated with newlines
// per the SSE specification. Non-data fields (event:, id:, retry:) are
// parsed but not included in the returned payload.
// Returns io.EOF when no more events are available.
func (sr *SSEReader) ReadMessage() ([]byte, error) {
	var data []string
	hasData := false

	for sr.scanner.Scan() {
		line := sr.scanner.Text()

		// Blank line = end of event.
		if line == "" {
			if hasData {
				joined := strings.Join(data, "\n")
				return []byte(joined), nil
			}
			continue
		}

		// Comment lines start with ':'.
		if strings.HasPrefix(line, ":") {
			continue
		}

		// Parse field: value.
		field, value, _ := strings.Cut(line, ":")
		// Per SSE spec: if value starts with a space, remove it.
		value = strings.TrimPrefix(value, " ")

		switch field {
		case "data":
			data = append(data, value)
			hasData = true
		case "id":
			// Per SSE spec: if the id field value contains U+0000 NULL, ignore it.
			if !strings.Contains(value, "\x00") {
				sr.lastEventID = value
			}
		case "event", "retry":
			// Tracked but not used for message extraction.
		}
	}

	// Stream ended — check for scanner errors before returning partial data.
	// A partial event (data accumulated without a blank-line boundary) during
	// a scanner error means the event was interrupted mid-stream.
	if err := sr.scanner.Err(); err != nil {
		return nil, err
	}
	if hasData {
		joined := strings.Join(data, "\n")
		return []byte(joined), nil
	}
	return nil, io.EOF
}
