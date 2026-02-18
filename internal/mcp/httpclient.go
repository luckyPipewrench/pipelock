package mcp

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
)

// HTTPClient sends JSON-RPC 2.0 messages over HTTP POST and returns
// a MessageReader for each response. It implements the MCP Streamable HTTP
// transport specification, handling both JSON and SSE response types,
// session ID tracking, and 202 Accepted for notifications.
type HTTPClient struct {
	url       string
	headers   http.Header
	client    *http.Client
	sessionMu sync.Mutex
	sessionID string
}

// NewHTTPClient creates an HTTPClient that POSTs JSON-RPC messages to url.
// Extra headers (e.g., Authorization) are sent with every request.
// If headers is nil, no extra headers are added.
func NewHTTPClient(url string, headers http.Header) *HTTPClient {
	return &HTTPClient{
		url:     url,
		headers: headers,
		client:  &http.Client{},
	}
}

// SessionID returns the current MCP session ID, or empty if not yet established.
func (c *HTTPClient) SessionID() string {
	c.sessionMu.Lock()
	defer c.sessionMu.Unlock()
	return c.sessionID
}

// SendMessage POSTs msg as a JSON-RPC 2.0 request and returns a MessageReader
// for reading the response. The caller must drain the reader to release resources.
//
// Response handling:
//   - 202 Accepted: returns an emptyReader (EOF immediately). Used for notifications.
//   - Content-Type: text/event-stream: wraps body in SSEReader via closingSSEReader.
//   - Other Content-Types (typically application/json): reads body as a single message.
//   - 4xx/5xx status codes: returns an error (body is closed).
//
// The Mcp-Session-Id header is tracked from responses and sent on subsequent requests.
func (c *HTTPClient) SendMessage(msg []byte) (MessageReader, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, c.url, bytes.NewReader(msg))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")

	// Copy extra headers (e.g., Authorization).
	for key, vals := range c.headers {
		for _, v := range vals {
			req.Header.Set(key, v)
		}
	}

	// Include session ID if established.
	c.sessionMu.Lock()
	if c.sessionID != "" {
		req.Header.Set("Mcp-Session-Id", c.sessionID)
	}
	c.sessionMu.Unlock()

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sending request: %w", err)
	}

	// Track session ID from response.
	if sid := resp.Header.Get("Mcp-Session-Id"); sid != "" {
		c.sessionMu.Lock()
		c.sessionID = sid
		c.sessionMu.Unlock()
	}

	// 202 Accepted: notification acknowledged, no body to read.
	if resp.StatusCode == http.StatusAccepted {
		resp.Body.Close() //nolint:errcheck,gosec // best-effort cleanup
		return &emptyReader{}, nil
	}

	// Error status codes: return error and close body.
	if resp.StatusCode >= 400 {
		resp.Body.Close() //nolint:errcheck,gosec // best-effort cleanup
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	// Route based on Content-Type.
	ct := resp.Header.Get("Content-Type")
	if strings.HasPrefix(ct, "text/event-stream") {
		return &closingSSEReader{
			sse:  NewSSEReader(resp.Body),
			body: resp.Body,
		}, nil
	}

	// Default: treat as single JSON message.
	return &singleMessageReader{body: resp.Body}, nil
}

// emptyReader returns io.EOF on every ReadMessage call.
// Used for 202 Accepted responses where the server has no payload.
type emptyReader struct{}

func (*emptyReader) ReadMessage() ([]byte, error) {
	return nil, io.EOF
}

// singleMessageReader reads the entire response body as one message,
// then returns io.EOF on subsequent calls. The body is closed after
// the first read or on the EOF read.
type singleMessageReader struct {
	body io.ReadCloser
	done bool
}

func (r *singleMessageReader) ReadMessage() ([]byte, error) {
	if r.done {
		return nil, io.EOF
	}
	r.done = true

	data, err := io.ReadAll(io.LimitReader(r.body, int64(maxLineSize)))
	r.body.Close() //nolint:errcheck,gosec // best-effort cleanup after read
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil, io.EOF
	}
	return data, nil
}

// closingSSEReader wraps an SSEReader with the response body so that
// the body is closed when the SSE stream returns EOF.
type closingSSEReader struct {
	sse  *SSEReader
	body io.ReadCloser
}

func (r *closingSSEReader) ReadMessage() ([]byte, error) {
	msg, err := r.sse.ReadMessage()
	if err != nil {
		r.body.Close() //nolint:errcheck,gosec // best-effort cleanup on stream end
		return nil, err
	}
	return msg, nil
}

// OpenGETStream opens a GET SSE connection for server-initiated messages.
// Returns a MessageReader yielding SSE events. Returns an error if the server
// responds with 405 (doesn't support GET stream) or other error status.
func (c *HTTPClient) OpenGETStream() (MessageReader, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, c.url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating GET request: %w", err)
	}
	req.Header.Set("Accept", "text/event-stream")

	c.sessionMu.Lock()
	if c.sessionID != "" {
		req.Header.Set("Mcp-Session-Id", c.sessionID)
	}
	c.sessionMu.Unlock()

	for key, vals := range c.headers {
		for _, v := range vals {
			req.Header.Set(key, v)
		}
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP GET: %w", err)
	}

	if resp.StatusCode == http.StatusMethodNotAllowed {
		resp.Body.Close() //nolint:errcheck,gosec // best-effort cleanup
		return nil, fmt.Errorf("server does not support GET stream (405)")
	}
	if resp.StatusCode >= 400 {
		resp.Body.Close() //nolint:errcheck,gosec // best-effort cleanup
		return nil, fmt.Errorf("GET stream returned HTTP %d", resp.StatusCode)
	}

	return &closingSSEReader{
		sse:  NewSSEReader(resp.Body),
		body: resp.Body,
	}, nil
}

// DeleteSession sends an HTTP DELETE to terminate the MCP session.
func (c *HTTPClient) DeleteSession() {
	c.sessionMu.Lock()
	sid := c.sessionID
	c.sessionMu.Unlock()
	if sid == "" {
		return
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodDelete, c.url, nil)
	if err != nil {
		return
	}
	req.Header.Set("Mcp-Session-Id", sid)
	for key, vals := range c.headers {
		for _, v := range vals {
			req.Header.Set(key, v)
		}
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return
	}
	resp.Body.Close() //nolint:errcheck,gosec // best-effort cleanup
}
