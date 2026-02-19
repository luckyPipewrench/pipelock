package mcp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ErrStreamNotSupported indicates the upstream server returned HTTP 405 for
// a GET request, meaning it does not support server-initiated SSE streams.
var ErrStreamNotSupported = errors.New("server does not support GET stream")

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
// If headers is nil, no extra headers are added. Headers are cloned to
// prevent mutation after construction.
func NewHTTPClient(url string, headers http.Header) *HTTPClient {
	return &HTTPClient{
		url:     url,
		headers: headers.Clone(),
		client: &http.Client{
			// Disable redirects — the upstream URL is validated at the CLI layer,
			// and following redirects could bypass that validation (SSRF vector).
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
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
func (c *HTTPClient) SendMessage(ctx context.Context, msg []byte) (MessageReader, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(msg))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	// Apply extra headers first, then set transport-critical headers after
	// so they cannot be overridden by caller-provided extras.
	for key, vals := range c.headers {
		for _, v := range vals {
			req.Header.Add(key, v)
		}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")

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

	// Redirect or other 3xx — since we disabled redirect-following, treat these
	// as errors to avoid processing unexpected response bodies.
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		resp.Body.Close() //nolint:errcheck,gosec // best-effort cleanup
		return nil, fmt.Errorf("HTTP %d: unexpected redirect (redirects are disabled)", resp.StatusCode)
	}

	// Error status codes: read limited body for diagnostics, then return error.
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024)) //nolint:errcheck // best-effort read
		resp.Body.Close()                                      //nolint:errcheck,gosec // best-effort cleanup
		if len(body) > 0 {
			return nil, fmt.Errorf("HTTP %d: %s: %s", resp.StatusCode, resp.Status, bytes.TrimSpace(body))
		}
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
	_ = r.body.Close() // best-effort cleanup after read
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
// the body is closed when the SSE stream returns EOF or any error.
type closingSSEReader struct {
	sse    *SSEReader
	body   io.ReadCloser
	closed bool
}

func (r *closingSSEReader) ReadMessage() ([]byte, error) {
	if r.closed {
		return nil, io.EOF
	}
	msg, err := r.sse.ReadMessage()
	if err != nil {
		r.closed = true
		r.body.Close() //nolint:errcheck,gosec // best-effort cleanup on stream end
		return nil, err
	}
	return msg, nil
}

// OpenGETStream opens a GET SSE connection for server-initiated messages.
// Returns a MessageReader yielding SSE events. Returns an error if the server
// responds with 405 (doesn't support GET stream) or other error status.
func (c *HTTPClient) OpenGETStream(ctx context.Context) (MessageReader, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating GET request: %w", err)
	}
	// Apply extra headers first, then set transport-critical headers after.
	for key, vals := range c.headers {
		for _, v := range vals {
			req.Header.Add(key, v)
		}
	}
	req.Header.Set("Accept", "text/event-stream")

	c.sessionMu.Lock()
	if c.sessionID != "" {
		req.Header.Set("Mcp-Session-Id", c.sessionID)
	}
	c.sessionMu.Unlock()

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP GET: %w", err)
	}

	if resp.StatusCode == http.StatusMethodNotAllowed {
		resp.Body.Close() //nolint:errcheck,gosec // best-effort cleanup
		return nil, fmt.Errorf("%w (HTTP 405)", ErrStreamNotSupported)
	}
	// Redirect or other 3xx — since we disabled redirect-following, treat these
	// as errors (consistent with SendMessage).
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		resp.Body.Close() //nolint:errcheck,gosec // best-effort cleanup
		return nil, fmt.Errorf("GET stream HTTP %d: unexpected redirect (redirects are disabled)", resp.StatusCode)
	}

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024)) //nolint:errcheck // best-effort read
		resp.Body.Close()                                      //nolint:errcheck,gosec // best-effort cleanup
		if len(body) > 0 {
			return nil, fmt.Errorf("GET stream HTTP %d: %s", resp.StatusCode, bytes.TrimSpace(body))
		}
		return nil, fmt.Errorf("GET stream returned HTTP %d", resp.StatusCode)
	}

	return &closingSSEReader{
		sse:  NewSSEReader(resp.Body),
		body: resp.Body,
	}, nil
}

// DeleteSession sends an HTTP DELETE to terminate the MCP session.
// Uses a 5-second timeout since this is best-effort cleanup.
// Errors are logged to logW if non-nil.
func (c *HTTPClient) DeleteSession(logW io.Writer) {
	c.sessionMu.Lock()
	sid := c.sessionID
	c.sessionMu.Unlock()
	if sid == "" {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.url, nil)
	if err != nil {
		if logW != nil {
			_, _ = fmt.Fprintf(logW, "pipelock: session delete: %v\n", err)
		}
		return
	}
	for key, vals := range c.headers {
		for _, v := range vals {
			req.Header.Add(key, v)
		}
	}
	req.Header.Set("Mcp-Session-Id", sid)
	resp, err := c.client.Do(req)
	if err != nil {
		if logW != nil {
			_, _ = fmt.Fprintf(logW, "pipelock: session delete: %v\n", err)
		}
		return
	}
	resp.Body.Close() //nolint:errcheck,gosec // best-effort cleanup

	// Clear session ID unconditionally — even if the server returned an error,
	// the session should not be reused (prevents stale Mcp-Session-Id headers
	// on subsequent requests if reconnection occurs).
	c.sessionMu.Lock()
	c.sessionID = ""
	c.sessionMu.Unlock()

	if resp.StatusCode >= 400 && logW != nil {
		_, _ = fmt.Fprintf(logW, "pipelock: session delete: server returned HTTP %d\n", resp.StatusCode)
	}
}
