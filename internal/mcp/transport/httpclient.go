// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ErrStreamNotSupported indicates the upstream server returned HTTP 405 for
// a GET request, meaning it does not support server-initiated SSE streams.
var ErrStreamNotSupported = errors.New("server does not support GET stream")

// ErrCompressedResponse indicates the upstream returned a non-identity
// Content-Encoding. The downstream readers (SingleMessageReader, SSEReader)
// only see opaque bytes after this point, so compressed payloads must fail
// closed at the transport boundary or they bypass the body scanners. The
// constructor sets DisableCompression so Go's transport leaves the encoding
// header in place; this guard then fires on any non-identity encoding.
var ErrCompressedResponse = errors.New("compressed response cannot be scanned")

// ErrNonSSEStreamResponse indicates a successful GET stream response did not
// advertise a Server-Sent Events body. Treating it as an empty SSE stream would
// silently skip upstream content instead of failing closed.
var ErrNonSSEStreamResponse = errors.New("GET stream response is not text/event-stream")

// ErrUpstreamRequestFailed indicates the HTTP request to the upstream failed
// before a response could be safely processed. It intentionally omits the raw
// client.Do error because Go may include upstream-controlled response bytes.
var ErrUpstreamRequestFailed = errors.New("upstream request failed")

// hasNonIdentityEncoding mirrors internal/proxy/bodyscan.hasNonIdentityEncoding.
// Duplicated here to avoid an import cycle (proxy depends on mcp/transport).
func hasNonIdentityEncoding(ce string) bool {
	if ce == "" {
		return false
	}
	for _, enc := range strings.Split(ce, ",") {
		enc = strings.TrimSpace(strings.ToLower(enc))
		if enc != "" && enc != "identity" {
			return true
		}
	}
	return false
}

func IsSSEContentType(contentType string) bool {
	mediaType, _, err := mime.ParseMediaType(strings.TrimSpace(contentType))
	return err == nil && strings.EqualFold(mediaType, "text/event-stream")
}

func HasSingleSSEContentType(header http.Header) bool {
	values := header.Values("Content-Type")
	return len(values) == 1 && IsSSEContentType(values[0])
}

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
	// Clone http.DefaultTransport with DisableCompression: true so the
	// SSE/JSON upstream's Content-Encoding survives transparent-
	// decompression stripping. Without this, gzip-compressed MCP
	// responses would be silently decompressed by Go's default
	// transport and the compressed-stream guards downstream would
	// never fire on gzip while still firing on br/zstd. This has the
	// same root cause as the forward and reverse transport fixes.
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DisableCompression = true
	// Clone() inherits Proxy: http.ProxyFromEnvironment, which would let an
	// ambient HTTP_PROXY/HTTPS_PROXY silently redirect this client's egress to
	// the configured MCP upstream. The upstream URL is validated at the CLI
	// layer and redirects are disabled below for the same SSRF reason; honoring
	// an env proxy would route around both. Match the parity of the forward,
	// reverse, and TLS-intercept transports, which all dial the configured
	// upstream directly with a nil Proxy.
	transport.Proxy = nil
	return &HTTPClient{
		url:     url,
		headers: headers.Clone(),
		client: &http.Client{
			Transport: transport,
			// Disable redirects - the upstream URL is validated at the
			// CLI layer, and following redirects could bypass that
			// validation (SSRF vector). Envelope signing's redirect
			// refresh helper at internal/proxy/proxy.go:348 is a no-op
			// for this transport because no second hop ever happens;
			// if a future change enables redirect following here, the
			// CheckRedirect closure must call refreshEnvelopeForRedirect
			// (or its MCP equivalent) or pipelock will ship envelopes
			// with stale @target-uri on the redirected leg.
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
//   - 200 OK: response body is scanned by the returned reader.
//   - Content-Type: text/event-stream: wraps body in SSEReader via closingSSEReader.
//   - Other Content-Types (typically application/json): reads body as a single message.
//   - Other status codes: returns an error (body is closed).
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

	// Always remove any caller-supplied Mcp-Session-Id BEFORE the conditional
	// Set below: on the first request c.sessionID is empty and Set is skipped,
	// so without this Del a caller-supplied "Mcp-Session-Id: ..." in extras
	// would reach the upstream and let an attacker pin session correlation
	// to a value of their choice. The CLI's parseHeaderFlags rejects this
	// header at parse time too; this Del is the defense-in-depth layer for
	// programmatic callers that build *HTTPClient directly.
	req.Header.Del("Mcp-Session-Id")

	// Include session ID if established.
	c.sessionMu.Lock()
	if c.sessionID != "" {
		req.Header.Set("Mcp-Session-Id", c.sessionID)
	}
	c.sessionMu.Unlock()

	resp, err := c.client.Do(req)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, ErrUpstreamRequestFailed
	}

	trackSessionID := func() {
		if sid := resp.Header.Get("Mcp-Session-Id"); sid != "" {
			c.sessionMu.Lock()
			c.sessionID = sid
			c.sessionMu.Unlock()
		}
	}

	// 202 Accepted: notification acknowledged, no body to read.
	if resp.StatusCode == http.StatusAccepted {
		trackSessionID()
		_ = resp.Body.Close()
		return &emptyReader{}, nil
	}

	// Redirect or other 3xx - since we disabled redirect-following, treat these
	// as errors to avoid processing unexpected response bodies.
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("HTTP %d: unexpected redirect (redirects are disabled)", resp.StatusCode)
	}

	// Error status codes: do not echo attacker-controlled upstream body bytes
	// into returned errors; callers commonly log these strings.
	if resp.StatusCode >= 400 {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	// Only 200 OK and 202 Accepted are valid successful POST responses for
	// this transport. Treat other 2xx statuses (201/203/204/206/etc.) as
	// unexpected upstream responses instead of normalizing them to success.
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	trackSessionID()

	// Fail closed on compressed responses before wrapping the body in
	// SingleMessageReader or SSEReader. Both readers see opaque bytes
	// after this point; gzip/br/zstd would otherwise reach downstream
	// scanners as binary garbage and never trigger the body-scan guards.
	// DisableCompression on the transport guarantees the encoding header
	// survives transparent decompression, so this check is authoritative.
	if hasNonIdentityEncoding(resp.Header.Get("Content-Encoding")) {
		_ = resp.Body.Close()
		return nil, ErrCompressedResponse
	}

	// Route based on Content-Type.
	if HasSingleSSEContentType(resp.Header) {
		return &closingSSEReader{
			sse:  NewSSEReader(resp.Body),
			body: resp.Body,
		}, nil
	}

	// Default: treat as single JSON message.
	return &SingleMessageReader{Body: resp.Body}, nil
}

// emptyReader returns io.EOF on every ReadMessage call.
// Used for 202 Accepted responses where the server has no payload.
type emptyReader struct{}

func (*emptyReader) ReadMessage() ([]byte, error) {
	return nil, io.EOF
}

// SingleMessageReader reads the entire response body as one message,
// then returns io.EOF on subsequent calls. The body is closed after
// the first read or on the EOF read.
type SingleMessageReader struct {
	Body io.ReadCloser
	done bool
}

func (r *SingleMessageReader) ReadMessage() ([]byte, error) {
	if r.done {
		return nil, io.EOF
	}
	r.done = true

	// Read one extra byte beyond the limit so we can detect truncation
	// and return a clear error instead of passing incomplete JSON downstream.
	data, err := io.ReadAll(io.LimitReader(r.Body, int64(MaxLineSize)+1))
	_ = r.Body.Close() // best-effort cleanup after read
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}
	if len(data) > MaxLineSize {
		return nil, fmt.Errorf("response body exceeds maximum size (%d bytes)", MaxLineSize)
	}

	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil, io.EOF
	}
	return data, nil
}

// Close releases the underlying body so a caller can abort a read blocked on a
// slow or hung upstream (e.g. an MCP response timeout). Safe to call more than
// once; a redundant close on an already-closed body is ignored.
func (r *SingleMessageReader) Close() error {
	return r.Body.Close()
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

// Close releases the underlying body so a caller can abort a read blocked on a
// slow or hung SSE upstream (e.g. an MCP response timeout). Safe to call more
// than once; a redundant close is ignored.
func (r *closingSSEReader) Close() error {
	return r.body.Close()
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
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, ErrUpstreamRequestFailed
	}

	if resp.StatusCode == http.StatusMethodNotAllowed {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("%w (HTTP 405)", ErrStreamNotSupported)
	}
	// Redirect or other 3xx - since we disabled redirect-following, treat these
	// as errors (consistent with SendMessage).
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("GET stream HTTP %d: unexpected redirect (redirects are disabled)", resp.StatusCode)
	}

	if resp.StatusCode >= 400 {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("GET stream returned HTTP %d", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("GET stream returned HTTP %d", resp.StatusCode)
	}

	// Fail closed on compressed SSE responses. Same rationale as SendMessage:
	// SSEReader receives opaque bytes and would silently fail to parse a
	// gzipped event stream, which is a bypass vector against the streaming
	// scanners.
	if hasNonIdentityEncoding(resp.Header.Get("Content-Encoding")) {
		_ = resp.Body.Close()
		return nil, ErrCompressedResponse
	}

	if !HasSingleSSEContentType(resp.Header) {
		_ = resp.Body.Close()
		return nil, ErrNonSSEStreamResponse
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
	clearSession := func() {
		c.sessionMu.Lock()
		c.sessionID = ""
		c.sessionMu.Unlock()
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
			if ctxErr := ctx.Err(); ctxErr != nil {
				_, _ = fmt.Fprintf(logW, "pipelock: session delete: %v\n", ctxErr)
			} else {
				_, _ = fmt.Fprintf(logW, "pipelock: session delete: %v\n", ErrUpstreamRequestFailed)
			}
		}
		clearSession()
		return
	}
	_ = resp.Body.Close()

	// Clear session ID unconditionally - even if the server returned an error,
	// the session should not be reused (prevents stale Mcp-Session-Id headers
	// on subsequent requests if reconnection occurs).
	clearSession()

	if resp.StatusCode >= 400 && logW != nil {
		_, _ = fmt.Fprintf(logW, "pipelock: session delete: server returned HTTP %d\n", resp.StatusCode)
	}
}
