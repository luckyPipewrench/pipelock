// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/jsonscan"
	"github.com/luckyPipewrench/pipelock/internal/responseencoding"
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

// ErrInvalidPipelockSessionToken indicates that a listener returned a malformed
// Pipelock-owned state token. Accepting and replaying an arbitrary header would
// turn a hostile upstream response into client-controlled listener state.
var ErrInvalidPipelockSessionToken = errors.New("invalid Pipelock session token")

const pipelockSessionTokenHeader = "Pipelock-Session-Token"

const mcpProtocolVersionHeader = "Mcp-Protocol-Version"

func validPipelockSessionToken(token string) bool {
	if len(token) != 43 {
		return false
	}
	for i := range len(token) {
		if (token[i] < 'A' || token[i] > 'Z') &&
			(token[i] < 'a' || token[i] > 'z') &&
			(token[i] < '0' || token[i] > '9') &&
			token[i] != '-' && token[i] != '_' {
			return false
		}
	}
	return true
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
	url                  string
	headers              http.Header
	client               *http.Client
	sessionMu            sync.Mutex
	sessionID            string
	listenerSessionToken string
	protocolVersion      string
	initializeGeneration uint64
}

// NewHTTPClient creates an HTTPClient that POSTs JSON-RPC messages to url.
// Extra headers (e.g., Authorization) are sent with every request.
// If headers is nil, no extra headers are added. Headers are cloned to
// prevent mutation after construction.
func NewHTTPClient(url string, headers http.Header) *HTTPClient {
	return NewHTTPClientWithDialer(url, headers, nil)
}

// NewHTTPClientWithDialer creates an HTTPClient with an optional custom dialer.
// The dialer is used for every upstream POST, GET stream, DELETE, and reconnect
// performed by this client.
func NewHTTPClientWithDialer(url string, headers http.Header, dialContext func(ctx context.Context, network, addr string) (net.Conn, error)) *HTTPClient {
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
	if dialContext != nil {
		transport.DialContext = dialContext
	}
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
//   - 202 Accepted, 204 No Content, or another declared-empty 2xx: returns an
//     emptyReader (EOF immediately). Used for notifications.
//   - 200 OK: response body is scanned by the returned reader.
//   - 4xx carrying the JSON-RPC error for this request: returned as the response
//     so the caller scans and forwards the upstream's own answer.
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
	responseencoding.RequestIdentity(req.Header)

	// Always remove any caller-supplied Mcp-Session-Id BEFORE the conditional
	// Set below: on the first request c.sessionID is empty and Set is skipped,
	// so without this Del a caller-supplied "Mcp-Session-Id: ..." in extras
	// would reach the upstream and let an attacker pin session correlation
	// to a value of their choice. The CLI's parseHeaderFlags rejects this
	// header at parse time too; this Del is the defense-in-depth layer for
	// programmatic callers that build *HTTPClient directly.
	req.Header.Del("Mcp-Session-Id")
	req.Header.Del(pipelockSessionTokenHeader)

	// Include Pipelock-managed correlation state if established.
	initializeID := httpInitializeRequestID(msg)
	c.sessionMu.Lock()
	if initializeID != nil {
		c.initializeGeneration++
		c.protocolVersion = ""
	}
	generation := c.initializeGeneration
	if c.protocolVersion != "" {
		req.Header.Set(mcpProtocolVersionHeader, c.protocolVersion)
	}
	if c.sessionID != "" {
		req.Header.Set("Mcp-Session-Id", c.sessionID)
	}
	if c.listenerSessionToken != "" {
		req.Header.Set(pipelockSessionTokenHeader, c.listenerSessionToken)
	}
	c.sessionMu.Unlock()

	resp, err := c.client.Do(req)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, ErrUpstreamRequestFailed
	}

	trackSessionID := func() error {
		sid := resp.Header.Get("Mcp-Session-Id")
		token := resp.Header.Get(pipelockSessionTokenHeader)
		if token != "" && !validPipelockSessionToken(token) {
			return ErrInvalidPipelockSessionToken
		}
		c.sessionMu.Lock()
		defer c.sessionMu.Unlock()
		if sid != "" {
			c.sessionID = sid
		}
		if token != "" {
			c.listenerSessionToken = token
		}
		return nil
	}

	// An empty 2xx acknowledges a notification or client response; there is
	// no message to read. A request is owed an answer, so only the legacy 202
	// acknowledges one.
	if AcceptedWithoutBody(resp) && (resp.StatusCode == http.StatusAccepted || !ExpectsReply(msg)) {
		if err := trackSessionID(); err != nil {
			_ = resp.Body.Close()
			return nil, err
		}
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
	// into returned errors; callers commonly log these strings. A 4xx that
	// carries the JSON-RPC error answering this request is the upstream's
	// reply, not a transport failure, so it goes back to the caller as the
	// response and through the same scanning as any other.
	if resp.StatusCode >= 400 {
		if IsClientError(resp.StatusCode) {
			if requestID, ok := clientErrorCandidate(resp, msg); ok {
				// The body is read on the first ReadMessage, not here, so the
				// caller's per-response timeout bounds a refusal that sends
				// headers and then stalls, exactly as it bounds a 200 body.
				return &clientErrorReader{resp: resp, requestID: requestID}, nil
			}
		}
		_ = resp.Body.Close()
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	// Only 200 OK and the empty acknowledgements above are valid successful
	// POST responses for this transport. Treat a 2xx that carries content on
	// any other status (201/203/206/etc.) as an unexpected upstream response
	// instead of normalizing it to success.
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if err := trackSessionID(); err != nil {
		_ = resp.Body.Close()
		return nil, err
	}

	// Decode supported buffered JSON responses before scanning. Compressed SSE,
	// unsupported encodings, and malformed streams stay fail-closed.
	if responseencoding.HasNonIdentityContentEncoding(resp.Header) {
		if HasSingleSSEContentType(resp.Header) {
			_ = resp.Body.Close()
			return nil, ErrCompressedResponse
		}
		if err := responseencoding.DecodeResponse(resp); err != nil {
			_ = resp.Body.Close()
			return nil, ErrCompressedResponse
		}
	}

	// Route based on Content-Type.
	var reader interface {
		MessageReader
		io.Closer
	}
	if HasSingleSSEContentType(resp.Header) {
		reader = &closingSSEReader{
			sse:  NewSSEReader(resp.Body),
			body: resp.Body,
		}
	} else {
		reader = &SingleMessageReader{Body: resp.Body}
	}
	if initializeID != nil {
		reader = &initializeResponseReader{reader: reader, client: c, id: initializeID, generation: generation}
	}
	return reader, nil
}

// Protocol negotiation observes framed responses without consuming or changing
// the bytes that the MCP scanners receive. Only a matching initialize result can
// change the transport header, including when SSE carries other messages first.
type initializeResponseReader struct {
	reader interface {
		MessageReader
		io.Closer
	}
	client     *HTTPClient
	id         any
	generation uint64
	done       bool
	closed     bool // guarded by client.sessionMu, alongside version commitment
}

func httpRPCID(raw json.RawMessage) any {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var id any
	if decoder.Decode(&id) != nil {
		return nil
	}
	switch id.(type) {
	case string, json.Number:
		return id
	default:
		return nil
	}
}

// clientErrorCandidate reports whether a 4xx reply may carry the JSON-RPC
// error answering the request in msg: the request has a method and an ID, and
// the reply declares exactly one application/json type. It returns the
// request's raw ID. The body is not read here.
func clientErrorCandidate(resp *http.Response, msg []byte) (json.RawMessage, bool) {
	var request map[string]json.RawMessage
	if json.Unmarshal(msg, &request) != nil || request["method"] == nil || httpRPCID(request["id"]) == nil {
		return nil, false
	}
	contentTypes := resp.Header.Values("Content-Type")
	if len(contentTypes) != 1 {
		return nil, false
	}
	if mediaType, _, err := mime.ParseMediaType(contentTypes[0]); err != nil || mediaType != "application/json" {
		return nil, false
	}
	return request["id"], true
}

// UpstreamRequestFailedMessage is the error message a caller sees when an
// upstream refusal cannot be relayed. It matches the message the MCP bridges
// write for any other failed upstream request, so the two read the same.
const UpstreamRequestFailedMessage = "pipelock: upstream error: upstream HTTP request failed"

// clientErrorReader yields a 4xx reply as one message. A body that is the
// JSON-RPC error for this request is returned as-is, for the caller to scan.
// Anything else becomes a sanitized error carrying the request's ID, so the
// caller is answered without any upstream bytes. A notification never gets
// here: it has no ID to answer.
type clientErrorReader struct {
	resp      *http.Response
	requestID json.RawMessage
	done      bool
}

func (r *clientErrorReader) ReadMessage() ([]byte, error) {
	if r.done {
		return nil, io.EOF
	}
	r.done = true
	body, err := ReadClientErrorBody(r.resp)
	_ = r.resp.Body.Close()
	if errors.Is(err, ErrIncompleteResponse) {
		// Cancellation, a deadline or a dropped connection: report it the way
		// SingleMessageReader reports a broken 200 body, not as an answer.
		return nil, err
	}
	if err == nil && IsClientErrorReply(body, r.requestID) {
		return body, nil
	}
	return sanitizedClientErrorReply(r.requestID), nil
}

// Close releases the body so a caller can abort a read that stalls.
func (r *clientErrorReader) Close() error {
	return r.resp.Body.Close()
}

// sanitizedClientErrorReply is composed directly rather than encoded: id is a
// JSON string or number already accepted by httpRPCID, and the rest is
// constant, so the bytes are exactly what an encoder would produce.
func sanitizedClientErrorReply(id json.RawMessage) []byte {
	return []byte(`{"jsonrpc":"2.0","id":` + string(id) + `,"error":{"code":-32003,"message":"` + UpstreamRequestFailedMessage + `"}}`)
}

// IsClientErrorReply reports whether body is a JSON-RPC error answering id.
// Both HTTP transports use this guard before relaying a refusal as a message.
func IsClientErrorReply(body []byte, id json.RawMessage) bool {
	requestID := httpRPCID(id)
	if requestID == nil {
		return false
	}
	replyID, ok := jsonRPCErrorReplyID(body)
	return ok && httpRPCID(replyID) == requestID
}

// IsUncorrelatedErrorReply reports whether body is a JSON-RPC error whose ID
// is null. JSON-RPC 2.0 requires the id member in every response and sets it to
// null when the request could not be identified: the MCP reference server sends
// "Session not found" with a 404 and id null, and the specification tells a
// client to start a new session on that 404. Such an error answers no
// in-flight request, so a client cannot mistake it for another call's outcome.
// An absent id is a malformed response, not an uncorrelated one.
func IsUncorrelatedErrorReply(body []byte) bool {
	replyID, ok := jsonRPCErrorReplyID(body)
	return ok && string(replyID) == "null"
}

// jsonRPCErrorReplyID returns the raw ID of body when body is exactly a
// JSON-RPC 2.0 error: no result, method or params, an error object with an
// integer code and a string message, and no duplicate or case-folded envelope
// keys a client might read instead.
func jsonRPCErrorReplyID(body []byte) (json.RawMessage, bool) {
	var reply map[string]json.RawMessage
	if json.Unmarshal(body, &reply) != nil || jsonscan.RejectDuplicateKeys(body) != nil ||
		jsonscan.RejectCaseFoldedAliases(body, "jsonrpc", "id", "method", "result", "error", "params") != nil {
		return nil, false
	}
	var version string
	if json.Unmarshal(reply["jsonrpc"], &version) != nil || version != "2.0" ||
		reply["method"] != nil || reply["result"] != nil || reply["params"] != nil ||
		!validJSONRPCErrorObject(reply["error"]) {
		return nil, false
	}
	return reply["id"], true
}

// validJSONRPCErrorObject reports whether raw is an object whose code is an
// integer and whose message is a string, the two members the JSON-RPC 2.0
// specification requires of every error.
func validJSONRPCErrorObject(raw json.RawMessage) bool {
	// A map keeps member names exact: struct decoding would match "Code" and
	// "Message" case-insensitively and accept an error a client reads as empty.
	var errObj map[string]json.RawMessage
	var message *string
	if len(raw) == 0 || raw[0] != '{' || json.Unmarshal(raw, &errObj) != nil ||
		json.Unmarshal(errObj["message"], &message) != nil || message == nil {
		return false
	}
	code := errObj["code"]
	// Read the raw token so a quoted code such as "-32001", which json.Number
	// would accept, is refused.
	if len(code) == 0 || (code[0] != '-' && (code[0] < '0' || code[0] > '9')) {
		return false
	}
	_, err := json.Number(code).Int64()
	return err == nil
}

func httpInitializeRequestID(msg []byte) any {
	var request map[string]json.RawMessage
	if json.Unmarshal(msg, &request) != nil {
		return nil
	}
	var method, version string
	if json.Unmarshal(request["method"], &method) != nil || method != "initialize" ||
		json.Unmarshal(request["jsonrpc"], &version) != nil || version != "2.0" ||
		jsonscan.RejectDuplicateKeys(msg) != nil {
		return nil
	}
	return httpRPCID(request["id"])
}

func (r *initializeResponseReader) ReadMessage() ([]byte, error) {
	msg, err := r.reader.ReadMessage()
	if err != nil || r.done {
		return msg, err
	}
	var response map[string]json.RawMessage
	if json.Unmarshal(msg, &response) != nil || jsonscan.RejectDuplicateKeys(msg) != nil ||
		httpRPCID(response["id"]) != r.id {
		return msg, nil
	}
	var rpcVersion string
	if json.Unmarshal(response["jsonrpc"], &rpcVersion) != nil || rpcVersion != "2.0" || response["method"] != nil {
		return msg, nil
	}
	r.done = true
	if response["error"] != nil {
		return msg, nil
	}
	var result map[string]json.RawMessage
	var version string
	if json.Unmarshal(response["result"], &result) != nil ||
		json.Unmarshal(result["protocolVersion"], &version) != nil || len(version) != len(time.DateOnly) {
		return msg, nil
	}
	if _, err := time.Parse(time.DateOnly, version); err != nil {
		return msg, nil
	}
	r.client.sessionMu.Lock()
	if !r.closed && r.client.initializeGeneration == r.generation {
		r.client.protocolVersion = version
	}
	r.client.sessionMu.Unlock()
	return msg, nil
}

func (r *initializeResponseReader) Close() error {
	// Abort negotiation before closing the body: a concurrent read may already
	// have obtained a response and otherwise commit it after this Close returns.
	r.client.sessionMu.Lock()
	r.closed = true
	r.client.sessionMu.Unlock()
	return r.reader.Close()
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
		return nil, fmt.Errorf("%w: reading response body: %w", ErrIncompleteResponse, err)
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
	responseencoding.RequestIdentity(req.Header)

	c.sessionMu.Lock()
	req.Header.Del("Mcp-Session-Id")
	req.Header.Del(pipelockSessionTokenHeader)
	if c.protocolVersion != "" {
		req.Header.Set(mcpProtocolVersionHeader, c.protocolVersion)
	}
	if c.sessionID != "" {
		req.Header.Set("Mcp-Session-Id", c.sessionID)
	}
	if c.listenerSessionToken != "" {
		req.Header.Set(pipelockSessionTokenHeader, c.listenerSessionToken)
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
	if responseencoding.HasNonIdentityContentEncoding(resp.Header) {
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
	listenerToken := c.listenerSessionToken
	version := c.protocolVersion
	// Invalidate outstanding initialize readers even for stateless upstreams.
	c.initializeGeneration++
	c.protocolVersion = ""
	c.sessionMu.Unlock()
	if sid == "" && listenerToken == "" {
		return
	}
	clearSession := func() {
		c.sessionMu.Lock()
		c.sessionID = ""
		c.listenerSessionToken = ""
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
	responseencoding.RequestIdentity(req.Header)
	req.Header.Del("Mcp-Session-Id")
	req.Header.Del(pipelockSessionTokenHeader)
	if version != "" {
		req.Header.Set(mcpProtocolVersionHeader, version)
	}
	if sid != "" {
		req.Header.Set("Mcp-Session-Id", sid)
	}
	if listenerToken != "" {
		req.Header.Set(pipelockSessionTokenHeader, listenerToken)
	}
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
