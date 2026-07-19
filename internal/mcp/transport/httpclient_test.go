// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

const (
	testJSONID2 = `{"id":2}`
)

// drain reads all messages from a MessageReader until an error is returned.
func drain(t *testing.T, r MessageReader) {
	t.Helper()
	for {
		_, err := r.ReadMessage()
		if err != nil {
			return
		}
	}
}

func startRawHTTPResponseServer(t *testing.T, response string) (string, <-chan error) {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}

	errCh := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		defer func() { _ = conn.Close() }()

		br := bufio.NewReader(conn)
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				errCh <- err
				return
			}
			if line == "\r\n" {
				break
			}
		}
		_, err = io.WriteString(conn, response)
		errCh <- err
	}()

	t.Cleanup(func() { _ = ln.Close() })
	return "http://" + ln.Addr().String(), errCh
}

func waitRawHTTPResponseServer(t *testing.T, errCh <-chan error) {
	t.Helper()
	if err := <-errCh; err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatalf("raw HTTP server: %v", err)
	}
}

func TestHTTPClient_JSONResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request headers.
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", ct)
		}
		if accept := r.Header.Get("Accept"); accept != "application/json, text/event-stream" {
			t.Errorf("Accept = %q, want %q", accept, "application/json, text/event-stream")
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, nil)
	reader, err := c.SendMessage(context.Background(), []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
	if err != nil {
		t.Fatalf("SendMessage: %v", err)
	}

	msg, err := reader.ReadMessage()
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
	if string(msg) != `{"jsonrpc":"2.0","id":1,"result":{}}` {
		t.Errorf("got %q", string(msg))
	}

	// Next read should return io.EOF.
	_, err = reader.ReadMessage()
	if !errors.Is(err, io.EOF) {
		t.Errorf("expected io.EOF after single JSON message, got %v", err)
	}
}

func TestHTTPClient_SSEResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: {\"id\":1}\n\ndata: {\"id\":2}\n\n"))
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, nil)
	reader, err := c.SendMessage(context.Background(), []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	if err != nil {
		t.Fatalf("SendMessage: %v", err)
	}

	msg1, err := reader.ReadMessage()
	if err != nil {
		t.Fatalf("ReadMessage 1: %v", err)
	}
	if string(msg1) != testJSONID1 {
		t.Errorf("msg1 = %q, want %q", string(msg1), testJSONID1)
	}

	msg2, err := reader.ReadMessage()
	if err != nil {
		t.Fatalf("ReadMessage 2: %v", err)
	}
	if string(msg2) != testJSONID2 {
		t.Errorf("msg2 = %q, want %q", string(msg2), testJSONID2)
	}

	// Next read should return io.EOF.
	_, err = reader.ReadMessage()
	if !errors.Is(err, io.EOF) {
		t.Errorf("expected io.EOF after SSE events, got %v", err)
	}
}

func TestHTTPClient_SendMessage_MalformedResponseSanitizesRequestError(t *testing.T) {
	const injected = "INJECTED-FORGED-LOG"
	url, errCh := startRawHTTPResponseServer(t, "HTTP/1.1 200 OK\r\n"+injected+"\r\nContent-Length: 0\r\n\r\n")

	c := NewHTTPClient(url, nil)
	_, err := c.SendMessage(context.Background(), []byte(`{"jsonrpc":"2.0","id":1,"method":"test"}`))
	if err == nil {
		t.Fatal("expected malformed upstream response error")
	}
	if !errors.Is(err, ErrUpstreamRequestFailed) {
		t.Fatalf("errors.Is(err, ErrUpstreamRequestFailed) = false; err=%v", err)
	}
	if strings.Contains(err.Error(), injected) {
		t.Fatalf("error leaked malformed upstream bytes: %q", err.Error())
	}
	waitRawHTTPResponseServer(t, errCh)
}

func TestHTTPClient_OpenGETStream_MalformedResponseSanitizesRequestError(t *testing.T) {
	const injected = "INJECTED-FORGED-GET-LOG"
	url, errCh := startRawHTTPResponseServer(t, "HTTP/1.1 200 OK\r\n"+injected+"\r\nContent-Type: text/event-stream\r\n\r\n")

	c := NewHTTPClient(url, nil)
	_, err := c.OpenGETStream(context.Background())
	if err == nil {
		t.Fatal("expected malformed upstream response error")
	}
	if !errors.Is(err, ErrUpstreamRequestFailed) {
		t.Fatalf("errors.Is(err, ErrUpstreamRequestFailed) = false; err=%v", err)
	}
	if strings.Contains(err.Error(), injected) {
		t.Fatalf("error leaked malformed upstream bytes: %q", err.Error())
	}
	waitRawHTTPResponseServer(t, errCh)
}

func TestHTTPClient_ClientDoCancellationPreserved(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	c := NewHTTPClient("http://127.0.0.1:1", nil)
	_, err := c.SendMessage(ctx, []byte(`{"jsonrpc":"2.0","id":1,"method":"test"}`))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("SendMessage error = %v, want context.Canceled", err)
	}
	_, err = c.OpenGETStream(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("OpenGETStream error = %v, want context.Canceled", err)
	}
}

func TestHTTPClient_SessionIDTracking(t *testing.T) {
	var calls atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		call := calls.Add(1)

		if call == 1 {
			// First call: no session ID expected, set one in response.
			if got := r.Header.Get("Mcp-Session-Id"); got != "" {
				t.Errorf("call 1: unexpected Mcp-Session-Id header: %q", got)
			}
			w.Header().Set("Mcp-Session-Id", "sess-abc-123")
		} else {
			// Second call: session ID should be sent.
			if got := r.Header.Get("Mcp-Session-Id"); got != "sess-abc-123" {
				t.Errorf("call 2: Mcp-Session-Id = %q, want %q", got, "sess-abc-123")
			}
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, nil)

	// First request: establishes session.
	r1, err := c.SendMessage(context.Background(), []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
	if err != nil {
		t.Fatalf("SendMessage 1: %v", err)
	}
	drain(t, r1)

	if c.SessionID() != "sess-abc-123" {
		t.Errorf("SessionID() = %q, want %q", c.SessionID(), "sess-abc-123")
	}

	// Second request: should include session ID.
	r2, err := c.SendMessage(context.Background(), []byte(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`))
	if err != nil {
		t.Fatalf("SendMessage 2: %v", err)
	}
	drain(t, r2)

	if calls.Load() != 2 {
		t.Errorf("expected 2 calls, got %d", calls.Load())
	}
}

func TestHTTPClient_202Accepted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, nil)
	reader, err := c.SendMessage(context.Background(), []byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`))
	if err != nil {
		t.Fatalf("SendMessage: %v", err)
	}

	// 202 Accepted means no response body - should get EOF immediately.
	_, err = reader.ReadMessage()
	if !errors.Is(err, io.EOF) {
		t.Errorf("expected io.EOF for 202 Accepted, got %v", err)
	}
}

func TestHTTPClient_ErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, nil)
	_, err := c.SendMessage(context.Background(), []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
}

func TestHTTPClient_ErrorStatusOmitsBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"session expired"}`))
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, nil)
	_, err := c.SendMessage(context.Background(), []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	if err == nil {
		t.Fatal("expected error for 400 response")
	}
	if strings.Contains(err.Error(), "session expired") || strings.Contains(err.Error(), "error") {
		t.Errorf("error should omit upstream body, got: %v", err)
	}
	if !strings.Contains(err.Error(), "400") {
		t.Errorf("error should include status code, got: %v", err)
	}
}

func TestHTTPClient_AuthHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer tok-123" {
			t.Errorf("Authorization = %q, want %q", got, "Bearer tok-123")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	defer srv.Close()

	headers := http.Header{}
	headers.Set("Authorization", "Bearer tok-123")

	c := NewHTTPClient(srv.URL, headers)
	reader, err := c.SendMessage(context.Background(), []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
	if err != nil {
		t.Fatalf("SendMessage: %v", err)
	}
	drain(t, reader)
}

func TestHTTPClient_RedirectBlocked(t *testing.T) {
	// Second server (the redirect target) should never be reached.
	var targetCalled atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		targetCalled.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	defer target.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, nil)
	// SendMessage should return an error for 3xx (redirects are disabled).
	_, err := c.SendMessage(context.Background(), []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
	if err == nil {
		t.Fatal("expected error for redirect response, got nil")
	}
	if !strings.Contains(err.Error(), "unexpected redirect") {
		t.Errorf("expected redirect error, got: %v", err)
	}

	// The critical security property: the target server should NOT be contacted.
	if targetCalled.Load() != 0 {
		t.Error("redirect target was contacted — SSRF vulnerability")
	}
}

func TestHTTPClient_HeaderImmutability(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	defer srv.Close()

	headers := http.Header{}
	headers.Set("X-Custom", "original")

	c := NewHTTPClient(srv.URL, headers)

	// Mutate the original headers after construction.
	headers.Set("X-Custom", "mutated")

	// Client should still use the original value.
	reader, err := c.SendMessage(context.Background(), []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
	if err != nil {
		t.Fatalf("SendMessage: %v", err)
	}
	drain(t, reader)

	if c.headers.Get("X-Custom") != "original" {
		t.Errorf("header was mutated: got %q, want %q", c.headers.Get("X-Custom"), "original")
	}
}

// TestNewHTTPClient_IgnoresAmbientProxyEnv locks the transport invariant that
// the MCP HTTP client dials its configured upstream directly: a nil Proxy so an
// ambient HTTP_PROXY/HTTPS_PROXY cannot silently redirect egress around the
// CLI-validated upstream and the redirect-disabled SSRF posture. Also asserts
// DisableCompression stays set so the compressed-stream guard cannot regress.
func TestNewHTTPClient_IgnoresAmbientProxyEnv(t *testing.T) {
	c := NewHTTPClient("https://upstream.example/mcp", nil)
	tr, ok := c.client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport type = %T, want *http.Transport", c.client.Transport)
	}
	if tr.Proxy != nil {
		t.Error("HTTP client transport Proxy must be nil (no ambient HTTP_PROXY chaining)")
	}
	if !tr.DisableCompression {
		t.Error("DisableCompression must stay set (compressed-stream guard)")
	}
}

func TestHTTPClient_ExtraHeadersCannotOverrideTransport(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extra headers should NOT override Content-Type or Accept.
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %q, want application/json (should not be overridden)", ct)
		}
		if accept := r.Header.Get("Accept"); accept != "application/json, text/event-stream" {
			t.Errorf("Accept = %q, should not be overridden", accept)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	defer srv.Close()

	headers := http.Header{}
	headers.Set("Content-Type", "text/plain")
	headers.Set("Accept", "text/html")
	c := NewHTTPClient(srv.URL, headers)
	reader, err := c.SendMessage(context.Background(), []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
	if err != nil {
		t.Fatalf("SendMessage: %v", err)
	}
	drain(t, reader)
}

// TestHTTPClient_ExtrasCannotInjectMcpSessionIdOnFirstRequest is the regression
// for a defense-in-depth gap that survived the original
// TestHTTPClient_ExtraHeadersCannotOverrideTransport: that test only checked
// Content-Type / Accept, both of which are unconditionally Set after the
// extras Add loop. Mcp-Session-Id was only Set when the client already had
// a session ID - so on the very first request (empty session ID) a caller-
// supplied "Mcp-Session-Id" in extras flowed through to the upstream and
// let an attacker pin session correlation to a value of their choice.
//
// The fix unconditionally Dels Mcp-Session-Id from the request headers before
// the conditional Set, so first-request extras cannot reach upstream. The
// CLI parser rejects this header at parse time too (see
// runtime.parseHeaderFlags), but this transport-level guard catches
// programmatic callers that build a *HTTPClient directly.
func TestHTTPClient_ExtrasCannotInjectMcpSessionIdOnFirstRequest(t *testing.T) {
	var seen string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("Mcp-Session-Id")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	defer srv.Close()

	headers := http.Header{}
	headers.Set("Mcp-Session-Id", "attacker-pinned-session")
	c := NewHTTPClient(srv.URL, headers)

	reader, err := c.SendMessage(context.Background(), []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
	if err != nil {
		t.Fatalf("SendMessage: %v", err)
	}
	drain(t, reader)

	if seen != "" {
		t.Fatalf("upstream Mcp-Session-Id = %q, want empty (extras must not pin session correlation on the first request)", seen)
	}
}

func TestHTTPClient_OpenGETStream_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "expected GET", http.StatusMethodNotAllowed)
			return
		}
		if got := r.Header.Get("Accept"); got != "text/event-stream" {
			t.Errorf("Accept = %q, want text/event-stream", got)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: {\"msg\":\"hello\"}\n\n"))
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, nil)
	reader, err := c.OpenGETStream(context.Background())
	if err != nil {
		t.Fatalf("OpenGETStream: %v", err)
	}

	msg, err := reader.ReadMessage()
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
	if string(msg) != `{"msg":"hello"}` {
		t.Errorf("got %q", string(msg))
	}
}

func TestHTTPClient_OpenGETStream_405(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusMethodNotAllowed)
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, nil)
	_, err := c.OpenGETStream(context.Background())
	if err == nil {
		t.Fatal("expected error for 405 response")
	}
	if !strings.Contains(err.Error(), "405") {
		t.Errorf("error should mention 405, got: %v", err)
	}
}

func TestHTTPClient_OpenGETStream_ErrorOmitsBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("invalid session"))
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, nil)
	_, err := c.OpenGETStream(context.Background())
	if err == nil {
		t.Fatal("expected error for 400 response")
	}
	if strings.Contains(err.Error(), "invalid session") {
		t.Errorf("error should omit upstream body, got: %v", err)
	}
	if !strings.Contains(err.Error(), "400") {
		t.Errorf("error should include status code, got: %v", err)
	}
}

func TestHTTPClient_OpenGETStream_ErrorNoBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, nil)
	_, err := c.OpenGETStream(context.Background())
	if err == nil {
		t.Fatal("expected error for 403 response")
	}
	if !strings.Contains(err.Error(), "403") {
		t.Errorf("error should mention 403, got: %v", err)
	}
}

func TestHTTPClient_OpenGETStream_IncludesSessionID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.Header().Set("Mcp-Session-Id", "sess-get-test")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
			return
		}
		// GET: verify session ID header.
		if got := r.Header.Get("Mcp-Session-Id"); got != "sess-get-test" {
			t.Errorf("GET Mcp-Session-Id = %q, want %q", got, "sess-get-test")
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: {}\n\n"))
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, nil)

	// Establish session with POST.
	r, err := c.SendMessage(context.Background(), []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
	if err != nil {
		t.Fatalf("SendMessage: %v", err)
	}
	drain(t, r)

	// GET should include session ID.
	reader, err := c.OpenGETStream(context.Background())
	if err != nil {
		t.Fatalf("OpenGETStream: %v", err)
	}
	drain(t, reader)
}

func TestHTTPClient_ErrorResponseDoesNotOverwriteSessionID(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		callCount++
		if callCount == 1 {
			w.Header().Set("Mcp-Session-Id", "good-session")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
			return
		}
		w.Header().Set("Mcp-Session-Id", "evil-session")
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, nil)

	reader, err := c.SendMessage(context.Background(), []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
	if err != nil {
		t.Fatalf("first SendMessage: %v", err)
	}
	drain(t, reader)
	if c.SessionID() != "good-session" {
		t.Fatalf("session not established: got %q", c.SessionID())
	}

	_, err = c.SendMessage(context.Background(), []byte(`{"jsonrpc":"2.0","id":2,"method":"test"}`))
	if err == nil {
		t.Fatal("expected error for 500")
	}
	if c.SessionID() != "good-session" {
		t.Errorf("session ID overwritten by error response: got %q, want %q", c.SessionID(), "good-session")
	}
}

func TestHTTPClient_DeleteSession_Success(t *testing.T) {
	var deleteCalled atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.Header().Set("Mcp-Session-Id", "sess-del-test")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
			return
		}
		if r.Method == http.MethodDelete {
			deleteCalled.Add(1)
			if got := r.Header.Get("Mcp-Session-Id"); got != "sess-del-test" {
				t.Errorf("DELETE Mcp-Session-Id = %q, want %q", got, "sess-del-test")
			}
			w.WriteHeader(http.StatusOK)
			return
		}
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, nil)
	r, err := c.SendMessage(context.Background(), []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
	if err != nil {
		t.Fatalf("SendMessage: %v", err)
	}
	drain(t, r)

	var logBuf strings.Builder
	c.DeleteSession(&logBuf)

	if deleteCalled.Load() != 1 {
		t.Error("expected DELETE to be called")
	}
	if logBuf.Len() != 0 {
		t.Errorf("unexpected log output: %s", logBuf.String())
	}
	if c.SessionID() != "" {
		t.Errorf("sessionID should be cleared after delete, got %q", c.SessionID())
	}
}

func TestHTTPClient_DeleteSession_NoSession(t *testing.T) {
	var serverCalled atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		serverCalled.Add(1)
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, nil)
	c.DeleteSession(nil)

	if serverCalled.Load() != 0 {
		t.Error("server should not be called when no session exists")
	}
}

func TestHTTPClient_DeleteSession_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.Header().Set("Mcp-Session-Id", "sess-err")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, nil)
	r, err := c.SendMessage(context.Background(), []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
	if err != nil {
		t.Fatalf("SendMessage: %v", err)
	}
	drain(t, r)

	var logBuf strings.Builder
	c.DeleteSession(&logBuf)

	if !strings.Contains(logBuf.String(), "500") {
		t.Errorf("expected 500 in log, got: %s", logBuf.String())
	}
}

func TestHTTPClient_DeleteSession_ConnectionError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.Header().Set("Mcp-Session-Id", "sess-conn-err")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
			return
		}
	}))

	c := NewHTTPClient(srv.URL, nil)
	r, err := c.SendMessage(context.Background(), []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
	if err != nil {
		t.Fatalf("SendMessage: %v", err)
	}
	drain(t, r)

	srv.Close()

	var logBuf strings.Builder
	c.DeleteSession(&logBuf)

	if !strings.Contains(logBuf.String(), "session delete") {
		t.Errorf("expected connection error log, got: %s", logBuf.String())
	}
}

func TestHTTPClient_DeleteSession_MalformedResponseLogsSentinel(t *testing.T) {
	const injected = "INJECTED-DELETE-FORGED-LOG"
	url, errCh := startRawHTTPResponseServer(t, "HTTP/1.1 204 No Content\r\n"+injected+"\r\n\r\n")

	c := NewHTTPClient(url, nil)
	c.sessionID = "sess-malformed-delete"

	var logBuf strings.Builder
	c.DeleteSession(&logBuf)
	if !strings.Contains(logBuf.String(), ErrUpstreamRequestFailed.Error()) {
		t.Fatalf("delete log = %q, want sentinel", logBuf.String())
	}
	if strings.Contains(logBuf.String(), injected) {
		t.Fatalf("delete log leaked malformed upstream bytes: %q", logBuf.String())
	}
	if c.SessionID() != "" {
		t.Fatalf("session ID = %q, want cleared after failed DELETE attempt", c.SessionID())
	}
	waitRawHTTPResponseServer(t, errCh)
}

func TestHTTPClient_DeleteSession_ConnectionError_NilLog(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.Header().Set("Mcp-Session-Id", "sess-nil-log")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
			return
		}
	}))

	c := NewHTTPClient(srv.URL, nil)
	r, err := c.SendMessage(context.Background(), []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
	if err != nil {
		t.Fatalf("SendMessage: %v", err)
	}
	drain(t, r)

	srv.Close()

	c.DeleteSession(nil)
}

func TestErrStreamNotSupported_Sentinel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusMethodNotAllowed)
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, nil)
	_, err := c.OpenGETStream(context.Background())
	if err == nil {
		t.Fatal("expected error for 405")
	}
	if !errors.Is(err, ErrStreamNotSupported) {
		t.Errorf("expected errors.Is(err, ErrStreamNotSupported) = true, got false; err: %v", err)
	}
}

func TestHTTPClient_OpenGETStream_3xxRedirect(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: {}\n\n"))
	}))
	defer target.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, nil)
	_, err := c.OpenGETStream(context.Background())
	if err == nil {
		t.Fatal("expected error for 3xx redirect, got nil")
	}
	if !strings.Contains(err.Error(), "unexpected redirect") {
		t.Errorf("expected redirect error message, got: %v", err)
	}
}

func TestHTTPClient_SendMessage_3xxRedirect(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	defer target.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusMovedPermanently)
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, nil)
	_, err := c.SendMessage(context.Background(), []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
	if err == nil {
		t.Fatal("expected error for 3xx redirect, got nil")
	}
	if !strings.Contains(err.Error(), "unexpected redirect") {
		t.Errorf("expected redirect error message, got: %v", err)
	}
}

func TestHTTPClient_DeleteSession_ServerError_NilLog(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.Header().Set("Mcp-Session-Id", "sess-err-nillog")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, nil)
	r, err := c.SendMessage(context.Background(), []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
	if err != nil {
		t.Fatalf("SendMessage: %v", err)
	}
	drain(t, r)

	c.DeleteSession(nil)
}

func TestHTTPClient_OpenGETStream_IncludesHeaders(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: {}\n\n"))
	}))
	defer srv.Close()

	headers := http.Header{"Authorization": []string{"Bearer test-token"}}
	c := NewHTTPClient(srv.URL, headers)
	reader, err := c.OpenGETStream(context.Background())
	if err != nil {
		t.Fatalf("OpenGETStream: %v", err)
	}
	drain(t, reader)

	if gotAuth != "Bearer test-token" {
		t.Errorf("expected Authorization header, got %q", gotAuth)
	}
}

func TestHTTPClient_DeleteSession_IncludesExtraHeaders(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.Header().Set("Mcp-Session-Id", "sess-hdr")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
			return
		}
		if r.Method == http.MethodDelete {
			gotAuth = r.Header.Get("Authorization")
			w.WriteHeader(http.StatusOK)
			return
		}
	}))
	defer srv.Close()

	headers := http.Header{"Authorization": []string{"Bearer delete-tok"}}
	c := NewHTTPClient(srv.URL, headers)

	r, err := c.SendMessage(context.Background(), []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
	if err != nil {
		t.Fatalf("SendMessage: %v", err)
	}
	drain(t, r)

	c.DeleteSession(nil)

	if gotAuth != "Bearer delete-tok" {
		t.Errorf("DELETE should include Authorization header, got %q", gotAuth)
	}
}

func TestHTTPClient_DeleteSession_BadURL(t *testing.T) {
	c := &HTTPClient{
		url:       "http://\x00invalid",
		headers:   http.Header{},
		client:    &http.Client{},
		sessionID: "force-delete",
	}

	var logBuf strings.Builder
	c.DeleteSession(&logBuf)
	if !strings.Contains(logBuf.String(), "session delete") {
		t.Errorf("expected error log for bad URL, got: %s", logBuf.String())
	}
}

func TestHTTPClient_SendMessage_EmptyBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Empty response body.
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, nil)
	reader, err := c.SendMessage(context.Background(), []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	if err != nil {
		t.Fatalf("SendMessage: %v", err)
	}

	_, err = reader.ReadMessage()
	if !errors.Is(err, io.EOF) {
		t.Errorf("expected io.EOF for empty body, got %v", err)
	}
}

func TestHTTPClient_SendMessage_BadURL(t *testing.T) {
	c := &HTTPClient{
		url:     "http://\x00invalid",
		headers: http.Header{},
		client:  &http.Client{},
	}
	_, err := c.SendMessage(context.Background(), []byte(`{"jsonrpc":"2.0","id":1,"method":"test"}`))
	if err == nil {
		t.Fatal("expected error for bad URL")
	}
	if !strings.Contains(err.Error(), "creating request") {
		t.Errorf("expected 'creating request' error, got: %v", err)
	}
}

func TestHTTPClient_OpenGETStream_BadURL(t *testing.T) {
	c := &HTTPClient{
		url:     "http://\x00invalid",
		headers: http.Header{},
		client:  &http.Client{},
	}
	_, err := c.OpenGETStream(context.Background())
	if err == nil {
		t.Fatal("expected error for bad URL")
	}
	if !strings.Contains(err.Error(), "creating GET request") {
		t.Errorf("expected 'creating GET request' error, got: %v", err)
	}
}

func TestHTTPClient_SingleMessageReader_ReadError(t *testing.T) {
	errReader := &errReadCloser{err: errors.New("disk failure")}
	r := &SingleMessageReader{Body: errReader}

	_, err := r.ReadMessage()
	if err == nil {
		t.Fatal("expected error from ReadMessage")
	}
	if !strings.Contains(err.Error(), "disk failure") {
		t.Errorf("expected wrapped disk failure, got: %v", err)
	}
}

// errReadCloser is a ReadCloser that always returns an error.
type errReadCloser struct {
	err error
}

func (r *errReadCloser) Read(_ []byte) (int, error) {
	return 0, r.err
}

func (r *errReadCloser) Close() error {
	return nil
}

type closeRecordingBody struct {
	closed atomic.Int32
}

func (*closeRecordingBody) Read(_ []byte) (int, error) {
	return 0, io.EOF
}

func (b *closeRecordingBody) Close() error {
	b.closed.Add(1)
	return nil
}

func TestHTTPClient_ResponseReadersCloseBody(t *testing.T) {
	tests := []struct {
		name   string
		reader func(*closeRecordingBody) io.Closer
	}{
		{
			name: "single message reader",
			reader: func(body *closeRecordingBody) io.Closer {
				return &SingleMessageReader{Body: body}
			},
		},
		{
			name: "sse reader",
			reader: func(body *closeRecordingBody) io.Closer {
				return &closingSSEReader{sse: NewSSEReader(body), body: body}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := &closeRecordingBody{}
			reader := tt.reader(body)
			if err := reader.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}
			if body.closed.Load() != 1 {
				t.Fatalf("body close count = %d, want 1", body.closed.Load())
			}
		})
	}
}

func TestHTTPClient_ErrorStatusEmptyBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, nil)
	_, err := c.SendMessage(context.Background(), []byte(`{"jsonrpc":"2.0","id":1,"method":"test"}`))
	if err == nil {
		t.Fatal("expected error for 403")
	}
	if !strings.Contains(err.Error(), "403") {
		t.Errorf("expected 403 in error, got: %v", err)
	}
}

func TestHTTPClient_ErrorStatusDoesNotEchoUpstreamBody(t *testing.T) {
	const attackerBody = "upstream secret\r\nforged-log-line"
	for _, method := range []string{http.MethodPost, http.MethodGet} {
		t.Run(method, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != method {
					t.Fatalf("method = %s, want %s", r.Method, method)
				}
				http.Error(w, attackerBody, http.StatusInternalServerError)
			}))
			defer srv.Close()

			c := NewHTTPClient(srv.URL, nil)
			var err error
			if method == http.MethodPost {
				_, err = c.SendMessage(context.Background(), []byte(`{"jsonrpc":"2.0","id":1,"method":"test"}`))
			} else {
				_, err = c.OpenGETStream(context.Background())
			}
			if err == nil {
				t.Fatal("expected error for upstream 500")
			}
			if strings.Contains(err.Error(), attackerBody) ||
				strings.Contains(err.Error(), "upstream secret") ||
				strings.Contains(err.Error(), "forged-log-line") {
				t.Fatalf("error echoed upstream body: %q", err.Error())
			}
			if !strings.Contains(err.Error(), "500") {
				t.Fatalf("error = %q, want status code", err.Error())
			}
		})
	}
}

func writeSwitchingProtocolsResponse(t *testing.T, w http.ResponseWriter, contentType, body string) {
	t.Helper()
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		t.Fatal("response writer does not support hijacking")
	}
	conn, _, err := hijacker.Hijack()
	if err != nil {
		t.Fatalf("hijack: %v", err)
	}
	defer func() { _ = conn.Close() }()
	_, _ = io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nContent-Type: "+contentType+"\r\nConnection: Upgrade\r\nUpgrade: mcp-test\r\n\r\n"+body)
}

func TestHTTPClient_SendMessage_Unexpected2xxStatusFailsClosed(t *testing.T) {
	for _, status := range []int{http.StatusSwitchingProtocols, http.StatusCreated, http.StatusNonAuthoritativeInfo, http.StatusNoContent, http.StatusPartialContent} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if status == http.StatusSwitchingProtocols {
					writeSwitchingProtocolsResponse(t, w, "application/json", `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"unexpected 2xx body must not leak"}]}}`)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(status)
				_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"unexpected 2xx body must not leak"}]}}`))
			}))
			defer srv.Close()

			c := NewHTTPClient(srv.URL, nil)
			reader, err := c.SendMessage(context.Background(), []byte(`{"jsonrpc":"2.0","id":1,"method":"test"}`))
			if err == nil {
				if reader != nil {
					msg, readErr := reader.ReadMessage()
					t.Fatalf("SendMessage returned reader for unexpected HTTP %d; first message=%q readErr=%v", status, msg, readErr)
				}
				t.Fatalf("expected fail-closed error for unexpected HTTP %d", status)
			}
			if strings.Contains(err.Error(), "unexpected 2xx body must not leak") {
				t.Fatalf("error echoed upstream body: %q", err.Error())
			}
			if !strings.Contains(err.Error(), strconv.Itoa(status)) {
				t.Fatalf("error = %q, want status code %d", err.Error(), status)
			}
		})
	}
}

func TestHTTPClient_IsSSEContentTypeExact(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		want        bool
	}{
		{name: "bare", contentType: "text/event-stream", want: true},
		{name: "charset", contentType: "text/event-stream; charset=utf-8", want: true},
		{name: "uppercase", contentType: "TEXT/EVENT-STREAM", want: true},
		{name: "leading whitespace", contentType: " text/event-stream", want: true},
		{name: "trailing whitespace", contentType: "text/event-stream ", want: true},
		{name: "missing", contentType: "", want: false},
		{name: "json", contentType: "application/json", want: false},
		{name: "suffix lookalike", contentType: "text/event-streamx", want: false},
		{name: "trailing junk", contentType: "text/event-stream junk", want: false},
		{name: "long suffix lookalike", contentType: "text/event-stream" + strings.Repeat("x", 8192), want: false},
		{name: "invalid parameter", contentType: "text/event-stream; charset", want: false},
		{name: "comma joined", contentType: "text/event-stream, application/json", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsSSEContentType(tt.contentType); got != tt.want {
				t.Fatalf("IsSSEContentType(%q) = %v, want %v", tt.contentType, got, tt.want)
			}
		})
	}
}

func TestHTTPClient_HasSingleSSEContentTypeRejectsPathologicalHeaders(t *testing.T) {
	manyValues := make(http.Header)
	for range 4096 {
		manyValues.Add("Content-Type", "text/event-stream")
	}
	if HasSingleSSEContentType(manyValues) {
		t.Fatal("expected repeated Content-Type values to fail closed")
	}

	longInvalid := "text/event-stream" + strings.Repeat("; charset", 4096)
	if IsSSEContentType(longInvalid) {
		t.Fatal("expected long malformed Content-Type to fail closed")
	}
}

func TestHTTPClient_SendMessage_ErrorStatusDoesNotEchoReasonPhrase(t *testing.T) {
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	errCh := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		defer func() { _ = conn.Close() }()

		br := bufio.NewReader(conn)
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				errCh <- err
				return
			}
			if line == "\r\n" {
				break
			}
		}
		_, err = io.WriteString(conn, "HTTP/1.1 500 upstream secret forged-log-line\r\nContent-Length: 0\r\n\r\n")
		errCh <- err
	}()

	c := NewHTTPClient("http://"+ln.Addr().String(), nil)
	_, err = c.SendMessage(context.Background(), []byte(`{"jsonrpc":"2.0","id":1,"method":"test"}`))
	if err == nil {
		t.Fatal("expected error for upstream 500")
	}
	if strings.Contains(err.Error(), "upstream secret") || strings.Contains(err.Error(), "forged-log-line") {
		t.Fatalf("error echoed upstream reason phrase: %q", err.Error())
	}
	if !strings.Contains(err.Error(), "500") {
		t.Fatalf("error = %q, want status code", err.Error())
	}

	if serveErr := <-errCh; serveErr != nil {
		t.Fatalf("raw HTTP server: %v", serveErr)
	}
}

func TestHTTPClient_SingleMessageReader_Overflow(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":"`))
		_, _ = w.Write(make([]byte, MaxLineSize))
		_, _ = w.Write([]byte(`"}`))
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, nil)
	reader, err := c.SendMessage(context.Background(), []byte(`{"jsonrpc":"2.0","id":1,"method":"test"}`))
	if err != nil {
		t.Fatalf("SendMessage: %v", err)
	}
	_, err = reader.ReadMessage()
	if err == nil {
		t.Fatal("expected overflow error")
	}
	if !strings.Contains(err.Error(), "exceeds maximum size") {
		t.Errorf("expected 'exceeds maximum size' error, got: %v", err)
	}
}

// TestHTTPClient_SendMessage_CompressedResponseBlocked covers the streamable
// HTTP transport: SendMessage hands the response body to
// SingleMessageReader/closingSSEReader, both of which see opaque bytes
// after this point. Compressed responses must fail closed at the transport
// boundary or the body scanners run on garbage and silently miss content.
func TestHTTPClient_SendMessage_CompressedResponseBlocked(t *testing.T) {
	for _, enc := range []string{"gzip", "br", "zstd"} {
		t.Run(enc, func(t *testing.T) {
			for _, contentType := range []string{"application/json", "text/event-stream"} {
				t.Run(contentType, func(t *testing.T) {
					srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						w.Header().Set("Content-Type", contentType)
						w.Header().Set("Content-Encoding", enc)
						_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
					}))
					defer srv.Close()

					c := NewHTTPClient(srv.URL, nil)
					_, err := c.SendMessage(context.Background(), []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
					if !errors.Is(err, ErrCompressedResponse) {
						t.Fatalf("expected ErrCompressedResponse on Content-Encoding=%s Content-Type=%s, got %v", enc, contentType, err)
					}
				})
			}
		})
	}
}

func TestHTTPClient_OpenGETStream_NonSSEContentTypeFailsClosed(t *testing.T) {
	for _, contentType := range []string{"application/json", "text/event-streamx"} {
		t.Run(contentType, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Fatalf("method = %s, want GET", r.Method)
				}
				w.Header().Set("Content-Type", contentType)
				_, _ = w.Write([]byte("data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\"}\n\n"))
			}))
			defer srv.Close()

			c := NewHTTPClient(srv.URL, nil)
			reader, err := c.OpenGETStream(context.Background())
			if err == nil {
				if reader != nil {
					_, readErr := reader.ReadMessage()
					t.Fatalf("OpenGETStream returned reader instead of fail-closed error; first read err=%v", readErr)
				}
				t.Fatal("expected fail-closed error for non-SSE GET stream")
			}
			if !errors.Is(err, ErrNonSSEStreamResponse) {
				t.Fatalf("expected ErrNonSSEStreamResponse, got %v", err)
			}
		})
	}
}

func TestHTTPClient_OpenGETStream_MultipleContentTypesFailClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("method = %s, want GET", r.Method)
		}
		w.Header().Add("Content-Type", "text/event-stream")
		w.Header().Add("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","method":"notifications/message"}`))
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, nil)
	reader, err := c.OpenGETStream(context.Background())
	if err == nil {
		if reader != nil {
			_, readErr := reader.ReadMessage()
			t.Fatalf("OpenGETStream returned reader instead of fail-closed error; first read err=%v", readErr)
		}
		t.Fatal("expected fail-closed error for multiple Content-Type values")
	}
	if !errors.Is(err, ErrNonSSEStreamResponse) {
		t.Fatalf("expected ErrNonSSEStreamResponse, got %v", err)
	}
}

func TestHTTPClient_OpenGETStream_NonOKSuccessStatusFailsClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("method = %s, want GET", r.Method)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, nil)
	reader, err := c.OpenGETStream(context.Background())
	if err == nil {
		if reader != nil {
			_, readErr := reader.ReadMessage()
			t.Fatalf("OpenGETStream returned reader instead of fail-closed error; first read err=%v", readErr)
		}
		t.Fatal("expected fail-closed error for non-200 GET stream status")
	}
	if !strings.Contains(err.Error(), "204") {
		t.Fatalf("error = %q, want status code", err.Error())
	}
}

// TestHTTPClient_OpenGETStream_CompressedResponseBlocked mirrors the
// SendMessage check for the GET SSE path. SSEReader can't parse a gzipped
// event stream; without DisableCompression + this guard, a compressed SSE
// response would be silently dropped by the stream parser and the streaming
// scanners would never see content.
func TestHTTPClient_OpenGETStream_CompressedResponseBlocked(t *testing.T) {
	for _, enc := range []string{"gzip", "br", "zstd"} {
		t.Run(enc, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Errorf("expected GET, got %s", r.Method)
				}
				w.Header().Set("Content-Type", "text/event-stream")
				w.Header().Set("Content-Encoding", enc)
				_, _ = w.Write([]byte("data: {}\n\n"))
			}))
			defer srv.Close()

			c := NewHTTPClient(srv.URL, nil)
			_, err := c.OpenGETStream(context.Background())
			if !errors.Is(err, ErrCompressedResponse) {
				t.Fatalf("expected ErrCompressedResponse on Content-Encoding=%s, got %v", enc, err)
			}
		})
	}
}

func TestHTTPClient_ClosingSSEReader_DoubleRead(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: {}\n\n"))
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, nil)
	reader, err := c.SendMessage(context.Background(), []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	if err != nil {
		t.Fatalf("SendMessage: %v", err)
	}

	// Read the event.
	_, _ = reader.ReadMessage()
	// Read until EOF.
	_, _ = reader.ReadMessage()
	// Subsequent reads after body close should return EOF, not panic.
	_, err = reader.ReadMessage()
	if !errors.Is(err, io.EOF) {
		t.Errorf("expected io.EOF on third read, got %v", err)
	}
}
