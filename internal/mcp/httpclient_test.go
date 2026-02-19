package mcp

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
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

func TestHTTPClient_JSONResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request headers.
		if ct := r.Header.Get("Content-Type"); ct != "application/json" { //nolint:goconst // test value
			t.Errorf("Content-Type = %q, want application/json", ct)
		}
		if accept := r.Header.Get("Accept"); accept != "application/json, text/event-stream" { //nolint:goconst // test value
			t.Errorf("Accept = %q, want %q", accept, "application/json, text/event-stream")
		}

		w.Header().Set("Content-Type", "application/json") //nolint:goconst // test value
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
	if string(msg) != `{"jsonrpc":"2.0","id":1,"result":{}}` { //nolint:goconst // test value
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
		w.Header().Set("Content-Type", "text/event-stream") //nolint:goconst // test value
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
	if string(msg1) != `{"id":1}` { //nolint:goconst // test value
		t.Errorf("msg1 = %q, want %q", string(msg1), `{"id":1}`)
	}

	msg2, err := reader.ReadMessage()
	if err != nil {
		t.Fatalf("ReadMessage 2: %v", err)
	}
	if string(msg2) != `{"id":2}` { //nolint:goconst // test value
		t.Errorf("msg2 = %q, want %q", string(msg2), `{"id":2}`)
	}

	// Next read should return io.EOF.
	_, err = reader.ReadMessage()
	if !errors.Is(err, io.EOF) {
		t.Errorf("expected io.EOF after SSE events, got %v", err)
	}
}

func TestHTTPClient_SessionIDTracking(t *testing.T) {
	var calls atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		call := calls.Add(1)

		if call == 1 {
			// First call: no session ID expected, set one in response.
			if got := r.Header.Get("Mcp-Session-Id"); got != "" { //nolint:goconst // test value
				t.Errorf("call 1: unexpected Mcp-Session-Id header: %q", got)
			}
			w.Header().Set("Mcp-Session-Id", "sess-abc-123") //nolint:goconst // test value
		} else {
			// Second call: session ID should be sent.
			if got := r.Header.Get("Mcp-Session-Id"); got != "sess-abc-123" { //nolint:goconst // test value
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

	// 202 Accepted means no response body — should get EOF immediately.
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

func TestHTTPClient_ErrorStatusIncludesBody(t *testing.T) {
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
	if !strings.Contains(err.Error(), "session expired") {
		t.Errorf("error should include body, got: %v", err)
	}
}

func TestHTTPClient_AuthHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer tok-123" { //nolint:goconst // test value
			t.Errorf("Authorization = %q, want %q", got, "Bearer tok-123")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	defer srv.Close()

	headers := http.Header{}
	headers.Set("Authorization", "Bearer tok-123") //nolint:goconst // test value

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
		w.Header().Set("Content-Type", "application/json") //nolint:goconst // test value
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
		w.Header().Set("Content-Type", "application/json") //nolint:goconst // test value
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	defer srv.Close()

	headers := http.Header{}
	headers.Set("X-Custom", "original") //nolint:goconst // test value

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

func TestHTTPClient_ExtraHeadersCannotOverrideTransport(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extra headers should NOT override Content-Type or Accept.
		if ct := r.Header.Get("Content-Type"); ct != "application/json" { //nolint:goconst // test value
			t.Errorf("Content-Type = %q, want application/json (should not be overridden)", ct)
		}
		if accept := r.Header.Get("Accept"); accept != "application/json, text/event-stream" { //nolint:goconst // test value
			t.Errorf("Accept = %q, should not be overridden", accept)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	defer srv.Close()

	headers := http.Header{}
	headers.Set("Content-Type", "text/plain") //nolint:goconst // test value
	headers.Set("Accept", "text/html")        //nolint:goconst // test value
	c := NewHTTPClient(srv.URL, headers)
	reader, err := c.SendMessage(context.Background(), []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
	if err != nil {
		t.Fatalf("SendMessage: %v", err)
	}
	drain(t, reader)
}

func TestHTTPClient_OpenGETStream_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "expected GET", http.StatusMethodNotAllowed)
			return
		}
		if got := r.Header.Get("Accept"); got != "text/event-stream" { //nolint:goconst // test value
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

func TestHTTPClient_OpenGETStream_ErrorWithBody(t *testing.T) {
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
	if !strings.Contains(err.Error(), "invalid session") {
		t.Errorf("error should include body, got: %v", err)
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
			w.Header().Set("Mcp-Session-Id", "sess-get-test") //nolint:goconst // test value
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
			return
		}
		// GET: verify session ID header.
		if got := r.Header.Get("Mcp-Session-Id"); got != "sess-get-test" { //nolint:goconst // test value
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

func TestHTTPClient_DeleteSession_Success(t *testing.T) {
	var deleteCalled atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.Header().Set("Mcp-Session-Id", "sess-del-test") //nolint:goconst // test value
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
			return
		}
		if r.Method == http.MethodDelete {
			deleteCalled.Add(1)
			if got := r.Header.Get("Mcp-Session-Id"); got != "sess-del-test" { //nolint:goconst // test value
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
	// Session ID should be cleared after successful delete.
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
			w.Header().Set("Mcp-Session-Id", "sess-err") //nolint:goconst // test value
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
	// Start server, establish session, then close server before DELETE.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.Header().Set("Mcp-Session-Id", "sess-conn-err") //nolint:goconst // test value
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

	// Close the server before DELETE — should log connection error.
	srv.Close()

	var logBuf strings.Builder
	c.DeleteSession(&logBuf)

	if !strings.Contains(logBuf.String(), "session delete") {
		t.Errorf("expected connection error log, got: %s", logBuf.String())
	}
}

func TestHTTPClient_DeleteSession_ConnectionError_NilLog(t *testing.T) {
	// Same as above but with nil logW — should not panic.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.Header().Set("Mcp-Session-Id", "sess-nil-log") //nolint:goconst // test value
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

	// Should not panic with nil logW.
	c.DeleteSession(nil)
}

func TestErrStreamNotSupported_Sentinel(t *testing.T) {
	// Verify errors.Is works with the wrapped sentinel.
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
	// GET to a redirecting server — redirect-following is disabled, so the
	// 302 status is returned directly. OpenGETStream should reject 3xx
	// responses as errors (consistent with SendMessage's fail-closed design).
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
	// SendMessage rejects 3xx responses (redirects are disabled).
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json") //nolint:goconst // test value
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
	// Server returns 500 but logW is nil — should not panic.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.Header().Set("Mcp-Session-Id", "sess-err-nillog") //nolint:goconst // test value
			w.Header().Set("Content-Type", "application/json")  //nolint:goconst // test value
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

	// Should not panic with nil logW and 500 response.
	c.DeleteSession(nil)
}

func TestHTTPClient_OpenGETStream_IncludesHeaders(t *testing.T) {
	// Verify extra headers are sent with GET stream requests.
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "text/event-stream") //nolint:goconst // test value
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
	// Verify that extra headers (e.g., Authorization) are sent with DELETE requests.
	// Previous tests used nil headers — this exercises the header-copy loop (lines 267-270).
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.Header().Set("Mcp-Session-Id", "sess-hdr") //nolint:goconst // test value
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
	// Exercise the req-creation error branch in DeleteSession (lines 261-265).
	// Use a URL with a control character that http.NewRequestWithContext rejects.
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
		w.Header().Set("Content-Type", "application/json") //nolint:goconst // test value
		// Empty response body.
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, nil)
	reader, err := c.SendMessage(context.Background(), []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	if err != nil {
		t.Fatalf("SendMessage: %v", err)
	}

	// Empty body should return EOF.
	_, err = reader.ReadMessage()
	if !errors.Is(err, io.EOF) {
		t.Errorf("expected io.EOF for empty body, got %v", err)
	}
}

func TestHTTPClient_SendMessage_BadURL(t *testing.T) {
	// Exercise the req-creation error branch (line 68-70).
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
	// Exercise the req-creation error branch in OpenGETStream (line 198-200).
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
	// Exercise the ReadAll error branch in singleMessageReader (line 161-163).
	errReader := &errReadCloser{err: errors.New("disk failure")}
	r := &singleMessageReader{body: errReader}

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

func TestHTTPClient_ErrorStatusEmptyBody(t *testing.T) {
	// Exercise the empty-body branch of error status (line 121).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		// No body written.
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

func TestHTTPClient_ClosingSSEReader_DoubleRead(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream") //nolint:goconst // test value
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
