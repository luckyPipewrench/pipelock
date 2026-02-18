package mcp

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
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
	reader, err := c.SendMessage([]byte(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
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
	reader, err := c.SendMessage([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
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
	r1, err := c.SendMessage([]byte(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
	if err != nil {
		t.Fatalf("SendMessage 1: %v", err)
	}
	drain(t, r1)

	if c.SessionID() != "sess-abc-123" {
		t.Errorf("SessionID() = %q, want %q", c.SessionID(), "sess-abc-123")
	}

	// Second request: should include session ID.
	r2, err := c.SendMessage([]byte(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`))
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
	reader, err := c.SendMessage([]byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`))
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
	_, err := c.SendMessage([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	if err == nil {
		t.Fatal("expected error for 500 response")
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
	reader, err := c.SendMessage([]byte(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
	if err != nil {
		t.Fatalf("SendMessage: %v", err)
	}
	drain(t, reader)
}
