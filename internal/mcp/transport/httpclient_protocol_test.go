// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const protocolTestVersion = "2025-06-18"

func TestHTTPClientNegotiatedProtocolRequests(t *testing.T) {
	for _, sse := range []bool{false, true} {
		t.Run(fmt.Sprintf("sse=%t", sse), func(t *testing.T) {
			seen := make(chan string, 8)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seen <- r.Method + ":" + strings.Join(r.Header.Values("Mcp-Protocol-Version"), ",")
				body, _ := io.ReadAll(r.Body)
				if strings.Contains(string(body), `"method":"initialize"`) {
					w.Header().Set("Mcp-Session-Id", "protocol-session")
					response := `{"jsonrpc":"2.0","id":"init","result":{"protocolVersion":"2025-06-18"}}`
					if sse {
						w.Header().Set("Content-Type", "text/event-stream")
						_, _ = fmt.Fprintf(w, "data: %s\n\n", response)
					} else {
						w.Header().Set("Content-Type", "application/json")
						_, _ = io.WriteString(w, response)
					}
					return
				}
				if r.Header.Get("Mcp-Protocol-Version") != protocolTestVersion {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				switch r.Method {
				case http.MethodGet:
					w.Header().Set("Content-Type", "text/event-stream")
					_, _ = io.WriteString(w, "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/ping\"}\n\n")
				case http.MethodDelete:
					w.WriteHeader(http.StatusNoContent)
				default:
					w.WriteHeader(http.StatusAccepted)
				}
			}))
			defer srv.Close()
			c := NewHTTPClient(srv.URL, http.Header{"Mcp-Protocol-Version": {"2025-03-26", "2024-11-05"}})
			r, err := c.SendMessage(t.Context(), []byte(`{"jsonrpc":"2.0","id":"init","method":"initialize","params":{"protocolVersion":"2025-06-18"}}`))
			if err != nil {
				t.Fatal(err)
			}
			drain(t, r)
			if got := <-seen; got != "POST:2025-03-26,2024-11-05" {
				t.Fatalf("initial explicit headers = %q", got)
			}
			r, err = c.SendMessage(t.Context(), []byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`))
			if err != nil {
				t.Fatalf("initialized: %v", err)
			}
			drain(t, r)
			r, err = c.OpenGETStream(t.Context())
			if err != nil {
				t.Fatalf("GET: %v", err)
			}
			drain(t, r)
			c.DeleteSession(nil)
			for _, method := range []string{http.MethodPost, http.MethodGet, http.MethodDelete} {
				if got := <-seen; got != method+":"+protocolTestVersion {
					t.Fatalf("negotiated request = %q", got)
				}
			}
			_, _ = c.SendMessage(t.Context(), []byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`))
			if got := <-seen; got != "POST:2025-03-26,2024-11-05" {
				t.Fatalf("deleted state retained version: %q", got)
			}
		})
	}
}

func TestHTTPClientProtocolResponseValidation(t *testing.T) {
	for _, tc := range []struct {
		name, request, response, want string
	}{
		{"valid", `{"jsonrpc":"2.0","id":1,"method":"initialize"}`, `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18"}}`, protocolTestVersion},
		{"server selects older", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`, `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26"}}`, "2025-03-26"},
		{"wrong id", `{"jsonrpc":"2.0","id":1,"method":"initialize"}`, `{"jsonrpc":"2.0","id":2,"result":{"protocolVersion":"2025-06-18"}}`, ""},
		{"error", `{"jsonrpc":"2.0","id":1,"method":"initialize"}`, `{"jsonrpc":"2.0","id":1,"error":{"code":-1},"result":{"protocolVersion":"2025-06-18"}}`, ""},
		{"notification", `{"jsonrpc":"2.0","id":1,"method":"initialize"}`, `{"jsonrpc":"2.0","method":"notifications/ping","result":{"protocolVersion":"2025-06-18"}}`, ""},
		{"method with matching id", `{"jsonrpc":"2.0","id":1,"method":"initialize"}`, `{"jsonrpc":"2.0","id":1,"method":"notifications/ping","result":{"protocolVersion":"2025-06-18"}}`, ""},
		{"wrong rpc", `{"jsonrpc":"2.0","id":1,"method":"initialize"}`, `{"jsonrpc":"1.0","id":1,"result":{"protocolVersion":"2025-06-18"}}`, ""},
		{"other method", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18"}}`, ""},
		{"no request id", `{"jsonrpc":"2.0","method":"initialize"}`, `{"jsonrpc":"2.0","result":{"protocolVersion":"2025-06-18"}}`, ""},
		{"null id", `{"jsonrpc":"2.0","id":null,"method":"initialize"}`, `{"jsonrpc":"2.0","id":null,"result":{"protocolVersion":"2025-06-18"}}`, ""},
		{"boolean id", `{"jsonrpc":"2.0","id":true,"method":"initialize"}`, `{"jsonrpc":"2.0","id":true,"result":{"protocolVersion":"2025-06-18"}}`, ""},
		{"malformed request", `{`, `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18"}}`, ""},
		{"duplicate request", `{"jsonrpc":"2.0","id":1,"method":"tools/list","method":"initialize"}`, `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18"}}`, ""},
		{"escaped id", `{"jsonrpc":"2.0","id":"init","method":"initialize"}`, `{"jsonrpc":"2.0","id":"\u0069nit","result":{"protocolVersion":"2025-06-18"}}`, protocolTestVersion},
		{"invalid json", `{"jsonrpc":"2.0","id":1,"method":"initialize"}`, `{`, ""},
		{"missing version", `{"jsonrpc":"2.0","id":1,"method":"initialize"}`, `{"jsonrpc":"2.0","id":1,"result":{}}`, ""},
		{"invalid date", `{"jsonrpc":"2.0","id":1,"method":"initialize"}`, `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-99-18"}}`, ""},
		{"header injection", `{"jsonrpc":"2.0","id":1,"method":"initialize"}`, `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18\r\nX-Test: yes"}}`, ""},
		{"duplicate result", `{"jsonrpc":"2.0","id":1,"method":"initialize"}`, `{"jsonrpc":"2.0","id":1,"result":{},"result":{"protocolVersion":"2025-06-18"}}`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			seen := make(chan string, 2)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seen <- r.Header.Get("Mcp-Protocol-Version")
				_, _ = io.WriteString(w, tc.response)
			}))
			defer srv.Close()
			c := NewHTTPClient(srv.URL, nil)
			r, err := c.SendMessage(t.Context(), []byte(tc.request))
			if err != nil {
				t.Fatal(err)
			}
			drain(t, r)
			<-seen
			r, err = c.SendMessage(t.Context(), []byte(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`))
			if err != nil {
				t.Fatal(err)
			}
			drain(t, r)
			if got := <-seen; got != tc.want {
				t.Fatalf("protocol header = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestHTTPClientProtocolFirstMatchingResponse(t *testing.T) {
	for _, tc := range []struct {
		name, first, want string
	}{
		{"success", `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26"}}`, "2025-03-26"},
		{"error", `{"jsonrpc":"2.0","id":1,"error":{"code":-1}}`, ""},
		{"invalid result", `{"jsonrpc":"2.0","id":1,"result":{}}`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			seen := make(chan string, 2)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seen <- r.Header.Get(mcpProtocolVersionHeader)
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = fmt.Fprintf(w, "data: %s\n\ndata: %s\n\n", tc.first,
					`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18"}}`)
			}))
			defer srv.Close()
			c := NewHTTPClient(srv.URL, nil)
			r, err := c.SendMessage(t.Context(), []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
			if err != nil {
				t.Fatal(err)
			}
			drain(t, r)
			<-seen
			r, err = c.SendMessage(t.Context(), []byte(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`))
			if err != nil {
				t.Fatal(err)
			}
			drain(t, r)
			if got := <-seen; got != tc.want {
				t.Fatalf("protocol header = %q, want first response version %q", got, tc.want)
			}
		})
	}
}

func TestHTTPClientProtocolFailedReinitialize(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusBadRequest, http.StatusAccepted} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			seen := make(chan string, 3)
			count := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seen <- r.Header.Get(mcpProtocolVersionHeader)
				count++
				if count == 1 {
					_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18"}}`)
					return
				}
				w.WriteHeader(status)
				if status == http.StatusOK {
					_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"error":{"code":-1}}`)
				}
			}))
			defer srv.Close()
			c := NewHTTPClient(srv.URL, nil)
			request := []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`)
			r, err := c.SendMessage(t.Context(), request)
			if err != nil {
				t.Fatal(err)
			}
			drain(t, r)
			<-seen
			r, err = c.SendMessage(t.Context(), request)
			if status == http.StatusBadRequest {
				if err == nil {
					t.Fatal("HTTP failure returned no error")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				drain(t, r)
			}
			if got := <-seen; got != "" {
				t.Fatalf("reinitialize sent old protocol version: %q", got)
			}
			_, _ = c.SendMessage(t.Context(), []byte(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`))
			if got := <-seen; got != "" {
				t.Fatalf("failed reinitialize retained old protocol version: %q", got)
			}
		})
	}
}

func TestHTTPClientProtocolStreamCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer srv.Close()
	c := NewHTTPClient(srv.URL, nil)
	r, err := c.SendMessage(t.Context(), []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
	if err != nil {
		t.Fatal(err)
	}
	closer, ok := r.(io.Closer)
	if !ok {
		t.Fatal("initialize stream cannot be cancelled")
	}
	if err := closer.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := r.ReadMessage(); err == nil {
		t.Fatal("closed initialize stream continued reading")
	}
}

func TestHTTPClientProtocolStreamMessages(t *testing.T) {
	notification := `{"jsonrpc":"2.0","method":"notifications/ping"}`
	result := `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18"}}`
	seen := make(chan string, 2)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Get("Mcp-Protocol-Version")
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = fmt.Fprintf(w, "data: %s\n\ndata: %s\n\n", notification, result)
	}))
	defer srv.Close()
	c := NewHTTPClient(srv.URL, nil)
	r, err := c.SendMessage(t.Context(), []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{notification, result} {
		msg, err := r.ReadMessage()
		if err != nil || string(msg) != want {
			t.Fatalf("message = %s, error = %v", msg, err)
		}
	}
	drain(t, r)
	<-seen
	r, err = c.SendMessage(t.Context(), []byte(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`))
	if err != nil {
		t.Fatal(err)
	}
	drain(t, r)
	if got := <-seen; got != protocolTestVersion {
		t.Fatalf("protocol header = %q", got)
	}
}

func TestHTTPClientProtocolLateInitialize(t *testing.T) {
	responses := []string{"2025-03-26", protocolTestVersion}
	count := 0
	seen := make(chan string, 3)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Get("Mcp-Protocol-Version")
		if count == 2 {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":%q}}`, responses[count])
		count++
	}))
	defer srv.Close()
	c := NewHTTPClient(srv.URL, nil)
	request := []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`)
	first, err := c.SendMessage(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	second, err := c.SendMessage(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	drain(t, second)
	drain(t, first)
	<-seen
	<-seen
	last, err := c.SendMessage(t.Context(), []byte(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`))
	if err != nil {
		t.Fatal(err)
	}
	drain(t, last)
	got := <-seen
	if got != protocolTestVersion {
		t.Fatalf("late initialize replaced version: %q", got)
	}
}

func TestHTTPClientProtocolDeletedPendingInitialize(t *testing.T) {
	seen := make(chan string, 2)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Get(mcpProtocolVersionHeader)
		_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":%q}}`, protocolTestVersion)
	}))
	defer srv.Close()
	c := NewHTTPClient(srv.URL, nil)
	reader, err := c.SendMessage(t.Context(), []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
	if err != nil {
		t.Fatal(err)
	}
	<-seen
	c.DeleteSession(io.Discard)
	drain(t, reader)
	reader, err = c.SendMessage(t.Context(), []byte(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`))
	if err != nil {
		t.Fatal(err)
	}
	drain(t, reader)
	if got := <-seen; got != "" {
		t.Fatalf("deleted session recovered protocol version from pending response: %q", got)
	}
}

// protocolPausedReader holds a completed read until the test releases it.
// Closing the body cannot undo bytes already obtained by the read goroutine.
type protocolPausedReader struct {
	reader interface {
		MessageReader
		io.Closer
	}
	ready   chan struct{}
	release chan struct{}
}

func (r *protocolPausedReader) ReadMessage() ([]byte, error) {
	msg, err := r.reader.ReadMessage()
	close(r.ready)
	<-r.release
	return msg, err
}

func (r *protocolPausedReader) Close() error {
	return r.reader.Close()
}

func awaitProtocolTestValue[T any](t *testing.T, values <-chan T, phase string) T {
	t.Helper()
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	select {
	case value := <-values:
		return value
	case <-timer.C:
		t.Fatalf("timed out waiting for %s", phase)
		var zero T
		return zero
	}
}

func TestHTTPClientProtocolClosePendingResponse(t *testing.T) {
	for _, sse := range []bool{false, true} {
		for _, mode := range []string{"complete", "abort", "timeout", "replacement"} {
			t.Run(fmt.Sprintf("sse=%t/%s", sse, mode), func(t *testing.T) {
				seen := make(chan string, 2)
				response := `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18"}}`
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					seen <- r.Header.Get(mcpProtocolVersionHeader)
					body, _ := io.ReadAll(r.Body)
					message := response
					if strings.Contains(string(body), `"id":2`) {
						message = `{"jsonrpc":"2.0","id":2,"result":{"protocolVersion":"2025-03-26"}}`
					}
					if sse {
						w.Header().Set("Content-Type", "text/event-stream")
						_, _ = fmt.Fprintf(w, "data: %s\n\n", message)
					} else {
						_, _ = io.WriteString(w, message)
					}
				}))
				defer srv.Close()
				client := NewHTTPClient(srv.URL, nil)
				reader, err := client.SendMessage(t.Context(), []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
				if err != nil {
					t.Fatal(err)
				}
				awaitProtocolTestValue(t, seen, "initial request")
				negotiation := reader.(*initializeResponseReader)
				paused := &protocolPausedReader{reader: negotiation.reader, ready: make(chan struct{}), release: make(chan struct{})}
				t.Cleanup(func() {
					select {
					case <-paused.release:
					default:
						close(paused.release)
					}
				})
				negotiation.reader = paused
				var timeoutReader *TimeoutReader
				if mode == "timeout" {
					timeoutReader = NewTimeoutReader(reader, time.Millisecond)
					reader = timeoutReader
				}
				result := make(chan ReadResult, 1)
				go func() {
					msg, readErr := reader.ReadMessage()
					result <- ReadResult{Msg: msg, Err: readErr}
				}()
				awaitProtocolTestValue(t, paused.ready, "completed inner read")
				if mode == "timeout" {
					if got := awaitProtocolTestValue(t, result, "timeout result"); !errors.Is(got.Err, ErrResponseTimeout) {
						t.Fatalf("read error = %v, want timeout", got.Err)
					}
				}
				if mode == "replacement" {
					replacement, err := client.SendMessage(t.Context(), []byte(`{"jsonrpc":"2.0","id":2,"method":"initialize"}`))
					if err != nil {
						t.Fatal(err)
					}
					drain(t, replacement)
					awaitProtocolTestValue(t, seen, "replacement request")
				}
				if mode != "complete" {
					if err := reader.(io.Closer).Close(); err != nil {
						t.Fatal(err)
					}
				}
				close(paused.release)
				completed := result
				if timeoutReader != nil {
					completed = timeoutReader.inflight
				}
				got := awaitProtocolTestValue(t, completed, "released read result")
				if got.Err != nil || string(got.Msg) != response {
					t.Fatalf("response = %s, error = %v", got.Msg, got.Err)
				}
				if err := negotiation.Close(); err != nil {
					t.Fatal(err)
				}
				reader, err = client.SendMessage(t.Context(), []byte(`{"jsonrpc":"2.0","id":3,"method":"tools/list"}`))
				if err != nil {
					t.Fatal(err)
				}
				drain(t, reader)
				want := protocolTestVersion
				switch mode {
				case "abort", "timeout":
					want = ""
				case "replacement":
					want = "2025-03-26"
				}
				if header := awaitProtocolTestValue(t, seen, "subsequent request"); header != want {
					t.Fatalf("protocol header after Close = %q, want %q", header, want)
				}
			})
		}
	}
}
