// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHTTPClientSessionClosePendingResponse(t *testing.T) {
	for _, sse := range []bool{false, true} {
		for _, seeded := range []bool{false, true} {
			for _, mode := range []string{"complete", "abort", "timeout"} {
				t.Run(fmt.Sprintf("sse=%t/seeded=%t/%s", sse, seeded, mode), func(t *testing.T) {
					type headers struct{ session, token string }
					seen := make(chan headers, 2)
					response := `{"jsonrpc":"2.0","id":1,"result":{}}`
					newToken := strings.Repeat("b", 43)
					srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						seen <- headers{r.Header.Get("Mcp-Session-Id"), r.Header.Get(pipelockSessionTokenHeader)}
						body, _ := io.ReadAll(r.Body)
						if strings.Contains(string(body), `"id":2`) {
							w.WriteHeader(http.StatusAccepted)
							return
						}
						w.Header().Set("Mcp-Session-Id", "new-session")
						w.Header().Set(pipelockSessionTokenHeader, newToken)
						if sse {
							w.Header().Set("Content-Type", "text/event-stream")
							_, _ = fmt.Fprintf(w, "data: %s\n\n", response)
						} else {
							_, _ = io.WriteString(w, response)
						}
					}))
					defer srv.Close()
					client := NewHTTPClient(srv.URL, nil)
					client.ResponseKeyValidator = func([]byte) error { return nil }
					want := headers{}
					if seeded {
						want = headers{"old-session", strings.Repeat("a", 43)}
						client.sessionID, client.listenerSessionToken = want.session, want.token
					}
					reader, err := client.SendMessage(t.Context(), []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
					if err != nil {
						t.Fatal(err)
					}
					if got := awaitProtocolTestValue(t, seen, "initial headers"); got != want {
						t.Fatalf("initial headers = %v, want %v", got, want)
					}
					admission := reader.(*sessionResponseReader)
					paused := &protocolPausedReader{reader: admission.reader, ready: make(chan struct{}), release: make(chan struct{})}
					admission.reader = paused
					t.Cleanup(func() {
						select {
						case <-paused.release:
						default:
							close(paused.release)
						}
						_ = admission.Close()
					})
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
						if got := awaitProtocolTestValue(t, result, "timeout"); !errors.Is(got.Err, ErrResponseTimeout) {
							t.Fatalf("read error = %v, want timeout", got.Err)
						}
					}
					if mode != "complete" {
						if err := reader.(io.Closer).Close(); err != nil {
							t.Fatal(err)
						}
					} else {
						want = headers{"new-session", newToken}
					}
					close(paused.release)
					completed := result
					if timeoutReader != nil {
						completed = timeoutReader.inflight
					}
					got := awaitProtocolTestValue(t, completed, "released read")
					if got.Err != nil || string(got.Msg) != response {
						t.Fatalf("response = %s, error = %v", got.Msg, got.Err)
					}
					if err := admission.Close(); err != nil {
						t.Fatal(err)
					}
					next, err := client.SendMessage(t.Context(), []byte(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`))
					if err != nil {
						t.Fatal(err)
					}
					drain(t, next)
					if got := awaitProtocolTestValue(t, seen, "next request headers"); got != want {
						t.Fatalf("abandoned response changed next request headers: got %v, want %v", got, want)
					}
				})
			}
		}
	}
}
