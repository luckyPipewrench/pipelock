// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestIsClientErrorReplyRequiresRequestID(t *testing.T) {
	for _, id := range []json.RawMessage{nil, []byte("null"), []byte("{}"), []byte("false")} {
		t.Run(string(id), func(t *testing.T) {
			body := []byte(`{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"Parse error"}}`)
			if IsClientErrorReply(body, id) {
				t.Fatal("accepted an error with no correlatable request ID")
			}
		})
	}
}

func TestAcceptedWithoutBody(t *testing.T) {
	tests := []struct {
		status        int
		contentLength int64
		want          bool
	}{
		{http.StatusAccepted, -1, true},
		{http.StatusAccepted, 12, true},
		{http.StatusNoContent, 0, true},
		{http.StatusResetContent, -1, true},
		{http.StatusOK, 0, false},
		{http.StatusCreated, 0, true},
		{http.StatusCreated, -1, false},
		{http.StatusCreated, 5, false},
		{http.StatusPartialContent, 0, true},
		{http.StatusMultipleChoices, 0, false},
		{http.StatusBadRequest, 0, false},
		{http.StatusSwitchingProtocols, 0, false},
	}
	for _, tt := range tests {
		t.Run(strconv.Itoa(tt.status)+"/"+strconv.FormatInt(tt.contentLength, 10), func(t *testing.T) {
			resp := &http.Response{StatusCode: tt.status, ContentLength: tt.contentLength}
			if got := AcceptedWithoutBody(resp); got != tt.want {
				t.Fatalf("AcceptedWithoutBody(%d, length %d) = %v, want %v", tt.status, tt.contentLength, got, tt.want)
			}
		})
	}
}

func TestIsClientError(t *testing.T) {
	for status, want := range map[int]bool{399: false, 400: true, 401: true, 404: true, 499: true, 500: false, 302: false} {
		if got := IsClientError(status); got != want {
			t.Fatalf("IsClientError(%d) = %v, want %v", status, got, want)
		}
	}
}

func TestReadClientErrorBody(t *testing.T) {
	gzipped := func(s string) []byte {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		_, _ = zw.Write([]byte(s))
		_ = zw.Close()
		return buf.Bytes()
	}
	tests := []struct {
		name     string
		encoding string
		body     []byte
		want     string
		wantErr  bool
	}{
		{name: "plain", body: []byte(`{"error":"denied"}`), want: `{"error":"denied"}`},
		{name: "empty", body: nil, want: ""},
		{name: "exactly at bound", body: bytes.Repeat([]byte("a"), MaxClientErrorBodySize), want: strings.Repeat("a", MaxClientErrorBodySize)},
		{name: "over bound", body: bytes.Repeat([]byte("a"), MaxClientErrorBodySize+1), wantErr: true},
		{name: "not UTF-8", body: []byte("bad \xff"), wantErr: true},
		{name: "gzip decoded", encoding: "gzip", body: gzipped("decoded"), want: "decoded"},
		{name: "unsupported encoding", encoding: "br", body: []byte("x"), wantErr: true},
		{name: "malformed gzip", encoding: "gzip", body: []byte("not gzip"), wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{StatusCode: http.StatusBadRequest, Header: http.Header{}, Body: io.NopCloser(bytes.NewReader(tt.body))}
			if tt.encoding != "" {
				resp.Header.Set("Content-Encoding", tt.encoding)
			}
			got, err := ReadClientErrorBody(resp)
			if tt.wantErr {
				if !errors.Is(err, ErrClientErrorNotRelayable) {
					t.Fatalf("err = %v, want ErrClientErrorNotRelayable", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ReadClientErrorBody: %v", err)
			}
			if string(got) != tt.want {
				t.Fatalf("body = %q, want %q", got, tt.want)
			}
		})
	}
	t.Run("nil body", func(t *testing.T) {
		got, err := ReadClientErrorBody(&http.Response{StatusCode: http.StatusBadRequest, Header: http.Header{}})
		if err != nil || got != nil {
			t.Fatalf("ReadClientErrorBody(nil body) = (%q, %v), want (nil, nil)", got, err)
		}
	})
	t.Run("read failure", func(t *testing.T) {
		resp := &http.Response{StatusCode: http.StatusBadRequest, Header: http.Header{}, Body: io.NopCloser(io.MultiReader(strings.NewReader("partial"), errReader{}))}
		_, err := ReadClientErrorBody(resp)
		if !errors.Is(err, ErrClientErrorNotRelayable) || !errors.Is(err, ErrIncompleteResponse) {
			t.Fatalf("err = %v, want ErrClientErrorNotRelayable and ErrIncompleteResponse", err)
		}
	})
	t.Run("policy rejection is not incomplete", func(t *testing.T) {
		resp := &http.Response{StatusCode: http.StatusBadRequest, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("bad \xff"))}
		if _, err := ReadClientErrorBody(resp); errors.Is(err, ErrIncompleteResponse) {
			t.Fatalf("err = %v, a body that is not UTF-8 is a policy rejection, not an incomplete read", err)
		}
	})
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("connection reset") }

func TestHTTPClient_SendMessage_EmptyAcknowledgementTracksSession(t *testing.T) {
	for _, status := range []int{http.StatusAccepted, http.StatusNoContent} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Mcp-Session-Id", "ack-session")
				w.WriteHeader(status)
			}))
			defer srv.Close()

			c := NewHTTPClient(srv.URL, nil)
			reader, err := c.SendMessage(context.Background(), []byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`))
			if err != nil {
				t.Fatalf("SendMessage on HTTP %d: %v", status, err)
			}
			if msg, readErr := reader.ReadMessage(); !errors.Is(readErr, io.EOF) || msg != nil {
				t.Fatalf("ReadMessage = (%q, %v), want immediate EOF", msg, readErr)
			}
			if got := c.SessionID(); got != "ack-session" {
				t.Fatalf("SessionID = %q, want ack-session", got)
			}
		})
	}
}

func TestHTTPClient_SendMessage_ClientErrorReply(t *testing.T) {
	const request = `{"jsonrpc":"2.0","id":7,"method":"server/discover"}`
	const reply = `{"jsonrpc":"2.0","id":7,"error":{"code":-32601,"message":"Method not found"}}`
	tests := []struct {
		name        string
		request     string
		status      int
		contentType []string
		encoding    string
		body        string
		wantReply   bool
	}{
		{name: "400 JSON-RPC error for this request", request: request, status: http.StatusBadRequest, contentType: []string{"application/json"}, body: reply, wantReply: true},
		{name: "charset parameter accepted", request: request, status: http.StatusBadRequest, contentType: []string{"application/json; charset=utf-8"}, body: reply, wantReply: true},
		{name: "string ID matches", request: `{"jsonrpc":"2.0","id":"a","method":"x"}`, status: http.StatusNotFound, contentType: []string{"application/json"}, body: `{"jsonrpc":"2.0","id":"a","error":{"code":-32001,"message":"Session not found"}}`, wantReply: true},
		{name: "gzip reply decoded", request: request, status: http.StatusBadRequest, contentType: []string{"application/json"}, encoding: "gzip", body: reply, wantReply: true},
		{name: "different ID", request: request, status: http.StatusBadRequest, contentType: []string{"application/json"}, body: `{"jsonrpc":"2.0","id":8,"error":{"code":-32601,"message":"other request"}}`},
		{name: "null ID", request: request, status: http.StatusBadRequest, contentType: []string{"application/json"}, body: `{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"Parse error"}}`},
		{name: "number and string IDs differ", request: request, status: http.StatusBadRequest, contentType: []string{"application/json"}, body: `{"jsonrpc":"2.0","id":"7","error":{"code":-32601,"message":"x"}}`},
		{name: "result present", request: request, status: http.StatusBadRequest, contentType: []string{"application/json"}, body: `{"jsonrpc":"2.0","id":7,"result":{},"error":{"code":1,"message":"x"}}`},
		{name: "case folded result", request: request, status: http.StatusBadRequest, contentType: []string{"application/json"}, body: `{"jsonrpc":"2.0","id":7,"Result":{},"error":{"code":1,"message":"x"}}`},
		{name: "case folded method", request: request, status: http.StatusBadRequest, contentType: []string{"application/json"}, body: `{"jsonrpc":"2.0","id":7,"Method":"sampling/createMessage","error":{"code":1,"message":"x"}}`},
		{name: "shadowed ID", request: request, status: http.StatusBadRequest, contentType: []string{"application/json"}, body: `{"jsonrpc":"2.0","id":7,"ID":8,"error":{"code":1,"message":"x"}}`},
		{name: "null result present", request: request, status: http.StatusBadRequest, contentType: []string{"application/json"}, body: `{"jsonrpc":"2.0","id":7,"result":null,"error":{"code":1,"message":"x"}}`},
		{name: "server request instead of reply", request: request, status: http.StatusBadRequest, contentType: []string{"application/json"}, body: `{"jsonrpc":"2.0","id":7,"method":"sampling/createMessage","error":{"code":1,"message":"x"}}`},
		{name: "no error member", request: request, status: http.StatusBadRequest, contentType: []string{"application/json"}, body: `{"jsonrpc":"2.0","id":7}`},
		{name: "null error member", request: request, status: http.StatusBadRequest, contentType: []string{"application/json"}, body: `{"jsonrpc":"2.0","id":7,"error":null}`},
		{name: "empty error object", request: request, status: http.StatusBadRequest, contentType: []string{"application/json"}, body: `{"jsonrpc":"2.0","id":7,"error":{}}`},
		{name: "error without message", request: request, status: http.StatusBadRequest, contentType: []string{"application/json"}, body: `{"jsonrpc":"2.0","id":7,"error":{"code":-32601}}`},
		{name: "wrong JSON-RPC version", request: request, status: http.StatusBadRequest, contentType: []string{"application/json"}, body: `{"jsonrpc":"1.0","id":7,"error":{"code":1,"message":"x"}}`},
		{name: "duplicate keys", request: request, status: http.StatusBadRequest, contentType: []string{"application/json"}, body: `{"jsonrpc":"2.0","id":8,"id":7,"error":{"code":1,"message":"x"}}`},
		{name: "not JSON", request: request, status: http.StatusBadRequest, contentType: []string{"application/json"}, body: `upstream body must not leak`},
		{name: "plain text type", request: request, status: http.StatusBadRequest, contentType: []string{"text/plain"}, body: reply},
		{name: "duplicate Content-Type", request: request, status: http.StatusBadRequest, contentType: []string{"application/json", "application/json"}, body: reply},
		{name: "malformed Content-Type", request: request, status: http.StatusBadRequest, contentType: []string{"application/json; =bad"}, body: reply},
		{name: "oversized body", request: request, status: http.StatusBadRequest, contentType: []string{"application/json"}, body: `{"jsonrpc":"2.0","id":7,"error":{"code":1,"message":"` + strings.Repeat("a", MaxClientErrorBodySize) + `"}}`},
		{name: "notification has nothing to answer", request: `{"jsonrpc":"2.0","method":"notifications/initialized"}`, status: http.StatusBadRequest, contentType: []string{"application/json"}, body: `{"jsonrpc":"2.0","id":null,"error":{"code":1,"message":"x"}}`},
		{name: "client response has nothing to answer", request: `{"jsonrpc":"2.0","id":7,"result":{}}`, status: http.StatusBadRequest, contentType: []string{"application/json"}, body: reply},
		{name: "unparseable request", request: `not json`, status: http.StatusBadRequest, contentType: []string{"application/json"}, body: reply},
		{name: "401 challenge without a JSON-RPC body", request: request, status: http.StatusUnauthorized, contentType: []string{"application/json"}, body: `{"error":"invalid_token"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header()["Content-Type"] = tt.contentType
				w.Header().Set("Mcp-Session-Id", "refused-session")
				body := []byte(tt.body)
				if tt.encoding == "gzip" {
					var buf bytes.Buffer
					zw := gzip.NewWriter(&buf)
					_, _ = zw.Write(body)
					_ = zw.Close()
					body = buf.Bytes()
					w.Header().Set("Content-Encoding", "gzip")
				}
				w.WriteHeader(tt.status)
				_, _ = w.Write(body)
			}))
			defer srv.Close()

			c := NewHTTPClient(srv.URL, nil)
			reader, err := c.SendMessage(context.Background(), []byte(tt.request))
			if c.SessionID() != "" {
				t.Fatalf("a refusal established session %q", c.SessionID())
			}
			// A JSON-typed refusal to a request is answered: with its own body
			// when that is the error for this request, otherwise with the
			// sanitized error carrying the request's ID. Anything else is a
			// transport error naming only the status.
			candidate := isRequestWithID(tt.request) && len(tt.contentType) == 1 && jsonMediaType(tt.contentType[0])
			if !candidate {
				if err == nil {
					t.Fatalf("SendMessage returned a reader for HTTP %d; want error", tt.status)
				}
				if err.Error() != "HTTP "+strconv.Itoa(tt.status) {
					t.Fatalf("error = %q, want only the status", err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("SendMessage: %v", err)
			}
			msg, readErr := reader.ReadMessage()
			if readErr != nil {
				t.Fatalf("ReadMessage: %v", readErr)
			}
			want := tt.body
			if !tt.wantReply {
				want = string(sanitizedClientErrorReply(json.RawMessage(requestIDOf(tt.request))))
			}
			if string(msg) != want {
				t.Fatalf("reply = %q, want %q", msg, want)
			}
			if _, readErr := reader.ReadMessage(); !errors.Is(readErr, io.EOF) {
				t.Fatalf("second ReadMessage err = %v, want EOF", readErr)
			}
		})
	}
}

func TestIsUncorrelatedErrorReply(t *testing.T) {
	tests := []struct {
		name string
		body string
		want bool
	}{
		{name: "null ID from the reference server", body: `{"jsonrpc":"2.0","error":{"code":-32001,"message":"Session not found"},"id":null}`, want: true},
		{name: "absent ID is malformed", body: `{"jsonrpc":"2.0","error":{"code":-32000,"message":"Bad Request"}}`},
		{name: "correlated ID is not uncorrelated", body: `{"jsonrpc":"2.0","id":1,"error":{"code":1,"message":"x"}}`},
		{name: "null ID result", body: `{"jsonrpc":"2.0","id":null,"result":{}}`},
		{name: "null ID server request", body: `{"jsonrpc":"2.0","id":null,"method":"sampling/createMessage","error":{"code":1,"message":"x"}}`},
		{name: "params beside the error", body: `{"jsonrpc":"2.0","id":null,"error":{"code":1,"message":"x"},"params":{}}`},
		{name: "null error", body: `{"jsonrpc":"2.0","id":null,"error":null}`},
		{name: "empty error object", body: `{"jsonrpc":"2.0","id":null,"error":{}}`},
		{name: "string code", body: `{"jsonrpc":"2.0","id":null,"error":{"code":"-32001","message":"x"}}`},
		{name: "fractional code", body: `{"jsonrpc":"2.0","id":null,"error":{"code":1.5,"message":"x"}}`},
		{name: "missing message", body: `{"jsonrpc":"2.0","id":null,"error":{"code":-32001}}`},
		{name: "non-string message", body: `{"jsonrpc":"2.0","id":null,"error":{"code":-32001,"message":7}}`},
		{name: "error is a string", body: `{"jsonrpc":"2.0","id":null,"error":"Session not found"}`},
		{name: "case-folded error members", body: `{"jsonrpc":"2.0","id":null,"error":{"Code":-32001,"Message":"x"}}`},
		{name: "null message", body: `{"jsonrpc":"2.0","id":null,"error":{"code":-32001,"message":null}}`},
		{name: "case folded ID", body: `{"jsonrpc":"2.0","ID":7,"error":{"code":1,"message":"x"}}`},
		{name: "duplicate keys", body: `{"jsonrpc":"2.0","id":null,"id":7,"error":{"code":1,"message":"x"}}`},
		{name: "not JSON", body: `Session not found`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsUncorrelatedErrorReply([]byte(tt.body)); got != tt.want {
				t.Fatalf("IsUncorrelatedErrorReply(%s) = %v, want %v", tt.body, got, tt.want)
			}
		})
	}
}

func TestExpectsReply(t *testing.T) {
	tests := []struct {
		msg  string
		want bool
	}{
		{`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, true},
		{`{"jsonrpc":"2.0","id":"a","method":"tools/call"}`, true},
		{`{"jsonrpc":"2.0","method":"notifications/initialized"}`, false},
		{`{"jsonrpc":"2.0","id":null,"method":"notifications/initialized"}`, false},
		{`{"jsonrpc":"2.0","id":1,"result":{}}`, false},
		{`not json`, false},
	}
	for _, tt := range tests {
		t.Run(tt.msg, func(t *testing.T) {
			if got := ExpectsReply([]byte(tt.msg)); got != tt.want {
				t.Fatalf("ExpectsReply(%s) = %v, want %v", tt.msg, got, tt.want)
			}
		})
	}
}

// A request answered with the legacy 202 still acknowledges: some servers send
// the answer on the GET stream.
func TestHTTPClient_SendMessage_RequestKeepsLegacyAccepted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	reader, err := NewHTTPClient(srv.URL, nil).SendMessage(context.Background(), []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	if err != nil {
		t.Fatalf("SendMessage: %v", err)
	}
	if msg, readErr := reader.ReadMessage(); !errors.Is(readErr, io.EOF) || msg != nil {
		t.Fatalf("ReadMessage = (%q, %v), want immediate EOF", msg, readErr)
	}
}

func isRequestWithID(msg string) bool {
	var request map[string]json.RawMessage
	return json.Unmarshal([]byte(msg), &request) == nil && request["method"] != nil && httpRPCID(request["id"]) != nil
}

func requestIDOf(msg string) string {
	var request map[string]json.RawMessage
	_ = json.Unmarshal([]byte(msg), &request)
	return string(request["id"])
}

func jsonMediaType(contentType string) bool {
	mediaType, _, err := mime.ParseMediaType(contentType)
	return err == nil && mediaType == "application/json"
}

// A refusal that sends its headers and then stalls must not block SendMessage:
// the body is read on ReadMessage, where the caller's response timeout applies.
func TestHTTPClient_SendMessage_StalledRefusalIsBoundedByTheReader(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.(http.Flusher).Flush()
		<-release
	}))
	defer srv.Close()
	defer close(release)

	sent := make(chan error, 1)
	var reader MessageReader
	go func() {
		var err error
		reader, err = NewHTTPClient(srv.URL, nil).SendMessage(context.Background(), []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
		sent <- err
	}()
	select {
	case err := <-sent:
		if err != nil {
			t.Fatalf("SendMessage: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("SendMessage blocked on a stalled refusal body")
	}
	_, err := NewTimeoutReader(reader, 50*time.Millisecond).ReadMessage()
	if !errors.Is(err, ErrResponseTimeout) {
		t.Fatalf("ReadMessage err = %v, want ErrResponseTimeout", err)
	}
	_ = reader.(interface{ Close() error }).Close()
}

// The composed reply must be exactly what an encoder would write, for every ID
// shape httpRPCID accepts.
func TestSanitizedClientErrorReplyMatchesEncoder(t *testing.T) {
	for _, id := range []string{`1`, `-7`, `1.5e3`, `"a"`, `"quote\"inside"`, `"é"`} {
		t.Run(id, func(t *testing.T) {
			type rpcErr struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			}
			want, err := json.Marshal(struct {
				JSONRPC string          `json:"jsonrpc"`
				ID      json.RawMessage `json:"id"`
				Error   rpcErr          `json:"error"`
			}{"2.0", json.RawMessage(id), rpcErr{-32003, UpstreamRequestFailedMessage}})
			if err != nil {
				t.Fatal(err)
			}
			if got := sanitizedClientErrorReply(json.RawMessage(id)); string(got) != string(want) {
				t.Fatalf("composed %s, encoder %s", got, want)
			}
		})
	}
}

// A refusal whose body read breaks is an incomplete response, not an answer:
// the caller must not see a synthetic error as if the upstream had replied.
func TestClientErrorReaderReportsBrokenReadAsIncomplete(t *testing.T) {
	r := &clientErrorReader{
		resp:      &http.Response{StatusCode: http.StatusBadRequest, Header: http.Header{}, Body: io.NopCloser(io.MultiReader(strings.NewReader(`{"jsonrpc"`), errReader{}))},
		requestID: json.RawMessage("1"),
	}
	msg, err := r.ReadMessage()
	if !errors.Is(err, ErrIncompleteResponse) || msg != nil {
		t.Fatalf("ReadMessage = (%q, %v), want ErrIncompleteResponse and no message", msg, err)
	}
}
