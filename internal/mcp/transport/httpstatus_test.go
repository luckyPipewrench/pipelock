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
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
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
		if _, err := ReadClientErrorBody(resp); !errors.Is(err, ErrClientErrorNotRelayable) {
			t.Fatalf("err = %v, want ErrClientErrorNotRelayable", err)
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
			if !tt.wantReply {
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
			if string(msg) != tt.body {
				t.Fatalf("reply = %q, want %q", msg, tt.body)
			}
			if _, readErr := reader.ReadMessage(); !errors.Is(readErr, io.EOF) {
				t.Fatalf("second ReadMessage err = %v, want EOF", readErr)
			}
		})
	}
}
