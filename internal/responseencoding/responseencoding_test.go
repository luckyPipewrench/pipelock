// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package responseencoding

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestRequestIdentity(t *testing.T) {
	header := http.Header{"Accept-Encoding": {"gzip", "deflate, br, zstd"}}
	RequestIdentity(header)
	if got := header.Values("Accept-Encoding"); len(got) != 1 || got[0] != "identity" {
		t.Fatalf("Accept-Encoding values = %q, want identity", got)
	}
}

func TestHasNonIdentityContentEncoding(t *testing.T) {
	for _, tt := range []struct {
		name   string
		values []string
		want   bool
	}{
		{name: "absent"},
		{name: "identity only", values: []string{"identity", "identity"}},
		{name: "identity before gzip", values: []string{"identity", "gzip"}, want: true},
		{name: "gzip before identity", values: []string{"gzip", "identity"}, want: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			header := make(http.Header)
			for _, value := range tt.values {
				header.Add("Content-Encoding", value)
			}
			if got := HasNonIdentityContentEncoding(header); got != tt.want {
				t.Fatalf("HasNonIdentityContentEncoding() = %t, want %t", got, tt.want)
			}
		})
	}
}

func TestDecodeResponse(t *testing.T) {
	const plain = "ordinary response body"

	tests := []struct {
		name     string
		encoding string
		body     func(*testing.T) []byte
		wantErr  string
		// wantReadErr marks a stream whose header is valid, so DecodeResponse
		// succeeds, and whose failure only surfaces when the caller reads it.
		wantReadErr bool
	}{
		{name: "identity", encoding: "identity", body: func(*testing.T) []byte { return []byte(plain) }},
		{name: "gzip", encoding: "gzip", body: func(t *testing.T) []byte { return gzipBody(t, plain) }},
		{name: "x-gzip", encoding: "x-gzip", body: func(t *testing.T) []byte { return gzipBody(t, plain) }},
		{name: "deflate", encoding: "deflate", body: func(t *testing.T) []byte { return deflateBody(t, plain) }},
		{name: "unsupported", encoding: "br", body: func(*testing.T) []byte { return []byte("encoded") }, wantErr: "unsupported content encoding"},
		{name: "stacked", encoding: "gzip, deflate", body: func(*testing.T) []byte { return []byte("encoded") }, wantErr: "unsupported stacked content encodings"},
		{name: "malformed gzip", encoding: "gzip", body: func(*testing.T) []byte { return []byte("not gzip") }, wantErr: "decode gzip response"},
		{name: "truncated gzip", encoding: "gzip", body: func(t *testing.T) []byte {
			body := gzipBody(t, plain)
			return body[:len(body)-1]
		}, wantReadErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{
				Header: http.Header{
					"Content-Encoding": {tt.encoding},
					"Content-Length":   {"123"},
					"Content-MD5":      {"encoded-md5"},
					"Digest":           {"sha-256=encoded"},
					"ETag":             {`"encoded"`},
				},
				Body:          io.NopCloser(bytes.NewReader(tt.body(t))),
				ContentLength: 123,
			}
			err := DecodeResponse(resp)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("DecodeResponse() error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("DecodeResponse() error = %v", err)
			}
			if tt.wantReadErr {
				// A gzip header is valid on its own, so the truncation is only
				// discovered mid-read. A caller that checks DecodeResponse and
				// then ignores the read error would treat a partial body as the
				// whole response and scan less than was delivered.
				if _, err := io.ReadAll(resp.Body); err == nil {
					t.Fatal("reading a truncated decoded body succeeded; the truncation must surface as a read error")
				}
				if err := resp.Body.Close(); err != nil {
					t.Fatalf("close decoded body: %v", err)
				}
				return
			}
			got, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("read decoded body: %v", err)
			}
			if err := resp.Body.Close(); err != nil {
				t.Fatalf("close decoded body: %v", err)
			}
			if string(got) != plain {
				t.Fatalf("decoded body = %q, want %q", got, plain)
			}
			if tt.encoding != "identity" {
				if got := resp.Header.Get("Content-Encoding"); got != "" {
					t.Fatalf("Content-Encoding = %q, want removed", got)
				}
				if got := resp.Header.Get("Content-Length"); got != "" || resp.ContentLength != -1 || !resp.Uncompressed {
					t.Fatalf("decoded metadata = header %q length %d uncompressed %v", got, resp.ContentLength, resp.Uncompressed)
				}
				for _, name := range []string{"Content-MD5", "Digest", "ETag"} {
					if got := resp.Header.Get(name); got != "" {
						t.Fatalf("%s = %q, want removed after decoding", name, got)
					}
				}
			}
		})
	}
}

func TestDecodeResponseNilAndEmpty(t *testing.T) {
	if err := DecodeResponse(nil); err != nil {
		t.Fatalf("nil response: %v", err)
	}
	if err := DecodeResponse(&http.Response{Header: make(http.Header)}); err != nil {
		t.Fatalf("empty response: %v", err)
	}
}

func TestDecodeResponseRejectsEncodedPartial(t *testing.T) {
	body := gzipBody(t, "range fragment")
	resp := &http.Response{
		StatusCode: http.StatusPartialContent,
		Header: http.Header{
			"Content-Encoding": {"gzip"},
			"Content-Range":    {"bytes 0-13/100"},
		},
		Body: io.NopCloser(bytes.NewReader(body)),
	}
	if err := DecodeResponse(resp); err == nil || !strings.Contains(err.Error(), "partial response") {
		t.Fatalf("encoded partial response error = %v, want refusal", err)
	}
	if resp.Header.Get("Content-Encoding") != "gzip" || resp.Header.Get("Content-Range") == "" {
		t.Fatal("refusal changed upstream representation metadata")
	}
	if got, err := io.ReadAll(resp.Body); err != nil || !bytes.Equal(got, body) {
		t.Fatalf("refusal changed upstream body: bytes=%d err=%v", len(got), err)
	}
}

func gzipBody(t *testing.T, text string) []byte {
	t.Helper()
	var body bytes.Buffer
	w := gzip.NewWriter(&body)
	if _, err := io.WriteString(w, text); err != nil {
		t.Fatalf("write gzip body: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close gzip body: %v", err)
	}
	return body.Bytes()
}

func deflateBody(t *testing.T, text string) []byte {
	t.Helper()
	var body bytes.Buffer
	w := zlib.NewWriter(&body)
	if _, err := io.WriteString(w, text); err != nil {
		t.Fatalf("write deflate body: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close deflate body: %v", err)
	}
	return body.Bytes()
}
