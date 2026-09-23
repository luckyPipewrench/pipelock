// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package responseencoding normalizes upstream response encodings before
// Pipelock scans response bodies.
package responseencoding

import (
	"compress/gzip"
	"compress/zlib"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// RequestIdentity asks an upstream for uncompressed response bytes. Setting an
// explicit value is load-bearing: deleting Accept-Encoding lets net/http add
// gzip on transports where automatic compression is enabled.
func RequestIdentity(header http.Header) {
	header.Set("Accept-Encoding", "identity")
}

// HasNonIdentityContentEncoding reports whether any Content-Encoding header
// value contains an encoding other than identity. HTTP permits repeated header
// fields, so callers must inspect all values rather than Header.Get's first.
func HasNonIdentityContentEncoding(header http.Header) bool {
	return len(nonIdentityEncodings(header.Values("Content-Encoding"))) != 0
}

// DecodeResponse replaces a gzip- or deflate-encoded response body with a
// decoded stream and removes headers that describe the encoded representation.
// Callers retain their existing decoded-body size limits. Unsupported,
// malformed, and stacked encodings return an error so callers can fail closed.
func DecodeResponse(resp *http.Response) error {
	if resp == nil || resp.Body == nil {
		return nil
	}
	encodings := nonIdentityEncodings(resp.Header.Values("Content-Encoding"))
	if len(encodings) == 0 {
		return nil
	}
	if resp.StatusCode == http.StatusPartialContent {
		return fmt.Errorf("cannot decode a partial response without invalidating Content-Range")
	}
	if len(encodings) != 1 {
		return fmt.Errorf("unsupported stacked content encodings %q", strings.Join(encodings, ", "))
	}

	original := resp.Body
	var (
		decoded io.ReadCloser
		err     error
	)
	switch encodings[0] {
	case "gzip", "x-gzip":
		decoded, err = gzip.NewReader(original)
	case "deflate":
		decoded, err = zlib.NewReader(original)
	default:
		return fmt.Errorf("unsupported content encoding %q", encodings[0])
	}
	if err != nil {
		return fmt.Errorf("decode %s response: %w", encodings[0], err)
	}

	resp.Body = &decodedResponseBody{Reader: decoded, decoded: decoded, original: original}
	resp.Header.Del("Content-Encoding")
	resp.Header.Del("Content-Length")
	resp.Header.Del("Content-MD5")
	resp.Header.Del("Digest")
	resp.Header.Del("ETag")
	resp.ContentLength = -1
	resp.Uncompressed = true
	return nil
}

func nonIdentityEncodings(values []string) []string {
	var encodings []string
	for _, value := range values {
		for _, encoding := range strings.Split(value, ",") {
			encoding = strings.ToLower(strings.TrimSpace(encoding))
			if encoding != "" && encoding != "identity" {
				encodings = append(encodings, encoding)
			}
		}
	}
	return encodings
}

type decodedResponseBody struct {
	io.Reader
	decoded  io.Closer
	original io.Closer
}

func (b *decodedResponseBody) Close() error {
	decodedErr := b.decoded.Close()
	originalErr := b.original.Close()
	if decodedErr != nil {
		return decodedErr
	}
	return originalErr
}
