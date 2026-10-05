// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"io"
	"net/http"

	"github.com/luckyPipewrench/pipelock/internal/blockreason"
)

// applyFullResponsePolicy prepares an outbound request when headers are supplied,
// and checks an origin response when resp is supplied. Client cache validators
// do not prove approval of a complete representation. Remove Range with If-Range
// so dropping a stale validator cannot turn a full response into a slice.
// Neither a bodyless 304 nor a partial 206 establishes approval of the full
// representation. Refuse both before relaying any origin headers or status.
// This does not alter WebSocket upgrade headers.
func applyFullResponsePolicy(headers http.Header, resp *http.Response) bool {
	for _, name := range []string{"If-None-Match", "If-Modified-Since", "If-Range", "Range"} {
		headers.Del(name)
	}
	return resp == nil || (resp.StatusCode != http.StatusNotModified && resp.StatusCode != http.StatusPartialContent)
}

// fullResponseRefusal identifies the incomplete representation without treating
// the refusal as an upstream outage or an injection finding.
func fullResponseRefusal(resp *http.Response) (reason, pattern string) {
	if resp.StatusCode == http.StatusPartialContent {
		return "unbound partial response", "unbound_partial_content"
	}
	return "unbound not-modified response", "unbound_not_modified"
}

// writeFullResponseBlock uses the same synthetic response as the reverse path,
// including its block metadata, without copying any origin headers.
func writeFullResponseBlock(w http.ResponseWriter, reason string) {
	resp := &http.Response{Header: make(http.Header)}
	replaceWithBlockReason(resp, reason, blockInfoFor(blockreason.ParseError, "browser_cache"))
	for name, values := range resp.Header {
		w.Header()[name] = values
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
	_ = resp.Body.Close()
}
