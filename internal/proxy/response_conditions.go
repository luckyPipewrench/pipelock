// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import "net/http"

// applyFullResponsePolicy prepares an outbound request when headers are supplied,
// and checks an origin response when resp is supplied. Client cache validators
// do not prove approval of a complete representation. Remove Range with If-Range
// so dropping a stale validator cannot turn a full response into a slice.
// A bodyless 304 cannot establish approval and must be refused before relaying
// any origin headers or status. This does not alter WebSocket upgrade headers.
func applyFullResponsePolicy(headers http.Header, resp *http.Response) bool {
	for _, name := range []string{"If-None-Match", "If-Modified-Since", "If-Range", "Range"} {
		headers.Del(name)
	}
	return resp == nil || resp.StatusCode != http.StatusNotModified
}
