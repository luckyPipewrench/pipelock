// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package emit

import (
	"net/http"
	"time"
)

// newNoRedirectHTTPClient builds a client that never follows later hops.
// Webhook, OTLP, and sibling sinks validate the configured URL only; a
// redirect would send the POST (and for 307/308 its body) to a destination
// that never passed that check. http.ErrUseLastResponse keeps the 3xx as
// the final response so existing status handling fails closed without
// turning the hop into a retried network error.
func newNoRedirectHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
