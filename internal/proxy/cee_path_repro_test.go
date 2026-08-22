// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"net/http"
	"testing"
)

// TestRepro_ExactDuplicatePriming closes the reviewer's High finding. Sending
// the second half first cannot suppress its later occurrence: after the path
// position varies, every value is retained in arrival order.
func TestRepro_ExactDuplicatePriming(t *testing.T) {
	p, upstream := newPathFragmentProxy(t)
	half1, half2 := pathSecretHalves()

	_ = fetchPath(t, p, upstream.URL, "/upload/"+half2) // prime
	_ = fetchPath(t, p, upstream.URL, "/upload/"+half1)
	code := fetchPath(t, p, upstream.URL, "/upload/"+half2)

	if code != http.StatusForbidden {
		t.Fatalf("primed exact duplicate bypassed detection, got %d", code)
	}
}
