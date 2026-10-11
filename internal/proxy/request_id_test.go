// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/receiptcontent"
)

// TestRequestMetaMintsProvenRequestIDs gives every request a distinct ID that
// carries this process's origin proof, so receipts can tell it is Pipelock's.
func TestRequestMetaMintsProvenRequestIDs(t *testing.T) {
	seen := map[string]bool{}
	for range 64 {
		_, id := requestMeta(httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://api.vendor.example/", nil))
		rest, ok := strings.CutPrefix(id, receiptcontent.RequestIDPrefix)
		if !ok || !receiptcontent.VerifyGeneratedID(rest) {
			t.Fatalf("request ID %q carries no origin proof", id)
		}
		if seen[id] {
			t.Fatalf("request ID %q repeated", id)
		}
		seen[id] = true
	}
}
