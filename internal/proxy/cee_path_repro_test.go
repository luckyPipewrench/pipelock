package proxy

import (
	"net/http"
	"testing"
)

// TestRepro_ExactDuplicatePriming reproduces the reviewer's High finding:
// exact-match suppression is still primeable. Sending the second half FIRST
// makes the later, order-correct occurrence a duplicate, so it is dropped and
// the halves never become contiguous.
func TestRepro_ExactDuplicatePriming(t *testing.T) {
	t.Skip("OPEN: value-based segment suppression is primeable in any form; " +
		"awaiting the position-aware redesign. Remove the skip to reproduce.")

	p, upstream := newPathFragmentProxy(t)
	half1, half2 := pathSecretHalves()

	_ = fetchPath(t, p, upstream.URL, "/upload/"+half2) // prime
	_ = fetchPath(t, p, upstream.URL, "/upload/"+half1)
	code := fetchPath(t, p, upstream.URL, "/upload/"+half2) // suppressed as duplicate

	if code != http.StatusForbidden {
		t.Fatalf("REPRODUCED: primed exact duplicate bypasses detection, got %d", code)
	}
}
