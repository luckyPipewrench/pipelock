// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Protocol revision 2026-07-28 replaces the HTTP GET notification endpoint with
// subscriptions/listen: a single long-lived POST response stream. http.Client's
// Timeout bounds the WHOLE exchange including the body read, so any total
// timeout severs such a stream once it elapses, no matter how healthy it is.
//
// The guard against an unresponsive upstream has to bound the wait for response
// HEADERS instead, which leaves the body free to stream.
func TestReverseUpstreamClient_DoesNotBoundStreamingBodies(t *testing.T) {
	client := newReverseUpstreamClient(nil)

	if client.Timeout != 0 {
		t.Errorf("client.Timeout = %v, want 0: a total timeout cuts long-lived subscriptions/listen streams", client.Timeout)
	}

	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport type = %T, want *http.Transport", client.Transport)
	}
	if transport.ResponseHeaderTimeout <= 0 {
		t.Error("ResponseHeaderTimeout unset: an unresponsive upstream would hang the request forever")
	}
}

// The header bound must still fire, or removing the total timeout would trade a
// severed-stream bug for a hung-forever bug.
func TestReverseUpstreamClient_StillBoundsUnresponsiveUpstream(t *testing.T) {
	block := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		<-block // never writes headers
	}))
	defer upstream.Close()
	defer close(block)

	client := newReverseUpstreamClient(nil)
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport type = %T", client.Transport)
	}
	transport.ResponseHeaderTimeout = 150 * time.Millisecond

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, upstream.URL, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	start := time.Now()
	resp, err := client.Do(req)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("request succeeded against an upstream that never sent headers")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("took %v to give up on a header-less upstream", elapsed)
	}
}

// A response body that arrives slowly must stream through rather than being cut
// at a fixed deadline. Uses a body longer-lived than the header bound, which is
// the shape subscriptions/listen has.
func TestReverseUpstreamClient_StreamsBodySlowerThanHeaderBound(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher, ok := w.(http.Flusher)
		if !ok {
			return
		}
		ticker := time.NewTicker(60 * time.Millisecond)
		defer ticker.Stop()
		for range 6 {
			<-ticker.C
			_, _ = w.Write([]byte("data: {}\n\n"))
			flusher.Flush()
		}
	}))
	defer upstream.Close()

	client := newReverseUpstreamClient(nil)
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport type = %T", client.Transport)
	}
	// Deliberately shorter than the total body lifetime: a header bound must
	// not apply once headers have arrived.
	transport.ResponseHeaderTimeout = 200 * time.Millisecond

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, upstream.URL, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	buf := make([]byte, 4096)
	total := 0
	for {
		n, readErr := resp.Body.Read(buf)
		total += n
		if readErr != nil {
			break
		}
	}
	// A body deadline applied after headers would truncate the stream, and
	// "some bytes arrived" cannot detect that. Require every frame.
	const frames = 6
	if want := frames * len("data: {}\n\n"); total != want {
		t.Fatalf("read %d stream bytes, want %d: a post-header deadline truncated the body", total, want)
	}
}
