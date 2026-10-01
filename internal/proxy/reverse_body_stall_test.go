// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

const (
	testBodyStall = 300 * time.Millisecond
	// testBodyReadLimit fails a read that a missing bound would leave hanging.
	testBodyReadLimit = 10 * time.Second
)

func stallTransport() *upstreamBodyStallTransport {
	base := http.DefaultTransport.(*http.Transport).Clone()
	base.Proxy = nil
	return &upstreamBodyStallTransport{base: base, stall: testBodyStall}
}

func getVia(t *testing.T, rt http.RoundTripper, url string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// readWithin reads the whole body and fails the test if that takes longer
// than testBodyReadLimit, so a missing bound cannot hang the suite.
func readWithin(t *testing.T, body io.Reader) ([]byte, error) {
	t.Helper()
	type result struct {
		b   []byte
		err error
	}
	done := make(chan result, 1)
	go func() {
		b, err := io.ReadAll(body)
		done <- result{b, err}
	}()
	select {
	case r := <-done:
		return r.b, r.err
	case <-time.After(testBodyReadLimit):
		t.Fatalf("body read did not finish within %s", testBodyReadLimit)
		return nil, nil
	}
}

func TestUpstreamBodyStall_StalledBodyIsCutOff(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("partial"))
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(srv.Close)

	resp := getVia(t, stallTransport(), srv.URL)
	defer func() { _ = resp.Body.Close() }()
	_, err := readWithin(t, resp.Body)
	if err == nil {
		t.Fatal("a body that stops delivering bytes must end in an error, not a clean read")
	}
	if !errors.Is(err, context.Canceled) {
		t.Logf("stall surfaced as %v", err)
	}
}

func TestUpstreamBodyStall_SteadyTrickleCompletes(t *testing.T) {
	const chunks = 6
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		tick := time.NewTicker(testBodyStall / 3)
		defer tick.Stop()
		for range chunks {
			_, _ = w.Write([]byte("x"))
			w.(http.Flusher).Flush()
			select {
			case <-tick.C:
			case <-r.Context().Done():
				return
			}
		}
	}))
	t.Cleanup(srv.Close)

	resp := getVia(t, stallTransport(), srv.URL)
	defer func() { _ = resp.Body.Close() }()
	b, err := readWithin(t, resp.Body)
	if err != nil {
		t.Fatalf("a body that keeps making progress was cut off: %v", err)
	}
	if len(b) != chunks {
		t.Fatalf("got %d bytes, want %d", len(b), chunks)
	}
}

func TestUpstreamBodyStall_EventStreamIsExempt(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
		_, _ = w.Write([]byte("data: a\n\n"))
		w.(http.Flusher).Flush()
		select {
		case <-time.After(3 * testBodyStall):
		case <-r.Context().Done():
			return
		}
		_, _ = w.Write([]byte("data: b\n\n"))
	}))
	t.Cleanup(srv.Close)

	resp := getVia(t, stallTransport(), srv.URL)
	defer func() { _ = resp.Body.Close() }()
	b, err := readWithin(t, resp.Body)
	if err != nil {
		t.Fatalf("an idle event stream must not be cut off: %v", err)
	}
	if string(b) != "data: a\n\ndata: b\n\n" {
		t.Fatalf("event stream body = %q", b)
	}
}

func TestUpstreamBodyStall_UpgradeKeepsReadWriteBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, brw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: test\r\n\r\n")
		_ = brw.Flush()
		buf := make([]byte, 4)
		if _, err := io.ReadFull(brw, buf); err == nil {
			_, _ = conn.Write(buf)
		}
	}))
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "test")
	resp, err := stallTransport().RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	rw, ok := resp.Body.(io.ReadWriteCloser)
	if !ok {
		t.Fatalf("upgraded body %T is not an io.ReadWriteCloser; the reverse proxy cannot take over the connection", resp.Body)
	}
	if _, err := rw.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	got, err := readWithin(t, io.LimitReader(rw, 4))
	if err != nil || string(got) != "ping" {
		t.Fatalf("echo = %q, %v", got, err)
	}
}

// innerReverseTransport returns the *http.Transport under the body-stall
// wrapper, and requires the wrapper to be present with a positive window.
func innerReverseTransport(rt http.RoundTripper) (*http.Transport, bool) {
	stall, ok := rt.(*upstreamBodyStallTransport)
	if !ok || stall.stall <= 0 {
		return nil, false
	}
	base, ok := stall.base.(*http.Transport)
	return base, ok
}
