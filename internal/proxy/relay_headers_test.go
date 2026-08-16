// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestRemoveHopByHopHeadersStripsConnectionList(t *testing.T) {
	t.Parallel()

	h := make(http.Header)
	h.Set("Connection", "X-Foo, close")
	h.Set("X-Foo", "secret")
	h.Set("Keep-Alive", "timeout=5")
	h.Set("X-Keep", "stay")
	removeHopByHopHeaders(h)
	if h.Get("X-Foo") != "" {
		t.Fatal("Connection-listed X-Foo survived")
	}
	if h.Get("Keep-Alive") != "" {
		t.Fatal("standard hop-by-hop Keep-Alive survived")
	}
	if h.Get("Connection") != "" {
		t.Fatal("Connection header survived")
	}
	if h.Get("X-Keep") != "stay" {
		t.Fatalf("end-to-end header dropped: %v", h)
	}
}

func TestBidirectionalCopyRelaysAndCountsBytes(t *testing.T) {
	t.Parallel()

	clientA, clientB := net.Pipe()
	targetA, targetB := net.Pipe()
	t.Cleanup(func() {
		_ = clientA.Close()
		_ = clientB.Close()
		_ = targetA.Close()
		_ = targetB.Close()
	})

	done := make(chan int64, 1)
	go func() {
		done <- bidirectionalCopy(clientA, targetA, 0, time.Time{}, nil)
	}()

	payload := []byte("ping")
	writeErr := make(chan error, 1)
	go func() {
		_, err := clientB.Write(payload)
		writeErr <- err
		_ = clientB.Close()
	}()

	got := make([]byte, len(payload))
	if err := targetB.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	if _, err := io.ReadFull(targetB, got); err != nil {
		t.Fatalf("read relayed bytes: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("relayed = %q, want %q", got, payload)
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = targetB.Close()

	select {
	case n := <-done:
		if n != int64(len(payload)) {
			t.Fatalf("copied %d, want %d", n, len(payload))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("relay did not finish")
	}
}
