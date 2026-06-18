// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"errors"
	"io"
	"testing"
	"time"
)

// blockingReader never returns from ReadMessage until a response is pushed
// into the responses channel.
type blockingReader struct {
	responses chan ReadResult
}

func (br *blockingReader) ReadMessage() ([]byte, error) {
	r := <-br.responses
	return r.Msg, r.Err
}

func TestTimeoutReader_PassthroughWhenDisabled(t *testing.T) {
	br := &blockingReader{responses: make(chan ReadResult, 1)}
	br.responses <- ReadResult{Msg: []byte(`{"ok":true}`), Err: nil}
	tr := NewTimeoutReader(br, 0)
	msg, err := tr.ReadMessage()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(msg) != `{"ok":true}` {
		t.Fatalf("msg = %q", msg)
	}
}

func TestTimeoutReader_ReturnsBeforeDeadline(t *testing.T) {
	br := &blockingReader{responses: make(chan ReadResult, 1)}
	br.responses <- ReadResult{Msg: []byte(`{"id":1}`), Err: nil}
	tr := NewTimeoutReader(br, 5*time.Second)
	msg, err := tr.ReadMessage()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(msg) != `{"id":1}` {
		t.Fatalf("msg = %q", msg)
	}
}

func TestTimeoutReader_TimesOut(t *testing.T) {
	br := &blockingReader{responses: make(chan ReadResult, 1)}
	// Do not push a response - the reader will block.
	tr := NewTimeoutReader(br, 50*time.Millisecond)
	_, err := tr.ReadMessage()
	if !errors.Is(err, ErrResponseTimeout) {
		t.Fatalf("expected ErrResponseTimeout, got %v", err)
	}

	// Push the late response so the goroutine can drain.
	br.responses <- ReadResult{Msg: []byte(`{"id":1}`), Err: nil}

	// The next read reuses the inflight channel and should return the
	// buffered late response immediately (well within the 5s deadline).
	tr.timeout = 5 * time.Second
	msg, err := tr.ReadMessage()
	if err != nil {
		t.Fatalf("expected buffered response, got error: %v", err)
	}
	if string(msg) != `{"id":1}` {
		t.Fatalf("msg = %q", msg)
	}
}

func TestTimeoutReader_PropagatesEOF(t *testing.T) {
	br := &blockingReader{responses: make(chan ReadResult, 1)}
	br.responses <- ReadResult{Msg: nil, Err: io.EOF}
	tr := NewTimeoutReader(br, 5*time.Second)
	_, err := tr.ReadMessage()
	if !errors.Is(err, io.EOF) {
		t.Fatalf("expected io.EOF, got %v", err)
	}
}

// blockingCloseReader blocks in ReadMessage until Close releases it, modeling a
// hung upstream whose body read only returns once the connection is closed.
type blockingCloseReader struct {
	release chan struct{}
}

func (b *blockingCloseReader) ReadMessage() ([]byte, error) {
	<-b.release
	return nil, io.EOF
}

func (b *blockingCloseReader) Close() error {
	close(b.release)
	return nil
}

// TestTimeoutReader_CloseDrainsHungInner proves Close() aborts the in-flight
// inner read after a timeout so the background goroutine drains instead of
// leaking — the path the HTTP bridge uses to free a hung response on timeout.
func TestTimeoutReader_CloseDrainsHungInner(t *testing.T) {
	inner := &blockingCloseReader{release: make(chan struct{})}
	tr := NewTimeoutReader(inner, 20*time.Millisecond)

	if _, err := tr.ReadMessage(); !errors.Is(err, ErrResponseTimeout) {
		t.Fatalf("first read: want ErrResponseTimeout, got %v", err)
	}

	// Close aborts the still-blocked inner read so its goroutine completes.
	if err := tr.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := tr.ReadMessage()
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("drained read: want io.EOF, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ReadMessage hung after Close; background goroutine did not drain")
	}
}
