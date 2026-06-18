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

func TestTimeoutReader_ReadMessage(t *testing.T) {
	tests := []struct {
		name       string
		timeout    time.Duration
		initial    *ReadResult
		wantMsg    string
		wantErr    error
		late       *ReadResult
		lateMsg    string
		lateErr    error
		lateReadTO time.Duration
	}{
		{
			name:    "passthrough when disabled",
			timeout: 0,
			initial: &ReadResult{Msg: []byte(`{"ok":true}`)},
			wantMsg: `{"ok":true}`,
		},
		{
			name:    "returns before deadline",
			timeout: 5 * time.Second,
			initial: &ReadResult{Msg: []byte(`{"id":1}`)},
			wantMsg: `{"id":1}`,
		},
		{
			name:       "times out then drains late response",
			timeout:    50 * time.Millisecond,
			wantErr:    ErrResponseTimeout,
			late:       &ReadResult{Msg: []byte(`{"id":1}`)},
			lateMsg:    `{"id":1}`,
			lateReadTO: 5 * time.Second,
		},
		{
			name:    "propagates eof",
			timeout: 5 * time.Second,
			initial: &ReadResult{Err: io.EOF},
			wantErr: io.EOF,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			br := &blockingReader{responses: make(chan ReadResult, 1)}
			if tt.initial != nil {
				br.responses <- *tt.initial
			}
			tr := NewTimeoutReader(br, tt.timeout)

			msg, err := tr.ReadMessage()
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("ReadMessage error = %v, want %v", err, tt.wantErr)
				}
			} else if err != nil {
				t.Fatalf("ReadMessage unexpected error: %v", err)
			}
			if string(msg) != tt.wantMsg {
				t.Fatalf("ReadMessage msg = %q, want %q", msg, tt.wantMsg)
			}
			if tt.late == nil {
				return
			}

			// Push the late response so the goroutine can drain. The next read
			// reuses the inflight channel and should return the buffered result.
			br.responses <- *tt.late
			tr.timeout = tt.lateReadTO
			msg, err = tr.ReadMessage()
			if tt.lateErr != nil {
				if !errors.Is(err, tt.lateErr) {
					t.Fatalf("late ReadMessage error = %v, want %v", err, tt.lateErr)
				}
			} else if err != nil {
				t.Fatalf("late ReadMessage unexpected error: %v", err)
			}
			if string(msg) != tt.lateMsg {
				t.Fatalf("late ReadMessage msg = %q, want %q", msg, tt.lateMsg)
			}
		})
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

func TestTimeoutReader_CloseNoopWhenInnerNotCloser(t *testing.T) {
	tr := NewTimeoutReader(&blockingReader{responses: make(chan ReadResult, 1)}, time.Second)
	if err := tr.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}
