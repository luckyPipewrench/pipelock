// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package httpstream

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type failingWriter struct {
	n   int
	err error
}

func (w failingWriter) Write([]byte) (int, error) { return w.n, w.err }

func TestStreamErrors(t *testing.T) {
	for _, tt := range []struct {
		name string
		w    io.Writer
		want error
	}{
		{"write_error", failingWriter{0, io.ErrUnexpectedEOF}, io.ErrUnexpectedEOF},
		{"short_write", failingWriter{1, nil}, io.ErrShortWrite},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Copy(tt.w, strings.NewReader("body"))
			if !errors.Is(err, tt.want) || Reason(t.Context(), err) != Cancelled {
				t.Fatalf("copy error = %v", err)
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for _, tt := range []struct {
		name string
		ctx  context.Context
		err  error
		want string
	}{
		{"upstream_short", t.Context(), io.ErrUnexpectedEOF, Incomplete},
		{"upstream_timeout", t.Context(), context.DeadlineExceeded, Incomplete},
		{"client_cancel", ctx, io.ErrUnexpectedEOF, Cancelled},
		{"upstream_pipe_closed", t.Context(), io.ErrClosedPipe, Incomplete},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := Reason(tt.ctx, tt.err); got != tt.want {
				t.Fatalf("reason=%s, want=%s", got, tt.want)
			}
		})
	}
}

func TestAbortServerContext(t *testing.T) {
	for _, server := range []bool{false, true} {
		ctx := t.Context()
		if server {
			ctx = context.WithValue(ctx, http.ServerContextKey, &http.Server{ReadHeaderTimeout: time.Second})
		}
		if err := Abort(ctx, nil); err != nil {
			t.Fatalf("abort without error = %v", err)
		}
		func() {
			defer func() {
				got := recover()
				if !server {
					if got != nil {
						t.Fatalf("non-server abort panicked: %v", got)
					}
					return
				}
				err, ok := got.(error)
				if !ok || !errors.Is(err, http.ErrAbortHandler) {
					t.Fatalf("server abort panic = %v", got)
				}
			}()
			if err := Abort(ctx, io.ErrUnexpectedEOF); !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatalf("non-server abort error = %v", err)
			}
		}()
	}
}
