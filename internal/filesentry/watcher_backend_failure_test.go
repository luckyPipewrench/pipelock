// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package filesentry

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
)

func TestStartReportsBackendFailureWithActiveContext(t *testing.T) {
	backend, err := fsnotify.NewWatcher()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	backend.Errors = make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	watcher := &fsWatcher{watcher: backend}
	result := make(chan error, 1)
	go func() { result <- watcher.Start(ctx) }()
	wantErr := fsnotify.ErrEventOverflow
	backend.Errors <- wantErr
	select {
	case got := <-result:
		if !errors.Is(got, wantErr) || !strings.Contains(got.Error(), "fsnotify backend error") {
			t.Fatalf("Start() = %v, want wrapped backend overflow", got)
		}
		if ctx.Err() != nil {
			t.Fatalf("test reached cancellation path: %v", ctx.Err())
		}
	case <-time.After(filesentryPositiveBackstop):
		t.Fatal("Start did not report lost filesystem observation")
	}
}
