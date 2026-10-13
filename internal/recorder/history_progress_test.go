// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"context"
	"errors"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/verification"
)

func TestHistoryProgressInsideFileAndCancellation(t *testing.T) {
	dir := t.TempDir()
	const session = "history-progress"
	writeHistoryShard(t, dir, session, 0, 4)
	var readBytes int64
	entries := 0
	err := WalkSessionHistoryWithOptions(dir, session, verification.Options{Progress: func(p verification.Progress) error { readBytes += p.Bytes; return nil }}, func(Entry) error {
		if readBytes == 0 {
			t.Fatal("entry delivered before in-file byte progress")
		}
		entries++
		return nil
	})
	if err != nil || entries != 4 {
		t.Fatalf("entries=%d bytes=%d err=%v", entries, readBytes, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err = WalkSessionHistoryWithOptions(dir, session, verification.Options{Context: ctx, Progress: func(verification.Progress) error { cancel(); return nil }}, func(Entry) error { return nil })
	if !errors.Is(err, context.Canceled) || errors.Is(err, ErrTornTail) {
		t.Fatalf("cancellation classified as recoverable tail: %v", err)
	}
	failure := errors.New("notification failure")
	err = WalkSessionHistoryWithOptions(dir, session, verification.Options{Progress: func(verification.Progress) error { return failure }}, func(Entry) error { return nil })
	if !errors.Is(err, failure) || errors.Is(err, ErrTornTail) {
		t.Fatalf("progress error classified as recoverable tail: %v", err)
	}
}
