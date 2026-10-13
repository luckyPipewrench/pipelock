// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package verification

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestOptionsCancellationAndCallback(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		for _, callback := range []bool{false, true} {
			ctx, cancel := context.WithCancel(context.Background())
			if canceled {
				cancel()
			}
			calls := 0
			sentinel := errors.New("callback refused")
			options := Options{Context: ctx}
			if callback {
				options.Progress = func(p Progress) error {
					calls++
					if p.Bytes != 1 || p.Records != 1 {
						t.Fatal("progress changed")
					}
					return sentinel
				}
			}
			err := options.Report(Progress{Bytes: 1, Records: 1})
			if canceled {
				if !errors.Is(err, context.Canceled) || calls != 0 {
					t.Fatalf("canceled err=%v calls=%d", err, calls)
				}
			} else if callback {
				if !errors.Is(err, sentinel) || calls != 1 {
					t.Fatalf("callback err=%v calls=%d", err, calls)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			cancel()
		}
	}
	if err := (Options{}).Report(Progress{}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancelCause(context.Background())
	cancel(errors.New("owner stopped"))
	if err := (Options{Context: ctx}).Check(); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	ctx, cancelDeadline := context.WithDeadline(context.Background(), time.Time{})
	defer cancelDeadline()
	if err := (Options{Context: ctx}).Report(Progress{}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
}

func TestOptionsReportsSuccessfulProgress(t *testing.T) {
	want := Progress{Kind: "native_ael", Session: "session", Records: 2, Bytes: 3}
	var got Progress
	options := Options{Progress: func(p Progress) error { got = p; return nil }}
	if err := options.Report(want); err != nil || got != want {
		t.Fatalf("got=%+v err=%v", got, err)
	}
}
