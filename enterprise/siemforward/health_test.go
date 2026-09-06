//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package siemforward

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type healthObserver struct {
	delivered func()
	failed    func()
	dropped   func()
	succeeded func(time.Time)
}

func (*healthObserver) SetQueued(float64)     {}
func (*healthObserver) SetSpoolBytes(float64) {}
func (o *healthObserver) RecordDelivered() {
	if o.delivered != nil {
		o.delivered()
	}
}

func (o *healthObserver) RecordFailed() {
	if o.failed != nil {
		o.failed()
	}
}

func (o *healthObserver) RecordDropped() {
	if o.dropped != nil {
		o.dropped()
	}
}

func (o *healthObserver) SetLastSuccess(now time.Time) {
	if o.succeeded != nil {
		o.succeeded(now)
	}
}

func TestHealthPublishedBeforeFailureObserver(t *testing.T) {
	t.Parallel()
	for _, dropped := range []bool{false, true} {
		name := "failure"
		if dropped {
			name = "permanent drop"
		}
		t.Run(name, func(t *testing.T) {
			f := &Forwarder{}
			var snapshots []Health
			capture := func() { snapshots = append(snapshots, f.Health()) }
			f.observer = &healthObserver{failed: capture, dropped: capture}
			for i, message := range []string{"first error", "replacement error", "replacement error"} {
				if dropped {
					f.recordDroppedEvent(testEvent(i), errors.New(message))
				} else {
					f.recordFailure(errors.New(message))
				}
				if len(snapshots) != i+1 {
					t.Fatalf("observer calls = %d, want %d", len(snapshots), i+1)
				}
				h := snapshots[i]
				count := h.Failed
				if dropped {
					count = h.Dropped
				}
				if count != uint64(i+1) || h.LastError != message {
					t.Fatalf("observer health = %+v, want count %d with error %q", h, i+1, message)
				}
			}
		})
	}
}

func TestHealthPublishedBeforeDeliveryObserver(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	f, err := New(testConfig(t, "http://api.vendor.example/events"), Options{
		Resolver:      &sequenceResolver{answers: [][]string{{testPublicIP}}},
		DialContext:   routeToServer(t, srv),
		DeferredStart: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	f.recordFailure(errors.New("prior delivery failure"))
	var snapshots []Health
	var successes []time.Time
	f.observer = &healthObserver{
		delivered: func() { snapshots = append(snapshots, f.Health()) },
		succeeded: func(now time.Time) {
			snapshots = append(snapshots, f.Health())
			successes = append(successes, now)
		},
	}
	for i := range 2 {
		if err := f.appendEvent(testEvent(i)); err != nil {
			t.Fatal(err)
		}
		f.deliverPending()
		if len(snapshots) != 2*(i+1) || len(successes) != i+1 {
			t.Fatalf("observer calls = %d/%d, want %d/%d", len(snapshots), len(successes), 2*(i+1), i+1)
		}
		for _, h := range snapshots[2*i:] {
			if h.Delivered != uint64(i+1) || h.Failed != 1 || h.LastError != "" || h.LastSuccess.IsZero() || !h.LastSuccess.Equal(successes[i]) {
				t.Fatalf("observer health = %+v, want delivery %d at %v with cleared error", h, i+1, successes[i])
			}
		}
	}
}
