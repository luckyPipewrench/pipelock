// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import "testing"

func TestFlightRecorder_HeartbeatIntervalSecondsForReceipt(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		interval string
		want     int
	}{
		{"unset uses the 60s default", "", 60},
		{"whole seconds", "5s", 5},
		{"sub-second rounds up to 1, never 0 (which means disabled)", "500ms", 1},
		{"tiny positive interval still records 1", "1ms", 1},
		{"fractional rounds to nearest second (up)", "1500ms", 2},
		{"fractional rounds to nearest second (down)", "1400ms", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var f FlightRecorder
			f.Completeness.HeartbeatInterval = tc.interval
			if got := f.HeartbeatIntervalSecondsForReceipt(); got != tc.want {
				t.Fatalf("HeartbeatIntervalSecondsForReceipt(%q) = %d, want %d", tc.interval, got, tc.want)
			}
		})
	}
}
