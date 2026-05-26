// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"errors"
	"fmt"
	"strings"
	"syscall"
	"testing"
)

func TestWrapBindError(t *testing.T) {
	tests := []struct {
		name       string
		label      string
		addr       string
		cause      error
		wantNil    bool
		wantSubstr []string
		wantHint   bool
	}{
		{
			name:    "nil-cause-returns-nil",
			label:   "fetch_proxy.listen",
			addr:    ":8888",
			cause:   nil,
			wantNil: true,
		},
		{
			name:       "eaddrinuse-appends-doctor-hint",
			label:      "fetch_proxy.listen",
			addr:       "127.0.0.1:8888",
			cause:      fmt.Errorf("wrapper: %w", syscall.EADDRINUSE),
			wantSubstr: []string{"fetch_proxy.listen bind 127.0.0.1:8888", "doctor --check-ports"},
			wantHint:   true,
		},
		{
			name:       "permission-denied-no-hint",
			label:      "metrics_listen",
			addr:       ":9090",
			cause:      syscall.EACCES,
			wantSubstr: []string{"metrics_listen bind :9090"},
			wantHint:   false,
		},
		{
			name:       "wrapped-eaddrinuse-still-recognized",
			label:      "scan_api.listen",
			addr:       "[::1]:7777",
			cause:      fmt.Errorf("outer: %w", fmt.Errorf("inner: %w", syscall.EADDRINUSE)),
			wantSubstr: []string{"scan_api.listen bind [::1]:7777", "doctor --check-ports"},
			wantHint:   true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := wrapBindError(tc.label, tc.addr, tc.cause)
			if tc.wantNil {
				if err != nil {
					t.Fatalf("got err=%v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatal("got nil error, want wrapped")
			}
			// EADDRINUSE must remain unwrappable so callers can errors.Is it.
			if tc.wantHint && !errors.Is(err, syscall.EADDRINUSE) {
				t.Errorf("errors.Is(err, EADDRINUSE) = false; want true so callers can still detect the cause")
			}
			for _, s := range tc.wantSubstr {
				if !strings.Contains(err.Error(), s) {
					t.Errorf("error %q does not contain %q", err.Error(), s)
				}
			}
			hasHint := strings.Contains(err.Error(), "doctor --check-ports")
			if hasHint != tc.wantHint {
				t.Errorf("hint present = %v, want %v; err=%q", hasHint, tc.wantHint, err.Error())
			}
		})
	}
}

func TestWrapBindErrorNoDoctorHint(t *testing.T) {
	// Runtime-only listeners (mcp_listen, agents[*].listen) get the wrap
	// without the doctor hint, since doctor --check-ports cannot inspect
	// them. Verify both EADDRINUSE and other causes get the same format
	// (no hint either way).
	tests := []struct {
		name    string
		cause   error
		wantNil bool
	}{
		{"nil-cause", nil, true},
		{"eaddrinuse", syscall.EADDRINUSE, false},
		{"permission-denied", syscall.EACCES, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := wrapBindErrorNoDoctorHint("mcp_listen", "127.0.0.1:12345", tc.cause)
			if tc.wantNil {
				if err != nil {
					t.Fatalf("got err=%v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatal("got nil error, want wrapped")
			}
			if !strings.Contains(err.Error(), "mcp_listen bind 127.0.0.1:12345") {
				t.Errorf("error %q missing label/addr prefix", err.Error())
			}
			if strings.Contains(err.Error(), "doctor --check-ports") {
				t.Errorf("error %q must NOT contain doctor hint; doctor cannot inspect runtime-only listeners", err.Error())
			}
		})
	}
}
