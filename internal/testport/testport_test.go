// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package testport

import (
	"errors"
	"fmt"
	"net"
	"syscall"
	"testing"
)

func TestListenAddrsReturnsDistinctFreeAddrs(t *testing.T) {
	const count = 4
	addrs := ListenAddrs(t, count)
	if len(addrs) != count {
		t.Fatalf("ListenAddrs returned %d addrs, want %d", len(addrs), count)
	}

	seen := make(map[string]struct{}, count)
	for _, addr := range addrs {
		if _, _, err := net.SplitHostPort(addr); err != nil {
			t.Errorf("addr %q is not host:port: %v", addr, err)
		}
		if _, dup := seen[addr]; dup {
			t.Errorf("duplicate addr %q", addr)
		}
		seen[addr] = struct{}{}

		// Closed before return, so each addr must be bindable again.
		ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp4", addr)
		if err != nil {
			t.Errorf("addr %q not rebindable: %v", addr, err)
			continue
		}
		_ = ln.Close()
	}
}

func TestWithRetrySucceeds(t *testing.T) {
	const portCount = 2
	calls := 0
	WithRetry(t, portCount, func(addrs []string) error {
		calls++
		if len(addrs) != portCount {
			t.Errorf("fn got %d addrs, want %d", len(addrs), portCount)
		}
		return nil
	})
	if calls != 1 {
		t.Errorf("fn called %d times, want 1", calls)
	}
}

func TestIsBindCollision(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"typed errno", syscall.EADDRINUSE, true},
		{"wrapped errno", fmt.Errorf("run exited early: %w", syscall.EADDRINUSE), true},
		{"string form", errors.New("listen tcp 127.0.0.1:8080: bind: address already in use"), true},
		{"unrelated", errors.New("config validation failed"), false},
		{"connection refused", syscall.ECONNREFUSED, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsBindCollision(tc.err); got != tc.want {
				t.Errorf("IsBindCollision(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestRetrySucceedsFirstAttempt(t *testing.T) {
	calls := 0
	err := retry(stubAddrs, func([]string) error {
		calls++
		return nil
	})
	if err != nil {
		t.Fatalf("retry returned %v, want nil", err)
	}
	if calls != 1 {
		t.Errorf("fn called %d times, want 1", calls)
	}
}

func TestRetryRetriesOnCollisionThenSucceeds(t *testing.T) {
	calls := 0
	err := retry(stubAddrs, func([]string) error {
		calls++
		if calls < 3 {
			return fmt.Errorf("startup: %w", syscall.EADDRINUSE)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("retry returned %v, want nil", err)
	}
	if calls != 3 {
		t.Errorf("fn called %d times, want 3", calls)
	}
}

func TestRetryFailsFastOnNonCollision(t *testing.T) {
	calls := 0
	sentinel := errors.New("config validation failed")
	err := retry(stubAddrs, func([]string) error {
		calls++
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("retry error = %v, want wrapped %v", err, sentinel)
	}
	if calls != 1 {
		t.Errorf("fn called %d times, want 1 (no retry on real failure)", calls)
	}
}

func TestRetryExhaustsOnPersistentCollision(t *testing.T) {
	calls := 0
	err := retry(stubAddrs, func([]string) error {
		calls++
		return fmt.Errorf("startup: %w", syscall.EADDRINUSE)
	})
	if !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("retry error = %v, want wrapped EADDRINUSE", err)
	}
	if calls != maxAttempts {
		t.Errorf("fn called %d times, want %d", calls, maxAttempts)
	}
}

// stubAddrs supplies addresses without touching the network so the retry policy
// can be exercised independently of real port allocation.
func stubAddrs() []string { return []string{"127.0.0.1:1"} }
