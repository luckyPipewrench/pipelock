// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux && amd64

package mcp

import (
	"errors"
	"strings"
	"testing"
)

func TestHardenProxyProcessWith(t *testing.T) {
	called := false
	if err := hardenProxyProcessWith(func() error {
		called = true
		return nil
	}); err != nil {
		t.Fatalf("hardenProxyProcessWith: %v", err)
	}
	if !called {
		t.Fatal("PR_SET_DUMPABLE hardening was not invoked")
	}
}

func TestHardenProxyProcessWithFailsClosed(t *testing.T) {
	err := hardenProxyProcessWith(func() error { return errors.New("denied") })
	if err == nil || !strings.Contains(err.Error(), "set non-dumpable") {
		t.Fatalf("error = %v, want non-dumpable failure", err)
	}
}
