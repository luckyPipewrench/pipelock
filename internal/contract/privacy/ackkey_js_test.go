// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build js

package privacy_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/contract/privacy"
)

// On the browser target the acknowledgment key refuses a file source with
// its own platform rule, before the shared loader runs, and an environment
// key still resolves. This lives here because the config test binary does
// not build for js.
func TestMCPAckKeyFileSourceRefusedOnBrowserTarget(t *testing.T) {
	_, err := config.ResolveMCPAckKey("file:/run/pipelock/ack.key")
	if err == nil || !strings.Contains(err.Error(), "not supported on this platform") || errors.Is(err, privacy.ErrSaltFileUnsupported) {
		t.Fatalf("file key err = %v, want the acknowledgment key's platform refusal before the loader", err)
	}
	const key = "synthetic-acknowledgment-key-browser-0123"
	t.Setenv("PIPELOCK_TEST_JS_ACK_KEY", key)
	got, err := config.ResolveMCPAckKey("${PIPELOCK_TEST_JS_ACK_KEY}")
	if err != nil || string(got) != key {
		t.Fatalf("environment key = %q, %v", got, err)
	}
}
