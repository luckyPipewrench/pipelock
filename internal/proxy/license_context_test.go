// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/edition"
)

func TestAgentLicenseContext(t *testing.T) {
	t.Parallel()
	for _, alreadyRevoked := range []bool{false, true} {
		t.Run(map[bool]string{false: "open", true: "already-revoked"}[alreadyRevoked], func(t *testing.T) {
			done := make(chan struct{})
			if alreadyRevoked {
				close(done)
			}
			ctx, cancel := agentLicenseContext(t.Context(), &edition.ResolvedAgent{LicenseRevoked: done})
			defer cancel()
			if !alreadyRevoked {
				if ctx.Err() != nil {
					t.Fatal("unrevoked entitlement cancelled")
				}
				close(done)
			}
			select {
			case <-ctx.Done():
			case <-time.After(time.Second):
				t.Fatal("revocation did not cancel context")
			}
			if !errors.Is(context.Cause(ctx), errAgentLicenseRevoked) {
				t.Fatalf("wrong cancellation cause: %v", context.Cause(ctx))
			}
		})
	}
	ctx, cancel := agentLicenseContext(t.Context(), &edition.ResolvedAgent{})
	cancel()
	if ctx != t.Context() || ctx.Err() != nil {
		t.Fatal("free profile context changed")
	}
	parent, stop := context.WithCancel(t.Context())
	ctx, cancel = agentLicenseContext(parent, &edition.ResolvedAgent{LicenseRevoked: make(chan struct{})})
	defer cancel()
	stop()
	if !errors.Is(context.Cause(ctx), context.Canceled) {
		t.Fatal("parent cancellation lost")
	}
	ctx, cancel = agentLicenseContext(t.Context(), &edition.ResolvedAgent{LicenseRevoked: make(chan struct{})})
	cancel()
	if !errors.Is(context.Cause(ctx), context.Canceled) {
		t.Fatal("normal completion did not stop watcher")
	}
}
