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
			if alreadyRevoked && ctx.Err() == nil {
				t.Fatal("already-revoked context must be canceled synchronously")
			}
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

func TestAgentLicenseContextExpiry(t *testing.T) {
	t.Parallel()
	for _, future := range []bool{false, true} {
		t.Run(map[bool]string{false: "expired", true: "upcoming"}[future], func(t *testing.T) {
			deadline := time.Now().Add(-time.Second).Unix()
			if future {
				deadline = time.Now().Add(2 * time.Second).Unix()
			}
			ctx, release := agentLicenseContext(t.Context(), &edition.ResolvedAgent{LicenseRevoked: make(chan struct{}), LicenseExpiresAt: deadline})
			defer release()
			if !future && ctx.Err() == nil {
				t.Fatal("expired entitlement must cancel synchronously")
			}
			select {
			case <-ctx.Done():
			case <-time.After(3 * time.Second):
				t.Fatal("expiry did not cancel request")
			}
			if !errors.Is(context.Cause(ctx), errAgentLicenseRevoked) {
				t.Fatal(context.Cause(ctx))
			}
		})
	}
}
