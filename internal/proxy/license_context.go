// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"errors"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/edition"
)

var errAgentLicenseRevoked = errors.New("agent license revoked")

// agentLicenseContext carries the resolved entitlement's lifetime into an
// established connection. It also catches revocation between resolution and
// registering the watcher. Cancellation releases the watcher on normal close.
func agentLicenseContext(parent context.Context, resolved *edition.ResolvedAgent) (context.Context, context.CancelFunc) {
	if resolved.LicenseRevoked == nil {
		return parent, func() {}
	}
	ctx, cancel := context.WithCancelCause(parent)
	// Bound each request independently of the runtime watchdog so an expiry
	// teardown delayed by another lifecycle operation cannot prolong traffic.
	var expiry *time.Timer
	if resolved.LicenseExpiresAt > 0 {
		remaining := time.Until(time.Unix(resolved.LicenseExpiresAt, 0))
		if remaining <= 0 {
			cancel(errAgentLicenseRevoked)
		} else {
			expiry = time.AfterFunc(remaining, func() { cancel(errAgentLicenseRevoked) })
		}
	}
	select {
	case <-resolved.LicenseRevoked:
		cancel(errAgentLicenseRevoked)
	default:
		go func() {
			select {
			case <-resolved.LicenseRevoked:
				cancel(errAgentLicenseRevoked)
			case <-ctx.Done():
			}
		}()
	}
	return ctx, func() {
		if expiry != nil {
			expiry.Stop()
		}
		cancel(context.Canceled)
	}
}
