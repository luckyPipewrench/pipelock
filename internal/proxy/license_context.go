// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"errors"

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
	return ctx, func() { cancel(context.Canceled) }
}
