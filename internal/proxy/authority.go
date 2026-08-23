// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"net/http"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/authority"
)

const blockLayerAuthority = "authority"

func consumeAuthorityHeader(r *http.Request) (string, error) {
	if r == nil {
		return "", authority.ErrMissingReference
	}
	return authority.ExtractHTTPReference(r.Header)
}

func (p *Proxy) authorizeForward(
	ctx context.Context,
	ref string,
	carrierErr error,
	request authority.Request,
	auditCtx audit.LogContext,
	transport string,
) error {
	if p.authorityVerifier == nil {
		return nil
	}
	request.AuthorityRef = ref
	result, err := authority.Evaluate(ctx, p.authorityVerifier, request, carrierErr)
	if p.logger != nil {
		p.logger.LogAuthorityVerification(auditCtx, audit.NewAuthorityVerification(
			transport,
			result.Decision.String(),
			string(result.Reason),
			result.Issuer,
			result.Reference,
			err,
		))
	}
	return err
}
