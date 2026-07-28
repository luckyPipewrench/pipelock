// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"net/http"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/identitykey"
)

// dowSubjectTrust returns the denial-of-wallet subject key and how well that
// subject is identified. The key is always non-empty: an empty key would share
// one budget across every client, letting a single caller spend everyone
// else's allowance.
func (o MCPProxyOpts) dowSubjectTrustFor(r *http.Request) (string, config.DoWSubjectTrust) {
	if o.DoWAuthenticatedPrincipal != nil {
		if principal := strings.TrimSpace(o.DoWAuthenticatedPrincipal(r)); principal != "" {
			return principal, config.DoWTrustPrincipal
		}
	}
	client := adaptiveHostFromRemoteAddr(r.RemoteAddr)
	key := identitykey.CEESafeKey(o.DoWSubjectAgent, client, o.DoWSubjectAgentAuth)
	// CEESafeAgent returns empty for any agent identity Pipelock did not bind or
	// configure, which collapses the key to the client component. Grade on the
	// same condition so a self-declared name cannot satisfy an operator who
	// required agent grade.
	if identitykey.CEESafeAgent(o.DoWSubjectAgent, o.DoWSubjectAgentAuth) != "" {
		return key, config.DoWTrustAgent
	}
	return key, config.DoWTrustNetwork
}

// dowSubjectTrust is the package-level form used by the request path and tests.
func dowSubjectTrust(r *http.Request, opts MCPProxyOpts) (string, config.DoWSubjectTrust) {
	return opts.dowSubjectTrustFor(r)
}
