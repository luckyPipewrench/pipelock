//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package entcli

import (
	"net/http"

	"github.com/luckyPipewrench/pipelock/enterprise/dashboard"
)

// dashboardAuthorizerRegistry records the authenticators selected for one
// dashboard server. Registration order does not alter precedence: a configured
// client certificate authorizer is exclusive, while static tokens and OIDC
// retain their existing shared Bearer-token behavior when mTLS is absent.
type dashboardAuthorizerRegistry struct {
	metadataToken     string
	rawToken          string
	clientCertAuth    *dashboardClientCertAuthorizer
	oidcAuthenticator *dashboardOIDCAuthenticator
}

type dashboardComposedAuthorizers struct {
	metaAuthorized      func(*http.Request) bool
	authorizePermission func(*http.Request, dashboard.Permission) error
	rawAuthorized       func(*http.Request) bool
	authAuditInfo       func(*http.Request) dashboard.AuthAuditInfo
	failedAuthMode      func(*http.Request) string
	oidcAuthenticator   *dashboardOIDCAuthenticator
}

func newDashboardAuthorizerRegistry() *dashboardAuthorizerRegistry {
	return &dashboardAuthorizerRegistry{}
}

// registerStaticTokens adds the configured metadata and raw-access tokens. An
// empty value never authorizes: dashboardConfiguredTokenMatches fails closed.
func (r *dashboardAuthorizerRegistry) registerStaticTokens(metadataToken, rawToken string) {
	r.metadataToken = metadataToken
	r.rawToken = rawToken
}

// registerClientCertificate adds the mapped mTLS authenticator. Its presence
// makes mTLS exclusive so a missing or unmapped certificate cannot fall back to
// a valid static token or OIDC principal.
func (r *dashboardAuthorizerRegistry) registerClientCertificate(auth *dashboardClientCertAuthorizer) {
	r.clientCertAuth = auth
}

// registerOIDC adds the OIDC middleware and the verified principal it places
// on requests. A nil authenticator contributes no authorization decision.
func (r *dashboardAuthorizerRegistry) registerOIDC(auth *dashboardOIDCAuthenticator) {
	r.oidcAuthenticator = auth
}

// compose returns the callbacks installed by the dashboard server. The empty
// registry has no matching static token, certificate, or OIDC principal, so it
// denies every request and every route permission.
func (r *dashboardAuthorizerRegistry) compose() dashboardComposedAuthorizers {
	authorization := newDashboardRequestAuthorization(r.metadataToken, r.rawToken, r.oidcAuthenticator)
	metaAuthorized, authorizePermission, rawAuthorized := dashboardClientCertAuthorizers(
		r.clientCertAuth,
		authorization.metaAuthorized,
		authorization.authorizePermission,
		authorization.rawAuthorized,
	)
	composed := dashboardComposedAuthorizers{
		metaAuthorized:      metaAuthorized,
		authorizePermission: authorizePermission,
		rawAuthorized:       rawAuthorized,
		authAuditInfo:       authorization.authAuditInfo,
		failedAuthMode:      authorization.failedAuthMode,
		oidcAuthenticator:   r.oidcAuthenticator,
	}
	// mTLS is exclusive in all callback surfaces, including audit attribution
	// and emitted failure mode. Do not turn this into an authorizer fallback.
	if r.clientCertAuth != nil {
		composed.authAuditInfo = func(req *http.Request) dashboard.AuthAuditInfo {
			return dashboardClientCertAuthAuditInfo(r.clientCertAuth, req)
		}
		composed.failedAuthMode = nil
	}
	return composed
}

func (a dashboardComposedAuthorizers) wrap(next http.Handler) http.Handler {
	if a.oidcAuthenticator != nil {
		return a.oidcAuthenticator.middleware(next)
	}
	return next
}
