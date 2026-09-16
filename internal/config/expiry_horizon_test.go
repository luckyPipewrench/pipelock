// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
	"time"
)

func temporaryExpiryDate(maximum time.Duration) string {
	return todayUTC().Add(maximum - 24*time.Hour).Format("2006-01-02")
}

func TestTemporaryExpiryHorizons(t *testing.T) {
	today := todayUTC()
	dateAt := func(offset time.Duration) string {
		return today.Add(offset).Format("2006-01-02")
	}
	validateUnscannable := func(expires string) error {
		cfg := Defaults()
		cfg.ResponseScanning.SizeExemptDomains = []string{"downloads.vendor.example"}
		cfg.ResponseScanning.UnscannablePassthrough = []UnscannablePassthroughEntry{{
			Host: "downloads.vendor.example", Paths: []string{"/opaque/pkg.bin"},
			ContentTypes: []string{"application/octet-stream"}, Reason: "temporary opaque archive", Expires: expires,
		}}
		return cfg.Validate()
	}
	now := time.Now().UTC()

	tests := []struct {
		name        string
		field       string
		atHorizon   func() error
		oneDayPast  func() error
		omitted     func() error
		alreadyPast func() error
	}{
		{
			name:  "best effort sandbox",
			field: "sandbox: best_effort_expiry",
			atHorizon: func() error {
				return validateBestEffortAuthorization("sandbox", "temporary namespace failure", now.Add(MaxBestEffortConfigHorizon).Format(time.RFC3339), now)
			},
			oneDayPast: func() error {
				return validateBestEffortAuthorization("sandbox", "temporary namespace failure", now.Add(MaxBestEffortConfigHorizon+24*time.Hour).Format(time.RFC3339), now)
			},
			omitted: func() error {
				return Defaults().Validate()
			},
			alreadyPast: func() error {
				return validateBestEffortAuthorization("sandbox", "temporary namespace failure", now.Add(-time.Second).Format(time.RFC3339), now)
			},
		},
		{
			name:  "unscannable passthrough",
			field: "response_scanning.unscannable_passthrough[0].expires",
			atHorizon: func() error {
				return validateUnscannable(dateAt(MaxUnscannablePassthroughHorizon))
			},
			oneDayPast: func() error {
				return validateUnscannable(dateAt(MaxUnscannablePassthroughHorizon + 24*time.Hour))
			},
			omitted: func() error { return validateUnscannablePassthrough(nil) },
			alreadyPast: func() error {
				return validateUnscannable(dateAt(-24 * time.Hour))
			},
		},
		{
			name:  "path entropy exclusion",
			field: "fetch_proxy.monitoring.path_entropy_exclusions[0].expires",
			atHorizon: func() error {
				return validatePathEntropyExclusions([]PathEntropyExclusion{{Host: "docs.vendor.example", PathPrefix: "/document/d/", Expires: dateAt(MaxPathEntropyExclusionHorizon)}})
			},
			oneDayPast: func() error {
				return validatePathEntropyExclusions([]PathEntropyExclusion{{Host: "docs.vendor.example", PathPrefix: "/document/d/", Expires: dateAt(MaxPathEntropyExclusionHorizon + 24*time.Hour)}})
			},
			omitted: func() error {
				return validatePathEntropyExclusions([]PathEntropyExclusion{{Host: "docs.vendor.example", PathPrefix: "/document/d/"}})
			},
			alreadyPast: func() error {
				return validatePathEntropyExclusions([]PathEntropyExclusion{{Host: "docs.vendor.example", PathPrefix: "/document/d/", Expires: dateAt(-24 * time.Hour)}})
			},
		},
		{
			name:  "query entropy parameter exclusion",
			field: "fetch_proxy.monitoring.query_entropy_param_exclusions[0].expires",
			atHorizon: func() error {
				return validateQueryEntropyParamExclusions([]QueryEntropyParamExclusion{{Host: "api.vendor.example", Path: "/v1/download", Param: "token", Expires: dateAt(MaxQueryEntropyParamExclusionHorizon)}})
			},
			oneDayPast: func() error {
				return validateQueryEntropyParamExclusions([]QueryEntropyParamExclusion{{Host: "api.vendor.example", Path: "/v1/download", Param: "token", Expires: dateAt(MaxQueryEntropyParamExclusionHorizon + 24*time.Hour)}})
			},
			omitted: func() error {
				return validateQueryEntropyParamExclusions([]QueryEntropyParamExclusion{{Host: "api.vendor.example", Path: "/v1/download", Param: "token"}})
			},
			alreadyPast: func() error {
				return validateQueryEntropyParamExclusions([]QueryEntropyParamExclusion{{Host: "api.vendor.example", Path: "/v1/download", Param: "token", Expires: dateAt(-24 * time.Hour)}})
			},
		},
		{
			name:  "content entropy warning route",
			field: "request_body_scanning.content_entropy_warn_routes[0].expires",
			atHorizon: func() error {
				return validateRequestBodyEntropyWarnRoutes(&RequestBodyScanning{Enabled: true, ContentEntropyEnabled: true, ContentEntropyAction: ActionBlock, ContentEntropyWarnRoutes: []RequestBodyEntropyWarnRoute{{Host: "upload.vendor.example", Path: "/v1/files", ContentTypes: []string{"application/octet-stream"}, Reason: "temporary encrypted archive", Owner: "storage", Expires: dateAt(MaxRequestBodyEntropyWarnRouteHorizon)}}})
			},
			oneDayPast: func() error {
				return validateRequestBodyEntropyWarnRoutes(&RequestBodyScanning{Enabled: true, ContentEntropyEnabled: true, ContentEntropyAction: ActionBlock, ContentEntropyWarnRoutes: []RequestBodyEntropyWarnRoute{{Host: "upload.vendor.example", Path: "/v1/files", ContentTypes: []string{"application/octet-stream"}, Reason: "temporary encrypted archive", Owner: "storage", Expires: dateAt(MaxRequestBodyEntropyWarnRouteHorizon + 24*time.Hour)}}})
			},
			omitted: func() error { return validateRequestBodyEntropyWarnRoutes(&RequestBodyScanning{}) },
			alreadyPast: func() error {
				return validateRequestBodyEntropyWarnRoutes(&RequestBodyScanning{Enabled: true, ContentEntropyEnabled: true, ContentEntropyAction: ActionBlock, ContentEntropyWarnRoutes: []RequestBodyEntropyWarnRoute{{Host: "upload.vendor.example", Path: "/v1/files", ContentTypes: []string{"application/octet-stream"}, Reason: "temporary encrypted archive", Owner: "storage", Expires: dateAt(-24 * time.Hour)}}})
			},
		},
		{
			name:  "SigV4 credential route",
			field: "request_body_scanning.sigv4_credential_routes[0].expires",
			atHorizon: func() error {
				return validateRequestBodySigV4CredentialRoutes(&RequestBodyScanning{Enabled: true, SigV4CredentialRoutes: []RequestBodySigV4CredentialRoute{{Host: "api.vendor.example", Path: "/v1/graphql", ContentTypes: []string{"application/json"}, Methods: []string{"POST"}, Reason: "temporary attachment migration", Owner: "platform", Expires: dateAt(MaxRequestBodySigV4CredentialRouteHorizon)}}})
			},
			oneDayPast: func() error {
				return validateRequestBodySigV4CredentialRoutes(&RequestBodyScanning{Enabled: true, SigV4CredentialRoutes: []RequestBodySigV4CredentialRoute{{Host: "api.vendor.example", Path: "/v1/graphql", ContentTypes: []string{"application/json"}, Methods: []string{"POST"}, Reason: "temporary attachment migration", Owner: "platform", Expires: dateAt(MaxRequestBodySigV4CredentialRouteHorizon + 24*time.Hour)}}})
			},
			omitted: func() error { return validateRequestBodySigV4CredentialRoutes(&RequestBodyScanning{}) },
			alreadyPast: func() error {
				return validateRequestBodySigV4CredentialRoutes(&RequestBodyScanning{Enabled: true, SigV4CredentialRoutes: []RequestBodySigV4CredentialRoute{{Host: "api.vendor.example", Path: "/v1/graphql", ContentTypes: []string{"application/json"}, Methods: []string{"POST"}, Reason: "temporary attachment migration", Owner: "platform", Expires: dateAt(-24 * time.Hour)}}})
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, check := range []struct {
				name      string
				validate  func() error
				wantErr   bool
				wantField bool
			}{
				{name: "at horizon", validate: tt.atHorizon},
				{name: "one day past horizon", validate: tt.oneDayPast, wantErr: true, wantField: true},
				{name: "omitted", validate: tt.omitted},
				{name: "already past", validate: tt.alreadyPast, wantErr: true},
			} {
				t.Run(check.name, func(t *testing.T) {
					err := check.validate()
					if check.wantErr {
						if err == nil {
							t.Fatal("validation accepted an invalid temporary expiry")
						}
						if check.wantField && !strings.Contains(err.Error(), tt.field) {
							t.Fatalf("error = %q, want field %q", err, tt.field)
						}
						return
					}
					if err != nil {
						t.Fatalf("validation = %v, want nil", err)
					}
				})
			}
		})
	}
}

func TestDurableTrustedUpstreamAcceptsFarFutureExpiry(t *testing.T) {
	cfg := submitValidCfg()
	cfg.ReverseProxy.TrustedUpstream.Expires = "2099-12-31"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("durable trusted upstream rejected a far-future review date: %v", err)
	}
}
