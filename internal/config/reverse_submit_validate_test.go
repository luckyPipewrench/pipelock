// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
	"time"
)

// submitValidCfg builds a config that satisfies every submit-profile
// validation rule. Tests then mutate one field and assert the expected
// rejection — the negative-test pattern from validate.go's existing tests.
func submitValidCfg() *Config {
	cfg := Defaults()
	cfg.ReverseProxy.Enabled = true
	cfg.ReverseProxy.Listen = "127.0.0.1:8892"
	cfg.ReverseProxy.Upstream = "http://example.test:30891"
	cfg.ReverseProxy.Profile = ReverseProxyProfileSubmit
	cfg.ReverseProxy.AllowedMethods = []string{"POST"}
	cfg.ReverseProxy.AllowedPaths = []ReverseProxyPathRule{{Exact: "/v1/batch"}}
	cfg.ReverseProxy.MaxBodyBytes = 1024 * 1024
	cfg.ReverseProxy.RequestTimeoutSeconds = 30
	cfg.ReverseProxy.TrustedUpstream = ReverseProxyTrustedUpstream{
		Host:   "example.test",
		Port:   30891,
		Reason: "test",
		Added:  "2026-05-26",
	}
	cfg.ApplyDefaults()
	return cfg
}

func TestValidate_ReverseProxySubmit_AcceptsValidConfig(t *testing.T) {
	if err := submitValidCfg().Validate(); err != nil {
		t.Fatalf("valid submit-profile config rejected: %v", err)
	}
}

func TestValidate_ReverseProxySubmit_UnknownProfileRejected(t *testing.T) {
	cfg := submitValidCfg()
	cfg.ReverseProxy.Profile = "lenient"
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "not a known profile") {
		t.Fatalf("got %v, want unknown-profile rejection", err)
	}
}

func TestValidate_ReverseProxySubmit_FieldsRequiredWithoutProfile(t *testing.T) {
	// Setting submit-only fields without the profile selector must be
	// rejected so an operator can't silently lose submit semantics by
	// typo'ing the profile name.
	cfg := submitValidCfg()
	cfg.ReverseProxy.Profile = ""
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "only valid when profile") {
		t.Fatalf("got %v, want submit-only-fields rejection", err)
	}
}

func TestValidate_ReverseProxySubmit_TrustedUpstreamRequired(t *testing.T) {
	cfg := submitValidCfg()
	cfg.ReverseProxy.TrustedUpstream = ReverseProxyTrustedUpstream{}
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "trusted_upstream is required") {
		t.Fatalf("got %v, want trusted_upstream-required rejection", err)
	}
}

func TestValidate_ReverseProxySubmit_HostMismatchRejected(t *testing.T) {
	cfg := submitValidCfg()
	cfg.ReverseProxy.TrustedUpstream.Host = "other.test"
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "does not match upstream host") {
		t.Fatalf("got %v, want host-mismatch rejection", err)
	}
}

func TestValidate_ReverseProxySubmit_HostMatchNormalizesCaseAndTrailingDot(t *testing.T) {
	cfg := submitValidCfg()
	cfg.ReverseProxy.Upstream = "http://Example.Test.:30891"
	cfg.ReverseProxy.TrustedUpstream.Host = " EXAMPLE.TEST. "
	if err := cfg.Validate(); err != nil {
		t.Fatalf("case/trailing-dot equivalent host rejected: %v", err)
	}
	if cfg.ReverseProxy.TrustedUpstream.Host != "example.test" {
		t.Fatalf("trusted_upstream.host = %q, want normalized example.test", cfg.ReverseProxy.TrustedUpstream.Host)
	}
}

func TestValidate_ReverseProxySubmit_PortMismatchRejected(t *testing.T) {
	cfg := submitValidCfg()
	cfg.ReverseProxy.TrustedUpstream.Port = 12345
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "does not match upstream port") {
		t.Fatalf("got %v, want port-mismatch rejection", err)
	}
}

func TestValidate_ReverseProxySubmit_IPLiteralRejected(t *testing.T) {
	cfg := submitValidCfg()
	cfg.ReverseProxy.Upstream = "http://127.0.0.1:30891"
	cfg.ReverseProxy.TrustedUpstream.Host = "127.0.0.1"
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "IP literal") {
		t.Fatalf("got %v, want IP-literal rejection", err)
	}
}

func TestValidate_ReverseProxySubmit_UpstreamWithoutPortRejected(t *testing.T) {
	cfg := submitValidCfg()
	cfg.ReverseProxy.Upstream = "http://example.test"
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "explicit port") {
		t.Fatalf("got %v, want explicit-port rejection", err)
	}
}

func TestValidate_ReverseProxySubmit_ReasonRequired(t *testing.T) {
	cfg := submitValidCfg()
	cfg.ReverseProxy.TrustedUpstream.Reason = ""
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "reason is required") {
		t.Fatalf("got %v, want reason-required rejection", err)
	}
}

func TestValidate_ReverseProxySubmit_ReasonWhitespaceRejected(t *testing.T) {
	// A reason of "   \t  " satisfies the != "" check but provides no
	// audit content. Validation must trim before evaluating the guard.
	cfg := submitValidCfg()
	cfg.ReverseProxy.TrustedUpstream.Reason = "   \t  "
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "reason is required") {
		t.Fatalf("got %v, want whitespace-only-reason rejection", err)
	}
}

func TestValidate_ReverseProxySubmit_ReasonTrimmedOnAccept(t *testing.T) {
	cfg := submitValidCfg()
	cfg.ReverseProxy.TrustedUpstream.Reason = "   audit grant w/ trim   "
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid trimmed reason rejected: %v", err)
	}
	if got := cfg.ReverseProxy.TrustedUpstream.Reason; got != "audit grant w/ trim" {
		t.Errorf("reason = %q, want trimmed value", got)
	}
}

func TestValidate_ReverseProxySubmit_AddedRequired(t *testing.T) {
	cfg := submitValidCfg()
	cfg.ReverseProxy.TrustedUpstream.Added = ""
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "added is required") {
		t.Fatalf("got %v, want added-required rejection", err)
	}
}

func TestValidate_ReverseProxySubmit_AddedFormatRejected(t *testing.T) {
	cfg := submitValidCfg()
	cfg.ReverseProxy.TrustedUpstream.Added = "May 26 2026"
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "must be YYYY-MM-DD") {
		t.Fatalf("got %v, want added-format rejection", err)
	}
}

func TestValidate_ReverseProxySubmit_ExpiresPastRejected(t *testing.T) {
	cfg := submitValidCfg()
	cfg.ReverseProxy.TrustedUpstream.Expires = time.Now().UTC().AddDate(0, 0, -2).Format("2006-01-02")
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "in the past") {
		t.Fatalf("got %v, want expired rejection", err)
	}
}

func TestValidate_ReverseProxySubmit_ExpiresFutureAccepted(t *testing.T) {
	cfg := submitValidCfg()
	cfg.ReverseProxy.TrustedUpstream.Expires = time.Now().UTC().AddDate(0, 0, 30).Format("2006-01-02")
	if err := cfg.Validate(); err != nil {
		t.Fatalf("future-expiry rejected: %v", err)
	}
}

func TestValidate_ReverseProxySubmit_AllowedPathsRequired(t *testing.T) {
	cfg := submitValidCfg()
	cfg.ReverseProxy.AllowedPaths = nil
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "allowed_paths is required") {
		t.Fatalf("got %v, want allowed_paths-required rejection", err)
	}
}

func TestValidate_ReverseProxySubmit_AllowedPathNonCanonical(t *testing.T) {
	cfg := submitValidCfg()
	cfg.ReverseProxy.AllowedPaths = []ReverseProxyPathRule{{Exact: "/v1//batch"}}
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "not canonical") {
		t.Fatalf("got %v, want non-canonical rejection", err)
	}
}

func TestValidate_ReverseProxySubmit_AllowedPathMustStartWithSlash(t *testing.T) {
	cfg := submitValidCfg()
	cfg.ReverseProxy.AllowedPaths = []ReverseProxyPathRule{{Exact: "v1/batch"}}
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "must start with /") {
		t.Fatalf("got %v, want must-start-with-/ rejection", err)
	}
}

func TestValidate_ReverseProxySubmit_UnknownMethodRejected(t *testing.T) {
	cfg := submitValidCfg()
	cfg.ReverseProxy.AllowedMethods = []string{"WHATEVER"}
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "not a recognized HTTP method") {
		t.Fatalf("got %v, want unknown-method rejection", err)
	}
}

func TestValidate_ReverseProxySubmit_BodyBytesRequiredPositive(t *testing.T) {
	cfg := submitValidCfg()
	cfg.ReverseProxy.MaxBodyBytes = 0
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "max_body_bytes must be positive") {
		t.Fatalf("got %v, want max_body_bytes rejection", err)
	}
}

func TestValidate_ReverseProxySubmit_TimeoutRequiredPositive(t *testing.T) {
	cfg := submitValidCfg()
	cfg.ReverseProxy.RequestTimeoutSeconds = 0
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "request_timeout_seconds must be positive") {
		t.Fatalf("got %v, want request_timeout_seconds rejection", err)
	}
}
