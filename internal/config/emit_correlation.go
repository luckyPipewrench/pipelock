// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"net/http"
	"strings"

	"golang.org/x/net/http/httpguts"
)

// forbiddenCorrelationHeaders lists headers that may never be named by
// emit.correlation_header: RFC 9110 section 7.6.1 hop-by-hop headers (plus the
// non-standard Proxy-Connection), headers that carry credentials or session
// state, and framing headers whose value is not a client-chosen tag. Keys are
// lowercase. The configured request_body_scanning.sensitive_headers list is
// checked in addition to this one.
var forbiddenCorrelationHeaders = map[string]struct{}{
	// Hop-by-hop.
	"connection":          {},
	"keep-alive":          {},
	"proxy-authenticate":  {},
	"proxy-authorization": {},
	"proxy-connection":    {},
	"te":                  {},
	"trailer":             {},
	"transfer-encoding":   {},
	"upgrade":             {},
	// Credential or session bearing.
	"authorization":    {},
	"cookie":           {},
	"set-cookie":       {},
	"www-authenticate": {},
	"x-api-key":        {},
	"x-token":          {},
	"x-goog-api-key":   {},
	"private-token":    {},
	"job-token":        {},
	// Framing.
	"host":           {},
	"content-length": {},
}

// forbiddenCorrelationHeaderParts rejects header names that look
// credential-bearing even when they are not on the explicit list, such as
// X-Session-Token or X-Amz-Security-Token. Matched against the lowercase name.
var forbiddenCorrelationHeaderParts = []string{
	"auth",
	"token",
	"secret",
	"password",
	"passwd",
	"cookie",
	"credential",
	"api-key",
	"apikey",
	"access-key",
	"signature",
}

// validateEmitCorrelationHeader checks emit.correlation_header. Empty means
// the feature is off.
func (c *Config) validateEmitCorrelationHeader() error {
	name := c.Emit.CorrelationHeader
	if name == "" {
		return nil
	}
	if !httpguts.ValidHeaderFieldName(name) {
		return fmt.Errorf("invalid emit.correlation_header %q: must be a valid HTTP header name token", name)
	}
	lower := strings.ToLower(name)
	if _, ok := forbiddenCorrelationHeaders[lower]; ok {
		return fmt.Errorf("invalid emit.correlation_header %q: hop-by-hop, framing, and credential-bearing headers cannot be copied into emitted events", name)
	}
	for _, part := range forbiddenCorrelationHeaderParts {
		if strings.Contains(lower, part) {
			return fmt.Errorf("invalid emit.correlation_header %q: header names containing %q look credential-bearing and cannot be copied into emitted events", name, part)
		}
	}
	for _, sensitive := range c.RequestBodyScanning.SensitiveHeaders {
		if strings.EqualFold(strings.TrimSpace(sensitive), name) {
			return fmt.Errorf("invalid emit.correlation_header %q: listed in request_body_scanning.sensitive_headers", name)
		}
	}
	return nil
}

// normalizeEmitCorrelationHeader canonicalizes a valid header name so logs and
// docs show one spelling. Invalid names are left untouched for validation to
// report verbatim.
func (c *Config) normalizeEmitCorrelationHeader() {
	if c.Emit.CorrelationHeader != "" && httpguts.ValidHeaderFieldName(c.Emit.CorrelationHeader) {
		c.Emit.CorrelationHeader = http.CanonicalHeaderKey(c.Emit.CorrelationHeader)
	}
}
