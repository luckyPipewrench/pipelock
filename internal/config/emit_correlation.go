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

// credentialHeaderWords rejects header names that look credential-bearing
// even when they are not on the explicit list, such as X-Session-Id or
// Cf-Access-Jwt-Assertion. The name is lowercased and split into words on
// '-', '_', and '.'; every contiguous run of words is joined and matched
// exactly against this set. Joining runs catches split spellings such as
// X-Api_Key ("api"+"key") and Pass-Word, while exact word matching keeps
// harmless names such as X-Author and X-Authority from tripping on "auth".
var credentialHeaderWords = map[string]struct{}{
	"auth":          {},
	"authorization": {},
	"authn":         {},
	"authz":         {},
	"token":         {},
	"secret":        {},
	"password":      {},
	"passwd":        {},
	"pwd":           {},
	"pass":          {},
	"cookie":        {},
	"credential":    {},
	"credentials":   {},
	"apikey":        {},
	"accesskey":     {},
	"secretkey":     {},
	"privatekey":    {},
	"signature":     {},
	"sig":           {},
	"session":       {},
	"sessionid":     {},
	"jwt":           {},
	"bearer":        {},
	"assertion":     {},
	"csrf":          {},
	"xsrf":          {},
	"otp":           {},
	"totp":          {},
	"private":       {},
}

// credentialHeaderWordAffixes catches a credential word fused into a longer
// word, as in X-Sessiontoken or X-Apitoken. Config normalization canonicalizes
// the header name before validation, so camelCase boundaries are gone by the
// time this runs. Prefixes and suffixes are separate lists because short
// stems that are harmless at the start of a word (auth in author, pass in
// passthrough, sig in signal) are still credential-shaped at the end.
var (
	credentialHeaderWordPrefixes = []string{
		"token", "secret", "password", "passwd", "cookie", "credential",
		"apikey", "accesskey", "signature", "bearer", "assertion", "jwt",
	}
	credentialHeaderWordSuffixes = []string{
		"token", "secret", "password", "passwd", "cookie", "credential",
		"credentials", "apikey", "accesskey", "secretkey", "privatekey",
		"signature", "bearer", "assertion", "sessionid", "session", "jwt",
		"auth", "csrf", "xsrf",
	}
)

// credentialHeaderWord returns the credential-shaped word or word run found in
// a header name, or "" when the name looks harmless.
func credentialHeaderWord(name string) string {
	words := strings.FieldsFunc(strings.ToLower(name), func(r rune) bool {
		return r == '-' || r == '_' || r == '.'
	})
	for i := range words {
		joined := ""
		for j := i; j < len(words); j++ {
			joined += words[j]
			if _, ok := credentialHeaderWords[joined]; ok {
				return joined
			}
		}
	}
	for _, w := range words {
		for _, p := range credentialHeaderWordPrefixes {
			if strings.HasPrefix(w, p) {
				return w
			}
		}
		for _, s := range credentialHeaderWordSuffixes {
			if strings.HasSuffix(w, s) {
				return w
			}
		}
	}
	return ""
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
	if word := credentialHeaderWord(name); word != "" {
		return fmt.Errorf("invalid emit.correlation_header %q: header name word %q looks credential-bearing and cannot be copied into emitted events", name, word)
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
