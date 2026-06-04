// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"net/url"
	"strings"
	"testing"
)

// dlpLike returns a dlpClean that flags text containing any of the given
// secrets. It models the real DLP scanner closely enough to exercise the
// sanitizer's backstop paths: it checks the raw text, the percent-unescaped
// text, and the concatenation of all query-parameter values (which is how the
// production scanner reassembles a secret split across multiple params). Any
// hit means "dirty" (not clean).
func dlpLike(secrets ...string) dlpClean {
	return func(text string) bool {
		candidates := []string{text}
		if un, err := url.QueryUnescape(text); err == nil {
			candidates = append(candidates, un)
		}
		candidates = append(candidates, concatQueryValues(text))
		for _, c := range candidates {
			for _, s := range secrets {
				if s != "" && strings.Contains(c, s) {
					return false // dirty
				}
			}
		}
		return true // clean
	}
}

// concatQueryValues joins all query-parameter values (percent-decoded) in
// order, mirroring the scanner's split-secret reassembly.
func concatQueryValues(rawURL string) string {
	_, query, ok := strings.Cut(rawURL, "?")
	if !ok {
		return ""
	}
	query, _, _ = strings.Cut(query, "#")
	var b strings.Builder
	for _, pair := range strings.Split(query, "&") {
		_, val, _ := strings.Cut(pair, "=")
		if val == "" {
			continue
		}
		if un, err := url.QueryUnescape(val); err == nil {
			b.WriteString(un)
		} else {
			b.WriteString(val)
		}
	}
	return b.String()
}

func TestSanitizeTarget(t *testing.T) {
	t.Parallel()

	secret := "AKIA" + "IOSFODNN7EXAMPLE"
	creds := "s3cr3tp@ss"
	clean := dlpLike(secret, creds)

	tests := []struct {
		name        string
		target      string
		wantExact   string   // if non-empty, the precise expected output
		wantPrefix  string   // if non-empty, output must start with this
		mustNotHave []string // substrings that must be absent from output
	}{
		{
			name:      "clean url unchanged",
			target:    "https://api.vendor.example/v1/models?name=gpt",
			wantExact: "https://api.vendor.example/v1/models?name=gpt",
		},
		{
			name:        "userinfo stripped",
			target:      "https://user:" + creds + "@api.vendor.example/v1/keys",
			wantExact:   "https://api.vendor.example/v1/keys",
			mustNotHave: []string{creds, "user:", "@api.vendor.example"},
		},
		{
			name:        "secret query value redacted, key and siblings preserved",
			target:      "https://api.vendor.example/v1/keys?model=gpt&token=" + secret,
			wantExact:   "https://api.vendor.example/v1/keys?model=gpt&token=" + redactedValue,
			mustNotHave: []string{secret},
		},
		{
			name:        "secret in path coarsens to redacted path, host kept",
			target:      "https://api.vendor.example/v1/" + secret + "/info",
			wantPrefix:  "https://api.vendor.example/" + redactedSegment,
			mustNotHave: []string{secret},
		},
		{
			name:        "secret split across query params caught by backstop",
			target:      "https://api.vendor.example/v1/keys?a=AKIAIOSFOD&b=NN7EXAMPLE",
			wantExact:   "https://api.vendor.example/v1/keys",
			mustNotHave: []string{secret, "AKIAIOSFOD", "NN7EXAMPLE"},
		},
		{
			name:        "percent-encoded secret in query redacted",
			target:      "https://api.vendor.example/v1/keys?token=" + url.QueryEscape(secret),
			mustNotHave: []string{secret, url.QueryEscape(secret)},
		},
		{
			name:        "secret in fragment dropped",
			target:      "https://api.vendor.example/v1/keys#" + secret,
			wantExact:   "https://api.vendor.example/v1/keys",
			mustNotHave: []string{secret},
		},
		{
			name:        "non-standard param name still redacted",
			target:      "https://api.vendor.example/cb?xyzzy=" + secret,
			wantExact:   "https://api.vendor.example/cb?xyzzy=" + redactedValue,
			mustNotHave: []string{secret},
		},
		{
			name:      "opaque tool name clean passes through",
			target:    "search_web",
			wantExact: "search_web",
		},
		{
			name:        "opaque target carrying secret collapses to marker",
			target:      "tool_" + secret,
			wantExact:   redactedTarget,
			mustNotHave: []string{secret},
		},
		{
			name:        "secret in host collapses to marker",
			target:      "https://" + secret + ".evil.example/path",
			wantExact:   redactedTarget,
			mustNotHave: []string{secret},
		},
		{
			name:        "unparseable url with secret collapses to marker",
			target:      "https://h\x7fost.example/" + secret,
			wantExact:   redactedTarget,
			mustNotHave: []string{secret},
		},
		{
			name:        "valueless query param skipped, secret param redacted",
			target:      "https://api.vendor.example/x?flag&token=" + secret,
			wantExact:   "https://api.vendor.example/x?flag&token=" + redactedValue,
			mustNotHave: []string{secret},
		},
		{
			name:      "connect authority host:port clean passes through",
			target:    "api.vendor.example:443",
			wantExact: "api.vendor.example:443",
		},
		{
			name:      "empty target stays empty",
			target:    "",
			wantExact: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := sanitizeTarget(tt.target, clean)

			if tt.wantExact != "" || tt.target == "" {
				if got != tt.wantExact {
					t.Errorf("sanitizeTarget(%q) = %q, want %q", tt.target, got, tt.wantExact)
				}
			}
			if tt.wantPrefix != "" && !strings.HasPrefix(got, tt.wantPrefix) {
				t.Errorf("sanitizeTarget(%q) = %q, want prefix %q", tt.target, got, tt.wantPrefix)
			}
			for _, bad := range tt.mustNotHave {
				if strings.Contains(got, bad) {
					t.Errorf("sanitizeTarget(%q) = %q, must not contain %q", tt.target, got, bad)
				}
			}
			// Core invariant: every sanitized target must be DLP-clean, so the
			// recorder's post-sign redaction is always a no-op.
			if !clean(got) {
				t.Errorf("sanitizeTarget(%q) = %q is NOT DLP-clean", tt.target, got)
			}
			// Sanitization must never blank a non-empty target (Validate
			// requires target != "").
			if tt.target != "" && got == "" {
				t.Errorf("sanitizeTarget(%q) returned empty", tt.target)
			}
		})
	}
}

// TestSanitizeTarget_NilClean verifies the defensive no-op when no DLP function
// is supplied (redaction disabled): the target passes through untouched.
func TestSanitizeTarget_NilClean(t *testing.T) {
	t.Parallel()
	// Userinfo (added by credURL) is the sanitize trigger under test; the query
	// param is deliberately benign so pipelock's own credential-in-URL scanner
	// does not flag this fixture line in the self-scan dogfood check.
	in := credURL("api.vendor.example/x?ref=abc")
	if got := sanitizeTarget(in, nil); got != in {
		t.Errorf("sanitizeTarget with nil clean = %q, want unchanged %q", got, in)
	}
}

// TestSanitizeTarget_Idempotent confirms sanitizing an already-sanitized target
// is a fixed point (no further change), which the recorder relies on.
func TestSanitizeTarget_Idempotent(t *testing.T) {
	t.Parallel()
	secret := "AKIA" + "IOSFODNN7EXAMPLE"
	clean := dlpLike(secret)
	in := credURL("api.vendor.example/v1/" + secret + "?token=" + secret)
	once := sanitizeTarget(in, clean)
	twice := sanitizeTarget(once, clean)
	if once != twice {
		t.Errorf("sanitizeTarget not idempotent: once=%q twice=%q", once, twice)
	}
}
