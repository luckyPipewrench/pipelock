// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"strings"
	"testing"
)

// SanitizeTarget and CleanOrRedacted are the exported pre-sign sanitization
// boundary that internal/contract/proxydecision reuses instead of duplicating
// this logic (#676), plus internal/cli explain rendering. Ten production call
// sites stamp their results into a SIGNED payload, so the guarantee those
// callers depend on is that the returned value is DLP-clean under the same
// predicate they passed in. These tests assert that property directly rather
// than asserting a fixed output string, which would only restate the
// implementation.

// exportedClean adapts dlpLike to the plain func(string) bool that the
// exported wrappers accept. true means clean.
func exportedClean(secrets ...string) func(string) bool {
	return dlpLike(secrets...)
}

func TestSanitizeTargetExportedOutputIsClean(t *testing.T) {
	t.Parallel()

	const secret = "AKIAIOSFODNN7EXAMPLE"

	tests := []struct {
		name   string
		target string
	}{
		{"userinfo credential", "https://user:" + secret + "@api.vendor.example/v1/things"},
		{"query value secret", "https://api.vendor.example/v1?token=" + secret},
		{"secret split across query values", "https://api.vendor.example/v1?a=" + secret[:10] + "&b=" + secret[10:]},
		{"path segment secret", "https://api.vendor.example/v1/" + secret + "/read"},
		{"fragment secret", "https://api.vendor.example/v1#" + secret},
		{"secret in host label", "https://" + strings.ToLower(secret) + ".vendor.example/v1"},
		{"connect authority", "api.vendor.example:443"},
		{"connect authority carrying secret", secret + ".vendor.example:443"},
		{"mcp tool name", "@vendor/integrity_checker"},
		{"mcp tool name carrying secret", "@vendor/" + secret},
		{"clean url is preserved", "https://api.vendor.example/v1/things?page=2"},
		{"empty target", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			clean := exportedClean(secret)
			got := SanitizeTarget(tt.target, clean)

			if !clean(got) {
				t.Fatalf("SanitizeTarget(%q) = %q, which is NOT DLP-clean; a signed receipt would carry the secret", tt.target, got)
			}
			if strings.Contains(got, secret) {
				t.Fatalf("SanitizeTarget(%q) = %q, still contains the secret verbatim", tt.target, got)
			}
		})
	}
}

// A target that is already clean must survive byte-for-byte. Coarsening a
// clean target would destroy forensic detail for no security gain, and the
// callers stamp this value into evidence an operator later reads.
func TestSanitizeTargetExportedPreservesCleanTarget(t *testing.T) {
	t.Parallel()

	const target = "https://api.vendor.example/v1/things?page=2&sort=desc"
	clean := exportedClean("AKIAIOSFODNN7EXAMPLE")

	if got := SanitizeTarget(target, clean); got != target {
		t.Fatalf("SanitizeTarget(%q) = %q, want it unchanged", target, got)
	}
}

// The nil predicate means flight-recorder redaction is DISABLED, and the
// documented contract is that the target passes through unchanged. That is a
// deliberate fail-direction, not an oversight: with redaction off there is no
// scanner to decide what is secret. Pinning it keeps a later change from
// quietly turning redaction-off into redaction-on (which would rewrite signed
// evidence operators did not ask to be rewritten) or from assuming this call
// sanitizes when it does not.
func TestSanitizeTargetExportedNilPredicatePassesThrough(t *testing.T) {
	t.Parallel()

	targets := []string{
		"https://user:AKIAIOSFODNN7EXAMPLE@api.vendor.example/v1",
		"https://api.vendor.example/v1?token=AKIAIOSFODNN7EXAMPLE",
		"api.vendor.example:443",
		"",
	}

	for _, target := range targets {
		if got := SanitizeTarget(target, nil); got != target {
			t.Errorf("SanitizeTarget(%q, nil) = %q, want the target unchanged when redaction is off", target, got)
		}
	}
}

func TestCleanOrRedactedExported(t *testing.T) {
	t.Parallel()

	const secret = "AKIAIOSFODNN7EXAMPLE"

	tests := []struct {
		name  string
		value string
		want  string
	}{
		{"clean rule label is preserved", "dlp.aws_access_key_id", "dlp.aws_access_key_id"},
		{"label echoing matched bytes is redacted", "matched " + secret, redactedTarget},
		{"bare secret is redacted", secret, redactedTarget},
		{"empty value is clean", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			clean := exportedClean(secret)
			got := CleanOrRedacted(tt.value, clean)

			if got != tt.want {
				t.Fatalf("CleanOrRedacted(%q) = %q, want %q", tt.value, got, tt.want)
			}
			if !clean(got) {
				t.Fatalf("CleanOrRedacted(%q) = %q, which is NOT DLP-clean", tt.value, got)
			}
		})
	}
}

// Same deliberate fail-direction as SanitizeTarget's nil case: redaction off
// means the non-URL field is signed as sent.
func TestCleanOrRedactedExportedNilPredicatePassesThrough(t *testing.T) {
	t.Parallel()

	values := []string{"AKIAIOSFODNN7EXAMPLE", "dlp.aws_access_key_id", ""}
	for _, value := range values {
		if got := CleanOrRedacted(value, nil); got != value {
			t.Errorf("CleanOrRedacted(%q, nil) = %q, want the value unchanged when redaction is off", value, got)
		}
	}
}
