// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package sigv4scope_test

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/redact"
	"github.com/luckyPipewrench/pipelock/internal/sigv4scope"
)

func TestScopeAndRedactorCredentialScopeParity(t *testing.T) {
	long := strings.Repeat("a", 64)
	tooLong := strings.Repeat("a", 65)
	tests := []struct {
		name  string
		scope string
		want  bool
	}{
		{name: "application autoscaling", scope: "20260912/us-east-1/application-autoscaling/aws4_request", want: true},
		{name: "execute api", scope: "20260912/us-east-1/execute-api/aws4_request", want: true},
		{name: "s3", scope: "20260912/us-east-1/s3/aws4_request", want: true},
		{name: "sts", scope: "20260912/us-east-1/sts/aws4_request", want: true},
		{name: "64 character component", scope: "20260912/us-east-1/" + long + "/aws4_request", want: true},
		{name: "uppercase component", scope: "20260912/us-east-1/S3/aws4_request", want: false},
		{name: "empty component", scope: "20260912/us-east-1//aws4_request", want: false},
		{name: "65 character component", scope: "20260912/us-east-1/" + tooLong + "/aws4_request", want: false},
		{name: "slash containing component", scope: "20260912/us-east-1/s3/extra/aws4_request", want: false},
		{name: "missing terminator", scope: "20260912/us-east-1/s3/aws3_request", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scannerAccepted := sigv4scope.IsScope(tt.scope)
			if scannerAccepted != tt.want {
				t.Fatalf("scope acceptance = %v, want %v", scannerAccepted, tt.want)
			}
			for _, tail := range []string{"/" + tt.scope, "%2F" + strings.ReplaceAll(tt.scope, "/", "%2F")} {
				if redactorAccepted := redact.IsSigV4CredentialScopeTail(tail); redactorAccepted != scannerAccepted {
					t.Fatalf("redactor acceptance for %q = %v, scope = %v", tail, redactorAccepted, scannerAccepted)
				}
			}
		})
	}
}

// TestScopeTailRejectsExtendedTerminator pins the redactor's tail predicate to
// the scanner's whole-value grammar at the one point where a prefix match and
// a whole-value match can disagree: text appended to aws4_request. Each tail
// below carries a credential value the scanner rejects, so redacting the
// access key ID must not be skipped for any of them.
func TestScopeTailRejectsExtendedTerminator(t *testing.T) {
	base := "/20260528/us-east-1/s3/aws4_request"
	for _, suffix := range []string{"/extra", "%2Fextra", "%2fextra", "-x", "%2", "%", "+x", "=x", ".x", "~", "\xc3\xa9", "_x", "9"} {
		tail := base + suffix
		if sigv4scope.IsScopeTail(tail) {
			t.Errorf("IsScopeTail(%q) = true, want false", tail)
		}
		if redact.IsSigV4CredentialScopeTail(tail) {
			t.Errorf("redactor skipped redaction for %q", tail)
		}
	}
	for _, suffix := range []string{"", "&X-Amz-Signature=beef", "\"", "'", " ", "\n", "?x", "#frag", "</a>", "\"}", "\\n"} {
		tail := base + suffix
		if !sigv4scope.IsScopeTail(tail) {
			t.Errorf("IsScopeTail(%q) = false, want true", tail)
		}
	}
}

// TestIsScopeRejectsNonDigitDate covers the digit-validation branch in
// IsScope: a date segment containing a non-digit byte must be rejected even
// though it has the right length and slash structure.
func TestIsScopeRejectsNonDigitDate(t *testing.T) {
	for _, scope := range []string{
		"2026091a/us-east-1/s3/aws4_request",
		"a026091a/us-east-1/s3/aws4_request",
		"2026-091/us-east-1/s3/aws4_request",
	} {
		if sigv4scope.IsScope(scope) {
			t.Errorf("IsScope(%q) = true, want false (non-digit date)", scope)
		}
	}
}

// TestIsScopeTailStopsWithoutSecondSeparator covers the loop's !ok exit in
// IsScopeTail (and, on the way there, nextComponent's no-delimiter-found
// return and consumeSeparator's rejection of a value with no leading slash
// or percent-encoded slash): a tail carrying only one component and nothing
// after it has no second separator to consume, so it must fail closed rather
// than panic or accept a truncated scope.
func TestIsScopeTailStopsWithoutSecondSeparator(t *testing.T) {
	for _, tail := range []string{
		"/20260528",
		"%2F20260528",
	} {
		if sigv4scope.IsScopeTail(tail) {
			t.Errorf("IsScopeTail(%q) = true, want false (no second separator)", tail)
		}
	}
}
