// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"strings"
	"testing"
)

func buildSigV4Authorization(keyID string) string {
	return sigV4AlgorithmValue + " Credential=" + keyID + "/" + validSigV4Scope +
		", SignedHeaders=host;x-amz-date, Signature=" + validSigV4Signature
}

func TestDetectValidSigV4Authorization(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		value     string
		wantValid bool
		wantKeyID string
	}{
		{
			name:      "valid_AKIA_envelope",
			value:     buildSigV4Authorization(fakeAKIAExample),
			wantValid: true,
			wantKeyID: fakeAKIAExample,
		},
		{
			name:      "valid_ASIA_envelope",
			value:     buildSigV4Authorization(fakeASIAExample),
			wantValid: true,
			wantKeyID: fakeASIAExample,
		},
		{
			name:      "leading_and_trailing_whitespace",
			value:     "  " + buildSigV4Authorization(fakeAKIAExample) + "\t",
			wantValid: true,
			wantKeyID: fakeAKIAExample,
		},
		{
			name:      "tab_after_scheme",
			value:     sigV4AlgorithmValue + "\tCredential=" + fakeAKIAExample + "/" + validSigV4Scope + ", SignedHeaders=host, Signature=" + validSigV4Signature,
			wantValid: true,
			wantKeyID: fakeAKIAExample,
		},
		{
			name:      "spaces_around_equals_and_commas",
			value:     sigV4AlgorithmValue + " Credential = " + fakeAKIAExample + "/" + validSigV4Scope + " , SignedHeaders = host;x-amz-date , Signature = " + validSigV4Signature,
			wantValid: true,
			wantKeyID: fakeAKIAExample,
		},
		{
			name:      "field_order_signature_first",
			value:     sigV4AlgorithmValue + " Signature=" + validSigV4Signature + ", SignedHeaders=host, Credential=" + fakeAKIAExample + "/" + validSigV4Scope,
			wantValid: true,
			wantKeyID: fakeAKIAExample,
		},
		{
			name:      "no_space_after_commas",
			value:     sigV4AlgorithmValue + " Credential=" + fakeAKIAExample + "/" + validSigV4Scope + ",SignedHeaders=host,Signature=" + validSigV4Signature,
			wantValid: true,
			wantKeyID: fakeAKIAExample,
		},
		{
			name:  "lowercase_scheme",
			value: "aws4-hmac-sha256 Credential=" + fakeAKIAExample + "/" + validSigV4Scope + ", SignedHeaders=host, Signature=" + validSigV4Signature,
		},
		{
			name:  "missing_space_after_scheme",
			value: sigV4AlgorithmValue + "Credential=" + fakeAKIAExample + "/" + validSigV4Scope + ", SignedHeaders=host, Signature=" + validSigV4Signature,
		},
		{
			name:  "lowercase_credential_field",
			value: sigV4AlgorithmValue + " credential=" + fakeAKIAExample + "/" + validSigV4Scope + ", SignedHeaders=host, Signature=" + validSigV4Signature,
		},
		{
			name:  "missing_signature",
			value: sigV4AlgorithmValue + " Credential=" + fakeAKIAExample + "/" + validSigV4Scope + ", SignedHeaders=host",
		},
		{
			name:  "missing_credential",
			value: sigV4AlgorithmValue + " SignedHeaders=host, Signature=" + validSigV4Signature,
		},
		{
			name:  "missing_signed_headers",
			value: sigV4AlgorithmValue + " Credential=" + fakeAKIAExample + "/" + validSigV4Scope + ", Signature=" + validSigV4Signature,
		},
		{
			name:  "scope_four_segments",
			value: sigV4AlgorithmValue + " Credential=" + fakeAKIAExample + "/20260512/us-east-1/sts, SignedHeaders=host, Signature=" + validSigV4Signature,
		},
		{
			name:  "empty_region",
			value: sigV4AlgorithmValue + " Credential=" + fakeAKIAExample + "/20260512//sts/aws4_request, SignedHeaders=host, Signature=" + validSigV4Signature,
		},
		{
			name:  "empty_service",
			value: sigV4AlgorithmValue + " Credential=" + fakeAKIAExample + "/20260512/us-east-1//aws4_request, SignedHeaders=host, Signature=" + validSigV4Signature,
		},
		{
			name:  "wrong_terminator",
			value: sigV4AlgorithmValue + " Credential=" + fakeAKIAExample + "/20260512/us-east-1/sts/aws3_request, SignedHeaders=host, Signature=" + validSigV4Signature,
		},
		{
			name:  "short_signature",
			value: sigV4AlgorithmValue + " Credential=" + fakeAKIAExample + "/" + validSigV4Scope + ", SignedHeaders=host, Signature=abc123",
		},
		{
			name:  "long_signature",
			value: sigV4AlgorithmValue + " Credential=" + fakeAKIAExample + "/" + validSigV4Scope + ", SignedHeaders=host, Signature=" + validSigV4Signature + "aa",
		},
		{
			name:  "non_hex_signature",
			value: sigV4AlgorithmValue + " Credential=" + fakeAKIAExample + "/" + validSigV4Scope + ", SignedHeaders=host, Signature=" + strings.Repeat("g", 64),
		},
		{
			name:  "duplicate_credential",
			value: buildSigV4Authorization(fakeAKIAExample) + ", Credential=" + fakeASIAExample + "/" + validSigV4Scope,
		},
		{
			name:  "duplicate_signature",
			value: buildSigV4Authorization(fakeAKIAExample) + ", Signature=" + validSigV4Signature,
		},
		{
			name:  "unknown_field",
			value: buildSigV4Authorization(fakeAKIAExample) + ", Token=extra",
		},
		{
			name:  "trailing_comma",
			value: buildSigV4Authorization(fakeAKIAExample) + ",",
		},
		{
			name:  "signed_headers_without_host",
			value: sigV4AlgorithmValue + " Credential=" + fakeAKIAExample + "/" + validSigV4Scope + ", SignedHeaders=x-amz-date, Signature=" + validSigV4Signature,
		},
		{
			name:  "key_id_in_signed_headers",
			value: sigV4AlgorithmValue + " Credential=" + fakeAKIAExample + "/" + validSigV4Scope + ", SignedHeaders=host;" + fakeAKIAExample + ", Signature=" + validSigV4Signature,
		},
		{
			name:  "overlong_access_key",
			value: sigV4AlgorithmValue + " Credential=" + fakeAKIAExample + "EXTRA/" + validSigV4Scope + ", SignedHeaders=host, Signature=" + validSigV4Signature,
		},
		{
			name:  "second_key_appended_after_envelope",
			value: buildSigV4Authorization(fakeAKIAExample) + " " + fakeASIAExample,
		},
		{
			name:  "bearer_not_sigv4",
			value: "Bearer " + fakeAKIAExample,
		},
		{
			name:  "empty",
			value: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := detectValidSigV4Authorization(tc.value)
			if got.Valid != tc.wantValid {
				t.Fatalf("Valid = %v, want %v (value=%q)", got.Valid, tc.wantValid, tc.value)
			}
			if got.KeyID != tc.wantKeyID {
				t.Fatalf("KeyID = %q, want %q", got.KeyID, tc.wantKeyID)
			}
		})
	}
}

func TestScrubSigV4Authorization(t *testing.T) {
	t.Parallel()

	t.Run("replaces_only_the_access_key", func(t *testing.T) {
		t.Parallel()
		raw := buildSigV4Authorization(fakeAKIAExample)
		got := scrubSigV4Authorization(raw, fakeAKIAExample)
		if strings.Contains(got, fakeAKIAExample) {
			t.Fatalf("scrubbed value still contains access key: %q", got)
		}
		placeholder := strings.Repeat(string(sigV4AccessKeyPlaceholderRune), sigV4AccessKeyLength)
		if !strings.Contains(got, "Credential="+placeholder+"/") {
			t.Fatalf("scrubbed value missing placeholder credential: %q", got)
		}
		if !strings.Contains(got, validSigV4Signature) {
			t.Fatal("scrub removed the signature")
		}
	})

	t.Run("duplicate_key_id_refuses_to_scrub", func(t *testing.T) {
		t.Parallel()
		raw := buildSigV4Authorization(fakeAKIAExample) + " " + fakeAKIAExample
		got := scrubSigV4Authorization(raw, fakeAKIAExample)
		if got != raw {
			t.Fatalf("duplicate key ID was scrubbed: %q", got)
		}
	})

	t.Run("empty_or_wrong_length_key_refuses_to_scrub", func(t *testing.T) {
		t.Parallel()
		raw := buildSigV4Authorization(fakeAKIAExample)
		if got := scrubSigV4Authorization(raw, ""); got != raw {
			t.Fatalf("empty key scrubbed the value: %q", got)
		}
		if got := scrubSigV4Authorization(raw, fakeAKIAExample+"X"); got != raw {
			t.Fatalf("wrong-length key scrubbed the value: %q", got)
		}
	})
}

func TestScrubSigV4AuthorizationForTarget(t *testing.T) {
	t.Parallel()

	raw := buildSigV4Authorization(fakeAKIAExample)

	t.Run("aws_destination_scrubs", func(t *testing.T) {
		t.Parallel()
		got := ScrubSigV4AuthorizationForTarget(raw, "https://sts.us-east-1.amazonaws.com/")
		if strings.Contains(got, fakeAKIAExample) {
			t.Fatalf("AWS destination did not scrub: %q", got)
		}
	})

	t.Run("china_destination_scrubs", func(t *testing.T) {
		t.Parallel()
		got := ScrubSigV4AuthorizationForTarget(raw, "https://sts.cn-north-1.amazonaws.com.cn/")
		if strings.Contains(got, fakeAKIAExample) {
			t.Fatalf("AWS China destination did not scrub: %q", got)
		}
	})

	t.Run("non_aws_destination_leaves_key", func(t *testing.T) {
		t.Parallel()
		got := ScrubSigV4AuthorizationForTarget(raw, "https://attacker.example/exfil")
		if got != raw {
			t.Fatalf("non-AWS destination scrubbed: %q", got)
		}
	})

	t.Run("empty_target_leaves_key", func(t *testing.T) {
		t.Parallel()
		got := ScrubSigV4AuthorizationForTarget(raw, "")
		if got != raw {
			t.Fatalf("empty target scrubbed: %q", got)
		}
	})

	t.Run("malformed_envelope_on_aws_host_leaves_key", func(t *testing.T) {
		t.Parallel()
		malformed := "AWS4-HMAC-SHA256 Credential=" + fakeAKIAExample
		got := ScrubSigV4AuthorizationForTarget(malformed, "https://sts.us-east-1.amazonaws.com/")
		if got != malformed {
			t.Fatalf("malformed envelope scrubbed: %q", got)
		}
	})
}
