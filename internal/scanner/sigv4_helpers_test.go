// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import "testing"

// The envelope-level tests exercise these helpers through
// detectValidSigV4Authorization, which cannot reach every rejection branch
// because earlier checks shadow some of them. These drive the helpers
// directly so each fail-closed path is covered on its own terms.

func TestParseSigV4CredentialRejections(t *testing.T) {
	key := "AKIA" + "IOSFODNN7EXAMPLE"
	for _, tc := range []struct {
		name string
		cred string
	}{
		{"empty", ""},
		{"too_few_segments", key + "/20260910/us-east-1/aws4_request"},
		{"too_many_segments", key + "/20260910/us-east-1/s3/extra/aws4_request"},
		{"wrong_terminator", key + "/20260910/us-east-1/s3/aws5_request"},
		{"key_not_access_id", "NOTAKEY/20260910/us-east-1/s3/aws4_request"},
		{"date_not_eight_digits", key + "/2026091/us-east-1/s3/aws4_request"},
		{"date_non_numeric", key + "/2026091x/us-east-1/s3/aws4_request"},
		{"empty_region", key + "/20260910//s3/aws4_request"},
		{"empty_service", key + "/20260910/us-east-1//aws4_request"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, ok := parseSigV4Credential(tc.cred); ok {
				t.Fatalf("parseSigV4Credential(%q) accepted a malformed scope", tc.cred)
			}
		})
	}
}

func TestParseSigV4CredentialAcceptsWellFormedScope(t *testing.T) {
	key := "AKIA" + "IOSFODNN7EXAMPLE"
	gotKey, gotDate, ok := parseSigV4Credential(key + "/20260910/us-east-1/s3/aws4_request")
	if !ok {
		t.Fatal("a well-formed credential scope was rejected")
	}
	if gotKey != key {
		t.Fatalf("key id = %q, want %q", gotKey, key)
	}
	if gotDate != "20260910" {
		t.Fatalf("scope date = %q, want 20260910", gotDate)
	}
}

func TestExtractSigV4AuthorizationFieldsRejections(t *testing.T) {
	for _, tc := range []struct {
		name string
		rest string
	}{
		{"empty", ""},
		{"empty_part_between_commas", "Credential=a,,Signature=b"},
		{"no_equals", "Credential"},
		{"empty_key", "=value"},
		{"empty_value", "Credential="},
		{"unknown_field", "Credential=a, Signature=b, SignedHeaders=c, Extra=d"},
		{"duplicate_known_field", "Credential=a, Credential=b"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, ok := extractSigV4AuthorizationFields(tc.rest); ok {
				t.Fatalf("extractSigV4AuthorizationFields(%q) accepted a malformed tail", tc.rest)
			}
		})
	}
}

func TestScrubSigV4AuthorizationRefusesAmbiguousInput(t *testing.T) {
	key := "AKIA" + "IOSFODNN7EXAMPLE"
	// Each of these must return the value untouched so core DLP still sees
	// the access key id.
	for _, tc := range []struct {
		name  string
		value string
		akia  string
	}{
		{"empty_value", "", key},
		{"empty_key", "AWS4-HMAC-SHA256 Credential=" + key, ""},
		{"wrong_length_key", "AWS4-HMAC-SHA256 Credential=" + key, "AKIASHORT"},
		{"key_appears_twice", "AWS4-HMAC-SHA256 Credential=" + key + " dup=" + key, key},
		{"key_absent", "AWS4-HMAC-SHA256 Credential=none", key},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := scrubSigV4Authorization(tc.value, tc.akia); got != tc.value {
				t.Fatalf("value was modified: got %q, want %q unchanged", got, tc.value)
			}
		})
	}
}
