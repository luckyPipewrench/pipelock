// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

const (
	// Fake AWS access keys assembled at runtime to keep gosec G101 happy
	// without obscuring intent. These are not real credentials.
	fakeAKIAExample = "AKIA" + "IOSFODNN7EXAMPLE"
	fakeASIAExample = "ASIA" + "Z5MHFQGAEXAMPLE1"

	// Canonical SigV4 query parameter values used across the table tests.
	// Signature is 64 hex chars; date is YYYYMMDDTHHMMSSZ.
	validSigV4Date      = "20260512T173720Z"
	validSigV4Signature = "4667401eda326e25245738e62377c28e0bc120b1fbcab22896f1cc85eb4d2e89"
	validSigV4Scope     = "20260512/us-east-1/s3/aws4_request"
)

func mustParseURL(t *testing.T, rawURL string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("url.Parse(%q) failed: %v", rawURL, err)
	}
	return parsed
}

// buildSigV4URL assembles a presigned-style URL with the supplied access key
// (or an empty credential when akia is ""), short or long expiry, and any
// extra query parameters appended literally. The order matches what real S3
// presigned URLs emit.
func buildSigV4URL(t *testing.T, akia, expires, extra string) string {
	t.Helper()
	cred := ""
	if akia != "" {
		cred = akia + "/" + validSigV4Scope
	}
	q := url.Values{}
	q.Set("X-Amz-Algorithm", sigV4AlgorithmValue)
	q.Set("X-Amz-Date", validSigV4Date)
	q.Set("X-Amz-SignedHeaders", "host")
	q.Set("X-Amz-Signature", validSigV4Signature)
	if cred != "" {
		q.Set("X-Amz-Credential", cred)
	}
	if expires != "" {
		q.Set("X-Amz-Expires", expires)
	}
	out := "https://examplebucket.s3.amazonaws.com/object/key.bin?" + q.Encode()
	if extra != "" {
		out += "&" + extra
	}
	return out
}

func TestDetectValidSigV4(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		rawURL    string
		wantValid bool
		wantKeyID string
		wantExp   int
	}{
		{
			name:      "valid_AKIA_with_24h_expiry",
			rawURL:    buildSigV4URL(t, fakeAKIAExample, "3600", ""),
			wantValid: true,
			wantKeyID: fakeAKIAExample,
			wantExp:   3600,
		},
		{
			name:      "valid_ASIA_STS_credential",
			rawURL:    buildSigV4URL(t, fakeASIAExample, "3600", ""),
			wantValid: true,
			wantKeyID: fakeASIAExample,
			wantExp:   3600,
		},
		{
			name:      "missing_expires_invalidates",
			rawURL:    buildSigV4URL(t, fakeAKIAExample, "", ""),
			wantValid: false,
		},
		{
			name:      "valid_long_expiry_3_days",
			rawURL:    buildSigV4URL(t, fakeAKIAExample, "259200", ""),
			wantValid: true,
			wantKeyID: fakeAKIAExample,
			wantExp:   259200,
		},
		{
			name:      "missing_algorithm",
			rawURL:    strings.Replace(buildSigV4URL(t, fakeAKIAExample, "3600", ""), "X-Amz-Algorithm="+sigV4AlgorithmValue, "X-Amz-Algorithm=other", 1),
			wantValid: false,
		},
		{
			name:      "missing_credential",
			rawURL:    buildSigV4URL(t, "", "3600", ""),
			wantValid: false,
		},
		{
			name:      "malformed_credential_scope_4_segments",
			rawURL:    "https://examplebucket.s3.amazonaws.com/x?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Date=" + validSigV4Date + "&X-Amz-Signature=" + validSigV4Signature + "&X-Amz-Credential=" + fakeAKIAExample + "/20260512/us-east-1/s3",
			wantValid: false,
		},
		{
			name:      "wrong_terminator_segment",
			rawURL:    "https://examplebucket.s3.amazonaws.com/x?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Date=" + validSigV4Date + "&X-Amz-Signature=" + validSigV4Signature + "&X-Amz-Credential=" + fakeAKIAExample + "/20260512/us-east-1/s3/aws3_request",
			wantValid: false,
		},
		{
			name:      "credential_first_segment_not_an_AKIA",
			rawURL:    "https://examplebucket.s3.amazonaws.com/x?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Date=" + validSigV4Date + "&X-Amz-Signature=" + validSigV4Signature + "&X-Amz-Credential=NOTANID/20260512/us-east-1/s3/aws4_request",
			wantValid: false,
		},
		{
			name:      "credential_date_not_YYYYMMDD",
			rawURL:    "https://examplebucket.s3.amazonaws.com/x?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Date=" + validSigV4Date + "&X-Amz-Signature=" + validSigV4Signature + "&X-Amz-Credential=" + fakeAKIAExample + "/badDate/us-east-1/s3/aws4_request",
			wantValid: false,
		},
		{
			name:      "credential_scope_date_must_match_amz_date",
			rawURL:    "https://examplebucket.s3.amazonaws.com/x?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Date=" + validSigV4Date + "&X-Amz-Signature=" + validSigV4Signature + "&X-Amz-Credential=" + fakeAKIAExample + "/20260511/us-east-1/s3/aws4_request",
			wantValid: false,
		},
		{
			name:      "credential_access_key_must_be_exact_length",
			rawURL:    "https://examplebucket.s3.amazonaws.com/x?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Date=" + validSigV4Date + "&X-Amz-Signature=" + validSigV4Signature + "&X-Amz-Credential=" + fakeAKIAExample + "EXTRA/20260512/us-east-1/s3/aws4_request",
			wantValid: false,
		},
		{
			name:      "duplicate_algorithm_invalidates",
			rawURL:    buildSigV4URL(t, fakeAKIAExample, "3600", "X-Amz-Algorithm="+sigV4AlgorithmValue),
			wantValid: false,
		},
		{
			name:      "duplicate_date_invalidates",
			rawURL:    buildSigV4URL(t, fakeAKIAExample, "3600", "X-Amz-Date="+validSigV4Date),
			wantValid: false,
		},
		{
			name:      "duplicate_signature_invalidates",
			rawURL:    buildSigV4URL(t, fakeAKIAExample, "3600", "X-Amz-Signature="+validSigV4Signature),
			wantValid: false,
		},
		{
			name:      "duplicate_credential_invalidates",
			rawURL:    buildSigV4URL(t, fakeAKIAExample, "3600", "X-Amz-Credential="+url.QueryEscape(fakeASIAExample+"/"+validSigV4Scope)),
			wantValid: false,
		},
		{
			name:      "duplicate_expires_silences_long_expiry_warn",
			rawURL:    buildSigV4URL(t, fakeAKIAExample, "3600", "X-Amz-Expires=604800"),
			wantValid: false,
		},
		{
			name:      "bare_known_key_invalidates_even_with_valid_pair",
			rawURL:    buildSigV4URL(t, fakeAKIAExample, "3600", "X-Amz-Credential"),
			wantValid: false,
		},
		{
			name:      "missing_signature",
			rawURL:    strings.Replace(buildSigV4URL(t, fakeAKIAExample, "3600", ""), "X-Amz-Signature="+validSigV4Signature, "", 1),
			wantValid: false,
		},
		{
			name:      "short_signature",
			rawURL:    strings.Replace(buildSigV4URL(t, fakeAKIAExample, "3600", ""), validSigV4Signature, "abc123", 1),
			wantValid: false,
		},
		{
			name:      "malformed_date_value",
			rawURL:    strings.Replace(buildSigV4URL(t, fakeAKIAExample, "3600", ""), validSigV4Date, "2026-05-12T17:37:20Z", 1),
			wantValid: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			parsed := mustParseURL(t, tc.rawURL)
			got := detectValidSigV4(parsed)
			if got.Valid != tc.wantValid {
				t.Fatalf("Valid = %v, want %v (URL=%s)", got.Valid, tc.wantValid, tc.rawURL)
			}
			if !tc.wantValid {
				return
			}
			if got.KeyID != tc.wantKeyID {
				t.Errorf("KeyID = %q, want %q", got.KeyID, tc.wantKeyID)
			}
			if got.Expires != tc.wantExp {
				t.Errorf("Expires = %d, want %d", got.Expires, tc.wantExp)
			}
		})
	}
}

func TestScrubSigV4Credential(t *testing.T) {
	t.Parallel()

	t.Run("replaces_AKIA_with_same_length_placeholder", func(t *testing.T) {
		t.Parallel()
		raw := buildSigV4URL(t, fakeAKIAExample, "3600", "")
		parsed, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		scrubbed := scrubSigV4Credential(parsed, fakeAKIAExample)
		got := scrubbed.Query().Get("X-Amz-Credential")
		want := strings.Repeat("a", len(fakeAKIAExample)) + "/" + validSigV4Scope
		if got != want {
			t.Errorf("scrubbed credential = %q, want %q", got, want)
		}
		// Verify original is not mutated.
		if parsed.Query().Get("X-Amz-Credential") != fakeAKIAExample+"/"+validSigV4Scope {
			t.Error("scrubSigV4Credential mutated the source URL")
		}
	})

	t.Run("preserves_other_query_params", func(t *testing.T) {
		t.Parallel()
		raw := buildSigV4URL(t, fakeAKIAExample, "3600", "other=value")
		parsed := mustParseURL(t, raw)
		scrubbed := scrubSigV4Credential(parsed, fakeAKIAExample)
		if scrubbed.Query().Get("other") != "value" {
			t.Errorf("other param dropped during scrub")
		}
		if scrubbed.Query().Get("X-Amz-Algorithm") != sigV4AlgorithmValue {
			t.Errorf("algorithm param dropped during scrub")
		}
	})

	t.Run("no_op_on_credential_AKIA_mismatch", func(t *testing.T) {
		t.Parallel()
		raw := buildSigV4URL(t, fakeAKIAExample, "3600", "")
		parsed := mustParseURL(t, raw)
		// Pass an AKIA different from what's in the URL — defensive guard.
		scrubbed := scrubSigV4Credential(parsed, fakeASIAExample)
		if scrubbed.Query().Get("X-Amz-Credential") != fakeAKIAExample+"/"+validSigV4Scope {
			t.Errorf("scrub fired when AKIA did not match the credential value")
		}
	})

	t.Run("no_op_on_nil_url", func(t *testing.T) {
		t.Parallel()
		if got := scrubSigV4Credential(nil, fakeAKIAExample); got != nil {
			t.Errorf("scrubSigV4Credential(nil, ...) = %v, want nil", got)
		}
	})

	t.Run("no_op_on_empty_akia", func(t *testing.T) {
		t.Parallel()
		raw := buildSigV4URL(t, fakeAKIAExample, "3600", "")
		parsed := mustParseURL(t, raw)
		got := scrubSigV4Credential(parsed, "")
		if got != parsed {
			t.Errorf("scrubSigV4Credential(parsed, \"\") returned new pointer; expected source pointer")
		}
	})

	t.Run("no_op_when_credential_field_absent", func(t *testing.T) {
		t.Parallel()
		parsed := mustParseURL(t, "https://example.com/path?other=value")
		got := scrubSigV4Credential(parsed, fakeAKIAExample)
		if got != parsed {
			t.Errorf("scrubSigV4Credential returned new pointer when credential absent")
		}
	})

	t.Run("no_op_when_raw_query_empty", func(t *testing.T) {
		t.Parallel()
		parsed := mustParseURL(t, "https://examplebucket.s3.amazonaws.com/path")
		got := scrubSigV4Credential(parsed, fakeAKIAExample)
		if got != parsed {
			t.Errorf("scrubSigV4Credential returned new pointer when RawQuery is empty")
		}
	})

	t.Run("preserves_malformed_pair_without_equals", func(t *testing.T) {
		t.Parallel()
		raw := buildSigV4URL(t, fakeAKIAExample, "3600", "bareflag")
		parsed := mustParseURL(t, raw)
		got := scrubSigV4Credential(parsed, fakeAKIAExample)
		if got == parsed {
			t.Fatalf("scrubSigV4Credential should still scrub the valid credential pair")
		}
		if !strings.Contains(got.RawQuery, "bareflag") {
			t.Errorf("malformed query pair without '=' was not preserved: %q", got.RawQuery)
		}
	})

	t.Run("no_op_on_malformed_credential_percent_encoding", func(t *testing.T) {
		t.Parallel()
		parsed := mustParseURL(t, "https://examplebucket.s3.amazonaws.com/path?X-Amz-Credential=%zz")
		got := scrubSigV4Credential(parsed, fakeAKIAExample)
		if got != parsed {
			t.Errorf("scrubSigV4Credential returned new pointer for malformed percent encoding")
		}
	})

	t.Run("no_op_on_duplicate_credential_values", func(t *testing.T) {
		t.Parallel()
		raw := buildSigV4URL(t, fakeAKIAExample, "3600", "X-Amz-Credential="+url.QueryEscape(fakeASIAExample+"/"+validSigV4Scope))
		parsed := mustParseURL(t, raw)
		got := scrubSigV4Credential(parsed, fakeAKIAExample)
		if got != parsed {
			t.Fatalf("scrubSigV4Credential returned new pointer for duplicate credentials")
		}
		values := got.Query()["X-Amz-Credential"]
		if len(values) != 2 {
			t.Fatalf("duplicate credential values collapsed: got %d values", len(values))
		}
		if values[1] != fakeASIAExample+"/"+validSigV4Scope {
			t.Errorf("second credential value = %q, want leaked duplicate preserved", values[1])
		}
	})
}

// TestDetectValidSigV4_DefensiveGuards covers nil-input and empty-segment
// branches that aren't exercised by the table-driven SigV4 detection cases.
func TestDetectValidSigV4_DefensiveGuards(t *testing.T) {
	t.Parallel()

	t.Run("nil_url_returns_invalid", func(t *testing.T) {
		t.Parallel()
		got := detectValidSigV4(nil)
		if got.Valid {
			t.Errorf("detectValidSigV4(nil).Valid = true, want false")
		}
	})

	t.Run("empty_region_in_credential_scope_invalidates", func(t *testing.T) {
		t.Parallel()
		raw := "https://examplebucket.s3.amazonaws.com/x?X-Amz-Algorithm=" + sigV4AlgorithmValue +
			"&X-Amz-Date=" + validSigV4Date +
			"&X-Amz-Signature=" + validSigV4Signature +
			"&X-Amz-Credential=" + fakeAKIAExample + "/20260512//s3/aws4_request" +
			"&X-Amz-Expires=3600"
		parsed := mustParseURL(t, raw)
		if got := detectValidSigV4(parsed); got.Valid {
			t.Errorf("empty region in credential scope should invalidate detection")
		}
	})

	t.Run("empty_service_in_credential_scope_invalidates", func(t *testing.T) {
		t.Parallel()
		raw := "https://examplebucket.s3.amazonaws.com/x?X-Amz-Algorithm=" + sigV4AlgorithmValue +
			"&X-Amz-Date=" + validSigV4Date +
			"&X-Amz-Signature=" + validSigV4Signature +
			"&X-Amz-Credential=" + fakeAKIAExample + "/20260512/us-east-1//aws4_request" +
			"&X-Amz-Expires=3600"
		parsed := mustParseURL(t, raw)
		if got := detectValidSigV4(parsed); got.Valid {
			t.Errorf("empty service in credential scope should invalidate detection")
		}
	})

	t.Run("negative_expires_invalidates", func(t *testing.T) {
		t.Parallel()
		raw := buildSigV4URL(t, fakeAKIAExample, "-1", "")
		parsed := mustParseURL(t, raw)
		if got := detectValidSigV4(parsed); got.Valid {
			t.Errorf("negative X-Amz-Expires should invalidate detection")
		}
	})

	t.Run("non_numeric_expires_invalidates", func(t *testing.T) {
		t.Parallel()
		raw := buildSigV4URL(t, fakeAKIAExample, "abc", "")
		parsed := mustParseURL(t, raw)
		if got := detectValidSigV4(parsed); got.Valid {
			t.Errorf("non-numeric X-Amz-Expires should invalidate detection")
		}
	})

	t.Run("zero_expires_invalidates", func(t *testing.T) {
		t.Parallel()
		raw := buildSigV4URL(t, fakeAKIAExample, "0", "")
		parsed := mustParseURL(t, raw)
		if got := detectValidSigV4(parsed); got.Valid {
			t.Errorf("zero X-Amz-Expires should invalidate detection")
		}
	})

	t.Run("non_aws_host_rejected", func(t *testing.T) {
		t.Parallel()
		raw := strings.Replace(
			buildSigV4URL(t, fakeAKIAExample, "3600", ""),
			"examplebucket.s3.amazonaws.com",
			"attacker.example",
			1,
		)
		parsed := mustParseURL(t, raw)
		if got := detectValidSigV4(parsed); got.Valid {
			t.Errorf("SigV4-shaped URL pointing at non-AWS host must not engage the carve-out")
		}
	})

	t.Run("attacker_suffix_lookalike_rejected", func(t *testing.T) {
		t.Parallel()
		// .amazonaws.com.evil.tld must not match the AWS suffix gate.
		raw := strings.Replace(
			buildSigV4URL(t, fakeAKIAExample, "3600", ""),
			"examplebucket.s3.amazonaws.com",
			"examplebucket.s3.amazonaws.com.evil.tld",
			1,
		)
		parsed := mustParseURL(t, raw)
		if got := detectValidSigV4(parsed); got.Valid {
			t.Errorf("attacker-controlled suffix lookalike must not engage the carve-out")
		}
	})

	t.Run("empty_host_rejected", func(t *testing.T) {
		t.Parallel()
		if isAWSEndpointHost("") {
			t.Errorf("empty hostname must not engage the carve-out")
		}
	})

	t.Run("aws_china_partition_accepted", func(t *testing.T) {
		t.Parallel()
		raw := strings.Replace(
			buildSigV4URL(t, fakeAKIAExample, "3600", ""),
			"examplebucket.s3.amazonaws.com",
			"examplebucket.s3.cn-north-1.amazonaws.com.cn",
			1,
		)
		parsed := mustParseURL(t, raw)
		if got := detectValidSigV4(parsed); !got.Valid {
			t.Errorf("AWS China partition host (.amazonaws.com.cn) must engage the carve-out")
		}
	})

	t.Run("a3t_prefix_must_be_20_chars_total", func(t *testing.T) {
		t.Parallel()
		// A3T is a 3-char prefix; total key length is still 20.
		// "A3T" + 17 alphanumerics = 20 chars.
		a3tKey := "A3T" + "ABCDEFGHIJKLMNOPQ" // 3 + 17 = 20
		raw := strings.Replace(
			buildSigV4URL(t, fakeAKIAExample, "3600", ""),
			"X-Amz-Credential="+url.QueryEscape(fakeAKIAExample+"/"+validSigV4Scope),
			"X-Amz-Credential="+url.QueryEscape(a3tKey+"/"+validSigV4Scope),
			1,
		)
		parsed := mustParseURL(t, raw)
		got := detectValidSigV4(parsed)
		if !got.Valid {
			t.Errorf("20-char A3T-prefixed key should engage carve-out, got Valid=false")
		}
		if got.KeyID != a3tKey {
			t.Errorf("KeyID = %q, want %q", got.KeyID, a3tKey)
		}
	})

	t.Run("a3t_prefix_19_chars_rejected", func(t *testing.T) {
		t.Parallel()
		// "A3T" + 16 alphanumerics = 19 chars total — must be rejected.
		shortA3T := "A3T" + "ABCDEFGHIJKLMNOP" // 3 + 16 = 19
		raw := strings.Replace(
			buildSigV4URL(t, fakeAKIAExample, "3600", ""),
			"X-Amz-Credential="+url.QueryEscape(fakeAKIAExample+"/"+validSigV4Scope),
			"X-Amz-Credential="+url.QueryEscape(shortA3T+"/"+validSigV4Scope),
			1,
		)
		parsed := mustParseURL(t, raw)
		if got := detectValidSigV4(parsed); got.Valid {
			t.Errorf("19-char A3T-prefixed key must be rejected (length mismatch)")
		}
	})

	t.Run("percent_encoded_sigv4_key_names_rejected", func(t *testing.T) {
		t.Parallel()
		// Attacker percent-encodes the canonical SigV4 key names. The decoder
		// used by parsed.Query() would canonicalize them and (without strict
		// literal-key handling) let the detector validate the URL. The
		// scrubber walks RawQuery byte-for-byte, so it would miss the pair
		// and leave the AKIA un-scrubbed despite the carve-out flag firing.
		// Detector must reject any percent-encoded SigV4 key name.
		raw := "https://examplebucket.s3.amazonaws.com/x" +
			"?X%2DAmz%2DAlgorithm=" + sigV4AlgorithmValue +
			"&X%2DAmz%2DCredential=" + fakeAKIAExample + "/" + validSigV4Scope +
			"&X%2DAmz%2DDate=" + validSigV4Date +
			"&X%2DAmz%2DExpires=3600" +
			"&X%2DAmz%2DSignature=" + validSigV4Signature
		parsed := mustParseURL(t, raw)
		if got := detectValidSigV4(parsed); got.Valid {
			t.Errorf("BYPASS: percent-encoded SigV4 key names engaged the carve-out; scrubber would miss the credential pair and leave AKIA unscrubbed")
		}
	})

	t.Run("mixed_literal_and_encoded_keys_rejected", func(t *testing.T) {
		t.Parallel()
		// Only the credential key is encoded — the other four are literal.
		// Still must invalidate, because the asymmetry hits one field only
		// and that's the one we scrub.
		raw := "https://examplebucket.s3.amazonaws.com/x" +
			"?X-Amz-Algorithm=" + sigV4AlgorithmValue +
			"&X%2DAmz%2DCredential=" + fakeAKIAExample + "/" + validSigV4Scope +
			"&X-Amz-Date=" + validSigV4Date +
			"&X-Amz-Expires=3600" +
			"&X-Amz-Signature=" + validSigV4Signature
		parsed := mustParseURL(t, raw)
		if got := detectValidSigV4(parsed); got.Valid {
			t.Errorf("encoded X-Amz-Credential key must invalidate detection")
		}
	})
}

// TestSigV4CarveoutEndToEnd exercises the full Scan() path: SigV4 validation,
// URL scrubbing, core DLP allow with ClassStructuralExemption, adaptive
// neutrality, and the long-expiry warn finding. Mirrors Codex's spec.
func TestSigV4CarveoutEndToEnd(t *testing.T) {
	t.Parallel()

	newCarveoutScanner := func(t *testing.T) *Scanner {
		t.Helper()
		cfg := config.Defaults()
		cfg.Internal = nil
		cfg.APIAllowlist = []string{
			"examplebucket.s3.amazonaws.com",
			"*.amazonaws.com",
			"example.com",
			"attacker.example",
		}
		s := New(cfg)
		t.Cleanup(s.Close)
		return s
	}

	cases := []struct {
		name            string
		rawURL          string
		wantAllowed     bool
		wantClass       ResultClass
		wantWarnPattern string // empty = no specific warn expected
		wantBlockReason string // substring required when wantAllowed=false
	}{
		{
			name:        "valid_SigV4_short_expiry_carved_out_neutral",
			rawURL:      buildSigV4URL(t, fakeAKIAExample, "3600", ""),
			wantAllowed: true,
			wantClass:   ClassStructuralExemption,
		},
		{
			name:            "valid_SigV4_3_day_expiry_attaches_warn",
			rawURL:          buildSigV4URL(t, fakeAKIAExample, "259200", ""),
			wantAllowed:     true,
			wantClass:       ClassStructuralExemption,
			wantWarnPattern: WarnPatternSigV4LongExpiry,
		},
		{
			name:            "malformed_SigV4_missing_signature_still_blocks_AKIA",
			rawURL:          strings.Replace(buildSigV4URL(t, fakeAKIAExample, "3600", ""), "X-Amz-Signature="+validSigV4Signature, "", 1),
			wantAllowed:     false,
			wantBlockReason: "AWS Access ID",
		},
		{
			name:            "AKIA_in_extra_query_param_blocks_even_with_valid_SigV4",
			rawURL:          buildSigV4URL(t, fakeAKIAExample, "3600", "leaked="+fakeASIAExample),
			wantAllowed:     false,
			wantBlockReason: "AWS Access ID",
		},
		{
			name:            "duplicate_X_Amz_Credential_with_AKIA_blocks",
			rawURL:          buildSigV4URL(t, fakeAKIAExample, "3600", "X-Amz-Credential="+url.QueryEscape(fakeASIAExample+"/"+validSigV4Scope)),
			wantAllowed:     false,
			wantBlockReason: "AWS Access ID",
		},
		{
			name: "AKIA_in_path_with_SigV4_query_set_on_AWS_host_blocks",
			rawURL: "https://examplebucket.s3.amazonaws.com/" + fakeAKIAExample +
				"/file.jpg?X-Amz-Algorithm=" + sigV4AlgorithmValue +
				"&X-Amz-Date=" + validSigV4Date +
				"&X-Amz-Signature=" + validSigV4Signature +
				"&X-Amz-Credential=" + fakeAKIAExample + "/" + validSigV4Scope +
				"&X-Amz-Expires=3600",
			wantAllowed:     false,
			wantBlockReason: "AWS Access ID",
		},
		{
			name:            "overlong_access_key_segment_blocks",
			rawURL:          "https://examplebucket.s3.amazonaws.com/x?X-Amz-Algorithm=" + sigV4AlgorithmValue + "&X-Amz-Date=" + validSigV4Date + "&X-Amz-Signature=" + validSigV4Signature + "&X-Amz-Credential=" + fakeAKIAExample + "EXTRA/" + validSigV4Scope + "&X-Amz-Expires=3600",
			wantAllowed:     false,
			wantBlockReason: "AWS Access ID",
		},
		{
			name:            "bare_AKIA_no_SigV4_structure_blocks",
			rawURL:          "https://example.com/some/path?key=" + fakeAKIAExample,
			wantAllowed:     false,
			wantBlockReason: "AWS Access ID",
		},
		{
			name: "SigV4_shaped_URL_to_non_AWS_host_still_blocks",
			rawURL: "https://attacker.example/exfil?X-Amz-Algorithm=" + sigV4AlgorithmValue +
				"&X-Amz-Date=" + validSigV4Date +
				"&X-Amz-Signature=" + validSigV4Signature +
				"&X-Amz-Credential=" + fakeAKIAExample + "/" + validSigV4Scope +
				"&X-Amz-Expires=3600",
			wantAllowed:     false,
			wantBlockReason: "AWS Access ID",
		},
		{
			name:            "bare_known_SigV4_key_invalidates_carveout_and_blocks",
			rawURL:          buildSigV4URL(t, fakeAKIAExample, "3600", "X-Amz-Credential"),
			wantAllowed:     false,
			wantBlockReason: "AWS Access ID",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			scanner := newCarveoutScanner(t)
			got := scanner.Scan(context.Background(), tc.rawURL)

			if got.Allowed != tc.wantAllowed {
				t.Fatalf("Allowed = %v, want %v (reason=%q)", got.Allowed, tc.wantAllowed, got.Reason)
			}

			if tc.wantAllowed {
				if got.Class != tc.wantClass {
					t.Errorf("Class = %d, want %d", got.Class, tc.wantClass)
				}
				// All structural exemptions must report as adaptive-neutral.
				if tc.wantClass == ClassStructuralExemption && !got.IsAdaptiveNeutral() {
					t.Error("ClassStructuralExemption result must report IsAdaptiveNeutral() == true")
				}
				if tc.wantWarnPattern != "" {
					found := false
					for _, w := range got.WarnMatches {
						if w.PatternName == tc.wantWarnPattern {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("expected warn pattern %q in WarnMatches, got %+v", tc.wantWarnPattern, got.WarnMatches)
					}
				}
			} else {
				if !strings.Contains(got.Reason, tc.wantBlockReason) {
					t.Errorf("Reason = %q, want substring %q", got.Reason, tc.wantBlockReason)
				}
				// Blocks must NOT be marked adaptive-neutral — they must
				// still feed SignalBlock for adaptive enforcement.
				if got.IsAdaptiveNeutral() {
					t.Errorf("blocked result classified as adaptive-neutral; would suppress SignalBlock")
				}
			}
		})
	}
}

// TestSigV4CarveoutDoesNotShortcircuitOtherScanners verifies that the carve-out
// only suppresses the AKIA finding inside the credential value. Other scanner
// stages (rate limit, URL length, data budget) still run normally on the
// scrubbed URL and can block if their own thresholds are exceeded.
func TestSigV4CarveoutDoesNotShortcircuitOtherScanners(t *testing.T) {
	t.Parallel()

	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.APIAllowlist = []string{"examplebucket.s3.amazonaws.com"}
	cfg.FetchProxy.Monitoring.MaxURLLength = 200 // intentionally short to trip length check

	scanner := New(cfg)
	defer scanner.Close()

	raw := buildSigV4URL(t, fakeAKIAExample, "3600", "")
	if len(raw) <= cfg.FetchProxy.Monitoring.MaxURLLength {
		t.Fatalf("test URL length %d is not > %d; cannot prove the carve-out is not a global pass", len(raw), cfg.FetchProxy.Monitoring.MaxURLLength)
	}

	got := scanner.Scan(context.Background(), raw)
	if got.Allowed {
		t.Errorf("expected URL length scanner to block oversize URL despite valid SigV4; got Allowed=true")
	}
	if got.Scanner != ScannerLength {
		t.Errorf("expected Scanner = %q, got %q", ScannerLength, got.Scanner)
	}
}

// TestSigV4ScrubPreservesQueryOrder pins the order-preservation contract
// of scrubSigV4Credential. The ordered-subsequence DLP detector walks
// values from RawQuery in iteration order and only tries strictly
// increasing index combinations. If the scrub reorders pairs (e.g., via
// url.Values.Encode() which sorts alphabetically), an attacker can split
// an AKIA-shaped value across two extra query params whose alphabetical
// order hides the matching concatenation.
//
// This test builds a SigV4-valid URL plus two extras: z_split1=AKIA
// (4 chars) and a_split2=IOSFODNN7EXAMPLE1 (17 chars). In original
// RawQuery iteration order the two parts concatenate to a valid AWS
// Access ID and the subsequence detector blocks. Alphabetical reorder
// would put a_split2 before z_split1 and the concat would not match.
func TestSigV4ScrubPreservesQueryOrder(t *testing.T) {
	t.Parallel()

	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.APIAllowlist = []string{"examplebucket.s3.amazonaws.com", "*.amazonaws.com"}

	sc := New(cfg)
	defer sc.Close()

	// 4 + 17 = 21 chars total; matches AWS Access ID pattern `AKIA[A-Z0-9]{16,}`.
	akiaPart1 := "AKIA"
	akiaPart2 := "IOSFODNN7EXAMPLE1"
	raw := buildSigV4URL(t, fakeAKIAExample, "3600",
		"z_split1="+akiaPart1+"&a_split2="+akiaPart2)

	got := sc.Scan(context.Background(), raw)
	if got.Allowed {
		t.Fatalf("BYPASS: split AKIA hidden by alphabetical scrub reorder passed core DLP; got Allowed=true, Class=%d", got.Class)
	}
	if !strings.Contains(got.Reason, "AWS Access ID") {
		t.Errorf("Reason = %q, want AWS Access ID match from subsequence detector", got.Reason)
	}
	if got.IsAdaptiveNeutral() {
		t.Errorf("block must not be classified adaptive-neutral; would suppress SignalBlock")
	}
}
