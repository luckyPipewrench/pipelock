// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"net/http"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

const (
	sigV4HeaderTestDate       = "20260512T173720Z"
	sigV4HeaderTestScope      = "20260512/us-east-1/sts/aws4_request"
	sigV4HeaderTestSignature  = "4667401eda326e25245738e62377c28e0bc120b1fbcab22896f1cc85eb4d2e89"
	sigV4HeaderAWSTarget      = "https://sts.us-east-1.amazonaws.com/"
	sigV4HeaderAttackerTarget = "https://attacker.example/exfil"
)

func sigV4HeaderTestKey() string {
	return "AKIA" + "IOSFODNN7EXAMPLE"
}

func sigV4HeaderTestAltKey() string {
	return "ASIA" + "Z5MHFQGAEXAMPLE1"
}

func buildSigV4Authorization(keyID string) string {
	return "AWS4-HMAC-SHA256 Credential=" + keyID + "/" + sigV4HeaderTestScope +
		", SignedHeaders=host;x-amz-date, Signature=" + sigV4HeaderTestSignature
}

func scanSigV4Headers(t *testing.T, headers http.Header, target string) *BodyScanResult {
	t.Helper()
	cfg := testScannerConfig()
	cfg.RequestBodyScanning.Action = config.ActionBlock
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	return scanRequestHeadersForTarget(context.Background(), headers, cfg, sc, target)
}

func TestScanRequestHeaders_SigV4AuthorizationEnvelopeAllowsAWSDestination(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", buildSigV4Authorization(sigV4HeaderTestKey()))
	headers.Set("X-Amz-Date", sigV4HeaderTestDate)

	result := scanSigV4Headers(t, headers, sigV4HeaderAWSTarget)
	if result != nil && !result.Clean {
		t.Fatalf("legitimate SigV4 Authorization to AWS was blocked: %+v", result)
	}
}

// requireSigV4HeaderBlocked asserts the header set is blocked. The allow test
// above cannot detect a carve-out that is too broad, so every deny case below
// is what actually constrains the change.
func requireSigV4HeaderBlocked(t *testing.T, headers http.Header, target, why string) {
	t.Helper()
	result := scanSigV4Headers(t, headers, target)
	if result == nil || result.Clean {
		t.Fatalf("%s: expected a block, got clean (result=%+v)", why, result)
	}
}

func TestScanRequestHeaders_SigV4EnvelopeBlockedAtNonAWSDestination(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", buildSigV4Authorization(sigV4HeaderTestKey()))
	headers.Set("X-Amz-Date", sigV4HeaderTestDate)

	requireSigV4HeaderBlocked(t, headers, sigV4HeaderAttackerTarget,
		"a structurally perfect envelope aimed at an attacker host is an exfiltration channel, not a signed AWS call")
}

func TestScanRequestHeaders_SigV4EnvelopeBlockedWhenTargetUnknown(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", buildSigV4Authorization(sigV4HeaderTestKey()))

	requireSigV4HeaderBlocked(t, headers, "",
		"an unresolvable destination must fail closed rather than inherit the carve-out")
}

func TestScanRequestHeaders_MalformedSigV4EnvelopeBlockedAtAWSDestination(t *testing.T) {
	// Reaching an AWS host is necessary but not sufficient: the envelope still
	// has to validate, or a bare key ID could ride to AWS wearing the scheme.
	for _, tc := range []struct {
		name  string
		value string
	}{
		{"scheme_only", "AWS4-HMAC-SHA256 Credential=" + sigV4HeaderTestKey()},
		{"lowercase_scheme", "aws4-hmac-sha256 Credential=" + sigV4HeaderTestKey() +
			"/" + sigV4HeaderTestScope + ", SignedHeaders=host, Signature=" + sigV4HeaderTestSignature},
		{"truncated_signature", "AWS4-HMAC-SHA256 Credential=" + sigV4HeaderTestKey() +
			"/" + sigV4HeaderTestScope + ", SignedHeaders=host, Signature=dead"},
		{"bare_key_id", sigV4HeaderTestKey()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			headers := http.Header{}
			headers.Set("Authorization", tc.value)
			requireSigV4HeaderBlocked(t, headers, sigV4HeaderAWSTarget,
				"malformed envelope to AWS must stay under core DLP")
		})
	}
}

func TestScanRequestHeaders_SigV4CarveOutIsNotASmugglingChannel(t *testing.T) {
	// A valid envelope must not launder a second credential travelling beside
	// it. This is the case that distinguishes a narrow carve-out from a hole.
	headers := http.Header{}
	headers.Set("Authorization", buildSigV4Authorization(sigV4HeaderTestKey()))
	headers.Set("X-Amz-Date", sigV4HeaderTestDate)
	// X-Api-Key is in the default sensitive-header set, so this exercises the
	// carve-out rather than the header-mode config. A header outside that set
	// is not scanned at all, which would make this test pass for the wrong
	// reason.
	headers.Set("X-Api-Key", sigV4HeaderTestAltKey())

	requireSigV4HeaderBlocked(t, headers, sigV4HeaderAWSTarget,
		"a second access key in another scanned header must still block")
}

func TestScanRequestHeaders_SigV4CarveOutIsAuthorizationOnly(t *testing.T) {
	// The carve-out is scoped to Authorization. A lookalike header carrying the
	// same envelope has no signing role and must not inherit the exemption.
	headers := http.Header{}
	headers.Set("Proxy-Authorization", buildSigV4Authorization(sigV4HeaderTestKey()))

	requireSigV4HeaderBlocked(t, headers, sigV4HeaderAWSTarget,
		"Proxy-Authorization is not the SigV4 signing header")
}

func TestScanRequestHeaders_SigV4CarveOutRequiresEncryptedTransport(t *testing.T) {
	// A real AWS API call is always TLS. Over cleartext the forwarded header
	// puts the key id on the wire in the clear, so the carve-out must not
	// apply even though the hostname is AWS-issued.
	for _, target := range []string{
		"http://sts.us-east-1.amazonaws.com/",
		"ws://sts.us-east-1.amazonaws.com/",
		"HTTP://sts.us-east-1.amazonaws.com/",
	} {
		t.Run(target, func(t *testing.T) {
			headers := http.Header{}
			headers.Set("Authorization", buildSigV4Authorization(sigV4HeaderTestKey()))
			requireSigV4HeaderBlocked(t, headers, target,
				"a cleartext destination must stay under core DLP")
		})
	}
}

func TestScanRequestHeaders_SigV4CarveOutRequiresASingleAuthorizationValue(t *testing.T) {
	// Scrubbing each value independently would leave the per-value and the
	// joined scans with no key id to find, so a repeated header disables the
	// carve-out entirely.
	headers := http.Header{}
	headers.Add("Authorization", buildSigV4Authorization(sigV4HeaderTestKey()))
	headers.Add("Authorization", buildSigV4Authorization(sigV4HeaderTestAltKey()))

	requireSigV4HeaderBlocked(t, headers, sigV4HeaderAWSTarget,
		"a repeated Authorization header must disable the carve-out")
}

func TestScanRequestHeaders_SigV4EnvelopeStillAllowedOverTLS(t *testing.T) {
	// Guards against over-tightening: the single legitimate shape must still
	// pass, or the fix above has re-broken what this change set out to fix.
	headers := http.Header{}
	headers.Set("Authorization", buildSigV4Authorization(sigV4HeaderTestKey()))
	headers.Set("X-Amz-Date", sigV4HeaderTestDate)

	result := scanSigV4Headers(t, headers, sigV4HeaderAWSTarget)
	if result != nil && !result.Clean {
		t.Fatalf("a single TLS-bound SigV4 header was blocked: %+v", result)
	}
}
