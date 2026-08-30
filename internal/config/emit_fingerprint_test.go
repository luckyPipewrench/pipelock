// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"regexp"
	"strings"
	"testing"
)

func TestEmitConfigFingerprintDeterministicAndCredentialSensitive(t *testing.T) {
	t.Parallel()
	first := Defaults().Emit
	first.Webhook.AuthToken = "webhook-secret-one"
	first.OTLP.Headers = map[string]string{
		"X-Tenant":      "tenant-one",
		"Authorization": "Bearer otlp-secret-one",
	}
	first.Forwarder.AuthToken = "forwarder-secret-one"

	second := first
	second.OTLP.Headers = map[string]string{
		"Authorization": "Bearer otlp-secret-one",
		"X-Tenant":      "tenant-one",
	}

	firstHash := first.Fingerprint()
	secondHash := second.Fingerprint()
	if firstHash != secondHash {
		t.Fatalf("equivalent emit configs produced different fingerprints: %q != %q", firstHash, secondHash)
	}
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(firstHash) {
		t.Fatalf("Fingerprint = %q, want a 64-character lowercase hex digest", firstHash)
	}
	for _, secret := range []string{"webhook-secret-one", "otlp-secret-one", "forwarder-secret-one"} {
		if strings.Contains(firstHash, secret) {
			t.Fatalf("Fingerprint exposed credential %q", secret)
		}
	}

	second.Forwarder.AuthToken = "forwarder-secret-two"
	changedHash := second.Fingerprint()
	if changedHash == firstHash {
		t.Fatal("credential-only emit change did not change the fingerprint")
	}
}
