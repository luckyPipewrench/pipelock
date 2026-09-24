// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"crypto/rand"
	"encoding/base64"
	"net/url"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// Entropy measures what a URL carries, not how it is written. A base64
// wrapped record id passes like the plain id it encodes; encoded random data
// is still blocked.
func TestEntropyMeasuresDecodedPayload(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	s := MustNew(cfg)
	defer s.Close()

	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	uuid := "2bcabc26-51e8-4341-9daa-35c0f1e7a9d4"
	wrapped := base64.RawURLEncoding.EncodeToString([]byte(uuid))
	typed := base64.StdEncoding.EncodeToString([]byte("gid://app/Record/" + uuid))
	randomB64 := base64.RawURLEncoding.EncodeToString(random)
	doubleB64 := base64.StdEncoding.EncodeToString([]byte(base64.StdEncoding.EncodeToString(random)))

	if ShannonEntropy(typed) <= 4.5 {
		t.Fatalf("fixture must exceed the threshold raw: %.2f", ShannonEntropy(typed))
	}
	for _, tc := range []struct {
		name  string
		raw   string
		block bool
	}{
		{"base64 uuid path segment", "https://app.vendor.example/job_forms/" + wrapped, false},
		{"base64 typed id path segment", "https://app.vendor.example/r/" + url.PathEscape(typed), false},
		{"base64 uuid query value", "https://app.vendor.example/x?id=" + url.QueryEscape(wrapped), false},
		{"random bytes as base64url path", "https://collector.evil.test/p/" + randomB64, true},
		{"random bytes as base64url query", "https://collector.evil.test/p?d=" + randomB64, true},
		{"double-encoded random", "https://collector.evil.test/p/" + url.PathEscape(doubleB64), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := url.Parse(tc.raw)
			if err != nil {
				t.Fatal(err)
			}
			r := s.checkEntropy(parsed)
			if blocked := !r.Allowed; blocked != tc.block {
				t.Fatalf("blocked = %v, want %v (%s)", blocked, tc.block, r.Reason)
			}
		})
	}
}
