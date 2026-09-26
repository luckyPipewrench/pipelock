// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"crypto/sha256"
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

	// Fixed bytes, not crypto/rand: roughly one random draw in five hundred
	// encodes to a string just under the threshold, which made the
	// double-encoded case fail at random. The premise checks below keep
	// the fixture honest.
	digest := sha256.Sum256([]byte("entropy-decoded-payload-fixture"))
	random := digest[:]
	uuid := "2bcabc26-51e8-4341-9daa-35c0f1e7a9d4"
	wrapped := base64.RawURLEncoding.EncodeToString([]byte(uuid))
	typed := base64.StdEncoding.EncodeToString([]byte("gid://app/Record/" + uuid))
	randomB64 := base64.RawURLEncoding.EncodeToString(random)
	doubleB64 := base64.StdEncoding.EncodeToString([]byte(base64.StdEncoding.EncodeToString(random)))

	if ShannonEntropy(typed) <= 4.5 {
		t.Fatalf("fixture must exceed the threshold raw: %.2f", ShannonEntropy(typed))
	}
	for name, v := range map[string]string{"random base64url": randomB64, "random base64": base64.StdEncoding.EncodeToString(random)} {
		if ShannonEntropy(v) <= 4.5 {
			t.Fatalf("%s fixture must exceed the threshold: %.2f", name, ShannonEntropy(v))
		}
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
		// A semicolon sends the query down the ambiguous-query path, which
		// must measure values the same way.
		{"base64 typed id query value beside a semicolon", "https://app.vendor.example/x?a=1;b=2&id=" + url.QueryEscape(typed), false},
		{"random bytes beside a semicolon", "https://collector.evil.test/p?a=1;b=2&d=" + randomB64, true},
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
