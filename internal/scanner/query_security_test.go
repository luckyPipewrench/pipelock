// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"reflect"
	"testing"
)

func TestSeedPhraseRawQueryPairs(t *testing.T) {
	cfg := testConfig()
	cfg.Internal = nil
	cfg.FetchProxy.Monitoring.MaxURLLength = 4096
	cfg.SeedPhraseDetection.Enabled = ptrBool(true)
	cfg.SeedPhraseDetection.MinWords = 12
	cfg.SeedPhraseDetection.VerifyChecksum = ptrBool(true)
	sc := MustNew(cfg)
	t.Cleanup(sc.Close)
	for _, value := range []string{hex.EncodeToString([]byte(testSeedPhrase12)), url.QueryEscape(base64.StdEncoding.EncodeToString([]byte(testSeedPhrase12)))} {
		for _, query := range []string{"k=%ZZ" + value, "k=" + value + "%ZZ", "x=1;k=" + value, "%ZZ=x;k=" + value} {
			if r := sc.Scan(t.Context(), "https://api.vendor.example/?"+query); r.Allowed || r.Scanner != ScannerDLP {
				t.Errorf("seed query was not blocked by DLP: allowed=%v scanner=%s", r.Allowed, r.Scanner)
			}
		}
	}
}

func TestNestedURLRawQueryPairs(t *testing.T) {
	candidates := nestedURLCandidates("x=1;next=https%3A%2F%2Fapi.vendor.example%2F%ZZ", 4096)
	for _, candidate := range candidates {
		if candidate.key == "next" && candidate.text == "https://api.vendor.example/%ZZ" {
			return
		}
	}
	t.Fatal("semicolon pair lost nested destination")
}

func TestKnownURLCredentialRawQueryWindows(t *testing.T) {
	marker := "Zq7Lm2Xc9Vb4" + "Nn8Kp3Rt6Wy1"
	for _, raw := range []string{"k=" + marker + "%ZZ", "x=1;k=" + marker} {
		windows, err := urlCredentialWindowsBounded("https://api.vendor.example/?"+raw, 1000)
		if err != nil || len(windows[marker[:minKnownSecretSubstringLen]]) == 0 {
			t.Fatalf("credential query windows lost: %v", err)
		}
	}
}

func TestRawQuerySecurityPairs(t *testing.T) {
	for _, tc := range []struct {
		query string
		want  []rawQuerySecurityPair
	}{
		{"", nil},
		{"&&;;", nil},
		{"a=%ZZ;b=%41&c=%26%3B", []rawQuerySecurityPair{{"a", "%ZZ", true}, {"b", "%41", true}, {"c", "%26%3B", true}}},
		{"a=1&a=2&key&=value&k=", []rawQuerySecurityPair{{"a", "1", true}, {"a", "2", true}, {"key", "", false}, {"", "value", true}, {"k", "", true}}},
	} {
		if got := rawQuerySecurityPairs(tc.query); !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("raw pairs differ: got %#v, want %#v", got, tc.want)
		}
	}
}

func TestScan_NestedURLRawQueryPairs(t *testing.T) {
	cfg := nestedURLConfig()
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = nil
	sc := MustNew(cfg)
	t.Cleanup(sc.Close)
	sc.resolver = failOnLookupResolver{t: t}
	target := nestedURLOuterHost + "?x=1;next=" + url.QueryEscape(nestedURLMetadataPath)
	if result := sc.Scan(t.Context(), target); result.Allowed {
		t.Fatal("semicolon nested metadata destination was allowed")
	}
}
