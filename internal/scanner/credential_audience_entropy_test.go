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

// Unlike credentialAudienceTestConfig, this keeps the default entropy
// threshold so query entropy and the audience rule run together.
func credentialAudienceEntropyConfig() *config.Config {
	cfg := config.Defaults()
	cfg.Internal = nil
	return cfg
}

func TestScan_QueryEntropyHonorsCredentialAudience(t *testing.T) {
	t.Parallel()
	s := MustNew(credentialAudienceEntropyConfig())
	defer s.Close()

	// Built at runtime so no literal credential sits in source.
	key := "AI" + "za" + "Sy9fK2qLmR7xWvT4bNcZ8pH3jD6gE1uYo0A"
	if len(key) != 39 {
		t.Fatalf("fixture key length = %d, want 39", len(key))
	}
	if ShannonEntropy(key) <= config.Defaults().FetchProxy.Monitoring.EntropyThreshold {
		t.Fatal("fixture key does not exceed the entropy threshold, so the test cannot prove anything")
	}

	t.Run("control: entropy alone blocks the value off-audience", func(t *testing.T) {
		// A value that no credential pattern owns is scored by entropy.
		r := s.Scan(context.Background(), "https://maps.googleapis.com/maps/api/js?key=Zq"+key[4:])
		if r.Allowed || r.Scanner != ScannerEntropy {
			t.Fatalf("non-credential random value: allowed=%v scanner=%q reason=%q", r.Allowed, r.Scanner, r.Reason)
		}
	})

	t.Run("audience destination allows the whole key", func(t *testing.T) {
		r := s.Scan(context.Background(), "https://maps.googleapis.com/maps/api/js?key="+key+"&callback=initMap")
		if !r.Allowed {
			t.Fatalf("Google API key to its audience blocked: %s (%s)", r.Reason, r.Scanner)
		}
		assertCredentialAudienceAllow(t, r, "Google API Key", "url", "maps.googleapis.com")
	})

	t.Run("wrong destination still blocks", func(t *testing.T) {
		r := s.Scan(context.Background(), "https://api.vendor.example/js?key="+key)
		if r.Allowed {
			t.Fatal("Google API key to a non-audience host allowed")
		}
	})

	t.Run("lookalike destination still blocks", func(t *testing.T) {
		r := s.Scan(context.Background(), "https://maps.googleapis.com.evil.example/js?key="+key)
		if r.Allowed {
			t.Fatal("Google API key to a lookalike host allowed")
		}
	})

	t.Run("extra bytes beside the key keep entropy scoring", func(t *testing.T) {
		smuggled := key + "-" + "Qx7Lp2Vr9Tk4Wm8Zs3Nb6Hd1Jf5Gc0"
		r := s.Scan(context.Background(), "https://maps.googleapis.com/maps/api/js?key="+smuggled)
		if r.Allowed {
			t.Fatal("key with appended random data allowed on the audience host")
		}
		if r.Scanner != ScannerEntropy || !strings.Contains(r.Reason, `"key"`) {
			t.Fatalf("appended data blocked by %q (%s), want query entropy on key", r.Scanner, r.Reason)
		}
	})

	t.Run("audience key in a different param does not cover a random neighbor", func(t *testing.T) {
		r := s.Scan(context.Background(), "https://maps.googleapis.com/maps/api/js?key="+key+"&x=Zq"+key[4:])
		if r.Allowed || r.Scanner != ScannerEntropy {
			t.Fatalf("random neighbor param: allowed=%v scanner=%q reason=%q", r.Allowed, r.Scanner, r.Reason)
		}
	})
}

// Scan runs DLP before entropy, so off-audience hosts in the test above are
// rejected before the new guard is consulted. These cases call the entropy
// stage directly so a regression in the audience decision itself fails.
func TestCheckEntropy_AudienceGuardRejectsOffAudienceHosts(t *testing.T) {
	t.Parallel()
	s := MustNew(credentialAudienceEntropyConfig())
	defer s.Close()

	key := "AI" + "za" + "Sy9fK2qLmR7xWvT4bNcZ8pH3jD6gE1uYo0A"
	for _, raw := range []string{
		"https://api.vendor.example/js?key=" + key,
		"https://maps.googleapis.com.evil.example/js?key=" + key,
	} {
		parsed, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		r := s.checkEntropyWithContext(context.Background(), parsed)
		if r.Allowed || r.Scanner != ScannerEntropy {
			t.Fatalf("%s: allowed=%v scanner=%q, want entropy block", parsed.Host, r.Allowed, r.Scanner)
		}
	}

	parsed, err := url.Parse("https://maps.googleapis.com/maps/api/js?key=" + key)
	if err != nil {
		t.Fatal(err)
	}
	if r := s.checkEntropyWithContext(context.Background(), parsed); !r.Allowed {
		t.Fatalf("positive control: audience host blocked by %q: %s", r.Scanner, r.Reason)
	}
	if s.queryValueIsAudienceCredential("https://maps.googleapis.com/", "") {
		t.Fatal("empty value treated as an audience credential")
	}
}
