// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"encoding/base64"
	"net/url"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// Every malformed shape is refused by the strict parser, so the caller keeps
// the whole-value check. Each case starts from a message that parses and
// breaks exactly one thing.
func TestParseDNSMessageRejectsMalformed(t *testing.T) {
	question := func() []byte {
		w := make([]byte, 12)
		w[5] = 1
		w = append(w, dnsNameWire([]string{"www", "example", "test"})...)
		return append(w, 0x00, 0x01, 0x00, 0x01)
	}
	withRecord := func(owner, rest []byte) []byte {
		w := question()
		w[11] = 1
		w = append(w, owner...)
		return append(w, rest...)
	}
	if _, ok := parseDNSMessage(question()); !ok {
		t.Fatal("premise: the base question parses")
	}
	longName := make([]byte, 12)
	longName[5] = 1
	for range 5 {
		longName = append(longName, 63)
		longName = append(longName, strings.Repeat("a", 63)...)
	}
	longName = append(longName, 0, 0x00, 0x01, 0x00, 0x01)
	for _, tc := range []struct {
		name string
		wire []byte
	}{
		{"short header", make([]byte, 11)},
		{"question count beyond message", func() []byte { w := question(); w[4] = 0xFF; return w }()},
		{"question type truncated", question()[:len(question())-2]},
		{"label length over 63", func() []byte { w := question(); w[12] = 64; return w }()},
		{"label runs past end", func() []byte { w := question()[:15]; w[12] = 40; return w }()},
		{"name longer than 255", longName},
		{"reserved label type 0x40", func() []byte { w := question(); w[12] = 0x41; return w }()},
		{"pointer truncated", func() []byte { w := make([]byte, 12); w[5] = 1; return append(w, 0xC0) }()},
		{"pointer outside message", func() []byte {
			w := make([]byte, 12)
			w[5] = 1
			return append(w, 0xC0, 0xFF, 0x00, 0x01, 0x00, 0x01)
		}()},
		{"pointer loop", func() []byte {
			w := make([]byte, 12)
			w[5] = 1
			return append(w, 0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01)
		}()},
		{"record header truncated", withRecord([]byte{0}, []byte{0x00, 0x01})},
		{"rdata past end", withRecord([]byte{0}, []byte{0x00, 0x10, 0x00, 0x01, 0, 0, 0, 0, 0x00, 0x20, 'a'})},
		{"edns option header truncated", withRecord([]byte{0}, []byte{0x00, 0x29, 0x10, 0x00, 0, 0, 0, 0, 0x00, 0x02, 0x00, 0x0C})},
		{"edns option past rdata", withRecord([]byte{0}, []byte{0x00, 0x29, 0x10, 0x00, 0, 0, 0, 0, 0x00, 0x05, 0x00, 0x0C, 0x00, 0x09, 'a'})},
		{"record owner malformed", withRecord([]byte{0xC0}, nil)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, ok := parseDNSMessage(tc.wire); ok {
				t.Fatal("malformed message parsed")
			}
		})
	}
}

func TestParseDNSQueryEntryRules(t *testing.T) {
	encoded := base64.RawURLEncoding.EncodeToString(dnsQueryWire(t, []string{"www", "example", "test"}))
	if _, ok := parseDNSQuery("dns=" + encoded); !ok {
		t.Fatal("premise: the canonical query parses")
	}
	// A label whose bytes encode to '+' and '/' in the standard alphabet, so
	// the standard and URL-safe encodings of one valid message differ only in
	// alphabet. RFC 8484 requires the URL-safe one.
	altWire := dnsQueryWire(t, []string{"\xfb\xff", "example", "test"})
	altURL := base64.RawURLEncoding.EncodeToString(altWire)
	altStd := base64.RawStdEncoding.EncodeToString(altWire)
	if altStd == altURL || !strings.ContainsAny(altStd, "+/") {
		t.Fatalf("premise: standard encoding %q must differ from URL-safe %q", altStd, altURL)
	}
	if _, ok := parseDNSQuery("dns=" + altURL); !ok {
		t.Fatal("premise: the URL-safe encoding of the same message parses")
	}
	for name, raw := range map[string]string{
		"empty":             "",
		"empty pair":        "dns=" + encoded + "&",
		"no value":          "dns",
		"other parameter":   "dns=" + encoded + "&ct=x",
		"bad escape":        "dns=%zz",
		"empty value":       "dns=",
		"standard base64":   "dns=" + url.QueryEscape(altStd),
		"non-canonical b64": "dns=" + encoded[:len(encoded)-1] + "B",
	} {
		if _, ok := parseDNSQuery(raw); ok {
			t.Errorf("%s: query %q qualified as a DNS message", name, raw)
		}
	}
}

func TestInspectDNSPayload(t *testing.T) {
	s := newProtocolEntropyScanner(t)
	got := s.InspectDNSPayload(dnsQueryWire(t, []string{"www", "example", "test"}))
	if !got.Parsed || len(got.DLPTexts) == 0 || len(got.EntropyTexts) == 0 {
		t.Fatalf("parsed message = %+v", got)
	}
	if got := s.InspectDNSPayload([]byte("not a dns message at all")); got.Parsed || got.DLPTexts != nil {
		t.Fatalf("opaque body = %+v", got)
	}
}

// A URL carried as a query value can itself be a DoH query; its message is
// read the same way at the nested level.
func TestNestedURLDoHQuery(t *testing.T) {
	s := newProtocolEntropyScanner(t)
	benign := "https://resolver.vendor.example/dns-query?dns=" + base64.RawURLEncoding.EncodeToString(dnsQueryWire(t, []string{"www", "example", "test"}))
	binary := "https://resolver.vendor.example/dns-query?dns=" + base64.RawURLEncoding.EncodeToString(dnsRecordWire(t, nil, dnsTestBytes("nested-rdata", 48)))
	for _, tc := range []struct {
		name, inner string
		allowed     bool
	}{
		{"benign", benign, true},
		{"random rdata", binary, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := url.Parse("https://app.vendor.example/login?next=" + url.QueryEscape(tc.inner))
			if err != nil {
				t.Fatal(err)
			}
			if r := s.checkEntropy(parsed); r.Allowed != tc.allowed {
				t.Fatalf("allowed = %v, want %v (%s)", r.Allowed, tc.allowed, r.Reason)
			}
		})
	}
}

// A malformed percent escape in a ';'-separated query keeps the raw text for
// scoring instead of dropping the pair.
func TestSplitQueryEntropyPairsKeepsUndecodable(t *testing.T) {
	pairs := splitQueryEntropyPairs("a%zz=v%zz;b=2")
	if len(pairs) != 2 || pairs[0].key != "a%zz" || pairs[0].value != "v%zz" || pairs[1].value != "2" {
		t.Fatalf("pairs = %+v", pairs)
	}
}

// Configured DLP decodes HTML entities in a URL query value too, so a
// configurable pattern (not only the core floor) sees the decoded text.
func TestConfiguredDLPDecodesURLHTMLEntities(t *testing.T) {
	key := "sk-ant-" + "api03-" + strings.Repeat("AbCdEfGhIj", 9) + "-" + "AAAAAAAA"
	if config.IsCoreDLPPatternName("Anthropic API Key") {
		t.Fatal("premise: the pattern must be configured, not core")
	}
	var html strings.Builder
	for _, c := range key {
		html.WriteString("&#" + itoa(int(c)) + ";")
	}
	s := newProtocolEntropyScanner(t)
	r := s.Scan(context.Background(), "https://api.vendor.example/x?d="+url.QueryEscape(html.String()))
	if r.Allowed || r.Scanner != ScannerDLP {
		t.Fatalf("allowed=%v scanner=%q reason=%q, want configured DLP", r.Allowed, r.Scanner, r.Reason)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}
