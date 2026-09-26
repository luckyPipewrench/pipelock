// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// dnsTestBytes returns n deterministic high-entropy bytes, so a test that
// needs "random" message content cannot flake.
func dnsTestBytes(seed string, n int) []byte {
	var out []byte
	block := sha256.Sum256([]byte(seed))
	for len(out) < n {
		out = append(out, block[:]...)
		block = sha256.Sum256(block[:])
	}
	return out[:n]
}

// dnsManyEmptyRecordsWire is one ordinary question followed by count
// additional records with a root owner and no RDATA. Each record carries
// eight sender-chosen bytes in its type, class and TTL.
func dnsManyEmptyRecordsWire(t *testing.T, count int) []byte {
	t.Helper()
	wire := make([]byte, 12)
	wire[5] = 1
	wire[10], wire[11] = byte(count>>8), byte(count) // #nosec G115 -- DNS test lengths are small fixed values below 256 (and 65536 for RDLENGTH).
	wire = append(wire, dnsNameWire([]string{"cache", "example", "test"})...)
	wire = append(wire, 0x00, 0x01, 0x00, 0x01)
	payload := dnsTestBytes("fixed-fields", 8*count)
	for i := range count {
		wire = append(wire, 0) // root owner
		wire = append(wire, payload[i*8:i*8+8]...)
		wire = append(wire, 0, 0) // RDLENGTH 0
	}
	return wire
}

// dnsRecordWire is one ordinary question and one additional record of an
// unregistered type whose RDATA is rdata.
func dnsRecordWire(t *testing.T, owner []string, rdata []byte) []byte {
	t.Helper()
	wire := make([]byte, 12)
	wire[5] = 1
	wire[11] = 1
	wire = append(wire, dnsNameWire([]string{"cache", "example", "test"})...)
	wire = append(wire, 0x00, 0x01, 0x00, 0x01)
	wire = append(wire, dnsNameWire(owner)...)
	wire = append(wire, 0xFF, 0x00, 0x00, 0x01, 0, 0, 0, 0, byte(len(rdata)>>8), byte(len(rdata))) // #nosec G115 -- DNS test lengths are small fixed values below 256 (and 65536 for RDLENGTH).
	return append(wire, rdata...)
}

// dnsOrdinaryQueryWire is what a stub resolver sends: a random ID, recursion
// desired, one A question, and an OPT record carrying a client cookie and
// block-length padding.
func dnsOrdinaryQueryWire(t *testing.T) []byte {
	t.Helper()
	wire := make([]byte, 12)
	copy(wire[0:2], dnsTestBytes("query-id", 2))
	wire[2] = 0x01 // RD
	wire[5] = 1
	wire[11] = 1
	wire = append(wire, dnsNameWire([]string{"www", "example", "test"})...)
	wire = append(wire, 0x00, 0x01, 0x00, 0x01)
	cookie := append([]byte{0x00, 0x0A, 0x00, 0x08}, dnsTestBytes("client-cookie", 8)...)
	padding := append([]byte{0x00, 0x0C, 0x00, 0x40}, make([]byte, 0x40)...)
	options := append(cookie, padding...)
	wire = append(wire, 0)                                                                                // root owner
	wire = append(wire, 0x00, 0x29, 0x04, 0xD0, 0, 0, 0x80, 0, byte(len(options)>>8), byte(len(options))) // #nosec G115 -- DNS test lengths are small fixed values below 256 (and 65536 for RDLENGTH).
	return append(wire, options...)
}

func TestDoHQueryInspectsEveryPart(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	s := MustNew(cfg)
	defer s.Close()

	key := awsExampleAccessKeyID()
	half := len(key) / 2
	splitAcrossNames := make([]byte, 12)
	splitAcrossNames[5] = 2
	splitAcrossNames = append(splitAcrossNames, dnsNameWire([]string{key[:half], "example", "test"})...)
	splitAcrossNames = append(splitAcrossNames, 0x00, 0x01, 0x00, 0x01)
	splitAcrossNames = append(splitAcrossNames, dnsNameWire([]string{key[half:], "example", "test"})...)
	splitAcrossNames = append(splitAcrossNames, 0x00, 0x01, 0x00, 0x01)

	cases := []struct {
		name    string
		wire    []byte
		allowed bool
		scanner string
	}{
		{"ordinary query with cookie and padding", dnsOrdinaryQueryWire(t), true, ""},
		{"payload in fixed-width record fields", dnsManyEmptyRecordsWire(t, 40), false, ScannerEntropy},
		{"random binary record data", dnsRecordWire(t, nil, dnsTestBytes("rdata", 48)), false, ScannerEntropy},
		{"random binary label", dnsRecordWire(t, []string{string(dnsTestBytes("label", 48))}, nil), false, ScannerEntropy},
		{"key split across two names", splitAcrossNames, false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msg, ok := parseDNSMessage(tc.wire)
			if !ok {
				t.Fatal("fixture is not a strict DNS message, so this case would not exercise the parser")
			}
			if _, ok := parseDNSQuery("dns=" + base64.RawURLEncoding.EncodeToString(tc.wire)); !ok {
				t.Fatal("fixture does not qualify as a DoH query")
			}
			_ = msg
			raw := "https://resolver.vendor.example/dns-query?dns=" + base64.RawURLEncoding.EncodeToString(tc.wire)
			r := s.Scan(context.Background(), raw)
			if r.Allowed != tc.allowed {
				t.Fatalf("allowed = %v, want %v (%s: %s)", r.Allowed, tc.allowed, r.Scanner, r.Reason)
			}
			if !tc.allowed && tc.scanner != "" && r.Scanner != tc.scanner {
				t.Fatalf("scanner = %q, want %q (%s)", r.Scanner, tc.scanner, r.Reason)
			}
		})
	}
}

// A binary piece is measured by its base64url form. Measured as a Go string,
// every byte above 0x7F is the same replacement rune and random data reads
// as nearly uniform, which is the failure this pins.
func TestDNSEntropySubjectEncodesBinary(t *testing.T) {
	random := dnsTestBytes("subject", 32)
	if got := dnsEntropySubject(random, false); got != base64.RawURLEncoding.EncodeToString(random) {
		t.Fatalf("binary subject = %q", got)
	}
	if got := dnsEntropySubject([]byte("MixedCase"), true); got != "MIXEDCASE" {
		t.Fatalf("folded label = %q", got)
	}
	if got := dnsEntropySubject([]byte("MixedCase"), false); got != "MixedCase" {
		t.Fatalf("printable rdata = %q", got)
	}
	if ShannonEntropy(string(random)) > ShannonEntropy(base64.RawURLEncoding.EncodeToString(random)) {
		t.Fatal("premise: the base64url form must not score lower than the raw string")
	}
}

// The immutable floor decodes every encoding configured DLP decodes in a URL
// query value. With the configured list empty, only the floor can block.
func TestCoreFloorDecodesURLEncodingsWithEmptyConfiguredList(t *testing.T) {
	sc := newEncodedCredentialScanner(t, true)
	key := awsExampleAccessKeyID()
	var html, uesc strings.Builder
	for _, c := range key {
		_, _ = fmt.Fprintf(&html, "&#%d;", c)
		_, _ = fmt.Fprintf(&uesc, "\\u%04x", c)
	}
	for name, v := range map[string]string{
		"html entities":   html.String(),
		"json unicode":    uesc.String(),
		"base32 lower":    strings.ToLower(base32NoPad(key)),
		"base32hex lower": strings.ToLower(strings.TrimRight(base32.HexEncoding.EncodeToString([]byte(key)), "=")),
	} {
		t.Run(name, func(t *testing.T) {
			r := sc.Scan(context.Background(), "https://api.vendor.example/x?d="+url.QueryEscape(v))
			if r.Allowed || r.Scanner != ScannerCoreDLP {
				t.Fatalf("allowed=%v scanner=%q reason=%q, want the core floor to block", r.Allowed, r.Scanner, r.Reason)
			}
		})
	}
}

// A key inside a DNS-over-HTTPS message gets the same credential-audience
// decision as the same key in an ordinary query parameter, because the
// message's pieces are ordinary checkDLP targets rather than an early block:
// allowed when the request goes to the key's issuer, blocked anywhere else.
func TestDoHQueryMatchesPlainQueryAudienceDecision(t *testing.T) {
	key := "sk-ant-" + "api03-" + strings.Repeat("AbCdEfGhIj", 9) + "-" + "AAAAAAAA"
	cfg := config.Defaults()
	cfg.Internal = nil
	s := MustNew(cfg)
	defer s.Close()
	doh := "?dns=" + base64.RawURLEncoding.EncodeToString(dnsRecordWire(t, nil, []byte(key)))
	plain := "?k=" + url.QueryEscape(key)
	for _, tc := range []struct {
		host    string
		allowed bool
	}{
		{"api.anthropic.com", true},
		{"resolver.vendor.example", false},
	} {
		p := s.Scan(context.Background(), "https://"+tc.host+"/dns-query"+plain)
		d := s.Scan(context.Background(), "https://"+tc.host+"/dns-query"+doh)
		if p.Allowed != tc.allowed {
			t.Fatalf("premise: plain query to %s allowed=%v, want %v (%s)", tc.host, p.Allowed, tc.allowed, p.Reason)
		}
		if d.Allowed != p.Allowed {
			t.Fatalf("DoH to %s allowed=%v, plain query allowed=%v (%s: %s)", tc.host, d.Allowed, p.Allowed, d.Scanner, d.Reason)
		}
	}
}

func TestDNSMessageSizeCapAndPointerBytes(t *testing.T) {
	// Two OPT records of padding: one byte under the cap parses, one byte over does not.
	build := func(total int) []byte {
		wire := make([]byte, 12)
		wire[11] = 2
		remaining := total - 12 - 2*(1+10+4)
		first := remaining / 2
		for _, n := range []int{first, remaining - first} {
			opt := append([]byte{0x00, 0x0C, byte(n >> 8), byte(n)}, make([]byte, n)...)                  // #nosec G115 -- n < 65536
			wire = append(wire, 0, 0x00, 0x29, 0x10, 0x00, 0, 0, 0, 0, byte(len(opt)>>8), byte(len(opt))) // #nosec G115 -- bounded
			wire = append(wire, opt...)
		}
		return wire
	}
	if _, ok := parseDNSMessage(build(dnsMaxMessageLen)); !ok {
		t.Fatal("a message at the RFC ceiling must parse")
	}
	if _, ok := parseDNSMessage(build(dnsMaxMessageLen + 1)); ok {
		t.Fatal("a message over the RFC ceiling must not parse")
	}

	// A second question that names the first by compression pointer: the
	// pointer bytes are part of what the entropy gate scores.
	wire := make([]byte, 12)
	wire[5] = 2
	wire = append(wire, dnsNameWire([]string{"cache", "example", "test"})...)
	wire = append(wire, 0x00, 0x01, 0x00, 0x01)
	wire = append(wire, 0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01)
	msg, ok := parseDNSMessage(wire)
	if !ok {
		t.Fatal("pointer message must parse")
	}
	if !bytes.Contains(msg.fixed, []byte{0xC0, 0x0C}) {
		t.Fatalf("pointer bytes missing from fixed fields: %x", msg.fixed)
	}
}

// One malformed escape must not discard the decoded view: appending a lone
// surrogate, a truncated escape or a stray \u to a credential written as
// JSON escapes used to drop the whole json_unicode view.
func TestJSONUnicodeDecodeSurvivesMalformedEscapes(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	s := MustNew(cfg)
	defer s.Close()
	var esc strings.Builder
	for _, c := range awsExampleAccessKeyID() {
		_, _ = fmt.Fprintf(&esc, "\\u%04x", c)
	}
	for name, v := range map[string]string{
		"trailing lone surrogate": esc.String() + "\\uDC00",
		"trailing truncated":      esc.String() + "\\u12",
		"trailing stray":          esc.String() + " C:\\users",
		"leading unpaired high":   "\\uD800" + esc.String(),
	} {
		t.Run(name, func(t *testing.T) {
			if r := s.Scan(context.Background(), "https://api.vendor.example/x?d="+url.QueryEscape(v)); r.Allowed {
				t.Fatal("URL allowed a JSON-escaped key beside a malformed escape")
			}
			if s.ScanTextForDLP(context.Background(), "x "+v+" y").Clean {
				t.Fatal("text allowed a JSON-escaped key beside a malformed escape")
			}
		})
	}
}

// A key split across two names, with printable '.' bytes as the type and
// class between them, is seen whole by the joined-label view.
func TestDoHQueryKeySplitAcrossNamesWithPrintableGap(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	s := MustNew(cfg)
	defer s.Close()
	key := awsExampleAccessKeyID()
	half := len(key) / 2
	wire := make([]byte, 12)
	wire[5] = 2
	wire = append(wire, dnsNameWire([]string{key[:half]})...)
	wire = append(wire, '.', '.', '.', '.')
	wire = append(wire, dnsNameWire([]string{key[half:]})...)
	wire = append(wire, '.', '.', '.', '.')
	if _, ok := parseDNSMessage(wire); !ok {
		t.Fatal("premise: fixture must parse")
	}
	r := s.Scan(context.Background(), "https://resolver.vendor.example/dns-query?dns="+base64.RawURLEncoding.EncodeToString(wire))
	if r.Allowed {
		t.Fatal("key split across two names was allowed")
	}
}

// Data split across short labels, each under the length floor, is caught by
// the joined view of the message; the benign RFC 8484 Bench lookup stays
// allowed even at the stricter 4.00 threshold the Bench configuration uses.
func TestDoHQueryJoinedEntropy(t *testing.T) {
	var labels []string
	seed := dnsTestBytes("split-get", 32*4)
	for i := range 4 {
		labels = append(labels, base64.RawURLEncoding.EncodeToString(seed[i*32 : (i+1)*32])[:19])
	}
	split := "?dns=" + base64.RawURLEncoding.EncodeToString(dnsQueryWire(t, append(labels, "example", "test")))
	benign := "?dns=AAABAAABAAAAAAAAIGp5M3ZjbmNzaGJrZGV2cnprNHp2cW5remd6bmRjcWpxAXgFY2FjaGUEdGVzdAAAAQAB"
	for _, threshold := range []float64{4.5, 4.0} {
		cfg := config.Defaults()
		cfg.Internal = nil
		cfg.FetchProxy.Monitoring.EntropyThreshold = threshold
		s := MustNew(cfg)
		r := s.Scan(context.Background(), "https://resolver.vendor.example/dns-query"+split)
		if r.Allowed || !strings.Contains(r.Reason, "DNS message") {
			t.Fatalf("threshold %.1f: split labels allowed=%v %q", threshold, r.Allowed, r.Reason)
		}
		if r := s.Scan(context.Background(), "https://resolver.vendor.example/dns-query"+benign); !r.Allowed {
			t.Fatalf("threshold %.1f: benign lookup blocked: %s", threshold, r.Reason)
		}
		s.Close()
	}
}

// DLP reads the DNS message even when the query carries other parameters,
// which keep the whole-value entropy check but no longer hide the message's
// names from DLP.
func TestDoHQueryDLPWithExtraParameters(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	s := MustNew(cfg)
	defer s.Close()
	key := awsExampleAccessKeyID()
	half := len(key) / 2
	wire := make([]byte, 12)
	wire[5] = 2
	wire = append(wire, dnsNameWire([]string{key[:half]})...)
	wire = append(wire, '.', '.', '.', '.')
	wire = append(wire, dnsNameWire([]string{key[half:]})...)
	wire = append(wire, '.', '.', '.', '.')
	dns := base64.RawURLEncoding.EncodeToString(wire)
	for _, q := range []string{"?dns=" + dns + "&ct=application/dns-message", "?ct=x&d%6es=" + dns} {
		if r := s.Scan(context.Background(), "https://resolver.vendor.example/dns-query"+q); r.Allowed {
			t.Fatalf("%s: key split across names allowed beside other parameters", q)
		}
	}
}

// A value split across two TXT character-strings is read joined. The length
// octet between the halves here is '-' (45), which alone breaks the match.
func TestDoHTXTCharacterStringsJoined(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	s := MustNew(cfg)
	defer s.Close()
	key := awsExampleAccessKeyID()
	first := strings.Repeat("x", 45-8) + key[:8]
	second := key[8:] + strings.Repeat("y", 45-len(key[8:]))
	rdata := append([]byte{byte(len(first))}, first...) // #nosec G115 -- 45
	rdata = append(rdata, byte(len(second)))            // #nosec G115 -- 45
	rdata = append(rdata, second...)
	if strings.Contains(string(rdata), key) {
		t.Fatal("premise: the raw RDATA must not already contain the key")
	}
	wire := dnsTXTRecordWire(t, rdata)
	if r := s.Scan(context.Background(), "https://resolver.vendor.example/dns-query?dns="+base64.RawURLEncoding.EncodeToString(wire)); r.Allowed {
		t.Fatal("key split across TXT character-strings was allowed")
	}
}

func dnsTXTRecordWire(t *testing.T, rdata []byte) []byte {
	t.Helper()
	wire := make([]byte, 12)
	wire[5] = 1
	wire[11] = 1
	wire = append(wire, dnsNameWire([]string{"www", "example", "test"})...)
	wire = append(wire, 0x00, 0x01, 0x00, 0x01)
	wire = append(wire, 0)
	wire = append(wire, 0x00, 0x10, 0x00, 0x01, 0, 0, 0, 0, byte(len(rdata)>>8), byte(len(rdata))) // #nosec G115 -- bounded
	return append(wire, rdata...)
}
