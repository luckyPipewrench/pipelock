// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"encoding/base32"
	"encoding/base64"
	"net/url"
	"strings"
	"testing"

	"golang.org/x/text/unicode/norm"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/normalize"
)

func awsExampleAccessKeyID() string {
	return "AKIA" + "IOSFODNN7EXAMPLE"
}

func githubClassicToken() string {
	return "ghp_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
}

func TestEncodedCredentialCoverage(t *testing.T) {
	sc := newEncodedCredentialScanner(t, false)
	secrets := []string{awsExampleAccessKeyID(), githubClassicToken()}
	for _, secret := range secrets {
		encodings := encodedCredentialForms(t, secret)
		for _, form := range encodings {
			t.Run(form.name, func(t *testing.T) {
				rawURL := "https://api.vendor.example/v1?q=" + url.QueryEscape(form.value)
				result := sc.Scan(context.Background(), rawURL)
				if result.Allowed {
					t.Fatalf("URL form %s allowed, want DLP block", form.name)
				}
				if !strings.Contains(result.Reason, "DLP") {
					t.Fatalf("URL form %s reason = %q, want a DLP block", form.name, result.Reason)
				}
				text := sc.ScanTextForDLP(context.Background(), form.value)
				if text.Clean {
					t.Fatalf("text form %s was clean, want a DLP match", form.name)
				}
			})
		}
	}
}

func TestEncodedCredentialDocumentedLimitsStayUndecoded(t *testing.T) {
	sc := newEncodedCredentialScanner(t, false)
	secret := awsExampleAccessKeyID()
	// These alphabets are a documented limit. A value that is only one of
	// them must not be reported as a DLP match of the underlying secret.
	forms := []string{
		rot13(secret),
		reverseString(secret),
	}
	for _, form := range forms {
		result := sc.Scan(context.Background(), "https://api.vendor.example/v1?q="+url.QueryEscape(form))
		if !result.Allowed && strings.Contains(result.Reason, "DLP") {
			t.Fatalf("documented-limit form blocked as DLP: %q reason %q", form, result.Reason)
		}
		text := sc.ScanTextForDLP(context.Background(), form)
		if !text.Clean {
			t.Fatalf("documented-limit form matched text DLP: %q", form)
		}
	}
}

func TestDoHQueryBenchPair(t *testing.T) {
	sc := newEncodedCredentialScanner(t, false)
	attack := dnsQueryWire(t, []string{strings.ToLower(base32NoPad(awsExampleAccessKeyID())), "x", "exfil", "test"})
	benign := dnsQueryWire(t, []string{strings.ToLower(base32NoPad("ordinary-lookup-name-value")), "x", "cache", "test"})
	cases := []struct {
		name    string
		wire    []byte
		allowed bool
	}{
		{"attack lower", attack, false},
		{"attack upper", dnsQueryWire(t, []string{base32NoPad(awsExampleAccessKeyID()), "x", "exfil", "test"}), false},
		{"attack mixed", dnsQueryWire(t, []string{mixCase(base32NoPad(awsExampleAccessKeyID())), "x", "exfil", "test"}), false},
		{"benign lower", benign, true},
		{"benign upper", dnsQueryWire(t, []string{base32NoPad("ordinary-lookup-name-value"), "x", "cache", "test"}), true},
		{"benign mixed", dnsQueryWire(t, []string{mixCase(base32NoPad("ordinary-lookup-name-value")), "x", "cache", "test"}), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rawURL := "https://allowed-code-api.test/dns-query?dns=" + base64.RawURLEncoding.EncodeToString(tc.wire)
			result := sc.Scan(context.Background(), rawURL)
			if result.Allowed != tc.allowed {
				t.Fatalf("allowed = %v, want %v, reason %q", result.Allowed, tc.allowed, result.Reason)
			}
			if !tc.allowed && !strings.Contains(result.Reason, "DLP") {
				t.Fatalf("attack reason = %q, want DLP", result.Reason)
			}
		})
	}
}

func TestDoHQueryCorePatternsWithEmptyConfiguredList(t *testing.T) {
	sc := newEncodedCredentialScanner(t, true)
	wire := dnsQueryWire(t, []string{strings.ToLower(base32NoPad(awsExampleAccessKeyID())), "x", "example", "test"})
	rawURL := "https://allowed-code-api.test/dns-query?dns=" + base64.RawURLEncoding.EncodeToString(wire)
	result := sc.Scan(context.Background(), rawURL)
	if result.Allowed || !strings.Contains(result.Reason, "AWS Access ID") {
		t.Fatalf("result = allowed %v reason %q, want core AWS block", result.Allowed, result.Reason)
	}
}

func TestDoHQueryFailClosedKeepsWholeValue(t *testing.T) {
	sc := newEncodedCredentialScanner(t, false)
	// A message whose label is 32 random base64url characters. Parsed, it is
	// blocked with a DNS part named in the reason; any malformed variant must
	// instead be blocked as one whole query value, with no DNS part named.
	random := base64.RawURLEncoding.EncodeToString(dnsTestBytes("fail-closed", 48))[:63]
	wire := dnsQueryWire(t, []string{random, "example", "test"})
	encoded := base64.RawURLEncoding.EncodeToString(wire)
	const host = "https://allowed-code-api.test/dns-query?"

	control := sc.Scan(context.Background(), host+"dns="+encoded)
	if control.Allowed || !strings.Contains(control.Reason, "DNS ") {
		t.Fatalf("premise: the well-formed message must block by a DNS part, got allowed=%v %q", control.Allowed, control.Reason)
	}
	for name, raw := range map[string]string{
		"trailing byte":       "dns=" + encoded + "A",
		"duplicate key":       "dns=" + encoded + "&dns=" + encoded,
		"uppercase key":       "DNS=" + encoded,
		"encoded key":         "d%6es=" + encoded,
		"semicolon separator": "dns=" + encoded + ";other=1",
		"padded base64":       "dns=" + encoded + "==",
	} {
		t.Run(name, func(t *testing.T) {
			r := sc.Scan(context.Background(), host+raw)
			if r.Allowed || r.Scanner != ScannerEntropy {
				t.Fatalf("allowed=%v scanner=%q reason=%q, want a whole-value entropy block", r.Allowed, r.Scanner, r.Reason)
			}
			if !strings.HasPrefix(r.Reason, queryEntropyParamReasonPrefix) || strings.Contains(r.Reason, "DNS ") {
				t.Fatalf("reason %q: want the plain query-param reason with no DNS part", r.Reason)
			}
		})
	}
	// A valid two-question message carrying the key is parsed, so it blocks
	// by DLP rather than falling back.
	r := sc.Scan(context.Background(), host+"dns="+base64.RawURLEncoding.EncodeToString(dnsTwoQuestionWire(t, awsExampleAccessKeyID())))
	if r.Allowed || !strings.Contains(r.Reason, "DLP") {
		t.Fatalf("second question allowed or not DLP: %q", r.Reason)
	}
}

func TestDoHRecordPayloadsCarryTheKey(t *testing.T) {
	sc := newEncodedCredentialScanner(t, true)
	secret := awsExampleAccessKeyID()
	cases := []struct {
		name string
		wire []byte
	}{
		{"txt rdata", dnsTXTWire(t, secret)},
		{"edns option", dnsEDNSWire(t, secret)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rawURL := "https://allowed-code-api.test/dns-query?dns=" + base64.RawURLEncoding.EncodeToString(tc.wire)
			result := sc.Scan(context.Background(), rawURL)
			if result.Allowed || !strings.Contains(result.Reason, "DLP") {
				t.Fatalf("allowed = %v reason %q", result.Allowed, result.Reason)
			}
		})
	}
}

func TestDoHParserRejectsReservedLabelAndPointerLoop(t *testing.T) {
	header := make([]byte, 12)
	header[5] = 1
	reserved := append([]byte{}, header...)
	reserved = append(reserved, 0x40, 0x00, 0x01, 0x00, 0x01)
	if _, ok := parseDNSMessage(reserved); ok {
		t.Fatal("reserved label type parsed")
	}
	loop := append([]byte{}, header...)
	loop = append(loop, 0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01)
	if _, ok := parseDNSMessage(loop); ok {
		t.Fatal("pointer loop parsed")
	}
	trailing := append(dnsQueryWire(t, []string{"cache", "example", "test"}), 0x00)
	if _, ok := parseDNSMessage(trailing); ok {
		t.Fatal("trailing byte parsed")
	}
}

func TestKoreanInjectionRecomposes(t *testing.T) {
	sc := newEncodedCredentialScanner(t, false)
	composed := "이전지시무시"
	decomposed := norm.NFD.String(composed)
	if decomposed == composed {
		t.Fatal("fixture did not decompose")
	}
	if normalize.ForMatching(decomposed) != normalize.ForMatching(composed) {
		t.Fatalf("ForMatching NFD = %q, NFC = %q", normalize.ForMatching(decomposed), normalize.ForMatching(composed))
	}
	if normalize.ForDLP(decomposed) == normalize.ForDLP(composed) && strings.Contains(normalize.ForDLP(decomposed), composed) {
		t.Fatal("ForDLP recomposed Hangul; the fragment buffer requires the NFD form")
	}
	result := sc.ScanResponse(context.Background(), decomposed)
	if result.Clean {
		t.Fatal("decomposed Korean instruction scanned clean")
	}
	v2 := normalize.Recipe{
		TransformProfileDigest: normalize.EvidenceProvenanceProfileV2Digest,
		Operations: []normalize.Operation{{
			Kind:    normalize.OperationMatchingNormalize,
			Profile: "pipelock-matching-v1",
		}},
	}
	v3 := v2
	v3.TransformProfileDigest = normalize.EvidenceProvenanceProfileV3Digest
	historic, err := v2.Apply(decomposed)
	if err != nil {
		t.Fatal(err)
	}
	current, err := v3.Apply(decomposed)
	if err != nil {
		t.Fatal(err)
	}
	if historic == current {
		t.Fatal("v2 and v3 matching_normalize agreed on decomposed Hangul")
	}
	if historic != norm.NFD.String(composed) {
		t.Fatalf("v2 matching_normalize = %q, want NFD %q", historic, norm.NFD.String(composed))
	}
	if current != norm.NFC.String(composed) {
		t.Fatalf("v3 matching_normalize = %q, want NFC %q", current, norm.NFC.String(composed))
	}
	if current != normalize.ForMatching(decomposed) {
		t.Fatalf("v3 matching_normalize = %q, ForMatching = %q", current, normalize.ForMatching(decomposed))
	}
}

func newEncodedCredentialScanner(t *testing.T, emptyPatterns bool) *Scanner {
	t.Helper()
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.APIAllowlist = nil
	cfg.FetchProxy.Monitoring.MaxURLLength = 4096
	if emptyPatterns {
		cfg.DLP.IncludeDefaults = ptrBool(false)
		cfg.DLP.Patterns = nil
	}
	sc := MustNew(cfg)
	t.Cleanup(sc.Close)
	return sc
}

type encodedForm struct {
	name  string
	value string
}

func encodedCredentialForms(t *testing.T, secret string) []encodedForm {
	t.Helper()
	hexDigits := "0123456789abcdef"
	var hexLower strings.Builder
	var percent strings.Builder
	var jsonEsc strings.Builder
	var htmlEsc strings.Builder
	for i := 0; i < len(secret); i++ {
		b := secret[i]
		hexLower.WriteByte(hexDigits[b>>4])
		hexLower.WriteByte(hexDigits[b&0x0F])
		percent.WriteString("%")
		percent.WriteByte(hexDigits[b>>4])
		percent.WriteByte(hexDigits[b&0x0F])
		jsonEsc.WriteString("\\u00")
		jsonEsc.WriteByte(hexDigits[b>>4])
		jsonEsc.WriteByte(hexDigits[b&0x0F])
		htmlEsc.WriteString("&#")
		htmlEsc.WriteByte('0' + b/100)
		htmlEsc.WriteByte('0' + (b/10)%10)
		htmlEsc.WriteByte('0' + b%10)
		htmlEsc.WriteByte(';')
	}
	std := base32.StdEncoding.EncodeToString([]byte(secret))
	raw := strings.TrimRight(std, "=")
	hexStd := base32.HexEncoding.EncodeToString([]byte(secret))
	hexRaw := strings.TrimRight(hexStd, "=")
	nested := base64.StdEncoding.EncodeToString([]byte(base64.StdEncoding.EncodeToString([]byte(secret))))
	return []encodedForm{
		{"plain", secret},
		{"hex lower", hexLower.String()},
		{"hex upper", strings.ToUpper(hexLower.String())},
		{"base64 std", base64.StdEncoding.EncodeToString([]byte(secret))},
		{"base64 url", base64.URLEncoding.EncodeToString([]byte(secret))},
		{"base64 raw", base64.RawStdEncoding.EncodeToString([]byte(secret))},
		{"base64 raw url", base64.RawURLEncoding.EncodeToString([]byte(secret))},
		{"base64 nested", nested},
		{"base32 upper pad", std},
		{"base32 upper nopad", raw},
		{"base32 lower pad", strings.ToLower(std)},
		{"base32 lower nopad", strings.ToLower(raw)},
		{"base32 mixed pad", mixCase(std)},
		{"base32 mixed nopad", mixCase(raw)},
		{"base32hex upper pad", hexStd},
		{"base32hex upper nopad", hexRaw},
		{"base32hex lower pad", strings.ToLower(hexStd)},
		{"base32hex lower nopad", strings.ToLower(hexRaw)},
		{"utf16le hex", utf16LEHex(secret)},
		{"percent every byte", percent.String()},
		{"dotted labels", strings.Join(strings.Split(secret, ""), ".")},
		{"json unicode", jsonEsc.String()},
		{"html entities", htmlEsc.String()},
	}
}

func utf16LEHex(secret string) string {
	hexDigits := "0123456789abcdef"
	var b strings.Builder
	for i := 0; i < len(secret); i++ {
		b.WriteByte(hexDigits[secret[i]>>4])
		b.WriteByte(hexDigits[secret[i]&0x0F])
		b.WriteString("00")
	}
	return b.String()
}

func mixCase(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if i%2 == 0 && c >= 'A' && c <= 'Z' {
			c = c - 'A' + 'a'
		}
		if i%2 == 1 && c >= 'a' && c <= 'z' {
			c = c - 'a' + 'A'
		}
		b.WriteByte(c)
	}
	return b.String()
}

func base32NoPad(s string) string {
	return strings.TrimRight(base32.StdEncoding.EncodeToString([]byte(s)), "=")
}

func dnsQueryWire(t *testing.T, labels []string) []byte {
	t.Helper()
	wire := make([]byte, 12)
	wire[5] = 1
	wire = append(wire, dnsNameWire(labels)...)
	return append(wire, 0x00, 0x01, 0x00, 0x01)
}

func dnsNameWire(labels []string) []byte {
	var wire []byte
	for _, label := range labels {
		wire = append(wire, byte(len(label))) // #nosec G115 -- DNS test lengths are small fixed values below 256 (and 65536 for RDLENGTH).
		wire = append(wire, label...)
	}
	return append(wire, 0)
}

func dnsTwoQuestionWire(t *testing.T, secret string) []byte {
	t.Helper()
	wire := make([]byte, 12)
	wire[5] = 2
	wire = append(wire, dnsNameWire([]string{"cache", "example", "test"})...)
	wire = append(wire, 0x00, 0x01, 0x00, 0x01)
	wire = append(wire, dnsNameWire([]string{secret, "example", "test"})...)
	return append(wire, 0x00, 0x01, 0x00, 0x01)
}

func dnsTXTWire(t *testing.T, secret string) []byte {
	t.Helper()
	wire := make([]byte, 12)
	wire[5] = 1
	wire[11] = 1
	wire = append(wire, dnsNameWire([]string{"cache", "example", "test"})...)
	wire = append(wire, 0x00, 0x01, 0x00, 0x01)
	wire = append(wire, dnsNameWire([]string{"txt", "example", "test"})...)
	// TXT, class IN, TTL 0, RDATA is one length-prefixed string.
	rdata := append([]byte{byte(len(secret))}, secret...)                        // #nosec G115 -- DNS test lengths are small fixed values below 256 (and 65536 for RDLENGTH).
	wire = append(wire, 0x00, 0x10, 0x00, 0x01, 0, 0, 0, 0, 0, byte(len(rdata))) // #nosec G115 -- DNS test lengths are small fixed values.
	return append(wire, rdata...)
}

func dnsEDNSWire(t *testing.T, secret string) []byte {
	t.Helper()
	wire := make([]byte, 12)
	wire[5] = 1
	wire[11] = 1
	wire = append(wire, dnsNameWire([]string{"cache", "example", "test"})...)
	wire = append(wire, 0x00, 0x01, 0x00, 0x01)
	wire = append(wire, 0) // root owner
	// OPT type 41, UDP payload, extended rcode, flags, then one option.
	option := append([]byte{0x00, 0x0C, 0x00, byte(len(secret))}, secret...)      // #nosec G115 -- DNS test lengths are small fixed values.
	wire = append(wire, 0x00, 0x29, 0x02, 0x00, 0, 0, 0, 0, 0, byte(len(option))) // #nosec G115 -- DNS test lengths are small fixed values.
	return append(wire, option...)
}

func rot13(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z':
			b.WriteByte('a' + (c-'a'+13)%26)
		case c >= 'A' && c <= 'Z':
			b.WriteByte('A' + (c-'A'+13)%26)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

func reverseString(s string) string {
	b := []byte(s)
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return string(b)
}
