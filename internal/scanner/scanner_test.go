// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"bytes"
	"context"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

const (
	testAlphabet   = "abcdefghijklmnopqrstuvwxyz"
	testLowEntropy = "aaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testUpperPad   = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	testSecretVal  = "SuperSecretValue123456"
)

// testSeedPhrase12 is a known-valid BIP-39 12-word mnemonic (checksum passes).
const testSeedPhrase12 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

func ptrBool(v bool) *bool { return &v }

func testConfig() *config.Config {
	cfg := config.Defaults()
	// Use a higher entropy threshold for test predictability
	cfg.FetchProxy.Monitoring.EntropyThreshold = 4.5
	cfg.FetchProxy.Monitoring.MaxURLLength = 200
	// Disable SSRF by default so tests don't depend on DNS resolution.
	// SSRF-specific tests override this.
	cfg.Internal = nil
	// Disable allowlist by default so tests don't depend on the default
	// domain list. Allowlist-specific tests override this.
	cfg.APIAllowlist = nil
	return cfg
}

func TestScan_AllowsNormalURLs(t *testing.T) {
	s := New(testConfig())

	tests := []string{
		"https://example.com",
		"https://example.com/page",
		"https://example.com/search?q=golang",
		"https://stackoverflow.com/questions/12345/how-to-do-thing",
		"http://docs.python.org/3/library/os.html",
	}

	for _, url := range tests {
		result := s.Scan(context.Background(), url)
		if !result.Allowed {
			t.Errorf("expected %s to be allowed, got blocked: %s", url, result.Reason)
		}
	}
}

func TestScan_BlocksBlocklistedDomains(t *testing.T) {
	s := New(testConfig())

	tests := []struct {
		url    string
		reason string
	}{
		{"https://pastebin.com/raw/abc123", "pastebin.com"},
		{"https://x.pastebin.com/raw/abc123", "sub.pastebin.com"},
		{"https://hastebin.com/something", "hastebin.com"},
		{"https://paste.ee/p/abc", "paste.ee"},
		{"https://transfer.sh/abc/file.txt", "transfer.sh"},
		{"https://file.io/abc123", "file.io"},
	}

	for _, tt := range tests {
		result := s.Scan(context.Background(), tt.url)
		if result.Allowed {
			t.Errorf("expected %s to be blocked (%s)", tt.url, tt.reason)
		}
		if result.Scanner != "blocklist" {
			t.Errorf("expected scanner=blocklist for %s, got %s", tt.url, result.Scanner)
		}
	}
}

func TestScan_BlocksDLPPatterns(t *testing.T) {
	s := New(testConfig())

	tests := []struct {
		url     string
		pattern string
	}{
		{"https://example.com/api?key=sk-ant-abcdefghijklmnopqrstu", "Anthropic API Key"},
		{"https://example.com/path?token=" + "AKIA" + "IOSFODNN7EXAMPLE", "AWS Access ID"},
		{"https://example.com/path?" + "token=" + "ASIA" + "IOSFODNN7EXAMPLE", "AWS Access ID"},
		{"https://example.com/path/ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl", "GitHub Token"},
		{"https://example.com/path/gho_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl", "GitHub Token"},
		{"https://example.com/api?k=fw_" + "aBcDeFgHiJkLmNoPqRsTuVwX", "Fireworks API Key"},
		{"https://example.com/api?k=GOCSPX-" + "aBcDeFgHiJkLmNoPqRsTuVwXyZaB", "Google OAuth Client Secret"},
		{"https://example.com/api?k=AIza" + "SyA1234567890abcdefghijklmnopqrstuv", "Google API Key"},
		{"https://example.com/api?k=xapp-" + "1-A0B1C2D3E4-5678901234-abcdef0123456789", "Slack App Token"},
		{"https://example.com/api?jwt=" + "eyJhbGciOiJIUzI1NiIs" + "InR5cCI6IkpXVCJ9.eyJz" + "dWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U", "JWT Token"},
		// Crypto private keys — valid Base58Check WIF test vectors (Bitcoin wiki).
		// Uncompressed (5-prefix, 51 chars) and compressed (K-prefix, 52 chars).
		{"https://example.com/api?key=" + "5HueCGU8rMjx" + "EXxiPuD5BDku4MkFqe" + "Zyd4dZ1jvhTVqvbTLvyTJ", "Bitcoin WIF Private Key"},
		{"https://example.com/api?key=" + "KwdMAjGmer" + "Yanjeui5SHS7Jkmp" + "ZvVipYvB2LJGU1ZxJwYvP98617", "Bitcoin WIF Private Key"},
		{"https://example.com/api?key=xprv" + strings.Repeat("A", 107), "Extended Private Key"},
		{"https://example.com/api?key=yprv" + strings.Repeat("B", 107), "Extended Private Key"},
		{"https://example.com/api?key=zprv" + strings.Repeat("C", 107), "Extended Private Key"},
		{"https://example.com/api?key=tprv" + strings.Repeat("D", 107), "Extended Private Key"},
		{"https://example.com/api?key=0x" + strings.Repeat("ab", 32), "Ethereum Private Key"},
	}

	for _, tt := range tests {
		result := s.Scan(context.Background(), tt.url)
		if result.Allowed {
			t.Errorf("expected %s to be blocked (DLP: %s)", tt.url, tt.pattern)
		}
		if result.Scanner != ScannerDLP {
			t.Errorf("expected scanner=dlp for %s, got %s", tt.url, result.Scanner)
		}
	}
}

// TestScan_DLPFalsePositiveRegression guards against DLP patterns matching
// benign URL content. Each entry should remain allowed (not blocked by DLP).
func TestScan_DLPFalsePositiveRegression(t *testing.T) {
	cfg := testConfig()
	cfg.FetchProxy.Monitoring.EntropyThreshold = 0 // disable entropy so only DLP is tested
	cfg.FetchProxy.Monitoring.MaxURLLength = 4096
	s := New(cfg)

	tests := []struct {
		name string
		url  string
	}{
		// AWS-like prefixes in benign contexts
		{"ASIA in region slug", "https://example.com/regions/asia-pacific-southeast"},
		{"AIDA in product name", "https://example.com/products/aida-assistant"},
		{"ASIA contiguous uppercase (non-secret)", "https://example.com/reports/ASIA2025REPORT1234"},
		// JWT-like dotted identifiers
		{"version triple", "https://example.com/api/v2.1.0/resource"},
		{"dotted package name", "https://registry.npmjs.org/@scope/pkg/1.2.3"},
		// Google OAuth ID-like numeric prefix
		{"short numeric param", "https://example.com/api?id=12345-abcdef"},
		// Fireworks prefix in config key
		{"fw_ config param", "https://example.com/api?fw_version=2"},
		// GOCSPX too short
		{"GOCSPX short value", "https://example.com/api?code=GOCSPX-short"},
		// Slack xapp too short / wrong format
		{"xapp bare prefix", "https://example.com/api?v=xapp-incomplete"},
		// Google API key suffix too short
		{"AIza with 34 chars", "https://example.com/api?k=AIza" + "SyA1234567890abcdefghijklmnopqrstu"},
		// Crypto pattern false positives
		{"SHA-256 hash without 0x", "https://example.com/verify?hash=" + strings.Repeat("ab", 32)},
		{"short base58 not WIF", "https://example.com/api?id=5" + strings.Repeat("H", 30)},
		// Correct-length base58 string with invalid checksum — WIF validator rejects.
		{"invalid checksum WIF-length base58", "https://example.com/api?key=5" + strings.Repeat("H", 50)},
		{"xpub not xprv", "https://example.com/api?key=xpub" + strings.Repeat("A", 107)},
		// Seed phrase FP: normal hostname labels and path segments must not trigger.
		{"normal hostname with dots", "https://api.example.com/data?q=hello"},
		{"deep path segments", "https://example.com/api/v2/users/search/results/page/1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := s.Scan(context.Background(), tt.url)
			if !result.Allowed {
				t.Errorf("expected %s to be allowed (FP regression), got blocked: scanner=%s reason=%s",
					tt.url, result.Scanner, result.Reason)
			}
		})
	}
}

func TestScan_BlocksHighEntropySegments(t *testing.T) {
	s := New(testConfig())

	// Random base64-like string (high entropy, >20 chars)
	highEntropy := "https://example.com/data/aB3xK9mQ7pR2wE5tY8uI0oL4hG6fD1sZ"
	result := s.Scan(context.Background(), highEntropy)
	if result.Allowed {
		t.Error("expected high-entropy URL to be blocked")
	}
	if result.Scanner != ScannerEntropy {
		t.Errorf("expected scanner=entropy, got %s", result.Scanner)
	}
}

func TestScan_AllowsLowEntropySegments(t *testing.T) {
	s := New(testConfig())

	// Normal text path (low entropy)
	normalURL := "https://example.com/articles/how-to-write-golang-tests"
	result := s.Scan(context.Background(), normalURL)
	if !result.Allowed {
		t.Errorf("expected normal URL to be allowed, got blocked: %s", result.Reason)
	}
}

func TestScan_BlocksLongURLs(t *testing.T) {
	cfg := testConfig()
	cfg.FetchProxy.Monitoring.MaxURLLength = 100
	cfg.FetchProxy.Monitoring.EntropyThreshold = 0 // disable entropy so length check is hit
	s := New(cfg)

	// Build a long URL with valid, low-entropy characters
	padding := ""
	for i := 0; i < 200; i++ {
		padding += "a"
	}
	longURL := "https://example.com/" + padding
	result := s.Scan(context.Background(), longURL)
	if result.Allowed {
		t.Error("expected long URL to be blocked")
	}
	if result.Scanner != "length" {
		t.Errorf("expected scanner=length, got %s", result.Scanner)
	}
}

func TestScan_BlocksNonHTTPSchemes(t *testing.T) {
	s := New(testConfig())

	tests := []string{
		"ftp://example.com/file",
		"file:///etc/passwd",
		"gopher://evil.com",
		"javascript:alert(1)",
	}

	for _, url := range tests {
		result := s.Scan(context.Background(), url)
		if result.Allowed {
			t.Errorf("expected %s to be blocked (non-http scheme)", url)
		}
		if result.Scanner != "scheme" {
			t.Errorf("expected scanner=scheme for %s, got %s", url, result.Scanner)
		}
	}
}

func TestScan_InvalidURL(t *testing.T) {
	s := New(testConfig())

	result := s.Scan(context.Background(), "://not-a-url")
	if result.Allowed {
		t.Error("expected invalid URL to be blocked")
	}
}

func TestScan_BlocksSSRF_Loopback(t *testing.T) {
	cfg := testConfig()
	cfg.Internal = []string{"127.0.0.0/8", "10.0.0.0/8", "::1/128"}
	s := New(cfg)

	tests := []string{
		"http://127.0.0.1/admin",
		"http://localhost/admin",
	}

	for _, url := range tests {
		result := s.Scan(context.Background(), url)
		if result.Allowed {
			t.Errorf("expected %s to be blocked (SSRF)", url)
		}
		if result.Scanner != ScannerSSRF {
			t.Errorf("expected scanner=ssrf for %s, got %s", url, result.Scanner)
		}
	}
}

func TestScan_BlocksSSRF_IPv6ZoneID(t *testing.T) {
	cfg := testConfig()
	cfg.Internal = []string{"::1/128", "fe80::/10", "fc00::/7"}
	s := New(cfg)

	tests := []struct {
		name string
		url  string
	}{
		{"loopback with zone ID", "http://[::1%25eth0]/"},
		{"link-local with zone ID", "http://[fe80::1%25eth0]/"},
		{"ULA with zone ID", "http://[fc00::1%25eth0]/"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := s.Scan(context.Background(), tt.url)
			if result.Allowed {
				t.Errorf("expected %s to be blocked (SSRF zone ID bypass)", tt.url)
			}
			if result.Scanner != ScannerSSRF {
				t.Errorf("expected scanner=ssrf for %s, got %s", tt.url, result.Scanner)
			}
		})
	}
}

func TestScan_BlocksSSRF_Multicast(t *testing.T) {
	cfg := testConfig()
	cfg.Internal = []string{"224.0.0.0/4", "ff00::/8"}
	s := New(cfg)

	tests := []struct {
		name string
		url  string
	}{
		{"IPv4 multicast", "http://224.0.0.1/"},
		{"IPv6 multicast", "http://[ff02::1]/"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := s.Scan(context.Background(), tt.url)
			if result.Allowed {
				t.Errorf("expected %s to be blocked (multicast SSRF)", tt.url)
			}
			if result.Scanner != ScannerSSRF {
				t.Errorf("expected scanner=ssrf for %s, got %s", tt.url, result.Scanner)
			}
		})
	}
}

func TestParseAlternativeIP(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect string // empty = nil
	}{
		// Hex full address
		{"hex loopback", "0x7f000001", "127.0.0.1"},
		{"hex loopback upper", "0X7F000001", "127.0.0.1"},
		{"hex private 10.0.0.1", "0x0a000001", "10.0.0.1"},
		{"hex 192.168.0.1", "0xc0a80001", "192.168.0.1"},
		{"hex 169.254.169.254", "0xa9fea9fe", "169.254.169.254"},

		// Octal dotted
		{"octal loopback", "0177.0.0.1", "127.0.0.1"},
		{"octal 10.0.0.1", "012.0.0.1", "10.0.0.1"},
		{"octal 192.168.1.1", "0300.0250.01.01", "192.168.1.1"},

		// Hex dotted
		{"hex dotted loopback", "0x7f.0.0.1", "127.0.0.1"},
		{"hex dotted 10.10.0.1", "0x0a.0x0a.0.1", "10.10.0.1"},

		// Decimal integer
		{"decimal loopback", "2130706433", "127.0.0.1"},
		{"decimal 10.0.0.1", "167772161", "10.0.0.1"},

		// Octal full integer
		{"octal full loopback", "017700000001", "127.0.0.1"},

		// Non-IP inputs → nil
		{"standard decimal dotted", "127.0.0.1", ""},
		{"hostname", "example.com", ""},
		{"empty", "", ""},
		{"too many octets", "0x7f.0.0.0.1", ""},
		{"too few octets", "0x7f.0.1", ""},
		{"octet overflow", "0x7f.0.0.256", ""},
		{"negative", "-1", ""},
		{"overflow 32bit", "4294967296", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := parseAlternativeIP(tt.input)
			if tt.expect == "" {
				if ip != nil {
					t.Errorf("expected nil for %q, got %s", tt.input, ip)
				}
				return
			}
			if ip == nil {
				t.Fatalf("expected %s for %q, got nil", tt.expect, tt.input)
			}
			if ip.String() != tt.expect {
				t.Errorf("expected %s for %q, got %s", tt.expect, tt.input, ip)
			}
		})
	}
}

func TestScan_BlocksSSRF_HexOctalIP(t *testing.T) {
	cfg := testConfig()
	cfg.Internal = []string{"127.0.0.0/8", "10.0.0.0/8", "169.254.0.0/16", "192.168.0.0/16"}
	s := New(cfg)

	tests := []struct {
		name string
		url  string
	}{
		{"hex full loopback", "http://0x7f000001/admin"},
		{"hex upper loopback", "http://0X7F000001/admin"},
		{"octal loopback", "http://0177.0.0.1/admin"},
		{"decimal integer loopback", "http://2130706433/admin"},
		{"hex dotted loopback", "http://0x7f.0.0.1/admin"},
		{"hex metadata endpoint", "http://0xa9fea9fe/latest/meta-data/"},
		{"octal 10.x private", "http://012.0.0.1/"},
		{"hex 192.168", "http://0xc0a80001/"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := s.Scan(context.Background(), tt.url)
			if result.Allowed {
				t.Errorf("expected %s to be blocked (SSRF hex/octal bypass)", tt.url)
			}
			if result.Scanner != ScannerSSRF {
				t.Errorf("expected scanner=ssrf for %s, got %s", tt.url, result.Scanner)
			}
		})
	}
}

func TestScan_AllowsHexOctalIP_WhenExternal(t *testing.T) {
	cfg := testConfig()
	cfg.Internal = []string{"127.0.0.0/8", "10.0.0.0/8"}
	s := New(cfg)

	// 8.8.8.8 in hex = 0x08080808 — should be allowed (not internal).
	result := s.Scan(context.Background(), "http://0x08080808/")
	if !result.Allowed {
		t.Errorf("expected external hex IP to be allowed, got blocked: %s", result.Reason)
	}
}

func TestScan_EntropySkipsShortSegments(t *testing.T) {
	s := New(testConfig())

	// Short high-entropy segment (<20 chars) should be allowed
	shortEntropy := "https://example.com/aB3xK9mQ7"
	result := s.Scan(context.Background(), shortEntropy)
	if !result.Allowed {
		t.Errorf("expected short segment to be allowed, got blocked: %s", result.Reason)
	}
}

func TestScan_DLPChecksQueryValues(t *testing.T) {
	s := New(testConfig())

	// AWS key in query parameter value
	url := "https://api.example.com/data?access_key=AKIAIOSFODNN7EXAMPLE" //nolint:gosec // G101: test fake key
	result := s.Scan(context.Background(), url)
	if result.Allowed {
		t.Error("expected DLP to catch AWS key in query value")
	}
}

func TestScan_DisabledEntropy(t *testing.T) {
	cfg := testConfig()
	cfg.FetchProxy.Monitoring.EntropyThreshold = 0 // disabled
	s := New(cfg)

	highEntropy := "https://example.com/data/aB3xK9mQ7pR2wE5tY8uI0oL4hG6fD1sZ"
	result := s.Scan(context.Background(), highEntropy)
	if !result.Allowed {
		t.Error("expected entropy check to be disabled")
	}
}

func TestScan_DisabledURLLength(t *testing.T) {
	cfg := testConfig()
	cfg.FetchProxy.Monitoring.MaxURLLength = 0     // disabled
	cfg.FetchProxy.Monitoring.EntropyThreshold = 0 // also disable entropy
	s := New(cfg)

	padding := ""
	for i := 0; i < 5000; i++ {
		padding += "a"
	}
	longURL := "https://example.com/" + padding
	result := s.Scan(context.Background(), longURL)
	if !result.Allowed {
		t.Errorf("expected URL length check to be disabled, got blocked by %s: %s", result.Scanner, result.Reason)
	}
}

// --- Shannon Entropy Tests ---

func TestShannonEntropy_EmptyString(t *testing.T) {
	if e := ShannonEntropy(""); e != 0 {
		t.Errorf("expected 0 entropy for empty string, got %f", e)
	}
}

func TestShannonEntropy_SingleChar(t *testing.T) {
	if e := ShannonEntropy("aaaa"); e != 0 {
		t.Errorf("expected 0 entropy for repeated char, got %f", e)
	}
}

func TestShannonEntropy_TwoChars(t *testing.T) {
	// "ab" repeated should have entropy of 1.0 bit
	e := ShannonEntropy("abababab")
	if e < 0.99 || e > 1.01 {
		t.Errorf("expected ~1.0 entropy for 'abababab', got %f", e)
	}
}

func TestShannonEntropy_HighEntropy(t *testing.T) {
	// Random-looking string should have high entropy
	e := ShannonEntropy("aB3xK9mQ7pR2wE5tY8uI0oL4hG6fD1sZ")
	if e < 4.0 {
		t.Errorf("expected high entropy for random-looking string, got %f", e)
	}
}

func TestShannonEntropy_EnglishText(t *testing.T) {
	// English text should have moderate entropy (~3.5-4.5)
	e := ShannonEntropy("this-is-a-normal-url-path-segment")
	if e > 4.0 {
		t.Errorf("expected moderate entropy for English text, got %f", e)
	}
}

// --- Domain Matching Tests ---

func TestMatchDomain_ExactMatch(t *testing.T) {
	if !MatchDomain("example.com", "example.com") {
		t.Error("expected exact match")
	}
}

func TestMatchDomain_CaseInsensitive(t *testing.T) {
	if !MatchDomain("Example.COM", "example.com") {
		t.Error("expected case-insensitive match")
	}
}

func TestMatchDomain_WildcardSubdomain(t *testing.T) {
	if !MatchDomain("sub.example.com", "*.example.com") {
		t.Error("expected wildcard to match subdomain")
	}
}

func TestMatchDomain_WildcardMatchesBase(t *testing.T) {
	// *.example.com should also match example.com itself
	if !MatchDomain("example.com", "*.example.com") {
		t.Error("expected wildcard to match base domain")
	}
}

func TestMatchDomain_WildcardMultiLevel(t *testing.T) {
	if !MatchDomain("a.b.example.com", "*.example.com") {
		t.Error("expected wildcard to match multi-level subdomain")
	}
}

func TestMatchDomain_NoMatch(t *testing.T) {
	if MatchDomain("other.com", "example.com") {
		t.Error("expected no match for different domain")
	}
}

func TestMatchDomain_WildcardNoMatch(t *testing.T) {
	if MatchDomain("other.com", "*.example.com") {
		t.Error("expected no match for different domain with wildcard")
	}
}

func TestMatchDomain_PartialNoMatch(t *testing.T) {
	// "notexample.com" should NOT match "*.example.com"
	if MatchDomain("notexample.com", "*.example.com") {
		t.Error("expected no match for partial domain suffix")
	}
}

func TestMatchDomain_TrailingDots(t *testing.T) {
	// DNS FQDNs can have trailing dots — these should still match
	tests := []struct {
		hostname, pattern string
		expected          bool
	}{
		{"example.com.", "example.com", true},
		{"example.com", "example.com.", true},
		{"example.com.", "example.com.", true},
		{"sub.example.com.", "*.example.com", true},
		{"sub.example.com", "*.example.com.", true},
	}
	for _, tt := range tests {
		got := MatchDomain(tt.hostname, tt.pattern)
		if got != tt.expected {
			t.Errorf("MatchDomain(%q, %q) = %v, want %v", tt.hostname, tt.pattern, got, tt.expected)
		}
	}
}

func TestMatchDomain_EmptyHostname(t *testing.T) {
	if MatchDomain("", "example.com") {
		t.Error("empty hostname should not match")
	}
	if MatchDomain("", "*.example.com") {
		t.Error("empty hostname should not match wildcard")
	}
}

func TestShannonEntropy_Unicode(t *testing.T) {
	// Unicode strings with many distinct codepoints should have high entropy
	e := ShannonEntropy("こんにちは世界テスト日本語文字列")
	if e < 3.0 {
		t.Errorf("expected high entropy for Unicode string, got %f", e)
	}
}

func TestScan_EntropyScoreClamped(t *testing.T) {
	cfg := testConfig()
	// Set a very low threshold so the entropy check fires easily
	cfg.FetchProxy.Monitoring.EntropyThreshold = 1.0
	s := New(cfg)

	// This string has high entropy — score should never exceed 1.0
	result := s.Scan(context.Background(), "https://example.com/data/aB3xK9mQ7pR2wE5tY8uI0oL4hG6fD1sZ")
	if result.Allowed {
		t.Fatal("expected to be blocked by entropy")
	}
	if result.Score > 1.0 {
		t.Errorf("entropy score %f exceeds 1.0", result.Score)
	}
}

func TestScan_EntropyScoreClampedQueryParam(t *testing.T) {
	cfg := testConfig()
	cfg.FetchProxy.Monitoring.EntropyThreshold = 1.0
	s := New(cfg)

	result := s.Scan(context.Background(), "https://example.com/page?data=aB3xK9mQ7pR2wE5tY8uI0oL4hG6fD1sZ")
	if result.Allowed {
		t.Fatal("expected to be blocked by entropy")
	}
	if result.Score > 1.0 {
		t.Errorf("entropy score %f exceeds 1.0 for query param", result.Score)
	}
}

func TestScan_SSRFDisabledWhenNilCIDRs(t *testing.T) {
	cfg := testConfig()
	cfg.Internal = nil
	s := New(cfg)

	// localhost should be allowed when SSRF is disabled
	result := s.Scan(context.Background(), "http://127.0.0.1/test")
	if !result.Allowed {
		t.Errorf("expected 127.0.0.1 allowed with nil CIDRs, got blocked: %s", result.Reason)
	}
}

func TestScan_TrustedDomains_BypassesSSRF(t *testing.T) {
	cfg := testConfig()
	cfg.Internal = []string{"127.0.0.0/8", "10.0.0.0/8", "::1/128"}
	cfg.TrustedDomains = []string{"localhost", "*.internal.corp"}
	s := New(cfg)

	// localhost resolves to 127.0.0.1 (internal) but is trusted — should pass SSRF.
	result := s.Scan(context.Background(), "http://localhost/api/v1/inference")
	if !result.Allowed {
		t.Fatalf("expected trusted domain localhost to bypass SSRF, got blocked: %s", result.Reason)
	}
}

func TestScan_TrustedDomains_NonTrustedStillBlocked(t *testing.T) {
	cfg := testConfig()
	cfg.Internal = []string{"127.0.0.0/8", "10.0.0.0/8"}
	cfg.TrustedDomains = []string{"trusted.example.com"}
	s := New(cfg)

	// localhost is NOT in trusted_domains — should still be blocked.
	result := s.Scan(context.Background(), "http://localhost/admin")
	if result.Allowed {
		t.Errorf("expected non-trusted localhost to be blocked by SSRF")
	}
	if result.Scanner != ScannerSSRF {
		t.Errorf("expected scanner=ssrf, got %s", result.Scanner)
	}
}

func TestScan_TrustedDomains_WildcardMatch(t *testing.T) {
	// Verify wildcard matching semantics used by trusted_domains.
	// Direct MatchDomain test avoids DNS dependency on fake hostnames.
	if !MatchDomain("inference.local", "*.local") {
		t.Error("expected *.local to match inference.local")
	}
	if MatchDomain("inference.example.com", "*.local") {
		t.Error("expected *.local NOT to match inference.example.com")
	}
}

func TestScan_TrustedDomains_DLPStillApplies(t *testing.T) {
	cfg := testConfig()
	cfg.Internal = []string{"127.0.0.0/8"}
	cfg.TrustedDomains = []string{"localhost"}
	s := New(cfg)

	// Trusted domain bypasses SSRF but DLP still scans the URL.
	// Build fake key at runtime to avoid gosec G101.
	fakeKey := "AKIA" + "IOSFODNN7EXAMPLE"
	result := s.Scan(context.Background(), "http://localhost/api?key="+fakeKey)
	if result.Allowed {
		t.Error("expected DLP to block secret even on trusted domain")
	}
	if result.Scanner == ScannerSSRF {
		t.Error("expected DLP scanner, not SSRF — trusted domain should bypass SSRF")
	}
}

func TestNew_PanicsOnInvalidDLPRegex(t *testing.T) {
	cfg := testConfig()
	cfg.DLP.Patterns = []config.DLPPattern{
		{Name: "bad", Regex: "[invalid", Severity: "high"},
	}

	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for invalid DLP regex")
		}
	}()
	New(cfg)
}

func TestScanner_IsTrustedDomain(t *testing.T) {
	cfg := testConfig()
	cfg.Internal = []string{"127.0.0.0/8", "10.0.0.0/8"}
	cfg.TrustedDomains = []string{"localhost", "*.internal.corp", "api.example.com"}
	s := New(cfg)
	defer s.Close()

	tests := []struct {
		name     string
		hostname string
		expected bool
	}{
		{"exact match localhost", "localhost", true},
		{"exact match api.example.com", "api.example.com", true},
		{"wildcard match sub.internal.corp", "sub.internal.corp", true},
		{"wildcard match deeply.sub.internal.corp", "deeply.sub.internal.corp", true},
		{"wildcard match internal.corp itself", "internal.corp", true},
		{"no match example.com", "example.com", false},
		{"no match notinternal.corp", "notinternal.corp", false},
		{"IP not trusted", "192.168.1.1", false},
		{"uppercase normalized", "LOCALHOST", true},
		{"trailing dot stripped", "localhost.", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := s.IsTrustedDomain(tt.hostname)
			if result != tt.expected {
				t.Errorf("IsTrustedDomain(%q) = %v, want %v", tt.hostname, result, tt.expected)
			}
		})
	}
}

func TestNew_PanicsOnInvalidCIDR(t *testing.T) {
	cfg := testConfig()
	cfg.Internal = []string{"not-a-cidr"}

	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for invalid CIDR")
		}
	}()
	New(cfg)
}

// --- Fix 1: URL-encoded DLP bypass ---

func TestScan_DLPCatchesURLEncodedSecrets(t *testing.T) {
	s := New(testConfig())

	// Private key header with URL-encoded spaces (%20 instead of ' ')
	result := s.Scan(context.Background(), "https://example.com/api?data=-----BEGIN%20PRIVATE%20KEY-----")
	if result.Allowed {
		t.Error("expected DLP to catch URL-encoded private key header")
	}
	if result.Scanner != ScannerDLP {
		t.Errorf("expected scanner=dlp, got %s", result.Scanner)
	}
}

func TestScan_DLPCatchesURLEncodedDashes(t *testing.T) {
	s := New(testConfig())

	// Anthropic key with URL-encoded dashes (%2D instead of '-')
	result := s.Scan(context.Background(), "https://example.com/api?key=sk%2Dant%2DabcdefghijklmnopqrstuVW")
	if result.Allowed {
		t.Error("expected DLP to catch URL-encoded Anthropic key")
	}
	if result.Scanner != ScannerDLP {
		t.Errorf("expected scanner=dlp, got %s", result.Scanner)
	}
}

func TestScan_DLPChecksDecodedQueryKeys(t *testing.T) {
	s := New(testConfig())

	// AWS key stuffed into a query parameter NAME
	result := s.Scan(context.Background(), "https://example.com/api?AKIAIOSFODNN7EXAMPLE=true")
	if result.Allowed {
		t.Error("expected DLP to catch secret in query key")
	}
}

func TestScan_DLPCatchesDoubleEncodedSecret(t *testing.T) {
	s := New(testConfig())

	// Double-encoded dashes: %252D → first decode → %2D → second decode → -
	result := s.Scan(context.Background(), "https://example.com/api?key=sk%252Dant%252DabcdefghijklmnopqrstuVW")
	if result.Allowed {
		t.Error("expected DLP to catch double-encoded Anthropic key")
	}
	if result.Scanner != ScannerDLP {
		t.Errorf("expected scanner=dlp, got %s", result.Scanner)
	}
}

func TestScan_DLPCatchesTripleEncodedSecret(t *testing.T) {
	s := New(testConfig())

	// Triple-encoded: %25252D → %252D → %2D → -
	result := s.Scan(context.Background(), "https://example.com/api?key=sk%25252Dant%25252DabcdefghijklmnopqrstuVW")
	if result.Allowed {
		t.Error("expected DLP to catch triple-encoded Anthropic key")
	}
}

func TestIterativeDecode(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"no_encoding", "hello", "hello"},
		{"single", "sk%2Dant", "sk-ant"},
		{"double", "sk%252Dant", "sk-ant"},
		{"triple", "sk%25252Dant", "sk-ant"},
		{"malformed", "sk%ZZant", "sk%ZZant"},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IterativeDecode(tt.input)
			if got != tt.want {
				t.Errorf("IterativeDecode(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestNormalizeHex(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"colon-separated", "73:6b:2d:61:6e:74", "736b2d616e74"},
		{"space-separated", "73 6b 2d 61 6e 74", "736b2d616e74"},
		{"hyphen-separated", "73-6b-2d-61-6e-74", "736b2d616e74"},
		{"backslash-x notation", `\x73\x6b\x2d\x61\x6e\x74`, "736b2d616e74"},
		{"0x prefix only", "0x736b2d616e74", "736b2d616e74"},
		{"comma-separated", "73,6b,2d,61,6e,74", "736b2d616e74"},
		{"mixed delimiters", "73:6b 2d-61,6e:74", "736b2d616e74"},
		{"already contiguous hex", "736b2d616e74", "736b2d616e74"},
		{"odd length result", "73:6b:2", ""},
		{"too short", "ab", ""},
		{"empty", "", ""},
		{"non-hex chars after strip", "zz:yy:xx", ""},
		{"uppercase hex", "73:6B:2D:61:6E:74", "736B2D616E74"},
		{"0x per-byte", "0x730x6b0x2d0x610x6e0x74", "736b2d616e74"},
		{"0x per-byte with commas", "0x73,0x6b,0x2d,0x61,0x6e,0x74", "736b2d616e74"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeHex(tt.input)
			if got != tt.want {
				t.Errorf("normalizeHex(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestHexByteSep(t *testing.T) {
	tests := []struct {
		name   string
		hexStr string
		sep    string
		want   string
	}{
		{"colon", "736b2d", ":", "73:6b:2d"},
		{"space", "736b2d", " ", "73 6b 2d"},
		{"single byte", "73", ":", "73"},
		{"empty", "", ":", ""},
		{"two bytes", "736b", "-", "73-6b"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hexByteSep(tt.hexStr, tt.sep)
			if got != tt.want {
				t.Errorf("hexByteSep(%q, %q) = %q, want %q", tt.hexStr, tt.sep, got, tt.want)
			}
		})
	}
}

func TestHexBytePrefix(t *testing.T) {
	tests := []struct {
		name   string
		hexStr string
		prefix string
		want   string
	}{
		{"backslash-x", "736b2d", `\x`, `\x73\x6b\x2d`},
		{"0x", "736b2d", "0x", "0x730x6b0x2d"},
		{"single byte", "73", `\x`, `\x73`},
		{"empty", "", `\x`, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hexBytePrefix(tt.hexStr, tt.prefix)
			if got != tt.want {
				t.Errorf("hexBytePrefix(%q, %q) = %q, want %q", tt.hexStr, tt.prefix, got, tt.want)
			}
		})
	}
}

// --- Fix 2: IP address wildcard matching ---

func TestMatchDomain_WildcardIgnoredForIPv4(t *testing.T) {
	// "192" is NOT a subdomain of "168.1.1" — IPs get exact match only
	if MatchDomain("192.168.1.1", "*.168.1.1") {
		t.Error("expected wildcard not to match against IPv4 address")
	}
}

func TestMatchDomain_WildcardIgnoredForIPv6(t *testing.T) {
	if MatchDomain("::1", "*.1") {
		t.Error("expected wildcard not to match against IPv6 address")
	}
}

func TestMatchDomain_ExactIPv4Match(t *testing.T) {
	if !MatchDomain("192.168.1.1", "192.168.1.1") {
		t.Error("expected exact IPv4 match")
	}
}

func TestMatchDomain_ExactIPv6Match(t *testing.T) {
	if !MatchDomain("::1", "::1") {
		t.Error("expected exact IPv6 match")
	}
}

func TestMatchDomain_DifferentIPsNoMatch(t *testing.T) {
	if MatchDomain("10.0.0.1", "192.168.1.1") {
		t.Error("expected different IPs not to match")
	}
}

// --- Fix 3: Entropy on query keys ---

func TestScan_HighEntropyQueryKey(t *testing.T) {
	cfg := testConfig()
	cfg.FetchProxy.Monitoring.EntropyThreshold = 4.0
	cfg.DLP.Patterns = nil
	s := New(cfg)

	// Secret data stuffed into query parameter name
	result := s.Scan(context.Background(), "https://example.com/api?aB3xK9mQ7pR2wE5tY8uI0=true")
	if result.Allowed {
		t.Error("expected high-entropy query key to be blocked")
	}
	if result.Scanner != ScannerEntropy {
		t.Errorf("expected scanner=entropy, got %s", result.Scanner)
	}
}

// --- Additional Scanner Edge Cases ---

func TestScan_EmptyURL(t *testing.T) {
	s := New(testConfig())
	result := s.Scan(context.Background(), "")
	if result.Allowed {
		t.Error("expected empty URL to be blocked")
	}
}

func TestScan_URLWithPort(t *testing.T) {
	s := New(testConfig())
	result := s.Scan(context.Background(), "https://example.com:8443/api/data")
	if !result.Allowed {
		t.Errorf("expected URL with port to be allowed, got: %s", result.Reason)
	}
}

func TestScan_URLWithUserInfo(t *testing.T) {
	s := New(testConfig())
	// URL with userinfo (user:pass@host) — should still scan the hostname correctly
	result := s.Scan(context.Background(), "https://user:pass@example.com/page")
	if !result.Allowed {
		t.Errorf("expected URL with userinfo to be allowed, got: %s", result.Reason)
	}
}

func TestScan_URLWithFragment(t *testing.T) {
	s := New(testConfig())
	result := s.Scan(context.Background(), "https://example.com/page#section-1")
	if !result.Allowed {
		t.Errorf("expected URL with fragment to be allowed, got: %s", result.Reason)
	}
}

func TestScan_DLPInPath(t *testing.T) {
	s := New(testConfig())
	// AWS key directly in the path
	result := s.Scan(context.Background(), "https://example.com/upload/AKIAIOSFODNN7EXAMPLE/file.txt")
	if result.Allowed {
		t.Error("expected DLP to catch AWS key in URL path")
	}
	if result.Scanner != ScannerDLP {
		t.Errorf("expected scanner=dlp, got %s", result.Scanner)
	}
}

func TestScan_DLPInSubdomain(t *testing.T) {
	s := New(testConfig())
	// Secret encoded as a subdomain label — bypassed DLP before full-URL scanning.
	result := s.Scan(context.Background(), "https://sk-proj-abc123def456ghi789jkl012.evil.com/")
	if result.Allowed {
		t.Error("expected DLP to catch OpenAI key in subdomain")
	}
	if result.Scanner != ScannerDLP {
		t.Errorf("expected scanner=dlp, got %s", result.Scanner)
	}
}

func TestScan_DLPKeySplitAcrossParams(t *testing.T) {
	s := New(testConfig())
	// Key prefix in one param — full URL scan catches the prefix in the raw string.
	result := s.Scan(context.Background(), "https://example.com/callback?a=sk-proj-abc123def456ghi789jkl012mno345&b=extra")
	if result.Allowed {
		t.Error("expected DLP to catch OpenAI key split across params")
	}
}

func TestScan_DLPAWSKeyInSubdomain(t *testing.T) {
	s := New(testConfig())
	result := s.Scan(context.Background(), "https://AKIAIOSFODNN7EXAMPLE.s3.evil.com/data")
	if result.Allowed {
		t.Error("expected DLP to catch AWS key in subdomain")
	}
}

func TestScan_DLPSubdomainDotCollapse(t *testing.T) {
	s := New(testConfig())

	tests := []struct {
		name    string
		url     string
		blocked bool
	}{
		{
			name:    "anthropic key split across subdomains",
			url:     "https://sk-ant-api03-.AABBCCDDEE.FFGGHHIIJJ.KKLLMMNNOO.evil.com/",
			blocked: true,
		},
		{
			name:    "AWS key split across subdomains",
			url:     "https://AKIA.IOSFODNN.7EXAMPLE1.evil.com/",
			blocked: true,
		},
		{
			name:    "OpenAI key split across subdomains",
			url:     "https://sk-proj-.abc123def456.ghi789jkl012.evil.com/",
			blocked: true,
		},
		{
			name:    "normal domain - no false positive",
			url:     "https://www.google.com/search?q=hello",
			blocked: false,
		},
		{
			name:    "normal multi-level subdomain - no false positive",
			url:     "https://api.us-east-1.example.com/v1/data",
			blocked: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := s.Scan(context.Background(), tt.url)
			if tt.blocked && result.Allowed {
				t.Errorf("expected DLP to block dot-split secret in %s", tt.url)
			}
			if !tt.blocked && !result.Allowed {
				t.Errorf("expected normal URL to be allowed: %s (blocked: %s)", tt.url, result.Reason)
			}
			if tt.blocked && result.Scanner != ScannerDLP {
				t.Errorf("expected scanner=dlp, got %s", result.Scanner)
			}
		})
	}
}

func TestScan_DLPSlackToken(t *testing.T) {
	s := New(testConfig())
	token := "xoxb-" + "1234567890-abcdefghij"
	result := s.Scan(context.Background(), "https://example.com/api?token="+token)
	if result.Allowed {
		t.Error("expected DLP to catch Slack token")
	}
}

func TestScan_DLPPrivateKey(_ *testing.T) {
	s := New(testConfig())
	// Private key header in query (URL-encoded scenario)
	result := s.Scan(context.Background(), "https://example.com/api?data=-----BEGIN%20PRIVATE%20KEY-----")
	// Note: the DLP checks decoded query values, so this might or might not match
	// depending on whether the raw or decoded query is checked.
	// At minimum, it should not panic.
	_ = result
}

func TestScan_DLPOpenAIKey(t *testing.T) {
	s := New(testConfig())
	result := s.Scan(context.Background(), "https://example.com/api?key=sk-proj-abcdefghijklmnopqrstuvwxyz")
	if result.Allowed {
		t.Error("expected DLP to catch OpenAI key")
	}
}

func TestScan_DLPOpenAIKey_OldFormatNotMatched(t *testing.T) {
	s := New(testConfig())
	// Old sk- prefix without proj- should NOT be caught (too broad)
	result := s.Scan(context.Background(), "https://example.com/api?key=sk-abcdefghijklmnopqrstuvwxyz")
	if !result.Allowed {
		// May still be caught by entropy, check it's not DLP
		if result.Scanner == ScannerDLP {
			t.Error("expected old sk- prefix NOT to trigger DLP (too broad)")
		}
	}
}

func TestScan_DLPDiscordBotToken(t *testing.T) {
	s := New(testConfig())
	// Build token from parts to avoid GitHub push protection false positive.
	// Discord bot token format: M + 23+ chars . 6 chars . 27+ chars
	token := "MTIzNDU2Nzg5MDEyMzQ1Njc4" + "." + "AbCdEf" + "." + "ABCDEFGHIJKLMNOPQRSTUVWXYZabc"
	result := s.Scan(context.Background(), "https://example.com/api?token="+token)
	if result.Allowed {
		t.Error("expected DLP to catch Discord bot token")
	}
}

func TestScan_NoDLPPatterns(t *testing.T) {
	cfg := testConfig()
	cfg.DLP.Patterns = nil
	s := New(cfg)

	// Should not be blocked even with a secret-like string
	result := s.Scan(context.Background(), "https://example.com/api?key=AKIAIOSFODNN7EXAMPLE")
	if !result.Allowed {
		t.Errorf("expected URL allowed with no DLP patterns, got: %s (%s)", result.Reason, result.Scanner)
	}
}

func TestScan_EmptyBlocklist(t *testing.T) {
	cfg := testConfig()
	cfg.FetchProxy.Monitoring.Blocklist = nil
	s := New(cfg)

	result := s.Scan(context.Background(), "https://pastebin.com/raw/abc123")
	if !result.Allowed {
		t.Errorf("expected pastebin allowed with empty blocklist, got: %s", result.Reason)
	}
}

func TestScan_BlocklistExactMatch(t *testing.T) {
	cfg := testConfig()
	// Use exact match (no wildcard)
	cfg.FetchProxy.Monitoring.Blocklist = []string{"evil.com"}
	s := New(cfg)

	result := s.Scan(context.Background(), "https://evil.com/exfil")
	if result.Allowed {
		t.Error("expected exact blocklist match to block")
	}

	// Subdomain should NOT be blocked by exact match
	result = s.Scan(context.Background(), "https://sub.evil.com/exfil")
	if !result.Allowed {
		t.Error("expected subdomain to be allowed with exact match blocklist")
	}
}

func TestScan_URLExactlyAtMaxLength(t *testing.T) {
	cfg := testConfig()
	cfg.FetchProxy.Monitoring.EntropyThreshold = 0

	// Build URL exactly at limit
	base := "https://example.com/"
	maxLen := len(base) + 30 // 50 chars total
	cfg.FetchProxy.Monitoring.MaxURLLength = maxLen
	s := New(cfg)

	padding := ""
	for i := 0; i < 30; i++ {
		padding += "a"
	}
	exactURL := base + padding
	if len(exactURL) != maxLen {
		t.Fatalf("test setup: URL is %d chars, expected %d", len(exactURL), maxLen)
	}
	result := s.Scan(context.Background(), exactURL)
	if !result.Allowed {
		t.Errorf("expected URL at exact max length to be allowed, got: %s", result.Reason)
	}

	// URL one char over
	overURL := exactURL + "b"
	result = s.Scan(context.Background(), overURL)
	if result.Allowed {
		t.Error("expected URL one char over max to be blocked")
	}
}

func TestScan_EntropyExactlyAtThreshold(t *testing.T) {
	cfg := testConfig()
	// We need a string where entropy ≈ threshold. Use threshold=4.0
	cfg.FetchProxy.Monitoring.EntropyThreshold = 4.0
	s := New(cfg)

	// "abcdefghijklmnopqrst" has 20 unique chars → entropy = log2(20) ≈ 4.32
	result := s.Scan(context.Background(), "https://example.com/abcdefghijklmnopqrst")
	if result.Allowed {
		t.Error("expected string with entropy above threshold to be blocked")
	}
}

func TestScan_NumericOnlyPath(t *testing.T) {
	s := New(testConfig())
	// Numeric IDs (low entropy since only digits 0-9)
	result := s.Scan(context.Background(), "https://example.com/api/12345678901234567890")
	if !result.Allowed {
		t.Errorf("expected numeric path to be allowed (low entropy), got: %s", result.Reason)
	}
}

func TestScan_RepeatedCharsPath(t *testing.T) {
	s := New(testConfig())
	// All same character — entropy=0
	result := s.Scan(context.Background(), "https://example.com/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if !result.Allowed {
		t.Errorf("expected repeated chars to be allowed (zero entropy), got: %s", result.Reason)
	}
}

func TestScan_HexString(t *testing.T) {
	cfg := testConfig()
	cfg.FetchProxy.Monitoring.EntropyThreshold = 4.5
	s := New(cfg)

	// Hex string (entropy ~4.0 for random hex) — should be below 4.5 threshold
	result := s.Scan(context.Background(), "https://example.com/commit/deadbeefcafebabe1234")
	if !result.Allowed {
		t.Errorf("expected hex string (entropy ~4.0) to be allowed with threshold 4.5, got: %s (score: %f)", result.Reason, result.Score)
	}
}

func TestScan_Base64String(t *testing.T) {
	cfg := testConfig()
	cfg.FetchProxy.Monitoring.EntropyThreshold = 4.5
	cfg.DLP.Patterns = nil // don't trigger DLP
	s := New(cfg)

	// High-entropy base64-like string with mixed case, digits, special chars
	// Must be >20 chars and have entropy >4.5
	result := s.Scan(context.Background(), "https://example.com/data/aR7kM3qX9wB5tY2cE8nP4jL6hG0fD1sV")
	if result.Allowed {
		t.Error("expected high-entropy base64-like string to be blocked")
	}
	if result.Scanner != ScannerEntropy {
		t.Errorf("expected scanner=entropy, got %s", result.Scanner)
	}
}

func TestScan_MultipleQueryParams_OneTriggering(t *testing.T) {
	s := New(testConfig())

	// One query param is a secret, others are normal
	result := s.Scan(context.Background(), "https://example.com/api?user=josh&page=1&key=AKIAIOSFODNN7EXAMPLE")
	if result.Allowed {
		t.Error("expected URL with secret in one query param to be blocked")
	}
	if result.Scanner != ScannerDLP {
		t.Errorf("expected scanner=dlp, got %s", result.Scanner)
	}
}

func TestScan_BlocklistCaseInsensitive(t *testing.T) {
	s := New(testConfig())

	// Hostname should be lowered before matching
	result := s.Scan(context.Background(), "https://PASTEBIN.COM/raw/abc")
	if result.Allowed {
		t.Error("expected case-insensitive blocklist match")
	}
}

func TestScan_AllScannersPass(t *testing.T) {
	s := New(testConfig())

	result := s.Scan(context.Background(), "https://example.com/page?q=hello")
	if !result.Allowed {
		t.Errorf("expected clean URL to pass all scanners, got: %s (%s)", result.Reason, result.Scanner)
	}
	if result.Scanner != "all" {
		t.Errorf("expected scanner=all for passing URL, got %s", result.Scanner)
	}
	if result.Score != 0.0 {
		t.Errorf("expected score=0.0 for passing URL, got %f", result.Score)
	}
}

func TestScan_DataURIScheme(t *testing.T) {
	s := New(testConfig())
	result := s.Scan(context.Background(), "data:text/html,<script>alert(1)</script>")
	if result.Allowed {
		t.Error("expected data: URI to be blocked")
	}
}

func TestScan_ScanOrderBlocklistBeforeSSRF(t *testing.T) {
	cfg := testConfig()
	cfg.Internal = []string{"127.0.0.0/8"}
	cfg.FetchProxy.Monitoring.Blocklist = []string{"localhost"}
	s := New(cfg)

	// Blocklist fires before SSRF (no DNS resolution needed for blocklist).
	// localhost matches both blocklist and SSRF, but blocklist is checked first.
	result := s.Scan(context.Background(), "http://localhost/test")
	if result.Allowed {
		t.Fatal("expected to be blocked")
	}
	if result.Scanner != "blocklist" {
		t.Errorf("expected scanner=blocklist (checked first), got %s", result.Scanner)
	}
}

func TestScan_DLPCatchesSecretInHostnameBeforeDNS(t *testing.T) {
	cfg := testConfig()
	// Enable SSRF so DNS resolution would happen — but DLP should fire first.
	cfg.Internal = []string{"10.0.0.0/8"}
	s := New(cfg)

	// Attacker encodes an Anthropic key as a subdomain: DNS query for this
	// hostname would exfiltrate the key via DNS even if the request is later
	// blocked by SSRF. DLP must catch it BEFORE DNS resolution.
	result := s.Scan(context.Background(), "https://sk-ant-abcdefghijklmnopqrstuVW.evil.com/exfil")
	if result.Allowed {
		t.Fatal("expected DLP to catch secret in hostname")
	}
	if result.Scanner != ScannerDLP {
		t.Errorf("expected scanner=dlp (runs before DNS), got %s", result.Scanner)
	}
}

func TestScan_EntropyInQueryParam(t *testing.T) {
	cfg := testConfig()
	cfg.FetchProxy.Monitoring.EntropyThreshold = 4.0
	cfg.DLP.Patterns = nil // disable DLP so entropy is checked
	s := New(cfg)

	result := s.Scan(context.Background(), "https://example.com/page?data=aB3xK9mQ7pR2wE5tY8uI")
	if result.Allowed {
		t.Error("expected high-entropy query param to be blocked")
	}
	if result.Scanner != ScannerEntropy {
		t.Errorf("expected scanner=entropy, got %s", result.Scanner)
	}
}

func TestScan_URLWithEncodedCharacters(t *testing.T) {
	s := New(testConfig())
	// URL-encoded characters in path — should be treated normally
	result := s.Scan(context.Background(), "https://example.com/search?q=hello%20world&lang=en")
	if !result.Allowed {
		t.Errorf("expected URL with encoded chars to be allowed, got: %s", result.Reason)
	}
}

// --- MatchDomain Additional Tests ---

func TestMatchDomain_SingleLabelDomain(t *testing.T) {
	if !MatchDomain("localhost", "localhost") {
		t.Error("expected single label domain match")
	}
}

func TestMatchDomain_WildcardSingleLabel(t *testing.T) {
	// *.localhost should match sub.localhost
	if !MatchDomain("sub.localhost", "*.localhost") {
		t.Error("expected wildcard to match subdomain of single label")
	}
}

func TestMatchDomain_IPAddress(t *testing.T) {
	if !MatchDomain("192.168.1.1", "192.168.1.1") {
		t.Error("expected IP address exact match")
	}
	if MatchDomain("192.168.1.1", "*.168.1.1") {
		t.Error("expected wildcard not to apply to IP addresses")
	}
	if MatchDomain("10.0.0.1", "192.168.1.1") {
		t.Error("expected different IPs not to match")
	}
}

func TestMatchDomain_LongSubdomain(t *testing.T) {
	if !MatchDomain("a.b.c.d.e.f.example.com", "*.example.com") {
		t.Error("expected wildcard to match deeply nested subdomain")
	}
}

// --- Shannon Entropy Additional Tests ---

func TestShannonEntropy_AllPrintableASCII(t *testing.T) {
	// 95 printable ASCII characters → max entropy = log2(95) ≈ 6.57
	var s string
	for i := 32; i < 127; i++ {
		s += string(rune(i))
	}
	e := ShannonEntropy(s)
	if e < 6.5 || e > 6.6 {
		t.Errorf("expected entropy ~6.57 for all printable ASCII, got %f", e)
	}
}

func TestShannonEntropy_BinaryLike(t *testing.T) {
	// "01010101..." has entropy of exactly 1.0
	e := ShannonEntropy("0101010101010101")
	if e < 0.99 || e > 1.01 {
		t.Errorf("expected entropy ~1.0 for binary string, got %f", e)
	}
}

func TestShannonEntropy_SingleCharString(t *testing.T) {
	if e := ShannonEntropy("x"); e != 0 {
		t.Errorf("expected 0 entropy for single char, got %f", e)
	}
}

func TestShannonEntropy_FourDistinctChars(t *testing.T) {
	// Equal distribution of 4 chars → entropy = 2.0
	e := ShannonEntropy("abcdabcdabcd")
	if e < 1.99 || e > 2.01 {
		t.Errorf("expected entropy ~2.0 for 4 equal-frequency chars, got %f", e)
	}
}

func TestShannonEntropy_Base64Chars(t *testing.T) {
	// Simulated base64 with wide character set
	e := ShannonEntropy("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
	if e < 5.9 || e > 6.1 {
		t.Errorf("expected entropy ~6.0 for base64 alphabet, got %f", e)
	}
}

// --- DLP bypass via malformed percent-encoding ---

func TestScan_DLPCatchesMalformedPercentEncoding(t *testing.T) {
	s := New(testConfig())

	// Malformed %ZZ should not bypass DLP — raw query is scanned as fallback
	result := s.Scan(context.Background(), "https://example.com/api?key=AKIAIOSFODNN7EXAMPLE&junk=%ZZ")
	if result.Allowed {
		t.Error("expected DLP to catch AWS key even with malformed percent-encoding in query")
	}
	if result.Scanner != ScannerDLP {
		t.Errorf("expected scanner=dlp, got %s", result.Scanner)
	}
}

// --- IsInternalIP tests ---

func TestIsInternalIP_MatchesConfiguredCIDR(t *testing.T) {
	cfg := testConfig()
	cfg.Internal = []string{"10.0.0.0/8", "127.0.0.0/8"}
	s := New(cfg)

	tests := []struct {
		ip       string
		internal bool
	}{
		{"10.0.0.1", true},
		{"10.255.255.255", true},
		{"127.0.0.1", true},
		{"8.8.8.8", false},
		{"192.168.1.1", false},
	}

	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		got := s.IsInternalIP(ip)
		if got != tt.internal {
			t.Errorf("IsInternalIP(%s) = %v, want %v", tt.ip, got, tt.internal)
		}
	}
}

func TestIsInternalIP_IPv4MappedIPv6(t *testing.T) {
	cfg := testConfig()
	cfg.Internal = []string{"127.0.0.0/8", "10.0.0.0/8"}
	s := New(cfg)

	// IPv4-mapped IPv6 addresses like ::ffff:127.0.0.1 must match IPv4 CIDRs.
	// Without To4() normalization, the 16-byte IPv6 form wouldn't match the
	// 4-byte 127.0.0.0/8 CIDR — this was the original SSRF bypass vector.
	tests := []struct {
		ip       string
		internal bool
	}{
		{"::ffff:127.0.0.1", true},
		{"::ffff:10.0.0.1", true},
		{"::ffff:8.8.8.8", false},
		{"::ffff:192.168.1.1", false}, // 192.168.0.0/16 not in this config
	}

	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		if ip == nil {
			t.Fatalf("failed to parse IP %s", tt.ip)
		}
		got := s.IsInternalIP(ip)
		if got != tt.internal {
			t.Errorf("IsInternalIP(%s) = %v, want %v", tt.ip, got, tt.internal)
		}
	}
}

func TestIsInternalIP_DisabledReturnsAlwaysFalse(t *testing.T) {
	cfg := testConfig()
	cfg.Internal = nil
	s := New(cfg)

	if s.IsInternalIP(net.ParseIP("127.0.0.1")) {
		t.Error("expected false when SSRF is disabled")
	}
}

// --- DataBudget integration tests ---

func TestScan_DataBudgetExceeded(t *testing.T) {
	cfg := testConfig()
	cfg.FetchProxy.Monitoring.MaxDataPerMinute = 100 // 100 bytes/min/domain
	s := New(cfg)
	defer s.Close()

	// Record enough data to exceed the budget
	s.RecordRequest("example.com", 150)

	result := s.Scan(context.Background(), "https://example.com/page")
	if result.Allowed {
		t.Error("expected request blocked after exceeding data budget")
	}
	if result.Scanner != "databudget" {
		t.Errorf("expected scanner=databudget, got %s", result.Scanner)
	}
}

func TestScan_DataBudgetUnderLimit(t *testing.T) {
	cfg := testConfig()
	cfg.FetchProxy.Monitoring.MaxDataPerMinute = 1000
	s := New(cfg)
	defer s.Close()

	s.RecordRequest("example.com", 100)

	result := s.Scan(context.Background(), "https://example.com/page")
	if !result.Allowed {
		t.Errorf("expected request allowed under data budget, blocked: %s", result.Reason)
	}
}

func TestScan_DataBudgetDisabled(t *testing.T) {
	cfg := testConfig()
	cfg.FetchProxy.Monitoring.MaxDataPerMinute = 0 // disabled
	s := New(cfg)
	defer s.Close()

	// Should always be allowed when disabled
	result := s.Scan(context.Background(), "https://example.com/page")
	if !result.Allowed {
		t.Errorf("expected allowed when data budget disabled, blocked: %s", result.Reason)
	}
}

func TestRecordRequest_WithDataBudget(t *testing.T) {
	cfg := testConfig()
	cfg.FetchProxy.Monitoring.MaxDataPerMinute = 500
	s := New(cfg)
	defer s.Close()

	// RecordRequest should track data bytes
	s.RecordRequest("example.com", 200)
	s.RecordRequest("example.com", 200)

	// Now at 400 bytes, under 500 limit
	result := s.Scan(context.Background(), "https://example.com/page")
	if !result.Allowed {
		t.Errorf("expected allowed at 400/500 bytes, blocked: %s", result.Reason)
	}

	// Record 200 more to exceed
	s.RecordRequest("example.com", 200)

	result = s.Scan(context.Background(), "https://example.com/page")
	if result.Allowed {
		t.Error("expected blocked at 600/500 bytes")
	}
}

func TestRecordRequest_NilDataBudget(t *testing.T) {
	cfg := testConfig()
	cfg.FetchProxy.Monitoring.MaxDataPerMinute = 0 // no budget
	s := New(cfg)
	defer s.Close()

	// Should not panic
	s.RecordRequest("example.com", 1000)
}

func TestRecordRequest_ZeroBytes(t *testing.T) {
	cfg := testConfig()
	cfg.FetchProxy.Monitoring.MaxDataPerMinute = 100
	s := New(cfg)
	defer s.Close()

	// Zero bytes should not be recorded
	s.RecordRequest("example.com", 0)

	result := s.Scan(context.Background(), "https://example.com/page")
	if !result.Allowed {
		t.Error("expected allowed after recording 0 bytes")
	}
}

// --- DLP zero-width bypass tests ---

func TestScan_DLP_ZeroWidthBypass(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	// Try to bypass DLP with zero-width characters inside a known pattern
	// Build the pattern at runtime to avoid gitleaks
	prefix := testAnthropicPrefix
	suffix := testAlphabet
	zwsp := "\u200B" // zero-width space
	url := "https://example.com/api?key=" + prefix + zwsp + suffix

	result := s.Scan(context.Background(), url)
	if result.Allowed {
		t.Error("expected DLP to catch zero-width bypass of API key pattern")
	}
}

// --- DLP confusable/combining mark bypass tests (URL path) ---

func TestScan_DLP_ConfusableBypass(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	// Armenian ա (U+0561) in key prefix — maps to 'a', so sk-աnt- → sk-ant-
	prefix := "sk-\u0561nt-"
	suffix := testLowEntropy
	result := s.Scan(context.Background(), "https://example.com/api?key="+prefix+suffix)
	if result.Allowed {
		t.Error("expected DLP to catch Armenian confusable bypass")
	}
}

func TestScan_DLP_CombiningMarkBypass(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	// Combining long stroke overlay (U+0337) in key prefix
	prefix := "sk-a\u0337nt-"
	suffix := testLowEntropy
	result := s.Scan(context.Background(), "https://example.com/api?key="+prefix+suffix)
	if result.Allowed {
		t.Error("expected DLP to catch combining mark bypass in URL")
	}
}

func TestScan_DLP_CyrillicConfusableBypass(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	// Cyrillic а (U+0430) replacing Latin 'a' in key prefix
	prefix := "sk-\u0430nt-"
	suffix := testLowEntropy
	result := s.Scan(context.Background(), "https://example.com/api?key="+prefix+suffix)
	if result.Allowed {
		t.Error("expected DLP to catch Cyrillic confusable bypass in URL")
	}
}

func TestScan_DLP_PathDotSplitBypass(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	// Secret split by dots in URL path: sk-ant-api03-AAAA.AAAA.AAAA...
	// Dots break the regex character class; dot-collapse catches it.
	result := s.Scan(context.Background(), "https://httpbin.org/anything/sk-ant-api03-AAAA.AAAA.AAAA.AAAA.AAAA.AAAA.AAAA")
	if result.Allowed {
		t.Error("expected DLP to catch dot-split secret in URL path")
	}
}

func TestScan_DLP_QueryFieldSplitBypass(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	// Secret split across query parameters: part1=sk-ant-api03-&part2=AAAA...
	result := s.Scan(context.Background(), "https://httpbin.org/anything?part1=sk-ant-api03-&part2=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	if result.Allowed {
		t.Error("expected DLP to catch secret split across query parameters")
	}
}

func TestScan_DLP_QueryFieldSplit_CleanNoFalsePositive(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	// Normal multi-param URL should not trigger DLP
	result := s.Scan(context.Background(), "https://example.com/search?q=hello+world&page=1&sort=name")
	if !result.Allowed {
		t.Errorf("false positive on clean multi-param URL: %s", result.Reason)
	}
}

func TestScan_DLP_PathMixedSeparatorBypass(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	// Secret fragmented with encoded dots (%2E) and slashes (%2f) in path.
	// Go's url.Parse decodes these, creating /sk-ant-api03-AAAA.AAAA/AAAA_AAAA-AAAA.
	// stripURLNoise removes both dots and slashes to recover the full key.
	result := s.Scan(context.Background(), "https://httpbin.org/anything/sk-ant-api03-AAAA%2EAAAA%2fAAAA_AAAA-AAAA")
	if result.Allowed {
		t.Error("expected DLP to catch secret split by mixed path separators")
	}
}

func TestScan_DLP_QueryNoiseInjectionBypass(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	// Secret split across query params with noise values (%20 space) inserted between.
	// orderedQueryConcat includes noise; stripURLNoise removes spaces to recover key.
	result := s.Scan(context.Background(), "https://httpbin.org/anything?x=foo&part1=sk-ant-api03-&mid=%20&part2=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&y=bar")
	if result.Allowed {
		t.Error("expected DLP to catch query split with noise injection")
	}
}

func TestScan_DLP_PathSlashOnly_CleanNoFalsePositive(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	// Normal URL with multiple path segments should not trigger DLP
	result := s.Scan(context.Background(), "https://example.com/api/v1/users/123/profile")
	if !result.Allowed {
		t.Errorf("false positive on clean multi-segment path: %s", result.Reason)
	}
}

func TestScan_DLP_QueryInterleavedJunkBypass(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	// Secret fragments interleaved with junk alphanumeric values.
	// querySubsequenceDLP should try combinations and reconstruct the key.
	// Build key at runtime to avoid gitleaks.
	prefix := "sk-" + "ant-api03-"
	body := testUpperPad
	url := "https://evil.com/x?a=" + prefix[:3] + "&x1=junk&b=" + prefix[3:] + "&x2=noise&c=" + body + "&x3=filler"
	result := s.Scan(context.Background(), url)
	if result.Allowed {
		t.Error("expected DLP to catch interleaved junk query bypass")
	}
}

func TestScan_DLP_QueryInterleavedJunk_CleanNoFalsePositive(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	// Normal URL with many query params should not trigger subsequence DLP
	result := s.Scan(context.Background(), "https://example.com/search?q=hello&page=1&sort=name&dir=asc&limit=10")
	if !result.Allowed {
		t.Errorf("false positive on clean multi-param URL: %s", result.Reason)
	}
}

func TestScan_DLP_QuerySubsequence_TwoParamsOnly(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	// Only 2 query params — should use ordered concat, not subsequence (needs 3+)
	prefix := "sk-" + "ant-api03-"
	body := testUpperPad
	url := "https://evil.com/?a=" + prefix + "&b=" + body
	result := s.Scan(context.Background(), url)
	if result.Allowed {
		t.Error("expected DLP to catch key split across 2 query params via concat")
	}
}

func TestScan_DLP_QuerySubsequence_Over20ParamsCapped(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	// Secret split across params 3 and 5, with >20 total params (junk padding).
	// Should still catch it because we cap to first 20 values.
	prefix := "sk-" + "ant-api03-"
	body := testUpperPad
	u := "https://evil.com/x?j1=a&j2=b&secret1=" + prefix + "&j3=c&secret2=" + body
	for i := 0; i < 18; i++ {
		u += fmt.Sprintf("&pad%d=junk", i)
	}
	result := s.Scan(context.Background(), u)
	if result.Allowed {
		t.Error("expected DLP to catch secret split in >20 param URL (capped to first 20)")
	}
}

// --- DLP new pattern tests ---

func TestScan_DLP_GitHubFinegrainedPAT(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	// Build token at runtime to avoid gitleaks
	token := "github_pat_" + "aB1cD2eF3gH4iJ5kL6mN7oP8qR9sT0uV1wX2yZ3aB4cD5eF"
	result := s.Scan(context.Background(), "https://example.com/api?token="+token)
	if result.Allowed {
		t.Error("expected DLP to catch GitHub Fine-Grained PAT")
	}
}

func TestScan_DLP_OpenAIServiceKey(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	// Build key at runtime
	key := "sk-svcacct-" + testAlphabet
	result := s.Scan(context.Background(), "https://example.com/api?key="+key)
	if result.Allowed {
		t.Error("expected DLP to catch OpenAI Service Key")
	}
}

func TestScan_DLP_StripeKey(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	// Build key at runtime
	key := "sk_live_" + "abcdefghijklmnopqrstuvwx"
	result := s.Scan(context.Background(), "https://example.com/api?key="+key)
	if result.Allowed {
		t.Error("expected DLP to catch Stripe live key")
	}
}

func TestScan_DLP_StripeTestKey(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	key := "rk_test_" + "abcdefghijklmnopqrstuvwx"
	result := s.Scan(context.Background(), "https://example.com/api?key="+key)
	if result.Allowed {
		t.Error("expected DLP to catch Stripe test restricted key")
	}
}

// --- DLP evasion fixes (dot-separated, short key, credential-in-URL) ---

func TestScan_DLP_QueryValueDotSeparatedBypass(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	// Dot-separated key in a query parameter value. Before the fix,
	// stripURLNoise only ran on paths, not individual query values.
	prefix := "s.k.-.a.n.t.-."
	suffix := "A.B.C.D.E.F.G.H.I.J"
	result := s.Scan(context.Background(), "https://example.com/api?data="+prefix+suffix)
	if result.Allowed {
		t.Error("expected DLP to catch dot-separated key in query value")
	}
}

func TestScan_DLP_QueryKeyDotSeparatedBypass(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	// Dot-separated key stuffed into a query parameter NAME, not value.
	prefix := "s.k.-.a.n.t.-."
	suffix := "A.B.C.D.E.F.G.H.I.J"
	result := s.Scan(context.Background(), "https://example.com/api?"+prefix+suffix+"=1")
	if result.Allowed {
		t.Error("expected DLP to catch dot-separated key in query key")
	}
}

func TestScan_DLP_ShortAnthropicKey(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	// Key with 10-char suffix (previously needed 20+). The sk-ant- prefix
	// is distinctive enough that partial fragments should still be caught.
	key := "sk-ant-" + strings.Repeat("A", 10)
	result := s.Scan(context.Background(), "https://example.com/api?key="+key)
	if result.Allowed {
		t.Error("expected DLP to catch short Anthropic key prefix")
	}
}

func TestScan_DLP_ShortOpenAIKey(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	key := "sk-proj-" + strings.Repeat("A", 10)
	result := s.Scan(context.Background(), "https://example.com/api?key="+key)
	if result.Allowed {
		t.Error("expected DLP to catch short OpenAI key prefix")
	}
}

func TestScan_DLP_ShortSvcAcctKey(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	key := "sk-svcacct-" + strings.Repeat("A", 10)
	result := s.Scan(context.Background(), "https://example.com/api?key="+key)
	if result.Allowed {
		t.Error("expected DLP to catch short OpenAI service-account key prefix")
	}
}

func TestScan_DLP_VeryShortKeyNoFP(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	// Sample/test values under {10,} suffix threshold should not trigger.
	key := "sk-ant-" + "foobar"
	result := s.Scan(context.Background(), "https://example.com/api?note="+key)
	if !result.Allowed {
		t.Errorf("false positive on sample key value: %s", result.Reason)
	}
}

func TestScan_DLP_CredentialInURL_Password(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	result := s.Scan(context.Background(), "https://example.com/api?password=mysecret123")
	if result.Allowed {
		t.Error("expected DLP to catch password= in URL")
	}
}

func TestScan_DLP_CredentialInURL_Token(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	val := "abc123" + "def456"
	result := s.Scan(context.Background(), "https://example.com/webhook?token="+val)
	if result.Allowed {
		t.Error("expected DLP to catch token= in URL")
	}
}

func TestScan_DLP_CredentialInURL_ApiKey(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	result := s.Scan(context.Background(), "https://example.com/v1?apikey=secretvalue123")
	if result.Allowed {
		t.Error("expected DLP to catch apikey= in URL")
	}
}

func TestScan_DLP_CredentialInURL_Secret(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	result := s.Scan(context.Background(), "https://example.com/db?secret=hunter2abc")
	if result.Allowed {
		t.Error("expected DLP to catch secret= in URL")
	}
}

func TestScan_DLP_CredentialInURL_ShortValueNoFP(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	// Values under 4 chars should NOT trigger (avoids "token=yes", "password=no").
	result := s.Scan(context.Background(), "https://example.com/api?token=yes")
	if !result.Allowed {
		t.Errorf("false positive on short credential value: %s", result.Reason)
	}
}

func TestScan_DLP_CredentialInURL_WordBoundaryNoFP(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	// Compound param names containing "token", "secret", etc. as a SUBSTRING
	// should NOT trigger due to \b word boundary anchor.
	fps := []struct {
		name string
		url  string
	}{
		{"next_token", "https://example.com/api?next_token=" + "abcd1234" + "efgh"},
		{"page_token", "https://example.com/list?page_token=cursor12345"},
		{"csrf_token_id", "https://example.com/form?csrf_token_id=abc1234def"},
		{"auth_token_type", "https://example.com/oauth?auth_token_type=bearer123"},
		{"access_token_expiry", "https://example.com/auth?access_token_expiry=3600secs"},
		{"client_secret_hash", "https://example.com/app?client_secret_hash=sha256abcd"},
	}

	for _, fp := range fps {
		t.Run(fp.name, func(t *testing.T) {
			result := s.Scan(context.Background(), fp.url)
			if !result.Allowed {
				t.Errorf("false positive on %s: %s", fp.name, result.Reason)
			}
		})
	}
}

func TestScan_DLP_CredentialInURL_InQueryString(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	// Credential pattern in query string (connection string style URL).
	result := s.Scan(context.Background(), "https://example.com/connect?password=verysecretpassword&host=db.internal")
	if result.Allowed {
		t.Error("expected DLP to catch password= in connection string URL")
	}
}

// --- Hex/base64 encoded DLP in query params (fix #1: decodeEncodings) ---

func TestScan_DLP_HexEncodedAPIKeyInQuery(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	// hex(prefix + suffix) — build at runtime
	prefix := testAnthropicPrefix
	suffix := testAlphabet
	hexEncoded := hex.EncodeToString([]byte(prefix + suffix))
	result := s.Scan(context.Background(), "https://example.com/api?key="+hexEncoded)
	if result.Allowed {
		t.Error("expected hex-encoded API key in query param to be blocked")
	}
	if result.Scanner != ScannerDLP {
		t.Errorf("expected scanner=dlp, got %s", result.Scanner)
	}
}

func TestScan_DLP_Base64EncodedAPIKeyInQuery(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	// base64(prefix + suffix) — build at runtime
	prefix := testAnthropicPrefix
	suffix := testAlphabet
	b64Encoded := base64.StdEncoding.EncodeToString([]byte(prefix + suffix))
	result := s.Scan(context.Background(), "https://example.com/api?key="+b64Encoded)
	if result.Allowed {
		t.Error("expected base64-encoded API key in query param to be blocked")
	}
	if result.Scanner != ScannerDLP {
		t.Errorf("expected scanner=dlp, got %s", result.Scanner)
	}
}

func TestScan_DLP_EncodedQueryNoFalsePositives(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	// These should NOT trigger DLP when decoded
	tests := []struct {
		name string
		url  string
	}{
		{"hex of clean text", "https://example.com/api?data=" + hex.EncodeToString([]byte("hello world"))},
		{"base64 of clean text", "https://example.com/api?data=" + base64.StdEncoding.EncodeToString([]byte("hello world"))},
		{"short hex value", "https://example.com/api?color=ff00ff"},
		{"normal query params", "https://example.com/search?q=golang+tutorial"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := s.Scan(context.Background(), tt.url)
			if !result.Allowed {
				t.Errorf("false positive on clean encoded query: %s (reason: %s)", tt.url, result.Reason)
			}
		})
	}
}

// --- Hex/base64 encoded DLP in URL path segments (Rook bypass #1) ---

func TestScan_DLP_HexEncodedAPIKeyInPath(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	// hex(prefix + suffix) embedded in path segment
	prefix := testAnthropicPrefix
	suffix := testAlphabet
	hexEncoded := hex.EncodeToString([]byte(prefix + suffix))
	result := s.Scan(context.Background(), "https://example.com/exfil/"+hexEncoded+"/data")
	if result.Allowed {
		t.Error("expected hex-encoded API key in URL path to be blocked")
	}
	if result.Scanner != ScannerDLP {
		t.Errorf("expected scanner=dlp, got %s", result.Scanner)
	}
}

func TestScan_DLP_Base64EncodedAPIKeyInPath(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	// base64(prefix + suffix) embedded in path segment
	prefix := testAnthropicPrefix
	suffix := testAlphabet
	b64Encoded := base64.RawURLEncoding.EncodeToString([]byte(prefix + suffix))
	result := s.Scan(context.Background(), "https://example.com/exfil/"+b64Encoded)
	if result.Allowed {
		t.Error("expected base64-encoded API key in URL path to be blocked")
	}
	if result.Scanner != ScannerDLP {
		t.Errorf("expected scanner=dlp, got %s", result.Scanner)
	}
}

func TestScan_DLP_HexEncodedAWSKeyInPath(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	// hex-encode an AWS key in the path
	key := "AKIA" + "IOSFODNN7EXAMPLE1"
	hexEncoded := hex.EncodeToString([]byte(key))
	result := s.Scan(context.Background(), "https://example.com/"+hexEncoded)
	if result.Allowed {
		t.Error("expected hex-encoded AWS key in URL path to be blocked")
	}
	if result.Scanner != ScannerDLP {
		t.Errorf("expected scanner=dlp, got %s", result.Scanner)
	}
}

func TestScan_DLP_EncodedPathNoFalsePositives(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	tests := []struct {
		name string
		url  string
	}{
		{"hex of clean text in path", "https://example.com/" + hex.EncodeToString([]byte("hello world"))},
		{"base64 of clean text in path", "https://example.com/" + base64.RawURLEncoding.EncodeToString([]byte("hello world"))},
		{"short path segment", "https://example.com/abc123"},
		{"normal path", "https://example.com/api/v1/users/profile"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := s.Scan(context.Background(), tt.url)
			if !result.Allowed {
				t.Errorf("false positive on clean encoded path: %s (reason: %s)", tt.url, result.Reason)
			}
		})
	}
}

// --- Delimiter-separated hex DLP in query params and path segments ---

func TestScan_DLP_DelimiterHexInQuery(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	prefix := testAnthropicPrefix
	suffix := testAlphabet
	secret := prefix + suffix
	contiguousHex := hex.EncodeToString([]byte(secret))

	tests := []struct {
		name  string
		value string
	}{
		{"colon-separated", hexByteSep(contiguousHex, ":")},
		{"space-separated", hexByteSep(contiguousHex, " ")},
		{"hyphen-separated", hexByteSep(contiguousHex, "-")},
		{"comma-separated", hexByteSep(contiguousHex, ",")},
		{"backslash-x notation", hexBytePrefix(contiguousHex, `\x`)},
		{"0x prefix", "0x" + contiguousHex},
		{"0x per-byte contiguous", hexBytePrefix(contiguousHex, "0x")},
		{"0x per-byte comma-separated", func() string {
			// "0x73,0x6b,0x2d,..." — each byte with 0x prefix, comma-separated
			parts := make([]string, 0, len(contiguousHex)/2)
			for i := 0; i < len(contiguousHex); i += 2 {
				parts = append(parts, "0x"+contiguousHex[i:i+2])
			}
			return strings.Join(parts, ",")
		}()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := s.Scan(context.Background(), "https://example.com/api?key="+tt.value)
			if result.Allowed {
				t.Errorf("expected delimiter-hex %s API key in query to be blocked", tt.name)
			}
			if result.Scanner != ScannerDLP {
				t.Errorf("expected scanner=dlp, got %s", result.Scanner)
			}
		})
	}
}

func TestScan_DLP_DelimiterHexInPath(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	key := "AKIA" + "IOSFODNN7EXAMPLE1"
	contiguousHex := hex.EncodeToString([]byte(key))

	tests := []struct {
		name  string
		value string
	}{
		{"colon-separated", hexByteSep(contiguousHex, ":")},
		{"comma-separated", hexByteSep(contiguousHex, ",")},
		{"backslash-x notation", hexBytePrefix(contiguousHex, `\x`)},
		{"0x prefix", "0x" + contiguousHex},
		{"0x per-byte contiguous", hexBytePrefix(contiguousHex, "0x")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := s.Scan(context.Background(), "https://example.com/exfil/"+tt.value+"/data")
			if result.Allowed {
				t.Errorf("expected delimiter-hex %s AWS key in path to be blocked", tt.name)
			}
			if result.Scanner != ScannerDLP {
				t.Errorf("expected scanner=dlp, got %s", result.Scanner)
			}
		})
	}
}

func TestScan_DLP_DelimiterHexNoFalsePositives(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	tests := []struct {
		name string
		url  string
	}{
		{"colon-separated clean text", "https://example.com/api?data=" + hexByteSep(hex.EncodeToString([]byte("hello world!")), ":")},
		{"hyphen-separated short", "https://example.com/api?color=ff-00-ff"},
		{"0x prefixed clean", "https://example.com/api?data=0x" + hex.EncodeToString([]byte("hello world!"))},
		{"backslash-x clean", `https://example.com/api?data=\x68\x65\x6c\x6c\x6f`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := s.Scan(context.Background(), tt.url)
			if !result.Allowed {
				t.Errorf("false positive on delimiter-hex clean data: %s (reason: %s)", tt.url, result.Reason)
			}
		})
	}
}

// --- Env leak encoding tests ---

func TestScan_EnvLeak_HexEncoded(t *testing.T) {
	cfg := testConfig()
	cfg.DLP.ScanEnv = true
	s := New(cfg)
	defer s.Close()

	// Inject a known env secret into the scanner's env secrets list
	secret := testSecretVal
	s.envSecrets = []string{secret}

	// Hex encode the secret
	hexEncoded := ""
	for _, b := range []byte(secret) {
		hexEncoded += fmt.Sprintf("%02x", b)
	}

	result := s.Scan(context.Background(), "https://example.com/exfil?data="+hexEncoded)
	if result.Allowed {
		t.Error("expected hex-encoded env leak to be caught")
	}
	if result.Scanner != ScannerDLP {
		t.Errorf("expected scanner=dlp, got %s", result.Scanner)
	}
}

func TestScan_EnvLeak_DelimiterHex(t *testing.T) {
	cfg := testConfig()
	cfg.DLP.ScanEnv = true
	s := New(cfg)
	defer s.Close()

	secret := testSecretVal
	s.envSecrets = []string{secret}
	contiguousHex := hex.EncodeToString([]byte(secret))

	tests := []struct {
		name  string
		value string
	}{
		{"colon-separated", hexByteSep(contiguousHex, ":")},
		{"space-separated", hexByteSep(contiguousHex, " ")},
		{"hyphen-separated", hexByteSep(contiguousHex, "-")},
		{"backslash-x notation", hexBytePrefix(contiguousHex, `\x`)},
		{"0x per-byte notation", hexBytePrefix(contiguousHex, "0x")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := s.Scan(context.Background(), "https://example.com/exfil?data="+tt.value)
			if result.Allowed {
				t.Errorf("expected %s hex-encoded env leak to be caught", tt.name)
			}
			if result.Scanner != ScannerDLP {
				t.Errorf("expected scanner=dlp, got %s", result.Scanner)
			}
		})
	}
}

func TestScan_EnvLeak_Base32Encoded(t *testing.T) {
	cfg := testConfig()
	cfg.DLP.ScanEnv = true
	s := New(cfg)
	defer s.Close()

	secret := testSecretVal
	s.envSecrets = []string{secret}

	// Base32 StdEncoding
	encoded := base32.StdEncoding.EncodeToString([]byte(secret))

	result := s.Scan(context.Background(), "https://example.com/exfil?data="+encoded)
	if result.Allowed {
		t.Error("expected base32-encoded env leak to be caught")
	}
}

func TestScan_EnvLeak_Base32NoPadding(t *testing.T) {
	cfg := testConfig()
	cfg.DLP.ScanEnv = true
	s := New(cfg)
	defer s.Close()

	secret := testSecretVal
	s.envSecrets = []string{secret}

	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte(secret))

	result := s.Scan(context.Background(), "https://example.com/exfil?data="+encoded)
	if result.Allowed {
		t.Error("expected base32-no-padding env leak to be caught")
	}
}

// --- Scanner Close tests ---

func TestScanner_Close_WithDataBudget(t *testing.T) {
	cfg := testConfig()
	cfg.FetchProxy.Monitoring.MaxDataPerMinute = 1000
	s := New(cfg)
	s.Close() // should close data budget cleanup goroutine
}

func TestScanner_Close_NilDataBudget(t *testing.T) {
	cfg := testConfig()
	cfg.FetchProxy.Monitoring.MaxDataPerMinute = 0
	s := New(cfg)
	s.Close() // should not panic with nil data budget
}

// --- CheckAndRecord concurrent test ---

func TestCheckAndRecord_Concurrent(t *testing.T) {
	rl := NewRateLimiter(100) // 100 req/min
	defer rl.Close()

	var wg sync.WaitGroup
	allowed := int64(0)
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if rl.CheckAndRecord("example.com") {
				atomic.AddInt64(&allowed, 1)
			}
		}()
	}
	wg.Wait()

	if allowed > 100 {
		t.Errorf("expected at most 100 allowed, got %d", allowed)
	}
	if allowed == 0 {
		t.Error("expected some requests to be allowed")
	}
}

// --- baseDomain tests ---

func TestBaseDomain_Simple(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"example.com", "example.com"},
		{"sub.example.com", "example.com"},
		{"a.b.c.example.com", "example.com"},
		{"localhost", "localhost"},
		{"127.0.0.1", "127.0.0.1"},
		{"::1", "::1"},
		{"evil.com", "evil.com"},
		{"deeply.nested.sub.evil.com", "evil.com"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := baseDomain(tt.input)
			if got != tt.want {
				t.Errorf("baseDomain(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestDataBudget_SubdomainRotation(t *testing.T) {
	cfg := testConfig()
	cfg.FetchProxy.Monitoring.MaxDataPerMinute = 500
	cfg.DLP.Patterns = nil
	s := New(cfg)
	defer s.Close()

	// Record data across multiple subdomains — should aggregate under base domain.
	s.RecordRequest("a.evil.com", 200)
	s.RecordRequest("b.evil.com", 200)
	s.RecordRequest("c.evil.com", 200)

	// Budget should now be exceeded for any evil.com subdomain.
	result := s.Scan(context.Background(), "https://d.evil.com/")
	if result.Allowed {
		t.Error("expected data budget to block after subdomain rotation exceeds limit")
	}
	if result.Scanner != "databudget" {
		t.Errorf("expected scanner=databudget, got %s", result.Scanner)
	}
}

func TestCheckSubdomainEntropy_BlocksHighEntropyLabels(t *testing.T) {
	cfg := testConfig()
	cfg.FetchProxy.Monitoring.EntropyThreshold = 4.5
	cfg.DLP.Patterns = nil // avoid DLP matches on test data
	s := New(cfg)
	defer s.Close()

	tests := []struct {
		name string
		url  string
	}{
		{
			name: "random mixed subdomain",
			// 20 unique lowercase+digit chars → entropy = log2(20) ≈ 4.32
			url: "https://r7km2np9qw4xb5vy8za3.evil.com/",
		},
		{
			name: "random alphanumeric subdomain",
			// 22 unique chars → entropy well above 4.0
			url: "https://m3xp7ktw9vr2nj6qbhdf5y.evil.com/",
		},
		{
			name: "random alpha subdomain",
			// 20 unique lowercase chars → entropy = log2(20) ≈ 4.32
			url: "https://qwertyuiopasdfghjklz.evil.com/path",
		},
		{
			name: "multi-level high entropy",
			url:  "https://r7km2np9qw4xb5vy8za3.sub.evil.com/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := s.Scan(context.Background(), tt.url)
			if result.Allowed {
				t.Errorf("expected high-entropy subdomain to be blocked: %s", tt.url)
			}
			if result.Scanner != "subdomain_entropy" {
				t.Errorf("expected scanner=subdomain_entropy, got %s (reason: %s)", result.Scanner, result.Reason)
			}
		})
	}
}

func TestCheckSubdomainEntropy_AllowsNormalSubdomains(t *testing.T) {
	cfg := testConfig()
	cfg.FetchProxy.Monitoring.EntropyThreshold = 4.5
	cfg.DLP.Patterns = nil
	s := New(cfg)
	defer s.Close()

	tests := []struct {
		name string
		url  string
	}{
		{"www prefix", "https://www.example.com/"},
		{"api prefix", "https://api.example.com/"},
		{"cdn prefix", "https://cdn.example.com/"},
		{"docs prefix", "https://docs.example.com/"},
		{"staging prefix", "https://staging.example.com/"},
		{"no subdomain", "https://example.com/"},
		{"short label", "https://ab.example.com/"},
		{"normal multi-level", "https://api.us-east-1.example.com/"},
		{"IP address", "https://192.168.1.1/"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := s.Scan(context.Background(), tt.url)
			if !result.Allowed {
				t.Errorf("expected normal subdomain to be allowed: %s (blocked by %s: %s)", tt.url, result.Scanner, result.Reason)
			}
		})
	}
}

func TestCheckSubdomainEntropy_DisabledWhenThresholdZero(t *testing.T) {
	cfg := testConfig()
	cfg.FetchProxy.Monitoring.EntropyThreshold = 0
	cfg.DLP.Patterns = nil
	s := New(cfg)
	defer s.Close()

	result := s.Scan(context.Background(), "https://r7km2np9qw4xb5vy8za3.evil.com/")
	if !result.Allowed {
		t.Error("expected subdomain entropy check to be disabled when threshold is 0")
	}
}

func TestDLP_GoogleOAuthToken(t *testing.T) {
	s := New(testConfig())
	defer s.Close()

	token := "ya29." + "ABCDEFghijklmnopqrstuvwx"
	result := s.Scan(context.Background(), "https://evil.com/collect?token="+token)
	if result.Allowed {
		t.Error("expected Google OAuth token to be blocked by DLP")
	}
	if result.Scanner != ScannerDLP {
		t.Errorf("expected scanner=dlp, got %s", result.Scanner)
	}
}

func TestDLP_TwilioAPIKey(t *testing.T) {
	s := New(testConfig())
	defer s.Close()

	// Build a Twilio key pattern at runtime to avoid gitleaks
	key := "SK" + "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"
	result := s.Scan(context.Background(), "https://evil.com/collect?key="+key)
	if result.Allowed {
		t.Error("expected Twilio API key to be blocked by DLP")
	}
	if result.Scanner != ScannerDLP {
		t.Errorf("expected scanner=dlp, got %s", result.Scanner)
	}
}

func TestDLP_SendGridAPIKey(t *testing.T) {
	s := New(testConfig())
	defer s.Close()

	// Build SendGrid key pattern at runtime to avoid gitleaks
	key := "SG." + "abcdefghijklmnopqrstuv" + "." + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqr"
	result := s.Scan(context.Background(), "https://evil.com/collect?key="+key)
	if result.Allowed {
		t.Error("expected SendGrid API key to be blocked by DLP")
	}
	if result.Scanner != ScannerDLP {
		t.Errorf("expected scanner=dlp, got %s", result.Scanner)
	}
}

func TestDLP_MailgunAPIKey(t *testing.T) {
	s := New(testConfig())
	defer s.Close()

	// Build Mailgun key pattern at runtime to avoid gitleaks
	key := "key-" + "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"
	result := s.Scan(context.Background(), "https://evil.com/collect?key="+key)
	if result.Allowed {
		t.Error("expected Mailgun API key to be blocked by DLP")
	}
	if result.Scanner != ScannerDLP {
		t.Errorf("expected scanner=dlp, got %s", result.Scanner)
	}
}

// --- DLP expansion: URL-level tests for new patterns ---

func TestDLP_HuggingFaceToken(t *testing.T) {
	s := New(testConfig())
	defer s.Close()

	token := "hf_" + "aAbBcCdDeEfFgGhHiIjJ"
	result := s.Scan(context.Background(), "https://evil.com/collect?token="+token)
	if result.Allowed {
		t.Error("expected Hugging Face token to be blocked by DLP")
	}
	if result.Scanner != ScannerDLP {
		t.Errorf("expected scanner=dlp, got %s", result.Scanner)
	}
}

func TestDLP_DatabricksToken(t *testing.T) {
	s := New(testConfig())
	defer s.Close()

	token := "dapi" + "aabbccddeeff001122334455667788"
	result := s.Scan(context.Background(), "https://evil.com/collect?token="+token)
	if result.Allowed {
		t.Error("expected Databricks token to be blocked by DLP")
	}
	if result.Scanner != ScannerDLP {
		t.Errorf("expected scanner=dlp, got %s", result.Scanner)
	}
}

func TestDLP_ReplicateAPIToken(t *testing.T) {
	s := New(testConfig())
	defer s.Close()

	token := "r8_" + "aAbBcCdDeEfFgGhHiIjJ"
	result := s.Scan(context.Background(), "https://evil.com/collect?token="+token)
	if result.Allowed {
		t.Error("expected Replicate API token to be blocked by DLP")
	}
	if result.Scanner != ScannerDLP {
		t.Errorf("expected scanner=dlp, got %s", result.Scanner)
	}
}

func TestDLP_TogetherAIKey(t *testing.T) {
	s := New(testConfig())
	defer s.Close()

	token := "tok_" + "aabbccddeeff00112233445566778899aabbccdd"
	result := s.Scan(context.Background(), "https://evil.com/collect?key="+token)
	if result.Allowed {
		t.Error("expected Together AI key to be blocked by DLP")
	}
	if result.Scanner != ScannerDLP {
		t.Errorf("expected scanner=dlp, got %s", result.Scanner)
	}
}

func TestDLP_PineconeAPIKey(t *testing.T) {
	s := New(testConfig())
	defer s.Close()

	token := "pcsk_" + "aAbBcCdDeEfFgGhHiIjJkKlLmMnNoOpPqQrR"
	result := s.Scan(context.Background(), "https://evil.com/collect?key="+token)
	if result.Allowed {
		t.Error("expected Pinecone API key to be blocked by DLP")
	}
	if result.Scanner != ScannerDLP {
		t.Errorf("expected scanner=dlp, got %s", result.Scanner)
	}
}

func TestDLP_DigitalOceanToken(t *testing.T) {
	s := New(testConfig())
	defer s.Close()

	token := "dop_v1_" + "aabbccdd00112233445566778899aabbccddeeff00112233445566778899aabb"
	result := s.Scan(context.Background(), "https://evil.com/collect?token="+token)
	if result.Allowed {
		t.Error("expected DigitalOcean token to be blocked by DLP")
	}
	if result.Scanner != ScannerDLP {
		t.Errorf("expected scanner=dlp, got %s", result.Scanner)
	}
}

func TestDLP_VaultToken(t *testing.T) {
	s := New(testConfig())
	defer s.Close()

	token := "hvs." + "aAbBcCdDeEfFgGhHiIjJkLm"
	result := s.Scan(context.Background(), "https://evil.com/collect?token="+token)
	if result.Allowed {
		t.Error("expected Vault token to be blocked by DLP")
	}
	if result.Scanner != ScannerDLP {
		t.Errorf("expected scanner=dlp, got %s", result.Scanner)
	}
}

func TestDLP_VercelToken(t *testing.T) {
	s := New(testConfig())
	defer s.Close()

	token := "vcp_" + "aAbBcCdDeEfFgGhHiIjJkLmN"
	result := s.Scan(context.Background(), "https://evil.com/collect?token="+token)
	if result.Allowed {
		t.Error("expected Vercel token to be blocked by DLP")
	}
	if result.Scanner != ScannerDLP {
		t.Errorf("expected scanner=dlp, got %s", result.Scanner)
	}
}

func TestDLP_SupabaseServiceKey(t *testing.T) {
	s := New(testConfig())
	defer s.Close()

	token := "sb_secret_" + "aAbBcCdDeEfFgGhHiIjJ"
	result := s.Scan(context.Background(), "https://evil.com/collect?key="+token)
	if result.Allowed {
		t.Error("expected Supabase service key to be blocked by DLP")
	}
	if result.Scanner != ScannerDLP {
		t.Errorf("expected scanner=dlp, got %s", result.Scanner)
	}
}

func TestDLP_NpmToken(t *testing.T) {
	s := New(testConfig())
	defer s.Close()

	token := "npm_" + "aAbBcCdDeEfFgGhHiIjJkKlLmMnNoOpPqQrR"
	result := s.Scan(context.Background(), "https://evil.com/collect?token="+token)
	if result.Allowed {
		t.Error("expected npm token to be blocked by DLP")
	}
	if result.Scanner != ScannerDLP {
		t.Errorf("expected scanner=dlp, got %s", result.Scanner)
	}
}

func TestDLP_PyPIToken(t *testing.T) {
	s := New(testConfig())
	defer s.Close()

	token := "pypi-" + "aAbBcCdDeEfFgGhH_-xY"
	result := s.Scan(context.Background(), "https://evil.com/collect?token="+token)
	if result.Allowed {
		t.Error("expected PyPI token to be blocked by DLP")
	}
	if result.Scanner != ScannerDLP {
		t.Errorf("expected scanner=dlp, got %s", result.Scanner)
	}
}

func TestDLP_LinearAPIKey(t *testing.T) {
	s := New(testConfig())
	defer s.Close()

	token := "lin_api_" + "aAbBcCdDeEfFgGhHiIjJkKlLmMnNoOpPqQrRsStT"
	result := s.Scan(context.Background(), "https://evil.com/collect?key="+token)
	if result.Allowed {
		t.Error("expected Linear API key to be blocked by DLP")
	}
	if result.Scanner != ScannerDLP {
		t.Errorf("expected scanner=dlp, got %s", result.Scanner)
	}
}

func TestDLP_NotionAPIKey(t *testing.T) {
	s := New(testConfig())
	defer s.Close()

	token := "ntn_" + "aAbBcCdDeEfFgGhHiIjJkKlLmMnNoOpPqQrRsStT"
	result := s.Scan(context.Background(), "https://evil.com/collect?key="+token)
	if result.Allowed {
		t.Error("expected Notion API key to be blocked by DLP")
	}
	if result.Scanner != ScannerDLP {
		t.Errorf("expected scanner=dlp, got %s", result.Scanner)
	}
}

func TestDLP_SentryAuthToken(t *testing.T) {
	s := New(testConfig())
	defer s.Close()

	token := "sntrys_" + "aAbBcCdDeEfFgGhHiIjJkKlLmMnNoOpPqQrRsStT"
	result := s.Scan(context.Background(), "https://evil.com/collect?token="+token)
	if result.Allowed {
		t.Error("expected Sentry auth token to be blocked by DLP")
	}
	if result.Scanner != ScannerDLP {
		t.Errorf("expected scanner=dlp, got %s", result.Scanner)
	}
}

// --- Control char DLP bypass tests (fetch proxy URL path) ---

func TestScan_DLP_ControlCharBypass(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	// Build key at runtime to avoid gitleaks
	prefix := testAnthropicPrefix
	suffix := testAlphabet

	tests := []struct {
		name    string
		ctrlStr string
	}{
		{"null_byte", "\x00"},
		{"backspace", "\x08"},
		{"tab", "\x09"},
		{"newline", "\x0a"},
		{"carriage_return", "\x0d"},
		{"form_feed", "\x0c"},
		{"vertical_tab", "\x0b"},
		{"escape", "\x1b"},
		{"unit_separator", "\x1f"},
		{"DEL", "\x7f"},
	}

	for _, tt := range tests {
		t.Run(tt.name+"_in_query", func(t *testing.T) {
			// Control char injected between prefix and suffix in query param
			url := "https://example.com/api?key=" + prefix + tt.ctrlStr + suffix
			result := s.Scan(context.Background(), url)
			if result.Allowed {
				t.Errorf("expected DLP to catch key with %s control char in query", tt.name)
			}
		})
	}
}

func TestScan_DLP_NullByteInPath(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	// Null byte in URL path should not bypass DLP
	prefix := testAnthropicPrefix
	suffix := testAlphabet
	url := "https://example.com/" + prefix + "\x00" + suffix
	result := s.Scan(context.Background(), url)
	if result.Allowed {
		t.Error("expected DLP to catch key with null byte in path")
	}
}

func TestScan_DLP_MultipleControlChars(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	// Multiple different control chars scattered through the secret
	prefix := testAnthropicPrefix
	suffix := testAlphabet
	url := "https://example.com/api?key=" + prefix + "\x08\x09\x0a" + suffix
	result := s.Scan(context.Background(), url)
	if result.Allowed {
		t.Error("expected DLP to catch key with multiple control chars")
	}
}

func TestScan_AllowlistBlocksUnlistedDomain(t *testing.T) {
	cfg := testConfig()
	cfg.Mode = config.ModeStrict
	cfg.APIAllowlist = []string{"api.openai.com", "*.anthropic.com"}
	s := New(cfg)

	result := s.Scan(context.Background(), "https://evil.com/exfil")
	if result.Allowed {
		t.Fatal("expected allowlist to block unlisted domain")
	}
	if result.Scanner != "allowlist" {
		t.Errorf("expected scanner=allowlist, got %s", result.Scanner)
	}
}

func TestScan_AllowlistPermitsListedDomain(t *testing.T) {
	cfg := testConfig()
	cfg.Mode = config.ModeStrict
	cfg.APIAllowlist = []string{"api.openai.com", "*.anthropic.com"}
	s := New(cfg)

	result := s.Scan(context.Background(), "https://api.openai.com/v1/chat")
	if !result.Allowed {
		t.Errorf("expected allowlisted domain to be allowed, got blocked: %s", result.Reason)
	}
}

func TestScan_AllowlistPermitsWildcard(t *testing.T) {
	cfg := testConfig()
	cfg.Mode = config.ModeStrict
	cfg.APIAllowlist = []string{"*.anthropic.com"}
	s := New(cfg)

	result := s.Scan(context.Background(), "https://api.anthropic.com/v1/messages")
	if !result.Allowed {
		t.Errorf("expected wildcard-matched domain to be allowed, got blocked: %s", result.Reason)
	}
}

func TestScan_AllowlistEmptyPermitsAll(t *testing.T) {
	cfg := testConfig()
	cfg.Mode = config.ModeStrict
	cfg.APIAllowlist = nil
	s := New(cfg)

	result := s.Scan(context.Background(), "https://anything.example.com/path")
	if !result.Allowed {
		t.Errorf("expected empty allowlist to permit all domains, got blocked: %s", result.Reason)
	}
}

func TestScan_AllowlistNotEnforcedInBalancedMode(t *testing.T) {
	cfg := testConfig()
	cfg.Mode = config.ModeBalanced
	cfg.APIAllowlist = []string{"api.openai.com"}
	s := New(cfg)

	// In balanced mode, the allowlist is not enforced
	result := s.Scan(context.Background(), "https://example.com/page")
	if !result.Allowed {
		t.Errorf("expected balanced mode to not enforce allowlist, got blocked: %s", result.Reason)
	}
}

func TestScan_AllowlistNotEnforcedInAuditMode(t *testing.T) {
	cfg := testConfig()
	cfg.Mode = config.ModeAudit
	cfg.APIAllowlist = []string{"api.openai.com"}
	s := New(cfg)

	// In audit mode, the allowlist is not enforced
	result := s.Scan(context.Background(), "https://example.com/page")
	if !result.Allowed {
		t.Errorf("expected audit mode to not enforce allowlist, got blocked: %s", result.Reason)
	}
}

func TestScan_AllowlistCaseInsensitive(t *testing.T) {
	cfg := testConfig()
	cfg.Mode = config.ModeStrict
	cfg.APIAllowlist = []string{"api.openai.com"}
	s := New(cfg)

	// Hostname is lowercased by Scan(), so "API.OpenAI.com" should match "api.openai.com"
	result := s.Scan(context.Background(), "https://API.OpenAI.com/v1/chat")
	if !result.Allowed {
		t.Errorf("expected case-insensitive allowlist match, got blocked: %s", result.Reason)
	}
}

func TestScan_AllowlistRunsBeforeBlocklist(t *testing.T) {
	cfg := testConfig()
	cfg.Mode = config.ModeStrict
	// Set allowlist that doesn't include pastebin.com
	cfg.APIAllowlist = []string{"api.openai.com"}
	// pastebin.com is in the default blocklist
	s := New(cfg)

	result := s.Scan(context.Background(), "https://pastebin.com/raw/abc")
	if result.Allowed {
		t.Fatal("expected domain to be blocked")
	}
	// Allowlist should fire BEFORE blocklist
	if result.Scanner != "allowlist" {
		t.Errorf("expected scanner=allowlist (checked first), got %s", result.Scanner)
	}
}

// --- LoadSecretsFile Tests ---

func TestLoadSecretsFile_Basic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.txt")
	// Build at runtime to avoid gitleaks false positive (gosec G101)
	testVal := "xK9mP2nQ" + "7vR4wT6y"
	vaultVal := "hvs.CAESIJ9PQRs" + "TuVwXyZ0123456789"
	content := "# Database password\n" + testVal + "\n\n# Vault token\n" + vaultVal + "\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	secrets, err := LoadSecretsFile(path, 16)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(secrets) != 2 {
		t.Fatalf("expected 2 secrets, got %d", len(secrets))
	}
	if secrets[0] != testVal {
		t.Errorf("expected first secret %q, got %q", testVal, secrets[0])
	}
}

func TestLoadSecretsFile_CommentsAndBlankLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.txt")
	content := "# full comment\n  # indented comment\n\n\n  \nsecret1234567890xx\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	secrets, err := LoadSecretsFile(path, 16)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(secrets) != 1 {
		t.Fatalf("expected 1 secret, got %d: %v", len(secrets), secrets)
	}
}

func TestLoadSecretsFile_InlineHashPreserved(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.txt")
	content := "secret#with#hashes1\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	secrets, err := LoadSecretsFile(path, 16)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(secrets) != 1 || secrets[0] != "secret#with#hashes1" {
		t.Errorf("inline # should be preserved, got %v", secrets)
	}
}

func TestLoadSecretsFile_TrailingWhitespaceStripped(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.txt")
	content := "secret1234567890xx  \nsecret1234567890yy\t\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	secrets, err := LoadSecretsFile(path, 16)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, s := range secrets {
		if strings.ContainsAny(s, " \t\r") {
			t.Errorf("trailing whitespace not stripped: %q", s)
		}
	}
}

func TestLoadSecretsFile_CRLFLineEndings(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.txt")
	content := "secret1234567890xx\r\nsecret1234567890yy\r\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	secrets, err := LoadSecretsFile(path, 16)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(secrets) != 2 {
		t.Fatalf("expected 2 secrets with CRLF, got %d", len(secrets))
	}
	for _, s := range secrets {
		if strings.Contains(s, "\r") {
			t.Errorf("CR not stripped: %q", s)
		}
	}
}

func TestLoadSecretsFile_UTF8BOMStripped(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.txt")
	bom := "\xef\xbb\xbf"
	content := bom + "secret1234567890xx\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	secrets, err := LoadSecretsFile(path, 16)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(secrets) != 1 {
		t.Fatalf("expected 1 secret, got %d", len(secrets))
	}
	if strings.HasPrefix(secrets[0], bom) {
		t.Error("UTF-8 BOM not stripped from first line")
	}
	if secrets[0] != "secret1234567890xx" {
		t.Errorf("expected 'secret1234567890xx', got %q", secrets[0])
	}
}

func TestLoadSecretsFile_NullBytesSkipped(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.txt")
	content := "goodsecretvalue1234\nbad\x00secret12345678\nanothergoodsecret12\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	secrets, err := LoadSecretsFile(path, 16)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(secrets) != 2 {
		t.Fatalf("expected 2 secrets (null byte line skipped), got %d: %v", len(secrets), secrets)
	}
}

func TestLoadSecretsFile_MinLengthFiltered(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.txt")
	content := "short\nlongenoughsecretvalue1234\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	secrets, err := LoadSecretsFile(path, 16)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(secrets) != 1 {
		t.Fatalf("expected 1 secret (short filtered), got %d: %v", len(secrets), secrets)
	}
}

func TestLoadSecretsFile_MaxLineLengthEnforced(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.txt")
	longLine := strings.Repeat("a", 4097)
	content := longLine + "\nvalidsecretsixteen\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	secrets, err := LoadSecretsFile(path, 16)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(secrets) != 1 {
		t.Fatalf("expected 1 secret (long line skipped), got %d", len(secrets))
	}
}

func TestLoadSecretsFile_MaxEntriesEnforced(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.txt")
	var b strings.Builder
	for i := range 1001 {
		_, _ = fmt.Fprintf(&b, "secret%04d__padding\n", i)
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}

	secrets, err := LoadSecretsFile(path, 16)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(secrets) != 1000 {
		t.Fatalf("expected 1000 secrets (max enforced), got %d", len(secrets))
	}
}

func TestLoadSecretsFile_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.txt")
	if err := os.WriteFile(path, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}

	secrets, err := LoadSecretsFile(path, 16)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(secrets) != 0 {
		t.Fatalf("expected 0 secrets for empty file, got %d", len(secrets))
	}
}

func TestLoadSecretsFile_FileNotFound(t *testing.T) {
	_, err := LoadSecretsFile("/nonexistent/secrets.txt", 16)
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestLoadSecretsFile_DuplicatesPreserved(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.txt")
	content := "secret1234567890xx\nsecret1234567890xx\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	secrets, err := LoadSecretsFile(path, 16)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Duplicates within the file are preserved (dedup happens against envSecrets later)
	if len(secrets) != 2 {
		t.Fatalf("expected 2 secrets (duplicates preserved), got %d", len(secrets))
	}
}

// --- Scanner fileSecrets Tests ---

func TestNew_LoadsFileSecrets(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.txt")
	// Build at runtime to avoid gitleaks false positive (gosec G101)
	testVal := "xK9mP2nQ" + "7vR4wT6y"
	if err := os.WriteFile(path, []byte(testVal+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := testConfig()
	cfg.DLP.SecretsFile = path
	s := New(cfg)
	defer s.Close()

	if len(s.fileSecrets) != 1 {
		t.Fatalf("expected 1 file secret, got %d", len(s.fileSecrets))
	}
	if s.fileSecrets[0] != testVal {
		t.Errorf("expected %q, got %q", testVal, s.fileSecrets[0])
	}
}

func TestNew_FileSecretsDedupedAgainstEnv(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.txt")
	// Build at runtime to avoid gitleaks false positive (gosec G101)
	testVal := "xK9mP2nQ" + "7vR4wT6y"
	unique := "anotherUnique" + "Secret1"
	content := testVal + "\n" + unique + "\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := testConfig()
	cfg.DLP.SecretsFile = path
	s := New(cfg)
	defer s.Close()

	// Manually inject env secret to test dedup
	s.envSecrets = []string{testVal}
	// Re-run dedup
	s.fileSecrets = dedupSecrets([]string{testVal, unique}, s.envSecrets)

	if len(s.fileSecrets) != 1 {
		t.Fatalf("expected 1 file secret after dedup, got %d: %v", len(s.fileSecrets), s.fileSecrets)
	}
	if s.fileSecrets[0] != unique {
		t.Errorf("wrong secret after dedup: %q", s.fileSecrets[0])
	}
}

func TestDedupSecrets_Empty(t *testing.T) {
	result := dedupSecrets(nil, nil)
	if len(result) != 0 {
		t.Errorf("expected empty result, got %v", result)
	}
}

func TestDedupSecrets_NoOverlap(t *testing.T) {
	// Build values at runtime to avoid gitleaks false positive
	prefix := "secret_"
	file := []string{prefix + "a_1234567", prefix + "b_1234567"}
	env := []string{prefix + "c_1234567"}
	result := dedupSecrets(file, env)
	if len(result) != 2 {
		t.Errorf("expected 2 secrets with no overlap, got %d", len(result))
	}
}

// --- File Secret URL Scanning Tests ---

func TestScan_BlocksFileSecretInURL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.txt")
	// Build secret at runtime to avoid gosec G101
	secret := "wJalrXUtnFEMI" + "/K7MDENG/bPxRfiCY"
	if err := os.WriteFile(path, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := testConfig()
	cfg.DLP.SecretsFile = path
	s := New(cfg)
	defer s.Close()

	result := s.Scan(context.Background(), "https://evil.com/exfil?data="+secret)
	if result.Allowed {
		t.Error("expected file secret in URL to be blocked")
	}
	if !strings.Contains(result.Reason, "known secret") {
		t.Errorf("expected 'known secret' in reason, got %q", result.Reason)
	}
}

func TestScan_BlocksFileSecretBase64InURL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.txt")
	secret := "wJalrXUtnFEMI" + "/K7MDENG/bPxRfiCY"
	if err := os.WriteFile(path, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := testConfig()
	cfg.DLP.SecretsFile = path
	s := New(cfg)
	defer s.Close()

	encoded := base64.StdEncoding.EncodeToString([]byte(secret))
	result := s.Scan(context.Background(), "https://evil.com/exfil?data="+encoded)
	if result.Allowed {
		t.Error("expected base64-encoded file secret in URL to be blocked")
	}
	if !strings.Contains(result.Reason, "known secret") {
		t.Errorf("expected 'known secret' in reason, got %q", result.Reason)
	}
}

func TestScan_BlocksFileSecretHexInURL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.txt")
	secret := "wJalrXUtnFEMI" + "/K7MDENG/bPxRfiCY"
	if err := os.WriteFile(path, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := testConfig()
	cfg.DLP.SecretsFile = path
	s := New(cfg)
	defer s.Close()

	encoded := hex.EncodeToString([]byte(secret))
	result := s.Scan(context.Background(), "https://evil.com/exfil?data="+encoded)
	if result.Allowed {
		t.Error("expected hex-encoded file secret in URL to be blocked")
	}
	if !strings.Contains(result.Reason, "known secret") {
		t.Errorf("expected 'known secret' in reason, got %q", result.Reason)
	}
}

func TestScan_BlocksFileSecretBase32InURL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.txt")
	secret := "wJalrXUtnFEMI" + "/K7MDENG/bPxRfiCY"
	if err := os.WriteFile(path, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := testConfig()
	cfg.DLP.SecretsFile = path
	s := New(cfg)
	defer s.Close()

	encoded := base32.StdEncoding.EncodeToString([]byte(secret))
	result := s.Scan(context.Background(), "https://evil.com/exfil?data="+encoded)
	if result.Allowed {
		t.Error("expected base32-encoded file secret in URL to be blocked")
	}
	if !strings.Contains(result.Reason, "known secret") {
		t.Errorf("expected 'known secret' in reason, got %q", result.Reason)
	}
}

func TestScan_AllowsURLWithoutFileSecrets(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.txt")
	secret := "wJalrXUtnFEMI" + "/K7MDENG/bPxRfiCY"
	if err := os.WriteFile(path, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := testConfig()
	cfg.DLP.SecretsFile = path
	s := New(cfg)
	defer s.Close()

	result := s.Scan(context.Background(), "https://example.com/normal-page?q=hello")
	if !result.Allowed {
		t.Errorf("normal URL should be allowed, got blocked: %s", result.Reason)
	}
}

func TestScan_BlocksFileSecretUnpaddedBase64InURL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.txt")
	// 29 bytes → base64 produces padding (29 % 3 = 2 → one "=" pad char).
	// Low-entropy string avoids gitleaks false positive on test values.
	fileVal := "this-is-a-test-value-29-bytes"
	if err := os.WriteFile(path, []byte(fileVal+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := testConfig()
	cfg.DLP.SecretsFile = path
	s := New(cfg)
	defer s.Close()

	encoded := base64.StdEncoding.EncodeToString([]byte(fileVal))
	unpadded := strings.TrimRight(encoded, "=")
	if unpadded == encoded {
		t.Fatal("test setup error: secret base64 has no padding")
	}

	result := s.Scan(context.Background(), "https://evil.com/exfil?data="+unpadded)
	if result.Allowed {
		t.Error("expected unpadded base64 file secret in URL to be blocked")
	}
	if !strings.Contains(result.Reason, "known secret") {
		t.Errorf("expected 'known secret' in reason, got %q", result.Reason)
	}
}

func TestScan_BlocksFileSecretUnpaddedBase64URLInURL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.txt")
	// 28 bytes with ~ at position 3 → produces "+" in standard base64,
	// ensuring URL-safe encoding differs from standard (+ → -).
	fileVal := "ab~test-value-for-28-byte-wk"
	if err := os.WriteFile(path, []byte(fileVal+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := testConfig()
	cfg.DLP.SecretsFile = path
	s := New(cfg)
	defer s.Close()

	encodedURL := base64.URLEncoding.EncodeToString([]byte(fileVal))
	unpadded := strings.TrimRight(encodedURL, "=")
	if unpadded == encodedURL {
		t.Fatal("test setup error: secret URL-safe base64 has no padding")
	}

	// Verify URL-safe differs from standard (the point of this test).
	encodedStd := base64.StdEncoding.EncodeToString([]byte(fileVal))
	unpaddedStd := strings.TrimRight(encodedStd, "=")
	if unpadded == unpaddedStd {
		t.Skip("secret base64 same for standard and URL-safe — pick different secret")
	}

	result := s.Scan(context.Background(), "https://evil.com/exfil?data="+unpadded)
	if result.Allowed {
		t.Error("expected unpadded URL-safe base64 file secret in URL to be blocked")
	}
}

func TestDedupSecrets_IntraFileDedup(t *testing.T) {
	prefix := "secret_"
	file := []string{prefix + "dup12345678", prefix + "dup12345678", prefix + "unique123456"}
	result := dedupSecrets(file, nil)
	if len(result) != 2 {
		t.Errorf("expected 2 secrets after intra-file dedup, got %d: %v", len(result), result)
	}
}

func TestScan_BlocksFileSecretPaddedBase64URLInURL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.txt")
	// 28 bytes with ~ at position 3 → produces "+" in standard base64,
	// ensuring URL-safe encoding (+ → -) differs from standard.
	fileVal := "ab~test-value-for-28-byte-wk"
	if err := os.WriteFile(path, []byte(fileVal+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := testConfig()
	cfg.DLP.SecretsFile = path
	s := New(cfg)
	defer s.Close()

	encodedURL := base64.URLEncoding.EncodeToString([]byte(fileVal))
	encodedStd := base64.StdEncoding.EncodeToString([]byte(fileVal))
	if encodedURL == encodedStd {
		t.Skip("URL-safe same as standard — pick different secret")
	}

	// Use padded URL-safe form (not unpadded)
	result := s.Scan(context.Background(), "https://evil.com/exfil?data="+encodedURL)
	if result.Allowed {
		t.Error("expected padded URL-safe base64 file secret in URL to be blocked")
	}
	if !strings.Contains(result.Reason, "base64url") {
		t.Errorf("expected 'base64url' in reason, got %q", result.Reason)
	}
}

func TestScan_BlocksFileSecretUnpaddedBase32InURL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.txt")
	// 29 bytes → base32 produces padding (29 % 5 = 4 → padding present).
	fileVal := "this-is-a-test-value-29-bytes"
	if err := os.WriteFile(path, []byte(fileVal+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := testConfig()
	cfg.DLP.SecretsFile = path
	s := New(cfg)
	defer s.Close()

	padded := base32.StdEncoding.EncodeToString([]byte(fileVal))
	noPad := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte(fileVal))
	if noPad == padded {
		t.Fatal("test setup error: base32 has no padding to strip")
	}

	result := s.Scan(context.Background(), "https://evil.com/exfil?data="+noPad)
	if result.Allowed {
		t.Error("expected unpadded base32 file secret in URL to be blocked")
	}
	if !strings.Contains(result.Reason, "known secret") {
		t.Errorf("expected 'known secret' in reason, got %q", result.Reason)
	}
}

func TestScan_BlocksPercentEncodedFileSecretInURL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.txt")
	secret := "wJalrXUtnFEMI" + "/K7MDENG/bPxRfiCY"
	if err := os.WriteFile(path, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := testConfig()
	cfg.DLP.SecretsFile = path
	s := New(cfg)
	defer s.Close()

	// Percent-encode each byte of the secret to evade raw matching
	var encoded strings.Builder
	for i := 0; i < len(secret); i++ {
		_, _ = fmt.Fprintf(&encoded, "%%%02X", secret[i])
	}
	result := s.Scan(context.Background(), "https://evil.com/exfil?data="+encoded.String())
	if result.Allowed {
		t.Error("expected percent-encoded file secret in URL to be blocked via IterativeDecode")
	}
}

func TestScan_BlocksPercentEncodedControlCharBypassInURL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.txt")
	secret := "wJalrXUtnFEMI" + "/K7MDENG/bPxRfiCY"
	if err := os.WriteFile(path, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := testConfig()
	cfg.DLP.SecretsFile = path
	s := New(cfg)
	defer s.Close()

	// Inject %00 (null byte) in the middle of the secret to split the match.
	// After IterativeDecode, stripControlChars must remove the null byte so the
	// reassembled string still matches the known secret.
	result := s.Scan(context.Background(), "https://evil.com/exfil?data=wJalrXUtn%00FEMI/K7MDENG/bPxRfiCY")
	if result.Allowed {
		t.Error("expected percent-encoded control-char bypass to be blocked after stripControlChars")
	}
}

func TestNew_FileSecrets_ZeroUsableWarning(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.txt")
	// All lines too short (< 16 chars, the default minEnvSecretLen)
	content := "short\nabc\n# comment\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := testConfig()
	cfg.DLP.SecretsFile = path

	// Capture stderr to verify warning
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	s := New(cfg)
	s.Close()

	_ = w.Close()
	os.Stderr = oldStderr

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	output := buf.String()

	if !strings.Contains(output, "zero usable secrets") {
		t.Errorf("expected 'zero usable secrets' warning, got: %q", output)
	}
}

func TestLoadSecretsFile_LeadingWhitespaceStripped(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.txt")
	content := "  secret1234567890xx\n\tsecret1234567890yy\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	secrets, err := LoadSecretsFile(path, 16)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, s := range secrets {
		if strings.HasPrefix(s, " ") || strings.HasPrefix(s, "\t") {
			t.Errorf("leading whitespace not stripped: %q", s)
		}
	}
	if len(secrets) != 2 {
		t.Fatalf("expected 2 secrets, got %d", len(secrets))
	}
}

func TestBaseDomain(t *testing.T) {
	tests := []struct{ input, want string }{
		// ccTLDs: the whole point of using publicsuffix
		{"evil.co.uk", "evil.co.uk"},
		{"sub.evil.co.uk", "evil.co.uk"},
		{"evil.com.au", "evil.com.au"},
		{"sub.evil.com.au", "evil.com.au"},
		{"a.evil.gov.uk", "evil.gov.uk"},
		// Standard TLDs
		{"evil.com", "evil.com"},
		{"sub.evil.com", "evil.com"},
		{"a.b.c.evil.com", "evil.com"},
		// IP addresses: returned as-is
		{"192.168.1.1", "192.168.1.1"},
		{"::1", "::1"},
		// Single-label hosts
		{"localhost", "localhost"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := baseDomain(tt.input)
			if got != tt.want {
				t.Errorf("baseDomain(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestHintForBlock(t *testing.T) {
	tests := []struct {
		scanner string
		want    string
	}{
		{ScannerBlocklist, "Domain is on the blocklist. Remove from fetch_proxy.monitoring.blocklist if legitimate."},
		{ScannerDLP, "A DLP pattern matched this URL. If false positive, add a suppress entry for this rule."},
		{ScannerEntropy, "High-entropy content detected. Review the URL for data exfiltration attempts."},
		{ScannerSubdomainEntropy, "High-entropy content detected in subdomain. Review for data exfiltration via DNS."},
		{ScannerSSRF, "SSRF protection blocked this URL. It may resolve to a private IP or DNS resolution failed."},
		{ScannerRateLimit, "Rate limit exceeded. Retry later or adjust fetch_proxy.monitoring.max_requests_per_minute."},
		{ScannerLength, "URL exceeds maximum length. Check for data stuffing in query parameters."},
		{ScannerDataBudget, "Session data budget exceeded."},
		{ScannerScheme, "Only http and https schemes are allowed."},
		{ScannerAllowlist, "Domain not on the allowlist. In strict mode, only allowlisted domains are reachable."},
		{ScannerParser, "The URL could not be parsed."},
		{ScannerCRLF, "CRLF injection sequence detected in URL. This is never legitimate in normal traffic."},
		{ScannerPathTraversal, "Path traversal sequence detected. Review the URL for directory escape attempts."},
		{"unknown_scanner", ""},
	}
	for _, tt := range tests {
		t.Run(tt.scanner, func(t *testing.T) {
			r := &Result{Allowed: false, Scanner: tt.scanner}
			got := HintForBlock(r)
			if got != tt.want {
				t.Errorf("HintForBlock(scanner=%q) = %q, want %q", tt.scanner, got, tt.want)
			}
		})
	}
}

func TestHintForBlockAllowed(t *testing.T) {
	r := &Result{Allowed: true, Scanner: ScannerAll}
	if hint := HintForBlock(r); hint != "" {
		t.Errorf("expected empty hint for allowed result, got %q", hint)
	}
}

func TestHintForBlockNil(t *testing.T) {
	if hint := HintForBlock(nil); hint != "" {
		t.Errorf("expected empty hint for nil result, got %q", hint)
	}
}

func TestScanPopulatesHintOnBlock(t *testing.T) {
	cfg := testConfig()
	sc := New(cfg)
	defer sc.Close()

	// This URL should be blocked by DLP (AWS key pattern).
	fakeKey := "AKIA" + "IOSFODNN7EXAMPLE"
	result := sc.Scan(context.Background(), "https://example.com/?token="+fakeKey)
	if result.Allowed {
		t.Fatal("expected URL to be blocked by DLP")
	}
	if result.Hint == "" {
		t.Error("expected non-empty hint on blocked result")
	}
	if result.Scanner != ScannerDLP {
		t.Errorf("expected scanner=dlp, got %q", result.Scanner)
	}
}

func TestScan_RespectsContextCancellation(t *testing.T) {
	cfg := config.Defaults()
	cfg.DLP.Patterns = nil
	cfg.DLP.ScanEnv = false
	cfg.FetchProxy.Monitoring.EntropyThreshold = 0
	sc := New(cfg)
	defer sc.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	start := time.Now()
	result := sc.Scan(ctx, "https://example.com/test")
	elapsed := time.Since(start)

	// Cancelled context is caught by the fail-closed guard before scanning.
	if elapsed > 2*time.Second {
		t.Errorf("Scan with cancelled context took %v, expected fast return", elapsed)
	}
	if result.Allowed {
		t.Error("expected blocked result when context is cancelled")
	}
	if result.Scanner != ScannerContext {
		t.Errorf("expected scanner=%s, got %s", ScannerContext, result.Scanner)
	}
}

func TestScan_NilContext(t *testing.T) {
	sc := New(testConfig())
	defer sc.Close()

	// nil context must not panic; fail-closed guard blocks it.
	result := sc.Scan(nil, "https://example.com/test") //nolint:staticcheck // intentional nil context test
	if result.Allowed {
		t.Error("expected blocked result for nil context")
	}
	if result.Scanner != ScannerContext {
		t.Errorf("expected scanner=%s, got %s", ScannerContext, result.Scanner)
	}
}

func TestScan_CanceledContextWithSSRFDisabled(t *testing.T) {
	cfg := testConfig() // cfg.Internal = nil disables SSRF
	sc := New(cfg)
	defer sc.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Even with SSRF disabled, a cancelled context must block.
	result := sc.Scan(ctx, "https://example.com/test")
	if result.Allowed {
		t.Error("expected blocked result for cancelled context even with SSRF disabled")
	}
}

func TestScan_ContextTimeoutDuringDNS(t *testing.T) {
	cfg := config.Defaults()
	// SSRF enabled (non-nil Internal) so checkSSRF runs the DNS path.
	cfg.DLP.Patterns = nil
	cfg.DLP.ScanEnv = false
	cfg.FetchProxy.Monitoring.EntropyThreshold = 0
	sc := New(cfg)
	defer sc.Close()

	// 10ms timeout: passes the entry guard (ctx not yet expired) but
	// expires during or before DNS resolution, proving LookupHost
	// inherits the caller's context rather than the 5s ceiling.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond) //nolint:mnd // test timeout
	defer cancel()

	// Random subdomain forces a DNS cache miss so the resolver does real work.
	domain := fmt.Sprintf("ctx-test-%d.test.invalid", time.Now().UnixNano())
	start := time.Now()
	result := sc.Scan(ctx, "https://"+domain+"/path")
	elapsed := time.Since(start)

	// Must return near the 10ms caller timeout, not the 5s DNS ceiling.
	if elapsed > 2*time.Second {
		t.Errorf("expected return near caller timeout, got %v", elapsed)
	}
	if result.Allowed {
		t.Error("expected blocked when context expires during DNS resolution")
	}
	// DNS failure via caller timeout is ScannerSSRF; if the 10ms fires
	// before checkSSRF starts it may be ScannerContext instead.
	if result.Scanner != ScannerSSRF && result.Scanner != ScannerContext {
		t.Errorf("expected scanner=%s or %s, got %s", ScannerSSRF, ScannerContext, result.Scanner)
	}
}

func TestScanHintEmptyOnAllowed(t *testing.T) {
	cfg := testConfig()
	sc := New(cfg)
	defer sc.Close()

	result := sc.Scan(context.Background(), "https://example.com/")
	if !result.Allowed {
		t.Fatalf("expected URL to be allowed, got blocked: %s", result.Reason)
	}
	if result.Hint != "" {
		t.Errorf("expected empty hint on allowed result, got %q", result.Hint)
	}
}

// --- CRLF injection detection ---

func TestScan_BlocksCRLFInjection(t *testing.T) {
	s := New(testConfig())

	tests := []struct {
		name string
		url  string
	}{
		{"encoded_crlf", "https://example.com/path%0d%0aInjected-Header:evil"},
		{"uppercase_encoded", "https://example.com/path%0D%0ASet-Cookie:stolen=1"},
		{"double_encoded", "https://example.com/path%250d%250aInjected:yes"},
		{"in_query", "https://example.com/page?x=%0d%0aX-Evil:1"},
		{"bare_lf", "https://example.com/path%0aX-Injected:1"},
		{"bare_cr", "https://example.com/path%0dX-Injected:1"},
		{"bare_lf_uppercase", "https://example.com/path%0AX-Injected:1"},
		{"bare_cr_uppercase", "https://example.com/path%0DX-Injected:1"},
		{"double_encoded_bare_lf", "https://example.com/path%250aX-Injected:1"},
		{"double_encoded_bare_cr", "https://example.com/path%250dX-Injected:1"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := s.Scan(context.Background(), tc.url)
			if result.Allowed {
				t.Errorf("expected CRLF to be blocked: %s", tc.url)
			}
			if result.Scanner != ScannerCRLF {
				t.Errorf("expected scanner %q, got %q", ScannerCRLF, result.Scanner)
			}
		})
	}
}

// TestCheckSubdomainEntropy_Exclusions tests the subdomain entropy exclusion
// feature, which allows users to whitelist domains that legitimately use
// high-entropy subdomains (e.g., RunPod GPU instances, cloud preview URLs).
func TestCheckSubdomainEntropy_Exclusions(t *testing.T) {
	// 21-char label with entropy well above the 4.0 threshold used by
	// checkSubdomainEntropy (hardcoded constant, not the config threshold).
	const highEntropyLabel = "r7km2np9qw4xb5vy8za3b"

	tests := []struct {
		name           string
		exclusions     []string
		url            string
		shouldAllow    bool
		expectedReason string
	}{
		{
			name:           "no exclusions blocks high entropy",
			exclusions:     []string{},
			url:            fmt.Sprintf("https://%s.evil.com/", highEntropyLabel),
			shouldAllow:    false,
			expectedReason: ScannerSubdomainEntropy,
		},
		{
			name:        "wildcard exclusion allows matching domain",
			exclusions:  []string{"*.evil.com"},
			url:         fmt.Sprintf("https://%s.evil.com/", highEntropyLabel),
			shouldAllow: true,
		},
		{
			name:           "wildcard exclusion does not match different domain",
			exclusions:     []string{"*.evil.com"},
			url:            fmt.Sprintf("https://%s.different.com/", highEntropyLabel),
			shouldAllow:    false,
			expectedReason: ScannerSubdomainEntropy,
		},
		{
			name:        "exact match exclusion allows",
			exclusions:  []string{fmt.Sprintf("%s.trusted.example.com", highEntropyLabel)},
			url:         fmt.Sprintf("https://%s.trusted.example.com/", highEntropyLabel),
			shouldAllow: true,
		},
		{
			name:           "exact match exclusion does not match other subdomains",
			exclusions:     []string{"other.trusted.example.com"},
			url:            fmt.Sprintf("https://%s.trusted.example.com/", highEntropyLabel),
			shouldAllow:    false,
			expectedReason: ScannerSubdomainEntropy,
		},
		{
			name:        "wildcard matches multi-level subdomains",
			exclusions:  []string{"*.example.com"},
			url:         fmt.Sprintf("https://%s.deep.sub.example.com/", highEntropyLabel),
			shouldAllow: true,
		},
		{
			name:        "wildcard matches base domain itself",
			exclusions:  []string{"*.runpod.net"},
			url:         fmt.Sprintf("https://%s.runpod.net/", highEntropyLabel),
			shouldAllow: true,
		},
		{
			name:        "case insensitive matching",
			exclusions:  []string{"*.RunPod.NET"},
			url:         fmt.Sprintf("https://%s.runpod.net/", highEntropyLabel),
			shouldAllow: true,
		},
		{
			name:        "trailing dot normalization",
			exclusions:  []string{"*.runpod.net."},
			url:         fmt.Sprintf("https://%s.runpod.net/", highEntropyLabel),
			shouldAllow: true,
		},
		{
			name:        "multiple exclusions first match",
			exclusions:  []string{"*.evil.com", "*.trusted.com"},
			url:         fmt.Sprintf("https://%s.evil.com/", highEntropyLabel),
			shouldAllow: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := testConfig()
			cfg.DLP.Patterns = nil
			cfg.Internal = nil
			cfg.APIAllowlist = nil
			cfg.FetchProxy.Monitoring.Blocklist = nil
			cfg.FetchProxy.Monitoring.SubdomainEntropyExclusions = tt.exclusions
			s := New(cfg)
			defer s.Close()

			result := s.Scan(context.Background(), tt.url)

			if result.Allowed != tt.shouldAllow {
				if tt.shouldAllow {
					t.Errorf("expected allowed, got blocked by %s: %s", result.Scanner, result.Reason)
				} else {
					t.Errorf("expected blocked by %s, got allowed", tt.expectedReason)
				}
			}
			if !tt.shouldAllow && result.Scanner != tt.expectedReason {
				t.Errorf("expected scanner=%s, got %s", tt.expectedReason, result.Scanner)
			}
			if tt.shouldAllow && result.Scanner != ScannerAll {
				t.Errorf("expected scanner=all for allowed URL, got %s", result.Scanner)
			}
		})
	}
}

func TestScan_SubdomainEntropyExclusion_QueryEntropyStillChecked(t *testing.T) {
	// Regression: subdomain_entropy_exclusions must NOT skip query entropy.
	// Only subdomain and path entropy should be skipped.
	cfg := testConfig()
	cfg.DLP.Patterns = nil
	cfg.Internal = nil
	cfg.APIAllowlist = nil
	cfg.FetchProxy.Monitoring.Blocklist = nil
	cfg.FetchProxy.Monitoring.SubdomainEntropyExclusions = []string{"api.telegram.org"}
	s := New(cfg)
	defer s.Close()

	// High-entropy query value on an excluded domain should still be blocked.
	highEntropy := "aB3xK9mZ2wQ7rL5yN8vC4jF6hD1eG0t" // 32 chars, high entropy
	result := s.Scan(context.Background(), "https://api.telegram.org/send?payload="+highEntropy)
	if result.Allowed {
		t.Error("expected query entropy to still fire on excluded domain, but got allowed")
	}
	if result.Scanner != ScannerEntropy {
		t.Errorf("expected scanner=entropy, got %s", result.Scanner)
	}
}

func TestScan_AllowsCleanURLsNoCRLF(t *testing.T) {
	s := New(testConfig())

	clean := []string{
		"https://example.com/normal/path",
		"https://example.com/search?q=hello+world",
		"https://example.com/page#section",
		"https://example.com/path?encoded=%20space",
		"https://example.com/page#note=%0d%0ahello", // fragment never sent upstream
	}
	for _, u := range clean {
		result := s.Scan(context.Background(), u)
		if !result.Allowed {
			t.Errorf("expected %s to be allowed, got blocked: %s (scanner: %s)", u, result.Reason, result.Scanner)
		}
	}
}

// --- Path traversal detection ---

func TestScan_BlocksPathTraversal(t *testing.T) {
	s := New(testConfig())

	tests := []struct {
		name string
		url  string
	}{
		{"raw_traversal", "https://example.com/../../../etc/passwd"},
		{"mid_path", "https://example.com/app/../../../etc/shadow"},
		{"encoded_dots", "https://example.com/%2e%2e/%2e%2e/etc/passwd"},
		{"encoded_slash", "https://example.com/..%2f..%2fetc/passwd"},
		{"encoded_backslash", "https://example.com/..%5c..%5cetc/passwd"},
		{"partial_encode_dot_first", "https://example.com/%2e./etc/passwd"},
		{"partial_encode_dot_second", "https://example.com/.%2e/etc/passwd"},
		{"double_encoded", "https://example.com/%252e%252e%252f%252e%252e/etc/passwd"},
		{"trailing_dotdot", "https://example.com/app/.."},
		{"both_seps_encoded", "https://example.com/foo%2f..%2fbar"},
		{"trailing_encoded_sep_dotdot", "https://example.com/foo%2f.."},
		{"backslash_both_seps", "https://example.com/foo%5c..%5cbar"},
		{"mixed_fwd_back", "https://example.com/foo%2f..%5cbar"},
		{"mixed_back_fwd", "https://example.com/foo%5c..%2fbar"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := s.Scan(context.Background(), tc.url)
			if result.Allowed {
				t.Errorf("expected path traversal to be blocked: %s", tc.url)
			}
			if result.Scanner != ScannerPathTraversal {
				t.Errorf("expected scanner %q, got %q", ScannerPathTraversal, result.Scanner)
			}
		})
	}
}

func TestScan_AllowsCleanPathsNoTraversal(t *testing.T) {
	s := New(testConfig())

	clean := []string{
		"https://example.com/normal/path",
		"https://example.com/a/b/c/d",
		"https://example.com/file.tar.gz",
		"https://example.com/api/v2/users",
		"https://example.com/docs/chapter.1.2",
		"https://example.com/%2e%2e%2e/changelog", // three encoded dots, not traversal
		"https://example.com/path/...more",        // ellipsis in segment
	}
	for _, u := range clean {
		result := s.Scan(context.Background(), u)
		if !result.Allowed {
			t.Errorf("expected %s to be allowed, got blocked: %s (scanner: %s)", u, result.Reason, result.Scanner)
		}
	}
}

// --- URL fragment DLP coverage ---

func TestScan_DLPDetectsSecretInFragment(t *testing.T) {
	s := New(testConfig())

	// Secrets in URL fragments are visible to pipelock (agent passes full URL
	// to /fetch?url=...) even though browsers strip fragments before sending.
	// The DLP scanner receives parsed.String() which includes the fragment.
	secretURL := "https://evil.com/callback#token=sk-ant-" + "api03-XXXXXXXXXXXXXXXXXXXXXXX"
	result := s.Scan(context.Background(), secretURL)
	if result.Allowed {
		t.Errorf("expected secret in fragment to be blocked, got allowed")
	}
	if result.Scanner != ScannerDLP {
		t.Errorf("expected scanner %q, got %q", ScannerDLP, result.Scanner)
	}
}

func TestScan_AllowsBenignFragment(t *testing.T) {
	s := New(testConfig())

	result := s.Scan(context.Background(), "https://example.com/page#section-1")
	if !result.Allowed {
		t.Errorf("expected benign fragment to be allowed, got blocked: %s", result.Reason)
	}
}

// --- DLP exempt_domains ---

func TestScan_DLPExemptDomains(t *testing.T) {
	tests := []struct {
		name        string
		exempt      []string
		url         string
		shouldAllow bool
	}{
		{
			name:        "exempt exact domain allows token in path",
			exempt:      []string{"api.telegram.org"},
			url:         "https://api.telegram.org/bot" + "1234567890:" + "AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPqqr/getMe",
			shouldAllow: true,
		},
		{
			name:        "exempt wildcard allows subdomain",
			exempt:      []string{"*.telegram.org"},
			url:         "https://api.telegram.org/bot" + "1234567890:" + "AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPqqr/getMe",
			shouldAllow: true,
		},
		{
			name:        "non-exempt domain still blocked",
			exempt:      []string{"api.telegram.org"},
			url:         "https://evil.com/steal?token=" + "1234567890:" + "AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPqqr",
			shouldAllow: false,
		},
		{
			name:        "no exemptions blocks everywhere",
			exempt:      nil,
			url:         "https://api.telegram.org/bot" + "1234567890:" + "AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPqqr/getMe",
			shouldAllow: false,
		},
		{
			name:        "case insensitive exemption",
			exempt:      []string{"API.Telegram.ORG"},
			url:         "https://api.telegram.org/bot" + "1234567890:" + "AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPqqr/getMe",
			shouldAllow: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := testConfig()
			cfg.Internal = nil
			cfg.FetchProxy.Monitoring.EntropyThreshold = 0 // disable entropy to isolate DLP
			cfg.DLP.Patterns = []config.DLPPattern{
				{
					Name:          "Telegram Bot Token",
					Regex:         `[0-9]{8,10}:[A-Za-z0-9_-]{35}`,
					Severity:      "critical",
					ExemptDomains: tt.exempt,
				},
			}
			s := New(cfg)
			defer s.Close()

			result := s.Scan(context.Background(), tt.url)
			if result.Allowed != tt.shouldAllow {
				if tt.shouldAllow {
					t.Errorf("expected allowed, got blocked: %s (scanner: %s)", result.Reason, result.Scanner)
				} else {
					t.Errorf("expected blocked, got allowed")
				}
			}
		})
	}
}

func TestScan_DLPExemptDomainsOtherPatternsStillFire(t *testing.T) {
	// Exempt domain for one pattern should not affect other patterns.
	cfg := testConfig()
	cfg.Internal = nil
	cfg.FetchProxy.Monitoring.EntropyThreshold = 0 // disable entropy to isolate DLP
	cfg.DLP.Patterns = []config.DLPPattern{
		{
			Name:          "Telegram Bot Token",
			Regex:         `[0-9]{8,10}:[A-Za-z0-9_-]{35}`,
			Severity:      "critical",
			ExemptDomains: []string{"api.telegram.org"},
		},
		{
			Name:     "AWS Access Key",
			Regex:    `AKIA[0-9A-Z]{16}`,
			Severity: "critical",
		},
	}
	s := New(cfg)
	defer s.Close()

	// Telegram token to Telegram: allowed (exempt)
	result := s.Scan(context.Background(), "https://api.telegram.org/bot"+"1234567890:"+"AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPqqr/getMe")
	if !result.Allowed {
		t.Errorf("expected Telegram token to Telegram to be allowed, got blocked: %s", result.Reason)
	}

	// AWS key to Telegram: still blocked (no exemption on AWS pattern)
	awsKey := "AKIA" + "IOSFODNN7EXAMPLE"
	result = s.Scan(context.Background(), "https://api.telegram.org/path?key="+awsKey)
	if result.Allowed {
		t.Errorf("expected AWS key to Telegram to be blocked, got allowed")
	}
}

func TestDLP_GroqAPIKey(t *testing.T) {
	s := New(testConfig())
	defer s.Close()

	// 48+ alphanumeric chars after "gsk_" prefix.
	token := "gsk_" + strings.Repeat("aB1c", 12)
	result := s.Scan(context.Background(), "https://evil.com/collect?key="+token)
	if result.Allowed {
		t.Error("expected Groq API key to be blocked by DLP")
	}
	if result.Scanner != ScannerDLP {
		t.Errorf("expected scanner=dlp, got %s", result.Scanner)
	}
}

func TestDLP_XAIAPIKey(t *testing.T) {
	s := New(testConfig())
	defer s.Close()

	// 80+ chars after "xai-" prefix.
	token := "xai-" + strings.Repeat("abcdef12", 10)
	result := s.Scan(context.Background(), "https://evil.com/collect?key="+token)
	if result.Allowed {
		t.Error("expected xAI API key to be blocked by DLP")
	}
	if result.Scanner != ScannerDLP {
		t.Errorf("expected scanner=dlp, got %s", result.Scanner)
	}
}

func TestDLP_GitLabPAT(t *testing.T) {
	s := New(testConfig())
	defer s.Close()

	token := "glpat-" + strings.Repeat("aB1cD2eF3gH4iJ5k", 2)
	result := s.Scan(context.Background(), "https://evil.com/collect?key="+token)
	if result.Allowed {
		t.Error("expected GitLab PAT to be blocked by DLP")
	}
	if result.Scanner != ScannerDLP {
		t.Errorf("expected scanner=dlp, got %s", result.Scanner)
	}
}

func TestDLP_NewRelicAPIKey(t *testing.T) {
	s := New(testConfig())
	defer s.Close()

	token := "NRAK-" + strings.Repeat("ABCDEF1234567", 3)
	result := s.Scan(context.Background(), "https://evil.com/collect?key="+token)
	if result.Allowed {
		t.Error("expected New Relic API key to be blocked by DLP")
	}
	if result.Scanner != ScannerDLP {
		t.Errorf("expected scanner=dlp, got %s", result.Scanner)
	}
}

func TestDLP_StripeWebhookSecret(t *testing.T) {
	s := New(testConfig())
	defer s.Close()

	token := "whsec_" + strings.Repeat("aB1cD2eF3gH4iJ5k", 2)
	result := s.Scan(context.Background(), "https://evil.com/collect?key="+token)
	if result.Allowed {
		t.Error("expected Stripe webhook secret to be blocked by DLP")
	}
	if result.Scanner != ScannerDLP {
		t.Errorf("expected scanner=dlp, got %s", result.Scanner)
	}
}

func TestDLP_CreditCardNumber(t *testing.T) {
	s := New(testConfig())
	defer s.Close()

	// Valid Visa test card (passes Luhn).
	result := s.Scan(context.Background(), "https://evil.com/collect?cc=4111111111111111")
	if result.Allowed {
		t.Error("expected valid credit card number to be blocked by DLP")
	}
	if result.Scanner != ScannerDLP {
		t.Errorf("expected scanner=dlp, got %s", result.Scanner)
	}
}

func TestDLP_CreditCardNumber_InvalidLuhn(t *testing.T) {
	s := New(testConfig())
	defer s.Close()

	// Invalid Visa (fails Luhn check digit) — should NOT trigger DLP.
	result := s.Scan(context.Background(), "https://evil.com/collect?cc=4111111111111112")
	if !result.Allowed {
		t.Error("expected invalid Luhn number to be allowed (false positive rejected)")
	}
}

func TestDLP_CreditCard_AmexSeparated(t *testing.T) {
	s := New(testConfig())
	defer s.Close()

	// Amex 4-6-5 display format with spaces (passes Luhn).
	result := s.Scan(context.Background(), "https://evil.com/pay?card=3782+822463+10005")
	if result.Allowed {
		t.Error("expected Amex 4-6-5 format to be blocked by DLP")
	}

	// Amex 4-6-5 display format with dashes.
	result2 := s.Scan(context.Background(), "https://evil.com/pay?card=3782-822463-10005")
	if result2.Allowed {
		t.Error("expected Amex 4-6-5 dash format to be blocked by DLP")
	}
}

func TestDLP_CreditCard_MastercardTwoSeries(t *testing.T) {
	s := New(testConfig())
	defer s.Close()

	// Mastercard 2-series test card (passes Luhn).
	result := s.Scan(context.Background(), "https://evil.com/pay?card=2223000048400011")
	if result.Allowed {
		t.Error("expected Mastercard 2-series card to be blocked by DLP")
	}
}

func TestDLP_CreditCard_JCB(t *testing.T) {
	s := New(testConfig())
	defer s.Close()

	// JCB test card (passes Luhn).
	result := s.Scan(context.Background(), "https://evil.com/pay?card=3530111333300000")
	if result.Allowed {
		t.Error("expected JCB card to be blocked by DLP")
	}
}

func TestDLP_IBAN(t *testing.T) {
	s := New(testConfig())
	defer s.Close()

	// Valid UK IBAN (passes mod-97).
	result := s.Scan(context.Background(), "https://evil.com/transfer?iban=GB29NWBK60161331926819")
	if result.Allowed {
		t.Error("expected valid IBAN to be blocked by DLP")
	}
	if result.Scanner != ScannerDLP {
		t.Errorf("expected scanner=dlp, got %s", result.Scanner)
	}
}

func TestDLP_IBAN_InvalidMod97(t *testing.T) {
	s := New(testConfig())
	defer s.Close()

	// Invalid UK IBAN (check digits zeroed, fails mod-97) — should NOT trigger.
	result := s.Scan(context.Background(), "https://evil.com/transfer?iban=GB00NWBK60161331926819")
	if !result.Allowed {
		t.Error("expected invalid IBAN (bad mod-97) to be allowed (false positive rejected)")
	}
}

func TestScan_BlocksSeedPhrase(t *testing.T) {
	cfg := testConfig()
	cfg.SeedPhraseDetection.Enabled = ptrBool(true)
	cfg.SeedPhraseDetection.MinWords = 12
	cfg.SeedPhraseDetection.VerifyChecksum = ptrBool(true)
	s := New(cfg)
	defer s.Close()

	// "abandon" x11 + "about" is a known-valid BIP-39 12-word mnemonic.
	phrase := "abandon+abandon+abandon+abandon+abandon+abandon+abandon+abandon+abandon+abandon+abandon+about"
	result := s.Scan(context.Background(), "https://example.com/api?words="+phrase)
	if result.Allowed {
		t.Error("expected seed phrase in URL query param to be blocked")
	}
	if result.Scanner != ScannerDLP {
		t.Errorf("scanner = %s, want dlp", result.Scanner)
	}
}

func TestScan_AllowsBelowMinWords(t *testing.T) {
	cfg := testConfig()
	cfg.SeedPhraseDetection.Enabled = ptrBool(true)
	cfg.SeedPhraseDetection.MinWords = 12
	cfg.SeedPhraseDetection.VerifyChecksum = ptrBool(false)
	s := New(cfg)
	defer s.Close()

	// 11 words — below threshold.
	phrase := "abandon+abandon+abandon+abandon+abandon+abandon+abandon+abandon+abandon+abandon+abandon"
	result := s.Scan(context.Background(), "https://example.com/api?words="+phrase)
	if !result.Allowed {
		t.Error("expected 11 BIP-39 words to be allowed")
	}
}

func TestScan_SeedPhraseDisabled(t *testing.T) {
	cfg := testConfig()
	cfg.SeedPhraseDetection.Enabled = ptrBool(false)
	s := New(cfg)
	defer s.Close()

	phrase := "abandon+abandon+abandon+abandon+abandon+abandon+abandon+abandon+abandon+abandon+abandon+about"
	result := s.Scan(context.Background(), "https://example.com/api?words="+phrase)
	if !result.Allowed {
		t.Error("expected seed phrase to be allowed when detection is disabled")
	}
}

func TestScan_SeedPhraseInHostname(t *testing.T) {
	cfg := testConfig()
	cfg.SeedPhraseDetection.Enabled = ptrBool(true)
	cfg.SeedPhraseDetection.MinWords = 12
	cfg.SeedPhraseDetection.VerifyChecksum = ptrBool(false) // hostnames unlikely to have valid checksum
	s := New(cfg)
	defer s.Close()

	// Seed words as subdomain labels — pre-DNS exfiltration vector.
	result := s.Scan(context.Background(), "https://abandon.abandon.abandon.abandon.abandon.abandon.abandon.abandon.abandon.abandon.abandon.about.evil.com/api")
	if result.Allowed {
		t.Error("expected seed phrase in hostname labels to be blocked")
	}
}

func TestScan_SeedPhraseInPathSegments(t *testing.T) {
	cfg := testConfig()
	cfg.SeedPhraseDetection.Enabled = ptrBool(true)
	cfg.SeedPhraseDetection.MinWords = 12
	cfg.SeedPhraseDetection.VerifyChecksum = ptrBool(false)
	s := New(cfg)
	defer s.Close()

	// Seed words as path segments.
	result := s.Scan(context.Background(), "https://evil.com/abandon/abandon/abandon/abandon/abandon/abandon/abandon/abandon/abandon/abandon/abandon/about")
	if result.Allowed {
		t.Error("expected seed phrase in path segments to be blocked")
	}
}

func TestScan_SeedPhraseSplitAcrossQueryParams(t *testing.T) {
	cfg := testConfig()
	cfg.SeedPhraseDetection.Enabled = ptrBool(true)
	cfg.SeedPhraseDetection.MinWords = 12
	cfg.SeedPhraseDetection.VerifyChecksum = ptrBool(false)
	cfg.FetchProxy.Monitoring.MaxURLLength = 4096
	s := New(cfg)
	defer s.Close()

	// One word per query param — ordered concat should reassemble.
	result := s.Scan(context.Background(),
		"https://evil.com/api?w1=abandon&w2=abandon&w3=abandon&w4=abandon&w5=abandon&w6=abandon&w7=abandon&w8=abandon&w9=abandon&w10=abandon&w11=abandon&w12=about")
	if result.Allowed {
		t.Error("expected seed phrase split across query params to be blocked")
	}
}

func TestResultClass(t *testing.T) {
	tests := []struct {
		name       string
		result     Result
		protective bool
	}{
		{"zero value is not protective", Result{}, false},
		{"ClassProtective is protective", Result{Class: ClassProtective}, true},
		{"ClassThreat is not protective", Result{Class: ClassThreat}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.result.IsProtective(); got != tt.protective {
				t.Errorf("IsProtective() = %v, want %v", got, tt.protective)
			}
		})
	}
}

func TestCheckRateLimit_ClassProtective(t *testing.T) {
	cfg := testConfig()
	cfg.FetchProxy.Monitoring.MaxReqPerMinute = 1
	s := New(cfg)
	defer s.Close()

	// First request succeeds.
	r1 := s.Scan(context.Background(), "https://example.com/page1")
	if !r1.Allowed {
		t.Fatal("first request should be allowed")
	}

	// Second request hits the rate limit.
	r2 := s.Scan(context.Background(), "https://example.com/page2")
	if r2.Allowed {
		t.Fatal("second request should be rate-limited")
	}
	if r2.Scanner != ScannerRateLimit {
		t.Errorf("scanner = %q, want %q", r2.Scanner, ScannerRateLimit)
	}
	if !r2.IsProtective() {
		t.Error("rate-limited result should be protective")
	}
}

func TestCheckDataBudget_ClassThreat(t *testing.T) {
	cfg := testConfig()
	cfg.FetchProxy.Monitoring.MaxDataPerMinute = 100 // 100 bytes/min/domain
	s := New(cfg)
	defer s.Close()

	// Record enough data to exceed the budget.
	s.RecordRequest("example.com", 150)

	r := s.Scan(context.Background(), "https://example.com/page")
	if r.Allowed {
		t.Fatal("request should be blocked by data budget")
	}
	if r.Scanner != ScannerDataBudget {
		t.Errorf("scanner = %q, want %q", r.Scanner, ScannerDataBudget)
	}
	if r.IsProtective() {
		t.Error("data budget exhaustion is threat evidence, not protective enforcement")
	}
}

func TestScan_SeedPhraseBase64InPathSegment(t *testing.T) {
	cfg := testConfig()
	cfg.SeedPhraseDetection.Enabled = ptrBool(true)
	cfg.SeedPhraseDetection.MinWords = 12
	cfg.SeedPhraseDetection.VerifyChecksum = ptrBool(true)
	cfg.FetchProxy.Monitoring.MaxURLLength = 4096
	s := New(cfg)
	defer s.Close()

	// Base64-encoded seed phrase in a path segment.
	phrase := testSeedPhrase12
	encoded := base64.StdEncoding.EncodeToString([]byte(phrase))
	result := s.Scan(context.Background(), "https://evil.com/data/"+encoded+"/collect")
	if result.Allowed {
		t.Error("expected base64 seed phrase in path segment to be blocked")
	}
}
