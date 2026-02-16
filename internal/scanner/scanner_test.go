package scanner

import (
	"encoding/base32"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

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
		result := s.Scan(url)
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
		result := s.Scan(tt.url)
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
		{"https://example.com/path?token=AKIAIOSFODNN7EXAMPLE", "AWS Access Key"},
		{"https://example.com/path/ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl", "GitHub Token"},
	}

	for _, tt := range tests {
		result := s.Scan(tt.url)
		if result.Allowed {
			t.Errorf("expected %s to be blocked (DLP: %s)", tt.url, tt.pattern)
		}
		if result.Scanner != "dlp" { //nolint:goconst // test value
			t.Errorf("expected scanner=dlp for %s, got %s", tt.url, result.Scanner)
		}
	}
}

func TestScan_BlocksHighEntropySegments(t *testing.T) {
	s := New(testConfig())

	// Random base64-like string (high entropy, >20 chars)
	highEntropy := "https://example.com/data/aB3xK9mQ7pR2wE5tY8uI0oL4hG6fD1sZ"
	result := s.Scan(highEntropy)
	if result.Allowed {
		t.Error("expected high-entropy URL to be blocked")
	}
	if result.Scanner != "entropy" { //nolint:goconst // test value
		t.Errorf("expected scanner=entropy, got %s", result.Scanner)
	}
}

func TestScan_AllowsLowEntropySegments(t *testing.T) {
	s := New(testConfig())

	// Normal text path (low entropy)
	normalURL := "https://example.com/articles/how-to-write-golang-tests"
	result := s.Scan(normalURL)
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
	result := s.Scan(longURL)
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
		result := s.Scan(url)
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

	result := s.Scan("://not-a-url")
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
		result := s.Scan(url)
		if result.Allowed {
			t.Errorf("expected %s to be blocked (SSRF)", url)
		}
		if result.Scanner != "ssrf" {
			t.Errorf("expected scanner=ssrf for %s, got %s", url, result.Scanner)
		}
	}
}

func TestScan_EntropySkipsShortSegments(t *testing.T) {
	s := New(testConfig())

	// Short high-entropy segment (<20 chars) should be allowed
	shortEntropy := "https://example.com/aB3xK9mQ7"
	result := s.Scan(shortEntropy)
	if !result.Allowed {
		t.Errorf("expected short segment to be allowed, got blocked: %s", result.Reason)
	}
}

func TestScan_DLPChecksQueryValues(t *testing.T) {
	s := New(testConfig())

	// AWS key in query parameter value
	url := "https://api.example.com/data?access_key=AKIAIOSFODNN7EXAMPLE" //nolint:gosec // G101: test fake key
	result := s.Scan(url)
	if result.Allowed {
		t.Error("expected DLP to catch AWS key in query value")
	}
}

func TestScan_DisabledEntropy(t *testing.T) {
	cfg := testConfig()
	cfg.FetchProxy.Monitoring.EntropyThreshold = 0 // disabled
	s := New(cfg)

	highEntropy := "https://example.com/data/aB3xK9mQ7pR2wE5tY8uI0oL4hG6fD1sZ"
	result := s.Scan(highEntropy)
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
	result := s.Scan(longURL)
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
	result := s.Scan("https://example.com/data/aB3xK9mQ7pR2wE5tY8uI0oL4hG6fD1sZ")
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

	result := s.Scan("https://example.com/page?data=aB3xK9mQ7pR2wE5tY8uI0oL4hG6fD1sZ")
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
	result := s.Scan("http://127.0.0.1/test")
	if !result.Allowed {
		t.Errorf("expected 127.0.0.1 allowed with nil CIDRs, got blocked: %s", result.Reason)
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
	result := s.Scan("https://example.com/api?data=-----BEGIN%20PRIVATE%20KEY-----")
	if result.Allowed {
		t.Error("expected DLP to catch URL-encoded private key header")
	}
	if result.Scanner != "dlp" {
		t.Errorf("expected scanner=dlp, got %s", result.Scanner)
	}
}

func TestScan_DLPCatchesURLEncodedDashes(t *testing.T) {
	s := New(testConfig())

	// Anthropic key with URL-encoded dashes (%2D instead of '-')
	result := s.Scan("https://example.com/api?key=sk%2Dant%2DabcdefghijklmnopqrstuVW")
	if result.Allowed {
		t.Error("expected DLP to catch URL-encoded Anthropic key")
	}
	if result.Scanner != "dlp" {
		t.Errorf("expected scanner=dlp, got %s", result.Scanner)
	}
}

func TestScan_DLPChecksDecodedQueryKeys(t *testing.T) {
	s := New(testConfig())

	// AWS key stuffed into a query parameter NAME
	result := s.Scan("https://example.com/api?AKIAIOSFODNN7EXAMPLE=true")
	if result.Allowed {
		t.Error("expected DLP to catch secret in query key")
	}
}

func TestScan_DLPCatchesDoubleEncodedSecret(t *testing.T) {
	s := New(testConfig())

	// Double-encoded dashes: %252D → first decode → %2D → second decode → -
	result := s.Scan("https://example.com/api?key=sk%252Dant%252DabcdefghijklmnopqrstuVW")
	if result.Allowed {
		t.Error("expected DLP to catch double-encoded Anthropic key")
	}
	if result.Scanner != "dlp" {
		t.Errorf("expected scanner=dlp, got %s", result.Scanner)
	}
}

func TestScan_DLPCatchesTripleEncodedSecret(t *testing.T) {
	s := New(testConfig())

	// Triple-encoded: %25252D → %252D → %2D → -
	result := s.Scan("https://example.com/api?key=sk%25252Dant%25252DabcdefghijklmnopqrstuVW")
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
			got := iterativeDecode(tt.input)
			if got != tt.want {
				t.Errorf("iterativeDecode(%q) = %q, want %q", tt.input, got, tt.want)
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
	result := s.Scan("https://example.com/api?aB3xK9mQ7pR2wE5tY8uI0=true")
	if result.Allowed {
		t.Error("expected high-entropy query key to be blocked")
	}
	if result.Scanner != "entropy" {
		t.Errorf("expected scanner=entropy, got %s", result.Scanner)
	}
}

// --- Additional Scanner Edge Cases ---

func TestScan_EmptyURL(t *testing.T) {
	s := New(testConfig())
	result := s.Scan("")
	if result.Allowed {
		t.Error("expected empty URL to be blocked")
	}
}

func TestScan_URLWithPort(t *testing.T) {
	s := New(testConfig())
	result := s.Scan("https://example.com:8443/api/data")
	if !result.Allowed {
		t.Errorf("expected URL with port to be allowed, got: %s", result.Reason)
	}
}

func TestScan_URLWithUserInfo(t *testing.T) {
	s := New(testConfig())
	// URL with userinfo (user:pass@host) — should still scan the hostname correctly
	result := s.Scan("https://user:pass@example.com/page")
	if !result.Allowed {
		t.Errorf("expected URL with userinfo to be allowed, got: %s", result.Reason)
	}
}

func TestScan_URLWithFragment(t *testing.T) {
	s := New(testConfig())
	result := s.Scan("https://example.com/page#section-1")
	if !result.Allowed {
		t.Errorf("expected URL with fragment to be allowed, got: %s", result.Reason)
	}
}

func TestScan_DLPInPath(t *testing.T) {
	s := New(testConfig())
	// AWS key directly in the path
	result := s.Scan("https://example.com/upload/AKIAIOSFODNN7EXAMPLE/file.txt")
	if result.Allowed {
		t.Error("expected DLP to catch AWS key in URL path")
	}
	if result.Scanner != "dlp" {
		t.Errorf("expected scanner=dlp, got %s", result.Scanner)
	}
}

func TestScan_DLPInSubdomain(t *testing.T) {
	s := New(testConfig())
	// Secret encoded as a subdomain label — bypassed DLP before full-URL scanning.
	result := s.Scan("https://sk-proj-abc123def456ghi789jkl012.evil.com/")
	if result.Allowed {
		t.Error("expected DLP to catch OpenAI key in subdomain")
	}
	if result.Scanner != "dlp" {
		t.Errorf("expected scanner=dlp, got %s", result.Scanner)
	}
}

func TestScan_DLPKeySplitAcrossParams(t *testing.T) {
	s := New(testConfig())
	// Key prefix in one param — full URL scan catches the prefix in the raw string.
	result := s.Scan("https://example.com/callback?a=sk-proj-abc123def456ghi789jkl012mno345&b=extra")
	if result.Allowed {
		t.Error("expected DLP to catch OpenAI key split across params")
	}
}

func TestScan_DLPAWSKeyInSubdomain(t *testing.T) {
	s := New(testConfig())
	result := s.Scan("https://AKIAIOSFODNN7EXAMPLE.s3.evil.com/data")
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
			result := s.Scan(tt.url)
			if tt.blocked && result.Allowed {
				t.Errorf("expected DLP to block dot-split secret in %s", tt.url)
			}
			if !tt.blocked && !result.Allowed {
				t.Errorf("expected normal URL to be allowed: %s (blocked: %s)", tt.url, result.Reason)
			}
			if tt.blocked && result.Scanner != "dlp" {
				t.Errorf("expected scanner=dlp, got %s", result.Scanner)
			}
		})
	}
}

func TestScan_DLPSlackToken(t *testing.T) {
	s := New(testConfig())
	result := s.Scan("https://example.com/api?token=xoxb-1234567890-abcdefghij")
	if result.Allowed {
		t.Error("expected DLP to catch Slack token")
	}
}

func TestScan_DLPPrivateKey(_ *testing.T) {
	s := New(testConfig())
	// Private key header in query (URL-encoded scenario)
	result := s.Scan("https://example.com/api?data=-----BEGIN%20PRIVATE%20KEY-----")
	// Note: the DLP checks decoded query values, so this might or might not match
	// depending on whether the raw or decoded query is checked.
	// At minimum, it should not panic.
	_ = result
}

func TestScan_DLPOpenAIKey(t *testing.T) {
	s := New(testConfig())
	result := s.Scan("https://example.com/api?key=sk-proj-abcdefghijklmnopqrstuvwxyz")
	if result.Allowed {
		t.Error("expected DLP to catch OpenAI key")
	}
}

func TestScan_DLPOpenAIKey_OldFormatNotMatched(t *testing.T) {
	s := New(testConfig())
	// Old sk- prefix without proj- should NOT be caught (too broad)
	result := s.Scan("https://example.com/api?key=sk-abcdefghijklmnopqrstuvwxyz")
	if !result.Allowed {
		// May still be caught by entropy, check it's not DLP
		if result.Scanner == "dlp" {
			t.Error("expected old sk- prefix NOT to trigger DLP (too broad)")
		}
	}
}

func TestScan_DLPDiscordBotToken(t *testing.T) {
	s := New(testConfig())
	// Build token from parts to avoid GitHub push protection false positive.
	// Discord bot token format: M + 23+ chars . 6 chars . 27+ chars
	token := "MTIzNDU2Nzg5MDEyMzQ1Njc4" + "." + "AbCdEf" + "." + "ABCDEFGHIJKLMNOPQRSTUVWXYZabc"
	result := s.Scan("https://example.com/api?token=" + token)
	if result.Allowed {
		t.Error("expected DLP to catch Discord bot token")
	}
}

func TestScan_NoDLPPatterns(t *testing.T) {
	cfg := testConfig()
	cfg.DLP.Patterns = nil
	s := New(cfg)

	// Should not be blocked even with a secret-like string
	result := s.Scan("https://example.com/api?key=AKIAIOSFODNN7EXAMPLE")
	if !result.Allowed {
		t.Errorf("expected URL allowed with no DLP patterns, got: %s (%s)", result.Reason, result.Scanner)
	}
}

func TestScan_EmptyBlocklist(t *testing.T) {
	cfg := testConfig()
	cfg.FetchProxy.Monitoring.Blocklist = nil
	s := New(cfg)

	result := s.Scan("https://pastebin.com/raw/abc123")
	if !result.Allowed {
		t.Errorf("expected pastebin allowed with empty blocklist, got: %s", result.Reason)
	}
}

func TestScan_BlocklistExactMatch(t *testing.T) {
	cfg := testConfig()
	// Use exact match (no wildcard)
	cfg.FetchProxy.Monitoring.Blocklist = []string{"evil.com"}
	s := New(cfg)

	result := s.Scan("https://evil.com/exfil")
	if result.Allowed {
		t.Error("expected exact blocklist match to block")
	}

	// Subdomain should NOT be blocked by exact match
	result = s.Scan("https://sub.evil.com/exfil")
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
	result := s.Scan(exactURL)
	if !result.Allowed {
		t.Errorf("expected URL at exact max length to be allowed, got: %s", result.Reason)
	}

	// URL one char over
	overURL := exactURL + "b"
	result = s.Scan(overURL)
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
	result := s.Scan("https://example.com/abcdefghijklmnopqrst")
	if result.Allowed {
		t.Error("expected string with entropy above threshold to be blocked")
	}
}

func TestScan_NumericOnlyPath(t *testing.T) {
	s := New(testConfig())
	// Numeric IDs (low entropy since only digits 0-9)
	result := s.Scan("https://example.com/api/12345678901234567890")
	if !result.Allowed {
		t.Errorf("expected numeric path to be allowed (low entropy), got: %s", result.Reason)
	}
}

func TestScan_RepeatedCharsPath(t *testing.T) {
	s := New(testConfig())
	// All same character — entropy=0
	result := s.Scan("https://example.com/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if !result.Allowed {
		t.Errorf("expected repeated chars to be allowed (zero entropy), got: %s", result.Reason)
	}
}

func TestScan_HexString(t *testing.T) {
	cfg := testConfig()
	cfg.FetchProxy.Monitoring.EntropyThreshold = 4.5
	s := New(cfg)

	// Hex string (entropy ~4.0 for random hex) — should be below 4.5 threshold
	result := s.Scan("https://example.com/commit/deadbeefcafebabe1234")
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
	result := s.Scan("https://example.com/data/aR7kM3qX9wB5tY2cE8nP4jL6hG0fD1sV")
	if result.Allowed {
		t.Error("expected high-entropy base64-like string to be blocked")
	}
	if result.Scanner != "entropy" {
		t.Errorf("expected scanner=entropy, got %s", result.Scanner)
	}
}

func TestScan_MultipleQueryParams_OneTriggering(t *testing.T) {
	s := New(testConfig())

	// One query param is a secret, others are normal
	result := s.Scan("https://example.com/api?user=josh&page=1&key=AKIAIOSFODNN7EXAMPLE")
	if result.Allowed {
		t.Error("expected URL with secret in one query param to be blocked")
	}
	if result.Scanner != "dlp" {
		t.Errorf("expected scanner=dlp, got %s", result.Scanner)
	}
}

func TestScan_BlocklistCaseInsensitive(t *testing.T) {
	s := New(testConfig())

	// Hostname should be lowered before matching
	result := s.Scan("https://PASTEBIN.COM/raw/abc")
	if result.Allowed {
		t.Error("expected case-insensitive blocklist match")
	}
}

func TestScan_AllScannersPass(t *testing.T) {
	s := New(testConfig())

	result := s.Scan("https://example.com/page?q=hello")
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
	result := s.Scan("data:text/html,<script>alert(1)</script>")
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
	result := s.Scan("http://localhost/test")
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
	result := s.Scan("https://sk-ant-abcdefghijklmnopqrstuVW.evil.com/exfil")
	if result.Allowed {
		t.Fatal("expected DLP to catch secret in hostname")
	}
	if result.Scanner != "dlp" {
		t.Errorf("expected scanner=dlp (runs before DNS), got %s", result.Scanner)
	}
}

func TestScan_EntropyInQueryParam(t *testing.T) {
	cfg := testConfig()
	cfg.FetchProxy.Monitoring.EntropyThreshold = 4.0
	cfg.DLP.Patterns = nil // disable DLP so entropy is checked
	s := New(cfg)

	result := s.Scan("https://example.com/page?data=aB3xK9mQ7pR2wE5tY8uI")
	if result.Allowed {
		t.Error("expected high-entropy query param to be blocked")
	}
	if result.Scanner != "entropy" {
		t.Errorf("expected scanner=entropy, got %s", result.Scanner)
	}
}

func TestScan_URLWithEncodedCharacters(t *testing.T) {
	s := New(testConfig())
	// URL-encoded characters in path — should be treated normally
	result := s.Scan("https://example.com/search?q=hello%20world&lang=en")
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
	result := s.Scan("https://example.com/api?key=AKIAIOSFODNN7EXAMPLE&junk=%ZZ")
	if result.Allowed {
		t.Error("expected DLP to catch AWS key even with malformed percent-encoding in query")
	}
	if result.Scanner != "dlp" {
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

	result := s.Scan("https://example.com/page")
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

	result := s.Scan("https://example.com/page")
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
	result := s.Scan("https://example.com/page")
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
	result := s.Scan("https://example.com/page")
	if !result.Allowed {
		t.Errorf("expected allowed at 400/500 bytes, blocked: %s", result.Reason)
	}

	// Record 200 more to exceed
	s.RecordRequest("example.com", 200)

	result = s.Scan("https://example.com/page")
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

	result := s.Scan("https://example.com/page")
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
	prefix := "sk-ant-"                    //nolint:goconst // test value
	suffix := "abcdefghijklmnopqrstuvwxyz" //nolint:goconst // test value
	zwsp := "\u200B"                       // zero-width space
	url := "https://example.com/api?key=" + prefix + zwsp + suffix

	result := s.Scan(url)
	if result.Allowed {
		t.Error("expected DLP to catch zero-width bypass of API key pattern")
	}
}

// --- DLP new pattern tests ---

func TestScan_DLP_GitHubFinegrainedPAT(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	// Build token at runtime to avoid gitleaks
	token := "github_pat_" + "aB1cD2eF3gH4iJ5kL6mN7oP8qR9sT0uV1wX2yZ3aB4cD5eF"
	result := s.Scan("https://example.com/api?token=" + token)
	if result.Allowed {
		t.Error("expected DLP to catch GitHub Fine-Grained PAT")
	}
}

func TestScan_DLP_OpenAIServiceKey(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	// Build key at runtime
	key := "sk-svcacct-" + "abcdefghijklmnopqrstuvwxyz"
	result := s.Scan("https://example.com/api?key=" + key)
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
	result := s.Scan("https://example.com/api?key=" + key)
	if result.Allowed {
		t.Error("expected DLP to catch Stripe live key")
	}
}

func TestScan_DLP_StripeTestKey(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	key := "rk_test_" + "abcdefghijklmnopqrstuvwx"
	result := s.Scan("https://example.com/api?key=" + key)
	if result.Allowed {
		t.Error("expected DLP to catch Stripe test restricted key")
	}
}

// --- Env leak encoding tests ---

func TestScan_EnvLeak_HexEncoded(t *testing.T) {
	cfg := testConfig()
	cfg.DLP.ScanEnv = true
	s := New(cfg)
	defer s.Close()

	// Inject a known env secret into the scanner's env secrets list
	secret := "SuperSecretValue123456" //nolint:goconst // test value
	s.envSecrets = []string{secret}

	// Hex encode the secret
	hexEncoded := ""
	for _, b := range []byte(secret) {
		hexEncoded += fmt.Sprintf("%02x", b)
	}

	result := s.Scan("https://example.com/exfil?data=" + hexEncoded)
	if result.Allowed {
		t.Error("expected hex-encoded env leak to be caught")
	}
	if result.Scanner != "dlp" {
		t.Errorf("expected scanner=dlp, got %s", result.Scanner)
	}
}

func TestScan_EnvLeak_Base32Encoded(t *testing.T) {
	cfg := testConfig()
	cfg.DLP.ScanEnv = true
	s := New(cfg)
	defer s.Close()

	secret := "SuperSecretValue123456"
	s.envSecrets = []string{secret}

	// Base32 StdEncoding
	encoded := base32.StdEncoding.EncodeToString([]byte(secret))

	result := s.Scan("https://example.com/exfil?data=" + encoded)
	if result.Allowed {
		t.Error("expected base32-encoded env leak to be caught")
	}
}

func TestScan_EnvLeak_Base32NoPadding(t *testing.T) {
	cfg := testConfig()
	cfg.DLP.ScanEnv = true
	s := New(cfg)
	defer s.Close()

	secret := "SuperSecretValue123456"
	s.envSecrets = []string{secret}

	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte(secret))

	result := s.Scan("https://example.com/exfil?data=" + encoded)
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
	result := s.Scan("https://d.evil.com/")
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
			result := s.Scan(tt.url)
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
			result := s.Scan(tt.url)
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

	result := s.Scan("https://r7km2np9qw4xb5vy8za3.evil.com/")
	if !result.Allowed {
		t.Error("expected subdomain entropy check to be disabled when threshold is 0")
	}
}

func TestDLP_GoogleOAuthToken(t *testing.T) {
	s := New(testConfig())
	defer s.Close()

	//nolint:goconst // test value
	token := "ya29." + "ABCDEFghijklmnopqrstuvwx"
	result := s.Scan("https://evil.com/collect?token=" + token)
	if result.Allowed {
		t.Error("expected Google OAuth token to be blocked by DLP")
	}
	if result.Scanner != "dlp" {
		t.Errorf("expected scanner=dlp, got %s", result.Scanner)
	}
}

func TestDLP_TwilioAPIKey(t *testing.T) {
	s := New(testConfig())
	defer s.Close()

	// Build a Twilio key pattern at runtime to avoid gitleaks
	key := "SK" + "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"
	result := s.Scan("https://evil.com/collect?key=" + key)
	if result.Allowed {
		t.Error("expected Twilio API key to be blocked by DLP")
	}
	if result.Scanner != "dlp" {
		t.Errorf("expected scanner=dlp, got %s", result.Scanner)
	}
}

func TestDLP_SendGridAPIKey(t *testing.T) {
	s := New(testConfig())
	defer s.Close()

	// Build SendGrid key pattern at runtime to avoid gitleaks
	key := "SG." + "abcdefghijklmnopqrstuv" + "." + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqr"
	result := s.Scan("https://evil.com/collect?key=" + key)
	if result.Allowed {
		t.Error("expected SendGrid API key to be blocked by DLP")
	}
	if result.Scanner != "dlp" {
		t.Errorf("expected scanner=dlp, got %s", result.Scanner)
	}
}

func TestDLP_MailgunAPIKey(t *testing.T) {
	s := New(testConfig())
	defer s.Close()

	// Build Mailgun key pattern at runtime to avoid gitleaks
	key := "key-" + "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"
	result := s.Scan("https://evil.com/collect?key=" + key)
	if result.Allowed {
		t.Error("expected Mailgun API key to be blocked by DLP")
	}
	if result.Scanner != "dlp" {
		t.Errorf("expected scanner=dlp, got %s", result.Scanner)
	}
}

// --- Control char DLP bypass tests (fetch proxy URL path) ---

func TestScan_DLP_ControlCharBypass(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	// Build key at runtime to avoid gitleaks
	prefix := "sk-ant-"
	suffix := "abcdefghijklmnopqrstuvwxyz" //nolint:goconst // test value

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
			result := s.Scan(url)
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
	prefix := "sk-ant-"
	suffix := "abcdefghijklmnopqrstuvwxyz" //nolint:goconst // test value
	url := "https://example.com/" + prefix + "\x00" + suffix
	result := s.Scan(url)
	if result.Allowed {
		t.Error("expected DLP to catch key with null byte in path")
	}
}

func TestScan_DLP_MultipleControlChars(t *testing.T) {
	cfg := testConfig()
	s := New(cfg)
	defer s.Close()

	// Multiple different control chars scattered through the secret
	prefix := "sk-ant-"
	suffix := "abcdefghijklmnopqrstuvwxyz" //nolint:goconst // test value
	url := "https://example.com/api?key=" + prefix + "\x08\x09\x0a" + suffix
	result := s.Scan(url)
	if result.Allowed {
		t.Error("expected DLP to catch key with multiple control chars")
	}
}

func TestScan_AllowlistBlocksUnlistedDomain(t *testing.T) {
	cfg := testConfig()
	cfg.Mode = config.ModeStrict
	cfg.APIAllowlist = []string{"api.openai.com", "*.anthropic.com"}
	s := New(cfg)

	result := s.Scan("https://evil.com/exfil")
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

	result := s.Scan("https://api.openai.com/v1/chat")
	if !result.Allowed {
		t.Errorf("expected allowlisted domain to be allowed, got blocked: %s", result.Reason)
	}
}

func TestScan_AllowlistPermitsWildcard(t *testing.T) {
	cfg := testConfig()
	cfg.Mode = config.ModeStrict
	cfg.APIAllowlist = []string{"*.anthropic.com"}
	s := New(cfg)

	result := s.Scan("https://api.anthropic.com/v1/messages")
	if !result.Allowed {
		t.Errorf("expected wildcard-matched domain to be allowed, got blocked: %s", result.Reason)
	}
}

func TestScan_AllowlistEmptyPermitsAll(t *testing.T) {
	cfg := testConfig()
	cfg.Mode = config.ModeStrict
	cfg.APIAllowlist = nil
	s := New(cfg)

	result := s.Scan("https://anything.example.com/path")
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
	result := s.Scan("https://example.com/page")
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
	result := s.Scan("https://example.com/page")
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
	result := s.Scan("https://API.OpenAI.com/v1/chat")
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

	result := s.Scan("https://pastebin.com/raw/abc")
	if result.Allowed {
		t.Fatal("expected domain to be blocked")
	}
	// Allowlist should fire BEFORE blocklist
	if result.Scanner != "allowlist" {
		t.Errorf("expected scanner=allowlist (checked first), got %s", result.Scanner)
	}
}
