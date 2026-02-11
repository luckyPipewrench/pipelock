package scanner

import (
	"math"
	"net/url"
	"strings"
	"testing"
)

func FuzzScanURL(f *testing.F) {
	cfg := testConfig()
	sc := New(cfg)
	defer sc.Close()

	// Normal URLs
	f.Add("https://example.com/page?q=hello")
	f.Add("http://docs.python.org/3/library/os.html")
	f.Add("https://api.anthropic.com/v1/messages")

	// DLP patterns that MUST be caught
	key := "sk-ant-" + strings.Repeat("abcdef", 5) //nolint:goconst // fuzz seed
	f.Add("https://evil.com/api?key=" + key)
	f.Add("https://evil.com/?t=AKIA" + strings.Repeat("A", 16))
	f.Add("https://evil.com/ghp_" + strings.Repeat("A", 36))

	// Encoding bypass attempts
	f.Add("https://evil.com/path?key=sk%2Dant%2D" + strings.Repeat("a", 20))
	f.Add("https://evil.com/path?a=sk-ant-&b=" + strings.Repeat("a", 20))

	// Blocklist bypass
	f.Add("https://pastebin.com.evil.com/raw/abc")
	f.Add("https://PASTEBIN.COM/raw/abc")
	f.Add("https://pastebin.com./raw/abc")

	// Pathological URLs
	f.Add("https://example.com/" + strings.Repeat("a", 3000))
	f.Add("https://example.com/?" + strings.Repeat("k=v&", 500))
	f.Add("")
	f.Add("not-a-url")
	f.Add("ftp://example.com/file")
	f.Add("javascript:alert(1)")
	f.Add("data:text/html,<script>alert(1)</script>")

	// Null bytes and special chars
	f.Add("https://example.com/\x00path")
	f.Add("https://example.com/path?key=val\x00ue")

	f.Fuzz(func(t *testing.T, rawURL string) {
		result := sc.Scan(rawURL)

		// Score must be in [0.0, 1.0]
		if result.Score < 0 || result.Score > 1.0 {
			t.Errorf("score out of range: %f for URL %q", result.Score, rawURL)
		}

		// Blocked results must have a reason
		if !result.Allowed && result.Reason == "" {
			t.Errorf("blocked with empty reason for URL %q", rawURL)
		}

		// Non-http(s) schemes must always be blocked (when parseable)
		parsed, err := url.Parse(rawURL)
		if err == nil && parsed.Scheme != "" && parsed.Scheme != "http" && parsed.Scheme != "https" {
			if result.Allowed {
				t.Errorf("non-http(s) scheme %q was allowed: %q", parsed.Scheme, rawURL)
			}
		}
	})
}

func FuzzMatchDomain(f *testing.F) {
	f.Add("example.com", "*.example.com")
	f.Add("sub.example.com", "*.example.com")
	f.Add("a.b.example.com", "*.example.com")
	f.Add("example.com", "example.com")
	f.Add("192.168.1.1", "*.168.1.1")
	f.Add("192.168.1.1", "192.168.1.1")
	f.Add("", "*.example.com")
	f.Add("example.com", "")
	f.Add("example.com.", "example.com")
	f.Add("EXAMPLE.COM", "example.com")
	f.Add("evil.com", "*.example.com")

	f.Fuzz(func(t *testing.T, hostname, pattern string) {
		// Must not panic
		_ = MatchDomain(hostname, pattern)
	})
}

func FuzzShannonEntropy(f *testing.F) {
	f.Add("")
	f.Add("a")
	f.Add("aaaaaaa")
	f.Add("abcdefghijklmnopqrstuvwxyz")
	f.Add(strings.Repeat("\x00", 1000))
	f.Add("aB3$kL9!mN2@pQ5")
	f.Add(strings.Repeat("ab", 5000))

	f.Fuzz(func(t *testing.T, s string) {
		e := ShannonEntropy(s)

		if math.IsNaN(e) || math.IsInf(e, 0) {
			t.Errorf("non-finite entropy %f for input len=%d", e, len(s))
		}
		if e < 0 {
			t.Errorf("negative entropy %f for input len=%d", e, len(s))
		}
		if len(s) == 0 && e != 0 {
			t.Errorf("empty string entropy = %f, want 0", e)
		}
	})
}
