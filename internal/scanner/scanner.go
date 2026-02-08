// Package scanner provides URL scanning for the Pipelock fetch proxy.
// It checks URLs against blocklists, DLP patterns, and entropy thresholds
// before allowing the fetch proxy to retrieve them.
package scanner

import (
	"encoding/base64"
	"fmt"
	"math"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// Result describes the outcome of scanning a URL.
type Result struct {
	Allowed bool    `json:"allowed"`
	Reason  string  `json:"reason,omitempty"`
	Scanner string  `json:"scanner,omitempty"` // which scanner triggered
	Score   float64 `json:"score"`             // anomaly score 0.0-1.0
}

// Scanner checks URLs for suspicious content before fetching.
type Scanner struct {
	blocklist        []string
	dlpPatterns      []*compiledPattern
	entropyThreshold float64
	entropyMinLen    int
	maxURLLength     int
	internalCIDRs    []*net.IPNet
	rateLimiter      *RateLimiter
	envSecrets       []string // filtered high-entropy env var values
}

type compiledPattern struct {
	name     string
	re       *regexp.Regexp
	severity string
}

// New creates a Scanner from config. Config must be validated first via
// config.Validate() — this function panics on invalid DLP patterns or CIDRs
// because those represent programming errors (validation should have caught them).
func New(cfg *config.Config) *Scanner {
	s := &Scanner{
		blocklist:        cfg.FetchProxy.Monitoring.Blocklist,
		entropyThreshold: cfg.FetchProxy.Monitoring.EntropyThreshold,
		entropyMinLen:    20,
		maxURLLength:     cfg.FetchProxy.Monitoring.MaxURLLength,
	}

	// Initialize rate limiter if enabled
	if cfg.FetchProxy.Monitoring.MaxReqPerMinute > 0 {
		s.rateLimiter = NewRateLimiter(cfg.FetchProxy.Monitoring.MaxReqPerMinute)
	}

	// Compile DLP patterns — must succeed since config.Validate checks these
	for _, p := range cfg.DLP.Patterns {
		re, err := regexp.Compile(p.Regex)
		if err != nil {
			panic(fmt.Sprintf("BUG: DLP pattern %q failed to compile after validation: %v", p.Name, err))
		}
		s.dlpPatterns = append(s.dlpPatterns, &compiledPattern{
			name:     p.Name,
			re:       re,
			severity: p.Severity,
		})
	}

	// Parse internal CIDRs — must succeed since config.Validate checks these
	for _, cidr := range cfg.Internal {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(fmt.Sprintf("BUG: internal CIDR %q failed to parse after validation: %v", cidr, err))
		}
		s.internalCIDRs = append(s.internalCIDRs, ipNet)
	}

	// Extract high-entropy environment variables for leak detection
	if cfg.DLP.ScanEnv {
		s.envSecrets = extractEnvSecrets()
	}

	return s
}

// Close releases scanner resources, including stopping the rate limiter
// cleanup goroutine. Safe to call multiple times.
func (s *Scanner) Close() {
	if s.rateLimiter != nil {
		s.rateLimiter.Close()
	}
}

// RecordRequest records a request timestamp for rate limiting.
// Call this AFTER Scan() returns Allowed=true and the request will be fetched.
func (s *Scanner) RecordRequest(hostname string) {
	if s.rateLimiter != nil {
		s.rateLimiter.Record(hostname)
	}
}

// Scan checks a URL against all scanners and returns the result.
// It runs scheme, SSRF, blocklist, rate limit, URL length, DLP, and entropy checks in order.
func (s *Scanner) Scan(rawURL string) Result {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return Result{Allowed: false, Reason: "invalid URL", Scanner: "parser", Score: 1.0}
	}

	// Normalize hostname for consistent matching
	hostname := strings.ToLower(parsed.Hostname())

	// 1. Scheme check
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return Result{
			Allowed: false,
			Reason:  fmt.Sprintf("scheme %q not allowed: only http and https", parsed.Scheme),
			Scanner: "scheme",
			Score:   1.0,
		}
	}

	// 2. SSRF protection — block requests to internal/private IPs
	if result := s.checkSSRF(hostname); !result.Allowed {
		return result
	}

	// 3. Blocklist check
	if result := s.checkBlocklist(hostname); !result.Allowed {
		return result
	}

	// 4. Rate limit check (per-domain)
	if result := s.checkRateLimit(hostname); !result.Allowed {
		return result
	}

	// 5. URL length check
	if s.maxURLLength > 0 && len(rawURL) > s.maxURLLength {
		return Result{
			Allowed: false,
			Reason:  fmt.Sprintf("URL length %d exceeds maximum %d", len(rawURL), s.maxURLLength),
			Scanner: "length",
			Score:   0.8,
		}
	}

	// 6. DLP pattern matching on path + query
	if result := s.checkDLP(parsed); !result.Allowed {
		return result
	}

	// 7. Entropy check on path segments and query values
	if result := s.checkEntropy(parsed); !result.Allowed {
		return result
	}

	return Result{Allowed: true, Scanner: "all", Score: 0.0}
}

// checkSSRF blocks requests to internal/private IP ranges.
// When no internal CIDRs are configured (nil slice), SSRF protection is disabled.
// To block loopback, link-local, etc., include those CIDRs in config.Internal.
func (s *Scanner) checkSSRF(hostname string) Result {
	if len(s.internalCIDRs) == 0 {
		return Result{Allowed: true}
	}

	// Resolve hostname to IP for SSRF check.
	// Fail closed: if we can't resolve DNS, we can't verify the IP is safe.
	ips, err := net.LookupHost(hostname)
	if err != nil {
		return Result{
			Allowed: false,
			Reason:  fmt.Sprintf("SSRF check failed: DNS resolution error for %s: %v", hostname, err),
			Scanner: "ssrf",
			Score:   1.0,
		}
	}

	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}

		// Check against internal CIDRs
		for _, cidr := range s.internalCIDRs {
			if cidr.Contains(ip) {
				return Result{
					Allowed: false,
					Reason:  fmt.Sprintf("SSRF blocked: %s resolves to internal IP %s", hostname, ipStr),
					Scanner: "ssrf",
					Score:   1.0,
				}
			}
		}

	}

	return Result{Allowed: true}
}

// checkBlocklist checks the hostname against the domain blocklist.
func (s *Scanner) checkBlocklist(hostname string) Result {
	for _, pattern := range s.blocklist {
		if MatchDomain(hostname, pattern) {
			return Result{
				Allowed: false,
				Reason:  fmt.Sprintf("domain blocked: %s matches %s", hostname, pattern),
				Scanner: "blocklist",
				Score:   1.0,
			}
		}
	}
	return Result{Allowed: true}
}

// checkRateLimit enforces per-domain rate limiting using a sliding window.
func (s *Scanner) checkRateLimit(hostname string) Result {
	if s.rateLimiter == nil {
		return Result{Allowed: true}
	}

	if !s.rateLimiter.IsAllowed(hostname) {
		return Result{
			Allowed: false,
			Reason:  fmt.Sprintf("rate limit exceeded for %s", hostname),
			Scanner: "ratelimit",
			Score:   0.7,
		}
	}

	return Result{Allowed: true}
}

// checkDLP runs DLP regex patterns against URL path and query parameters.
// All targets are URL-decoded before matching to prevent encoding bypass
// (e.g., %20 instead of space evading a regex that expects \s).
func (s *Scanner) checkDLP(parsed *url.URL) Result {
	// parsed.Path is already URL-decoded by Go's url.Parse.
	// For query strings, decode the full string to catch secrets split
	// across key=value boundaries, then also check individual decoded values.
	decodedQuery, _ := url.QueryUnescape(parsed.RawQuery)

	targets := []string{
		parsed.Path,
		decodedQuery,
	}

	// Also check decoded query keys and values individually
	for key, values := range parsed.Query() {
		targets = append(targets, key)
		targets = append(targets, values...)
	}

	for _, target := range targets {
		if target == "" {
			continue
		}
		for _, p := range s.dlpPatterns {
			if p.re.MatchString(target) {
				return Result{
					Allowed: false,
					Reason:  fmt.Sprintf("DLP match: %s (%s)", p.name, p.severity),
					Scanner: "dlp",
					Score:   1.0,
				}
			}
		}
	}

	// Check for environment variable leaks
	if result := s.checkEnvLeak(parsed); !result.Allowed {
		return result
	}

	return Result{Allowed: true}
}

// checkEnvLeak scans for environment variable values in the URL.
// Checks both raw and base64-encoded versions to catch common exfiltration patterns.
// Never logs the actual secret values to prevent accidental exposure.
func (s *Scanner) checkEnvLeak(parsed *url.URL) Result {
	if len(s.envSecrets) == 0 {
		return Result{Allowed: true}
	}

	fullURL := parsed.String()

	for _, secret := range s.envSecrets {
		if strings.Contains(fullURL, secret) {
			return Result{
				Allowed: false,
				Reason:  "environment variable leak detected",
				Scanner: "dlp",
				Score:   1.0,
			}
		}

		encoded := base64.StdEncoding.EncodeToString([]byte(secret))
		if strings.Contains(fullURL, encoded) {
			return Result{
				Allowed: false,
				Reason:  "environment variable leak detected (base64-encoded)",
				Scanner: "dlp",
				Score:   1.0,
			}
		}

		encodedURL := base64.URLEncoding.EncodeToString([]byte(secret))
		if encodedURL != encoded && strings.Contains(fullURL, encodedURL) {
			return Result{
				Allowed: false,
				Reason:  "environment variable leak detected (base64url-encoded)",
				Scanner: "dlp",
				Score:   1.0,
			}
		}
	}

	return Result{Allowed: true}
}

// extractEnvSecrets filters environment variables for likely secrets.
// Returns values >16 chars with Shannon entropy >3.0.
func extractEnvSecrets() []string {
	const minLen = 16
	const minEntropy = 3.0

	var secrets []string
	for _, env := range os.Environ() {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) != 2 {
			continue
		}

		value := parts[1]
		if len(value) < minLen {
			continue
		}

		if ShannonEntropy(value) > minEntropy {
			secrets = append(secrets, value)
		}
	}

	return secrets
}

// checkEntropy calculates Shannon entropy on URL path segments and query values.
func (s *Scanner) checkEntropy(parsed *url.URL) Result {
	if s.entropyThreshold <= 0 {
		return Result{Allowed: true}
	}

	// Check path segments
	for _, segment := range strings.Split(parsed.Path, "/") {
		if len(segment) >= s.entropyMinLen {
			entropy := ShannonEntropy(segment)
			if entropy > s.entropyThreshold {
				return Result{
					Allowed: false,
					Reason:  fmt.Sprintf("high entropy path segment (%.2f > %.2f threshold)", entropy, s.entropyThreshold),
					Scanner: "entropy",
					Score:   math.Min(entropy/8.0, 1.0), // normalize to 0-1
				}
			}
		}
	}

	// Check query parameter keys and values.
	// Keys are checked too — secrets can be stuffed into parameter names.
	for key, values := range parsed.Query() {
		if len(key) >= s.entropyMinLen {
			entropy := ShannonEntropy(key)
			if entropy > s.entropyThreshold {
				return Result{
					Allowed: false,
					Reason:  fmt.Sprintf("high entropy query key %q (%.2f > %.2f threshold)", key, entropy, s.entropyThreshold),
					Scanner: "entropy",
					Score:   math.Min(entropy/8.0, 1.0),
				}
			}
		}
		for _, v := range values {
			if len(v) >= s.entropyMinLen {
				entropy := ShannonEntropy(v)
				if entropy > s.entropyThreshold {
					return Result{
						Allowed: false,
						Reason:  fmt.Sprintf("high entropy query param %q (%.2f > %.2f threshold)", key, entropy, s.entropyThreshold),
						Scanner: "entropy",
						Score:   math.Min(entropy/8.0, 1.0),
					}
				}
			}
		}
	}

	return Result{Allowed: true}
}

// ShannonEntropy calculates the Shannon entropy of a string in bits per character.
// English text: ~3.5-4.0, base64: ~5.5-6.0, hex: ~4.0, encrypted: ~7.5-8.0
func ShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	freq := make(map[rune]int)
	total := 0
	for _, ch := range s {
		freq[ch]++
		total++
	}

	entropy := 0.0
	length := float64(total)
	for _, count := range freq {
		p := float64(count) / length
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

// MatchDomain checks if a hostname matches a pattern.
// Supports wildcard patterns like "*.example.com" which matches
// "sub.example.com", "a.b.example.com", and "example.com" itself.
// IP addresses only support exact match — wildcards are not applied to IPs
// to prevent false matches like "*.168.1.1" matching "192.168.1.1".
func MatchDomain(hostname, pattern string) bool {
	hostname = strings.ToLower(strings.TrimSuffix(hostname, "."))
	pattern = strings.ToLower(strings.TrimSuffix(pattern, "."))

	// IP addresses: exact match only, no wildcard expansion.
	// Dots in IPs are not domain separators — "192" is not a subdomain of "168.1.1".
	if net.ParseIP(hostname) != nil {
		return hostname == pattern
	}

	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // ".example.com"
		base := pattern[2:]   // "example.com"
		return hostname == base || strings.HasSuffix(hostname, suffix)
	}
	return hostname == pattern
}
