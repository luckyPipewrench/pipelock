// Package scanner provides URL scanning for the Pipelock fetch proxy.
// It checks URLs against blocklists, DLP patterns, and entropy thresholds
// before allowing the fetch proxy to retrieve them.
package scanner

import (
	"bufio"
	"context"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"

	"golang.org/x/text/unicode/norm"
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
	allowlist        []string
	blocklist        []string
	dlpPatterns      []*compiledPattern
	entropyThreshold float64
	entropyMinLen    int
	maxURLLength     int
	internalCIDRs    []*net.IPNet
	rateLimiter      *RateLimiter
	dataBudget       *DataBudget
	envSecrets       []string // filtered high-entropy env var values
	fileSecrets      []string // loaded from secrets_file config
	minEnvSecretLen  int      // minimum env var length for leak detection
	responsePatterns []*compiledPattern
	responseAction   string
	responseEnabled  bool
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
	// Only enforce the allowlist in strict mode. In balanced/audit modes,
	// the allowlist is a config field but not enforced at the scanner level.
	var allowlist []string
	if cfg.Mode == config.ModeStrict {
		allowlist = cfg.APIAllowlist
	}

	s := &Scanner{
		allowlist:        allowlist,
		blocklist:        cfg.FetchProxy.Monitoring.Blocklist,
		entropyThreshold: cfg.FetchProxy.Monitoring.EntropyThreshold,
		entropyMinLen:    20,
		maxURLLength:     cfg.FetchProxy.Monitoring.MaxURLLength,
	}

	// Initialize rate limiter if enabled
	if cfg.FetchProxy.Monitoring.MaxReqPerMinute > 0 {
		s.rateLimiter = NewRateLimiter(cfg.FetchProxy.Monitoring.MaxReqPerMinute)
	}

	// Compile DLP patterns — must succeed since config.Validate checks these.
	// Force case-insensitive matching: agents can trivially .toUpperCase() a
	// secret before exfiltration, so DLP patterns must match regardless of case.
	for _, p := range cfg.DLP.Patterns {
		pattern := p.Regex
		if !strings.HasPrefix(pattern, "(?i)") {
			pattern = "(?i)" + pattern
		}
		re, err := regexp.Compile(pattern)
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

	// Initialize data budget if configured
	if cfg.FetchProxy.Monitoring.MaxDataPerMinute > 0 {
		s.dataBudget = NewDataBudget(cfg.FetchProxy.Monitoring.MaxDataPerMinute)
	}

	// Set minimum env secret length from config (default 16)
	s.minEnvSecretLen = cfg.DLP.MinEnvSecretLength
	if s.minEnvSecretLen <= 0 {
		s.minEnvSecretLen = 16
	}

	// Extract high-entropy environment variables for leak detection
	if cfg.DLP.ScanEnv {
		s.envSecrets = extractEnvSecrets(s.minEnvSecretLen)
	}

	// Load explicit secrets from secrets file
	if cfg.DLP.SecretsFile != "" {
		fileSecrets, err := loadSecretsFile(cfg.DLP.SecretsFile, s.minEnvSecretLen)
		if err != nil {
			panic(fmt.Sprintf("BUG: secrets file %q failed after validation: %v",
				cfg.DLP.SecretsFile, err))
		}
		s.fileSecrets = dedupSecrets(fileSecrets, s.envSecrets)
	}

	// Compile response scanning patterns — must succeed since config.Validate checks these
	if cfg.ResponseScanning.Enabled {
		s.responseEnabled = true
		s.responseAction = cfg.ResponseScanning.Action
		for _, p := range cfg.ResponseScanning.Patterns {
			re, err := regexp.Compile(p.Regex)
			if err != nil {
				panic(fmt.Sprintf("BUG: response pattern %q failed after validation: %v", p.Name, err))
			}
			s.responsePatterns = append(s.responsePatterns, &compiledPattern{name: p.Name, re: re})
		}
	}

	return s
}

// IsInternalIP checks whether the given IP falls within any configured
// internal CIDR. Returns false when SSRF protection is disabled (no CIDRs).
func (s *Scanner) IsInternalIP(ip net.IP) bool {
	// Normalize IPv4-mapped IPv6 addresses (e.g., ::ffff:127.0.0.1) to
	// their 4-byte IPv4 form so they match IPv4 CIDRs like 127.0.0.0/8.
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	for _, cidr := range s.internalCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// Close releases scanner resources, including stopping the rate limiter
// cleanup goroutine. Safe to call multiple times.
func (s *Scanner) Close() {
	if s.rateLimiter != nil {
		s.rateLimiter.Close()
	}
	if s.dataBudget != nil {
		s.dataBudget.Close()
	}
}

// RecordRequest records response data for per-domain data budget tracking.
// Call this AFTER Scan() returns Allowed=true and the response is fetched.
// Rate limiting is handled atomically inside Scan() via CheckAndRecord.
// dataBytes is the response size; pass 0 if unknown or not yet fetched.
// Uses baseDomain normalization to match checkDataBudget's tracking.
func (s *Scanner) RecordRequest(hostname string, dataBytes int) {
	if s.dataBudget != nil && dataBytes > 0 {
		s.dataBudget.Record(baseDomain(hostname), dataBytes)
	}
}

// Scan checks a URL against all scanners and returns the result.
// DLP runs on the hostname BEFORE DNS resolution to prevent secret exfiltration
// via DNS queries (e.g., "sk-ant-xxx.evil.com" leaks the key during resolution).
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

	// 2. Allowlist check — if configured, only allowlisted domains are permitted.
	// Runs before DNS to reject disallowed domains without any network I/O.
	if result := s.checkAllowlist(hostname); !result.Allowed {
		return result
	}

	// 3. Blocklist check — before DNS to avoid resolving known-bad domains.
	if result := s.checkBlocklist(hostname); !result.Allowed {
		return result
	}

	// 4. DLP + entropy on hostname BEFORE DNS resolution.
	// Prevents secret exfiltration via DNS queries for domains like
	// "sk-ant-xxxx.evil.com" where the subdomain encodes a secret.
	if result := s.checkDLP(parsed); !result.Allowed {
		return result
	}
	if result := s.checkEntropy(parsed); !result.Allowed {
		return result
	}

	// 4b. Subdomain entropy check — catches base64/hex encoded data in subdomains
	// (e.g., "aGVsbG8.evil.com" exfiltrating data via DNS queries).
	if result := s.checkSubdomainEntropy(hostname); !result.Allowed {
		return result
	}

	// 5. SSRF protection — DNS resolution happens here, safe after DLP.
	if result := s.checkSSRF(hostname); !result.Allowed {
		return result
	}

	// 6. Rate limit check (per-domain)
	if result := s.checkRateLimit(hostname); !result.Allowed {
		return result
	}

	// 7. URL length check
	if s.maxURLLength > 0 && len(rawURL) > s.maxURLLength {
		return Result{
			Allowed: false,
			Reason:  fmt.Sprintf("URL length %d exceeds maximum %d", len(rawURL), s.maxURLLength),
			Scanner: "length",
			Score:   0.8,
		}
	}

	// 8. Data budget check (per-domain sliding window)
	if result := s.checkDataBudget(hostname); !result.Allowed {
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
	dnsCtx, dnsCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer dnsCancel()
	ips, err := net.DefaultResolver.LookupHost(dnsCtx, hostname)
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
		// Normalize IPv4-mapped IPv6 (::ffff:x.x.x.x) to 4-byte form.
		if v4 := ip.To4(); v4 != nil {
			ip = v4
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

// checkAllowlist rejects requests to domains not in the allowlist.
// When the allowlist is empty, all domains are permitted (allowlist is opt-in).
// Uses MatchDomain for consistent wildcard matching with the blocklist.
func (s *Scanner) checkAllowlist(hostname string) Result {
	if len(s.allowlist) == 0 {
		return Result{Allowed: true}
	}
	for _, pattern := range s.allowlist {
		if MatchDomain(hostname, pattern) {
			return Result{Allowed: true}
		}
	}
	return Result{
		Allowed: false,
		Reason:  fmt.Sprintf("domain not in allowlist: %s", hostname),
		Scanner: "allowlist",
		Score:   1.0,
	}
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
// Uses atomic CheckAndRecord to prevent TOCTOU races where concurrent
// requests could both pass the check before either records.
// Uses baseDomain normalization to prevent subdomain rotation bypass
// (e.g., a.evil.com, b.evil.com each getting separate rate limit windows).
func (s *Scanner) checkRateLimit(hostname string) Result {
	if s.rateLimiter == nil {
		return Result{Allowed: true}
	}

	if !s.rateLimiter.CheckAndRecord(baseDomain(hostname)) {
		return Result{
			Allowed: false,
			Reason:  fmt.Sprintf("rate limit exceeded for %s", hostname),
			Scanner: "ratelimit",
			Score:   0.7,
		}
	}

	return Result{Allowed: true}
}

// maxDecodeRounds is a safety ceiling for iterative URL decoding.
// The loop exits early when decoding produces no change (decoded == s),
// so this limit only matters for pathological inputs. URL decoding is
// microsecond-cheap per round, so a generous ceiling has no real cost.
const maxDecodeRounds = 500

// IterativeDecode applies URL decoding until the string stops changing
// or the safety ceiling is reached. Catches multi-layer encoding (e.g., %252D → %2D → -).
// Exported for use by the fetch proxy to normalize display URLs.
func IterativeDecode(s string) string {
	for range maxDecodeRounds {
		decoded, err := url.QueryUnescape(s)
		if err != nil || decoded == s {
			break
		}
		s = decoded
	}
	return s
}

// stripURLNoise removes URL separator characters that break DLP regex matching
// when secrets are fragmented across path/query boundaries. Strips characters that
// are valid in URLs but not in API key character classes [a-zA-Z0-9\-_]. Attackers
// insert dots, slashes, spaces, and other noise to split key patterns.
func stripURLNoise(s string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case '.', '/', ' ', '\t', '\n', '\r', '+', ',', ';', '|':
			return -1
		}
		return r
	}, s)
}

// orderedQueryConcat concatenates all query parameter values in their original URL
// order and returns the result. Catches secrets split across multiple query params
// (e.g., "?part1=sk-ant-api03-&part2=AAAA..." → "sk-ant-api03-AAAA...").
// Uses RawQuery instead of url.Values to preserve parameter order.
func orderedQueryConcat(rawQuery string) string {
	var b strings.Builder
	for _, pair := range strings.Split(rawQuery, "&") {
		_, value, _ := strings.Cut(pair, "=")
		if value != "" {
			b.WriteString(IterativeDecode(value))
		}
	}
	return b.String()
}

// checkDLP runs DLP regex patterns against the full URL string including hostname.
// Scanning the full URL catches secrets encoded in subdomains (e.g., sk-proj-xxx.evil.com)
// and secrets split across query parameters. Iterative URL decoding
// prevents multi-layer encoding bypass.
func (s *Scanner) checkDLP(parsed *url.URL) Result {
	// parsed.Path is already URL-decoded by Go's url.Parse.
	// For query strings, iteratively decode to catch multi-layer encoding.
	decodedQuery := IterativeDecode(parsed.RawQuery)

	targets := []string{
		parsed.String(), // full URL — catches secrets in hostname/subdomains
		parsed.Path,
		decodedQuery,
	}

	// Also check decoded query keys and values individually.
	for key, values := range parsed.Query() {
		targets = append(targets, IterativeDecode(key))
		for _, v := range values {
			targets = append(targets, IterativeDecode(v))
		}
	}

	// Also apply iterative decode to the raw path for double-encoded path segments.
	decodedPath := IterativeDecode(parsed.RawPath)
	if decodedPath != "" && decodedPath != parsed.Path {
		targets = append(targets, decodedPath)
	}

	// Dot-collapse the hostname to catch secrets split across DNS subdomains
	// (e.g. "sk-ant-api03-.AABBCCDD.EEFFGGHH.evil.com" → "sk-ant-api03-AABBCCDDEEFFGGHHevilcom").
	// Dots break regex character classes, so individual labels pass DLP checks.
	if hostname := parsed.Hostname(); strings.Contains(hostname, ".") {
		targets = append(targets, strings.ReplaceAll(hostname, ".", ""))
	}

	// Strip URL noise from path to catch secrets split by dots, slashes, and
	// other separators (e.g., "/sk-ant-api03-AAAA.AAAA/AAAA" → "sk-ant-api03-AAAAAAAAAAAA").
	// Covers both dot-split and encoded-slash attacks (%2f splitting path segments).
	if stripped := stripURLNoise(parsed.Path); stripped != parsed.Path {
		targets = append(targets, stripped)
	}

	// Concatenate all query values in URL order to catch secrets split across
	// query parameters (e.g. "?part1=sk-ant-api03-&part2=AAAA..." → "sk-ant-api03-AAAA...").
	// Uses RawQuery to preserve parameter order (url.Values is a map with random iteration).
	// Also noise-strip the concatenation to defeat inserted garbage params
	// (e.g., "?part1=sk-ant-&mid=%20&part2=AAAA" → "sk-ant-AAAA...").
	if parsed.RawQuery != "" && strings.Contains(parsed.RawQuery, "&") {
		concat := orderedQueryConcat(parsed.RawQuery)
		targets = append(targets, concat)
		if stripped := stripURLNoise(concat); stripped != concat {
			targets = append(targets, stripped)
		}
	}

	for _, target := range targets {
		if target == "" {
			continue
		}
		// Full normalization before DLP pattern matching: strip control chars,
		// NFKC, cross-script confusable mapping, and combining mark removal.
		// Must match response scanning depth — otherwise attackers use homoglyphs
		// in key prefixes (e.g., sk-օnt-... with Armenian օ U+0585 for 'a').
		cleaned := stripControlChars(target)
		cleaned = norm.NFKC.String(cleaned)
		cleaned = ConfusableToASCII(cleaned)
		cleaned = StripCombiningMarks(cleaned)
		for _, p := range s.dlpPatterns {
			if p.re.MatchString(cleaned) {
				return Result{
					Allowed: false,
					Reason:  fmt.Sprintf("DLP match: %s (%s)", p.name, p.severity),
					Scanner: "dlp",
					Score:   1.0,
				}
			}
		}
	}

	// Subsequence scan: try ordered combinations of query values (size 2-4)
	// to catch secrets split across params with junk values interleaved.
	// E.g., "?a=sk-&x=junk&b=ant-&y=junk&c=api03-&z=junk&d=AAAA..." —
	// combination (0,2,4,6) reconstructs "sk-ant-api03-AAAA...".
	if result := s.querySubsequenceDLP(parsed.RawQuery); !result.Allowed {
		return result
	}

	// Check for environment variable leaks
	if result := s.checkEnvLeak(parsed); !result.Allowed {
		return result
	}

	// Check for known file secret leaks
	if result := s.checkFileSecretLeak(parsed); !result.Allowed {
		return result
	}

	return Result{Allowed: true}
}

// querySubsequenceDLP checks ordered subsequences (combinations) of query
// parameter values for DLP pattern matches. Catches secrets split across
// multiple parameters with arbitrary junk values interleaved between fragments.
// Tries subsequences of size 2-4 for URLs with 3-20 query params.
// Cost: O(n^4) worst case, bounded at ~6k combinations for n=20.
func (s *Scanner) querySubsequenceDLP(rawQuery string) Result {
	if rawQuery == "" || !strings.Contains(rawQuery, "&") {
		return Result{Allowed: true}
	}

	var values []string
	for _, pair := range strings.Split(rawQuery, "&") {
		_, value, _ := strings.Cut(pair, "=")
		if value != "" {
			values = append(values, IterativeDecode(value))
		}
	}

	n := len(values)
	if n < 3 {
		return Result{Allowed: true}
	}
	// Cap to first 20 values to bound combinatorial cost (O(n^4)).
	if n > 20 {
		values = values[:20]
		n = 20
	}

	for size := 2; size <= 4 && size <= n; size++ {
		if result := s.checkDLPCombinations(values, n, size); !result.Allowed {
			return result
		}
	}

	return Result{Allowed: true}
}

// checkDLPCombinations generates all ordered combinations of the given size
// from the values slice and checks each concatenation against DLP patterns.
func (s *Scanner) checkDLPCombinations(values []string, n, size int) Result {
	indices := make([]int, size)
	for i := range indices {
		indices[i] = i
	}

	for {
		var b strings.Builder
		for _, idx := range indices {
			b.WriteString(values[idx])
		}
		concat := b.String()

		cleaned := stripControlChars(concat)
		cleaned = norm.NFKC.String(cleaned)
		cleaned = ConfusableToASCII(cleaned)
		cleaned = StripCombiningMarks(cleaned)

		for _, p := range s.dlpPatterns {
			if p.re.MatchString(cleaned) {
				return Result{
					Allowed: false,
					Reason:  fmt.Sprintf("DLP match: %s (%s)", p.name, p.severity),
					Scanner: "dlp",
					Score:   1.0,
				}
			}
		}

		if !nextCombination(indices, n) {
			break
		}
	}

	return Result{Allowed: true}
}

// nextCombination advances indices to the next lexicographic combination.
// Returns false when all combinations have been exhausted.
func nextCombination(indices []int, n int) bool {
	k := len(indices)
	for i := k - 1; i >= 0; i-- {
		if indices[i] < n-k+i {
			indices[i]++
			for j := i + 1; j < k; j++ {
				indices[j] = indices[j-1] + 1
			}
			return true
		}
	}
	return false
}

// checkEnvLeak scans for environment variable values in the URL.
// Checks both raw and base64-encoded versions to catch common exfiltration patterns.
// Never logs the actual secret values to prevent accidental exposure.
func (s *Scanner) checkEnvLeak(parsed *url.URL) Result {
	if len(s.envSecrets) == 0 {
		return Result{Allowed: true}
	}

	// Strip ALL control chars to prevent bypass via URL-encoded control chars
	// (e.g., %00 null byte, %08 backspace breaking substring match).
	fullURL := stripControlChars(parsed.String())
	// Pre-compute lowercase for case-insensitive hex comparison.
	lowerURL := strings.ToLower(fullURL)

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

		// Check hex encoding
		hexEncoded := hex.EncodeToString([]byte(secret))
		if strings.Contains(lowerURL, hexEncoded) {
			return Result{
				Allowed: false,
				Reason:  "environment variable leak detected (hex-encoded)",
				Scanner: "dlp",
				Score:   1.0,
			}
		}

		// Check base32 encoding (standard and no-padding variants)
		b32Std := base32.StdEncoding.EncodeToString([]byte(secret))
		if strings.Contains(fullURL, b32Std) {
			return Result{
				Allowed: false,
				Reason:  "environment variable leak detected (base32-encoded)",
				Scanner: "dlp",
				Score:   1.0,
			}
		}
		b32NoPad := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte(secret))
		if b32NoPad != b32Std && strings.Contains(fullURL, b32NoPad) {
			return Result{
				Allowed: false,
				Reason:  "environment variable leak detected (base32-encoded)",
				Scanner: "dlp",
				Score:   1.0,
			}
		}
	}

	return Result{Allowed: true}
}

// checkFileSecretLeak scans for secrets loaded from the secrets_file in the URL.
// Mirrors checkEnvLeak with distinct messages for incident response clarity.
func (s *Scanner) checkFileSecretLeak(parsed *url.URL) Result {
	if len(s.fileSecrets) == 0 {
		return Result{Allowed: true}
	}

	fullURL := stripControlChars(parsed.String())
	lowerURL := strings.ToLower(fullURL)

	for _, secret := range s.fileSecrets {
		if strings.Contains(fullURL, secret) {
			return Result{
				Allowed: false,
				Reason:  "known secret leak detected",
				Scanner: "dlp",
				Score:   1.0,
			}
		}

		encoded := base64.StdEncoding.EncodeToString([]byte(secret))
		if strings.Contains(fullURL, encoded) {
			return Result{
				Allowed: false,
				Reason:  "known secret leak detected (base64-encoded)",
				Scanner: "dlp",
				Score:   1.0,
			}
		}

		encodedURL := base64.URLEncoding.EncodeToString([]byte(secret))
		if encodedURL != encoded && strings.Contains(fullURL, encodedURL) {
			return Result{
				Allowed: false,
				Reason:  "known secret leak detected (base64url-encoded)",
				Scanner: "dlp",
				Score:   1.0,
			}
		}

		hexEncoded := hex.EncodeToString([]byte(secret))
		if strings.Contains(lowerURL, hexEncoded) {
			return Result{
				Allowed: false,
				Reason:  "known secret leak detected (hex-encoded)",
				Scanner: "dlp",
				Score:   1.0,
			}
		}

		b32Std := base32.StdEncoding.EncodeToString([]byte(secret))
		if strings.Contains(fullURL, b32Std) {
			return Result{
				Allowed: false,
				Reason:  "known secret leak detected (base32-encoded)",
				Scanner: "dlp",
				Score:   1.0,
			}
		}
		b32NoPad := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte(secret))
		if b32NoPad != b32Std && strings.Contains(fullURL, b32NoPad) {
			return Result{
				Allowed: false,
				Reason:  "known secret leak detected (base32-encoded)",
				Scanner: "dlp",
				Score:   1.0,
			}
		}
	}

	return Result{Allowed: true}
}

// extractEnvSecrets filters environment variables for likely secrets.
// Returns values >= minLen chars with Shannon entropy >3.0.
func extractEnvSecrets(minLen int) []string {
	const minEntropy = 3.0

	if minLen <= 0 {
		minLen = 16
	}

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

// dedupSecrets removes values from fileSecrets that already exist in envSecrets.
// This prevents double-scanning when a secret appears in both sources.
func dedupSecrets(fileSecrets, envSecrets []string) []string {
	if len(envSecrets) == 0 {
		return fileSecrets
	}
	existing := make(map[string]struct{}, len(envSecrets))
	for _, s := range envSecrets {
		existing[s] = struct{}{}
	}
	var result []string
	for _, s := range fileSecrets {
		if _, ok := existing[s]; !ok {
			result = append(result, s)
		}
	}
	return result
}

// loadSecretsFile reads explicit secret values from a file, one per line.
// Lines starting with # (after optional whitespace) are comments.
// Blank lines, null-byte lines, and lines below minLen are skipped.
// Max 4096 bytes per line, max 1000 entries.
func loadSecretsFile(path string, minLen int) ([]string, error) { //nolint:unparam // minLen varies in tests
	f, err := os.Open(path) //nolint:gosec // G304: path validated by config.Validate
	if err != nil {
		return nil, fmt.Errorf("opening secrets file: %w", err)
	}
	defer func() { _ = f.Close() }()

	const (
		maxLineLen = 4096
		maxEntries = 1000
	)

	var (
		secrets []string
		lineNum int
		first   = true
	)

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, maxLineLen*2), maxLineLen*2)

	for sc.Scan() {
		lineNum++
		line := sc.Text()

		// Strip UTF-8 BOM from first line.
		if first {
			line = strings.TrimPrefix(line, "\xef\xbb\xbf")
			first = false
		}

		// Strip trailing whitespace/tabs/CR.
		line = strings.TrimRight(line, " \t\r")

		// Skip blank lines.
		if line == "" {
			continue
		}

		// Skip comment lines (# as first non-whitespace).
		if strings.HasPrefix(strings.TrimLeft(line, " \t"), "#") {
			continue
		}

		// Reject lines with null bytes.
		if strings.ContainsRune(line, '\x00') {
			fmt.Fprintf(os.Stderr, "pipelock: warning: secrets_file line %d contains null byte, skipping\n", lineNum)
			continue
		}

		// Reject lines exceeding max length.
		if len(line) > maxLineLen {
			fmt.Fprintf(os.Stderr, "pipelock: warning: secrets_file line %d exceeds %d bytes, skipping\n", lineNum, maxLineLen)
			continue
		}

		// Skip values below minimum length.
		if len(line) < minLen {
			fmt.Fprintf(os.Stderr, "pipelock: warning: secrets_file line %d too short (%d < %d), skipping\n", lineNum, len(line), minLen)
			continue
		}

		// Enforce max entries.
		if len(secrets) >= maxEntries {
			fmt.Fprintf(os.Stderr, "pipelock: warning: secrets_file exceeds %d entries, ignoring remainder\n", maxEntries)
			break
		}

		secrets = append(secrets, line)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("reading secrets file: %w", err)
	}

	return secrets, nil
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
// English text: ~3.5-4.0, base64: ~5.5-6.0, hex: ~4.0, encrypted: ~7.5-8.0.
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

// checkDataBudget enforces per-domain data transfer limits.
// Uses baseDomain normalization to prevent subdomain rotation bypass.
func (s *Scanner) checkDataBudget(hostname string) Result {
	if s.dataBudget == nil {
		return Result{Allowed: true}
	}
	domain := baseDomain(hostname)
	if !s.dataBudget.IsAllowed(domain) {
		return Result{
			Allowed: false,
			Reason:  fmt.Sprintf("data budget exceeded for %s", hostname),
			Scanner: "databudget",
			Score:   0.8,
		}
	}
	return Result{Allowed: true}
}

// subdomainEntropyThreshold is the Shannon entropy threshold for flagging
// suspicious subdomain labels. Base64-encoded data typically has entropy > 4.0.
const subdomainEntropyThreshold = 4.0

// subdomainMinLabelLen is the minimum subdomain label length to check.
// Short labels (www, api, cdn) are normal and should not be flagged.
const subdomainMinLabelLen = 8

// checkSubdomainEntropy flags hostnames where subdomain labels contain
// high-entropy data, indicating base64/hex exfiltration via DNS queries.
// Only checks hostnames with 3+ labels (at least one subdomain beyond base domain).
func (s *Scanner) checkSubdomainEntropy(hostname string) Result {
	if s.entropyThreshold <= 0 {
		return Result{Allowed: true}
	}

	// Skip IP addresses
	if net.ParseIP(hostname) != nil {
		return Result{Allowed: true}
	}

	labels := strings.Split(hostname, ".")
	if len(labels) < 3 {
		return Result{Allowed: true}
	}

	// Check all labels except the last two (base domain + TLD)
	for _, label := range labels[:len(labels)-2] {
		if len(label) < subdomainMinLabelLen {
			continue
		}
		entropy := ShannonEntropy(label)
		if entropy > subdomainEntropyThreshold {
			return Result{
				Allowed: false,
				Reason:  fmt.Sprintf("high entropy subdomain label %q (%.2f bits)", label, entropy),
				Scanner: "subdomain_entropy",
				Score:   math.Min(entropy/8.0, 1.0),
			}
		}
	}

	return Result{Allowed: true}
}

// baseDomain returns the base domain for budget tracking, stripping subdomains
// to prevent bypass via subdomain rotation (a.evil.com, b.evil.com, etc.).
// Uses a simple heuristic: returns the last 2 domain labels. This doesn't
// handle ccTLDs (e.g., co.uk) perfectly but covers the common attack case.
// IP addresses are returned as-is.
func baseDomain(hostname string) string {
	if net.ParseIP(hostname) != nil {
		return hostname
	}
	parts := strings.Split(hostname, ".")
	if len(parts) <= 2 {
		return hostname
	}
	return strings.Join(parts[len(parts)-2:], ".")
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
