// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

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
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"

	"github.com/luckyPipewrench/pipelock/internal/addressprotect"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/normalize"
	"github.com/luckyPipewrench/pipelock/internal/seedprotect"
)

// Scanner label constants. These values flow into Prometheus metrics
// (pipelock_scanner_hits_total{scanner="..."}), suppression rules, and audit
// logs. Changing a value is a breaking change for dashboards and alerts.
const (
	ScannerParser           = "parser"
	ScannerScheme           = "scheme"
	ScannerLength           = "length"
	ScannerSSRF             = "ssrf"
	ScannerAllowlist        = "allowlist"
	ScannerBlocklist        = "blocklist"
	ScannerRateLimit        = "ratelimit"
	ScannerDLP              = "dlp"
	ScannerEntropy          = "entropy"
	ScannerSubdomainEntropy = "subdomain_entropy"
	ScannerDataBudget       = "databudget"
	ScannerPathTraversal    = "path_traversal"
	ScannerCRLF             = "crlf_injection"
	ScannerContext          = "context"
	ScannerAll              = "all"
)

// ResultClass distinguishes protective enforcement (rate limiting) from threat
// evidence (DLP matches, injection, SSRF, data budget exhaustion). The proxy's
// adaptive enforcement uses this to avoid penalising agents for protective blocks.
type ResultClass int

const (
	// ClassThreat is the zero value: the block indicates a genuine threat
	// signal (DLP match, injection, blocklist hit, etc.).
	ClassThreat ResultClass = iota
	// ClassProtective means the block is protective enforcement (rate
	// limiting, data budget) — not evidence of malicious intent.
	ClassProtective
	// ClassConfigMismatch means the block is due to a configuration gap
	// (e.g., domain in api_allowlist but not trusted_domains). Not a
	// real attack — should not feed adaptive escalation.
	ClassConfigMismatch
)

// WarnMatch describes a DLP pattern match from a warn-mode pattern.
// These are informational only — they do not block or alter the request.
type WarnMatch struct {
	PatternName string `json:"pattern_name"`
	Severity    string `json:"severity"`
}

// Result describes the outcome of scanning a URL.
type Result struct {
	Allowed     bool        `json:"allowed"`
	Reason      string      `json:"reason,omitempty"`
	Scanner     string      `json:"scanner,omitempty"` // which scanner triggered
	Hint        string      `json:"hint,omitempty"`    // actionable guidance when blocked
	Score       float64     `json:"score"`             // anomaly score 0.0-1.0
	Class       ResultClass `json:"-"`                 // internal: threat vs protective classification
	WarnMatches []WarnMatch `json:"warn_matches,omitempty"`
}

// IsProtective reports whether this result represents protective enforcement
// (e.g., rate limiting) rather than a threat detection.
func (r Result) IsProtective() bool {
	return r.Class == ClassProtective
}

// IsConfigMismatch reports whether this result represents a configuration
// gap rather than a real threat (e.g., SSRF blocking an allowlisted domain).
func (r Result) IsConfigMismatch() bool {
	return r.Class == ClassConfigMismatch
}

// dlpWarnCtxKey and DLPWarnContext are defined in warnctx.go.

// Scanner checks URLs for suspicious content before fetching.
type Scanner struct {
	core                       *compiledCoreScanner // immutable safety floor — always runs, no config knobs
	allowlist                  []string
	blocklist                  []string
	dlpPatterns                []*compiledPattern
	canaryTokens               []compiledCanaryToken
	dlpPreFilter               *dlpPreFilter
	entropyThreshold           float64
	subdomainEntropyThreshold  float64
	entropyMinLen              int
	maxURLLength               int
	internalCIDRs              []*net.IPNet
	ipAllowlistCIDRs           []*net.IPNet // SSRF-exempt IP ranges (ssrf.ip_allowlist)
	trustedDomains             []string     // SSRF-exempt domains (wildcard via MatchDomain)
	rawAPIAllowlist            []string     // full api_allowlist for SSRF hint generation (all modes)
	rateLimiter                *RateLimiter
	dataBudget                 *DataBudget
	envSecrets                 []string // filtered high-entropy env var values
	fileSecrets                []string // loaded from secrets_file config
	minEnvSecretLen            int      // minimum env var length for leak detection
	responsePatterns           []*compiledPattern
	responseOptSpacePatterns   []*compiledPattern // \s+ → \s* variants for ZW-stripped pass
	responseVowelFoldPatterns  []*compiledPattern // vowel-folded variants for confusable vowel attacks
	responsePreFilter          *responsePreFilter // keyword candidate gate for primary regex passes
	responseOptSpacePreFilter  *responsePreFilter // keyword candidate gate for opt-space pass
	responseVowelFoldPreFilter *responsePreFilter // keyword candidate gate for vowel-fold pass
	responseAction             string
	responseEnabled            bool
	subdomainExclusions        []string // domains excluded from subdomain entropy checks
	addressChecker             *addressprotect.Checker
	seedEnabled                bool
	seedMinWords               int
	seedVerifyChecksum         bool
	dlpWarnHook                func(ctx context.Context, patternName, severity string)
}

// SetDLPWarnHook sets the callback for warn-mode DLP matches.
// The hook receives the request context (which may carry DLPWarnContext
// metadata), pattern name, and severity. Called once per scanner instance
// from runtime startup and on config reload.
func (s *Scanner) SetDLPWarnHook(hook func(ctx context.Context, patternName, severity string)) {
	s.dlpWarnHook = hook
}

type compiledPattern struct {
	name          string
	re            *regexp.Regexp
	severity      string
	validate      func(string) bool // post-match checksum (nil = regex-only)
	exemptDomains []string          // domains where this pattern is skipped (wildcard supported)
	bundle        string            // empty for built-in/config patterns
	bundleVersion string
	warn          bool // true when pattern action is "warn" — matches are informational only
}

// matches returns true if text matches the regex AND passes the post-match
// validator (if any). For patterns without a validator, this uses the faster
// MatchString (no string extraction). For validated patterns (credit cards,
// IBANs), FindAllString extracts ALL matches and returns true if any pass
// checksum — prevents a checksum-failing decoy from suppressing a later
// valid match in the same text blob.
func (p *compiledPattern) matches(text string) bool {
	if p.validate == nil {
		return p.re.MatchString(text)
	}
	// Check all regex hits, not just the first. An attacker could front-load
	// BIN-matching decoys that fail checksum before the real card/IBAN.
	// No cap: regex specificity (BIN prefixes, IBAN format) and data budget
	// limits already bound the match count in practice.
	for _, m := range p.re.FindAllString(text, -1) {
		if p.validate(m) {
			return true
		}
	}
	return false
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
		core:                      initCoreScanner(),
		allowlist:                 allowlist,
		blocklist:                 cfg.FetchProxy.Monitoring.Blocklist,
		entropyThreshold:          cfg.FetchProxy.Monitoring.EntropyThreshold,
		subdomainEntropyThreshold: cfg.FetchProxy.Monitoring.SubdomainEntropyThreshold,
		entropyMinLen:             20,
		maxURLLength:              cfg.FetchProxy.Monitoring.MaxURLLength,
		subdomainExclusions:       cfg.FetchProxy.Monitoring.SubdomainEntropyExclusions,
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
		cp := &compiledPattern{
			name:          p.Name,
			re:            re,
			severity:      p.Severity,
			exemptDomains: p.ExemptDomains,
			bundle:        p.Bundle,
			bundleVersion: p.BundleVersion,
			warn:          p.Action == config.ActionWarn,
		}
		if p.Validator != "" {
			fn, ok := DLPValidators[p.Validator]
			if !ok {
				panic(fmt.Sprintf("BUG: unknown DLP validator %q for pattern %q", p.Validator, p.Name))
			}
			cp.validate = fn
		}
		s.dlpPatterns = append(s.dlpPatterns, cp)
	}

	// Build prefix pre-filter for fast DLP short-circuiting on clean input.
	s.dlpPreFilter = newDLPPreFilter(s.dlpPatterns)
	s.canaryTokens = compileCanaryTokens(cfg.CanaryTokens)

	// Seed phrase detection config — stateless, reads from config.
	s.seedEnabled = cfg.SeedPhraseDetection.Enabled == nil || *cfg.SeedPhraseDetection.Enabled
	s.seedMinWords = cfg.SeedPhraseDetection.MinWords
	if s.seedMinWords == 0 {
		s.seedMinWords = 12
	}
	s.seedVerifyChecksum = cfg.SeedPhraseDetection.VerifyChecksum == nil || *cfg.SeedPhraseDetection.VerifyChecksum

	// Parse internal CIDRs — must succeed since config.Validate checks these
	for _, cidr := range cfg.Internal {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(fmt.Sprintf("BUG: internal CIDR %q failed to parse after validation: %v", cidr, err))
		}
		s.internalCIDRs = append(s.internalCIDRs, ipNet)
	}

	// Parse SSRF IP allowlist CIDRs — must succeed since config.Validate checks these
	for _, cidr := range cfg.SSRF.IPAllowlist {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(fmt.Sprintf("BUG: SSRF IP allowlist CIDR %q failed to parse after validation: %v", cidr, err))
		}
		s.ipAllowlistCIDRs = append(s.ipAllowlistCIDRs, ipNet)
	}

	s.trustedDomains = cfg.TrustedDomains
	s.rawAPIAllowlist = cfg.APIAllowlist

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
		fileSecrets, err := LoadSecretsFile(cfg.DLP.SecretsFile, s.minEnvSecretLen)
		if err != nil {
			panic(fmt.Sprintf("BUG: secrets file %q failed after validation: %v",
				cfg.DLP.SecretsFile, err))
		}
		s.fileSecrets = dedupSecrets(fileSecrets, s.envSecrets)
		if len(s.fileSecrets) == 0 {
			fmt.Fprintf(os.Stderr, "pipelock: warning: secrets_file %q yielded zero usable secrets\n",
				cfg.DLP.SecretsFile)
		}
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
			s.responsePatterns = append(s.responsePatterns, &compiledPattern{
				name:          p.Name,
				re:            re,
				bundle:        p.Bundle,
				bundleVersion: p.BundleVersion,
			})

			// Compile optional-whitespace variant: \s+ → \s* so that
			// "ignoreallpreviousinstructions" (ZW-stripped with no spaces)
			// still matches injection patterns. Handles the combined attack
			// where ZW chars split keywords AND replace word separators.
			optRegex := strings.ReplaceAll(p.Regex, `\s+`, `\s*`)
			optRegex = strings.ReplaceAll(optRegex, `[-,;:.\s]+`, `[-,;:.\s]*`)
			if optRegex != p.Regex {
				optRe, optErr := regexp.Compile(optRegex)
				if optErr == nil {
					s.responseOptSpacePatterns = append(s.responseOptSpacePatterns, &compiledPattern{
						name:          p.Name,
						re:            optRe,
						bundle:        p.Bundle,
						bundleVersion: p.BundleVersion,
					})
				}
			}

			// Compile vowel-folded variant: fold all vowels (e,i,o,u -> a) in the
			// regex so that confusable-vowel attacks are caught. An attacker using
			// o-stroke (maps to o) to replace both 'o' and 'u' produces "instroctions"
			// after confusable mapping. Standard patterns fail. Vowel-folding both
			// the pattern and the content makes them match.
			// Extract any leading (?flags) group before folding. FoldVowels would
			// corrupt flag chars (e.g. i->a turning (?im) into (?am), which is invalid).
			vfRegex := p.Regex
			vfPrefix := ""
			if strings.HasPrefix(vfRegex, "(?") {
				if end := strings.Index(vfRegex, ")"); end > 1 {
					flags := vfRegex[2:end]
					allFlags := true
					for _, r := range flags {
						if !strings.ContainsRune("imsU-", r) {
							allFlags = false
							break
						}
					}
					if allFlags {
						vfPrefix = vfRegex[:end+1]
						vfRegex = vfRegex[end+1:]
					}
				}
			}
			vfRegex = vfPrefix + normalize.FoldVowels(vfRegex)
			if vfRegex != p.Regex {
				vfRe, vfErr := regexp.Compile(vfRegex)
				if vfErr == nil {
					s.responseVowelFoldPatterns = append(s.responseVowelFoldPatterns, &compiledPattern{
						name:          p.Name,
						re:            vfRe,
						bundle:        p.Bundle,
						bundleVersion: p.BundleVersion,
					})
				}
			}
		}
	}

	// Build response pre-filters for keyword-gated regex skipping.
	// Each pattern set gets its own pre-filter because opt-space and
	// vowel-fold transforms change which keywords appear in content.
	if len(s.responsePatterns) > 0 {
		s.responsePreFilter = newResponsePreFilter(s.responsePatterns)
	}
	if len(s.responseOptSpacePatterns) > 0 {
		s.responseOptSpacePreFilter = newResponsePreFilter(s.responseOptSpacePatterns)
	}
	if len(s.responseVowelFoldPatterns) > 0 {
		s.responseVowelFoldPreFilter = newResponsePreFilter(s.responseVowelFoldPatterns)
	}

	// Build address protection checker if enabled.
	if cfg.AddressProtection.Enabled {
		agentAddrs := make(map[string][]string)
		for name, agent := range cfg.Agents {
			if len(agent.AllowedAddresses) > 0 {
				agentAddrs[name] = agent.AllowedAddresses
			}
		}
		s.addressChecker = addressprotect.NewChecker(&cfg.AddressProtection, agentAddrs)
	}

	return s
}

// AddressChecker returns the address protection checker, or nil if disabled.
func (s *Scanner) AddressChecker() *addressprotect.Checker {
	return s.addressChecker
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

// IsTrustedDomain checks if a hostname matches any trusted domain pattern.
// Trusted domains allow connections to internal IPs with advisory logging
// instead of blocking. IP literals are always rejected — trusted domains
// only match hostnames to prevent SSRF bypass via raw IP addresses.
func (s *Scanner) IsTrustedDomain(hostname string) bool {
	// Reject IP literals: trusted domains match hostnames only.
	// Without this, an attacker could add a raw IP to trusted_domains
	// and bypass SSRF protection entirely.
	if net.ParseIP(hostname) != nil {
		return false
	}
	hostname = strings.ToLower(strings.TrimSuffix(hostname, "."))
	for _, pattern := range s.trustedDomains {
		if MatchDomain(hostname, pattern) {
			return true
		}
	}
	return false
}

// IsIPAllowlisted checks if an IP is in the SSRF IP allowlist (ssrf.ip_allowlist).
// Used by checkSSRF and the dial-level SSRF check to exempt specific IP ranges.
func (s *Scanner) IsIPAllowlisted(ip net.IP) bool {
	for _, cidr := range s.ipAllowlistCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// IsInAPIAllowlist checks if a hostname matches any entry in api_allowlist.
// Unlike the scanner's allowlist field (which is mode-gated to strict), this
// checks the raw config allowlist regardless of mode — used for SSRF hint
// generation and config-mismatch classification.
func (s *Scanner) IsInAPIAllowlist(hostname string) bool {
	hostname = strings.ToLower(strings.TrimSuffix(hostname, "."))
	for _, pattern := range s.rawAPIAllowlist {
		if MatchDomain(hostname, pattern) {
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

// scannerHints maps scanner labels to actionable guidance for operators.
// Keyed by scanner constants; TestHintForBlock covers all entries.
var scannerHints = map[string]string{
	ScannerBlocklist:        "Domain is on the blocklist. Remove from fetch_proxy.monitoring.blocklist if legitimate.",
	ScannerDLP:              "A DLP pattern matched this URL. If false positive, add a suppress entry for this rule.",
	ScannerEntropy:          "High-entropy content detected. Review the URL for data exfiltration attempts.",
	ScannerSubdomainEntropy: "High-entropy content detected in subdomain. Review for data exfiltration via DNS.",
	ScannerSSRF:             "SSRF protection blocked this URL. It may resolve to a private IP or DNS resolution failed.",
	ScannerRateLimit:        "Rate limit exceeded. Retry later or adjust fetch_proxy.monitoring.max_requests_per_minute.",
	ScannerLength:           "URL exceeds maximum length. Check for data stuffing in query parameters.",
	ScannerDataBudget:       "Session data budget exceeded.",
	ScannerScheme:           "Only http and https schemes are allowed.",
	ScannerAllowlist:        "Domain not on the allowlist. In strict mode, only allowlisted domains are reachable.",
	ScannerParser:           "The URL could not be parsed.",
	ScannerContext:          "The request context was nil or cancelled before the scan completed.",
	ScannerCRLF:             "CRLF injection sequence detected in URL. This is never legitimate in normal traffic.",
	ScannerPathTraversal:    "Path traversal sequence detected. Review the URL for directory escape attempts.",
	ScannerCoreDLP:          "Core DLP pattern matched. This is a critical credential detection that cannot be disabled.",
	ScannerCoreSSRF:         "Core SSRF protection blocked this URL. Private IP ranges are always blocked.",
	ScannerCoreResponse:     "Core response scanning detected a prompt injection pattern. This cannot be disabled.",
}

// HintForBlock returns actionable guidance for a blocked scan result.
// Returns empty string for unknown scanner labels (fail-safe).
func HintForBlock(r *Result) string {
	if r == nil || r.Allowed {
		return ""
	}
	return scannerHints[r.Scanner]
}

// Scan checks a URL against all scanners and returns the result.
// Blocked results include a Hint field with actionable guidance.
// Fail-closed: nil or already-cancelled contexts are rejected before scanning.
func (s *Scanner) Scan(ctx context.Context, rawURL string) Result {
	if ctx == nil || ctx.Err() != nil {
		return Result{
			Allowed: false,
			Reason:  "request context unavailable",
			Scanner: ScannerContext,
			Score:   1.0,
			Hint:    scannerHints[ScannerContext],
		}
	}
	r := s.scan(ctx, rawURL)
	if !r.Allowed && r.Hint == "" {
		r.Hint = HintForBlock(&r)
	}
	return r
}

// scan checks a URL against all scanners and returns the result.
// DLP runs on the hostname BEFORE DNS resolution to prevent secret exfiltration
// via DNS queries (e.g., "sk-ant-xxx.evil.com" leaks the key during resolution).
func (s *Scanner) scan(ctx context.Context, rawURL string) (result Result) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return Result{Allowed: false, Reason: "invalid URL", Scanner: ScannerParser, Score: 1.0}
	}

	// Normalize hostname for consistent matching
	hostname := strings.ToLower(parsed.Hostname())

	// Canonicalize non-standard IP notations (hex, octal, decimal integer)
	// so that allowlist/blocklist/DLP checks all see the same dotted-decimal
	// form. Without this, 0x7f000001 bypasses a blocklist entry for 127.0.0.1.
	// Also update parsed.Host so downstream consumers (checkDLP, checkEntropy,
	// exempt_domains matching) all see the canonical form.
	if altIP := parseAlternativeIP(hostname); altIP != nil {
		hostname = altIP.String()
		port := parsed.Port()
		if port != "" {
			parsed.Host = hostname + ":" + port
		} else {
			parsed.Host = hostname
		}
	}

	// Scheme check —
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return Result{
			Allowed: false,
			Reason:  fmt.Sprintf("scheme %q not allowed: only http and https", parsed.Scheme),
			Scanner: ScannerScheme,
			Score:   1.0,
		}
	}

	// CRLF injection check — %0D%0A in URLs enables header injection.
	// Runs early because CRLF is never legitimate in a URL.
	if result := checkCRLF(rawURL); !result.Allowed {
		return result
	}

	// Path traversal check — /../ sequences are defense-in-depth.
	if result := checkPathTraversal(parsed); !result.Allowed {
		return result
	}

	// Allowlist check — if configured, only allowlisted domains are permitted.
	// Runs before DNS to reject disallowed domains without any network I/O.
	if result := s.checkAllowlist(hostname); !result.Allowed {
		return result
	}

	// Blocklist check — before DNS to avoid resolving known-bad domains.
	if result := s.checkBlocklist(hostname); !result.Allowed {
		return result
	}

	// Core SSRF literal — immutable safety floor for IP literals. Runs ALWAYS,
	// even when cfg.Internal is nil (SSRF disabled). Blocks direct requests
	// to private IPs (127.0.0.1, 169.254.169.254, 10.x, etc.). Respects
	// ssrf.ip_allowlist for operator overrides.
	if result := s.checkCoreSSRFLiteral(hostname); !result.Allowed {
		return result
	}

	// Core DLP — immutable safety floor. Runs BEFORE main DLP, BEFORE DNS.
	// Core findings are FINAL; the main scanner cannot override a core block.
	if result := s.checkCoreDLP(parsed); !result.Allowed {
		return result
	}

	// DLP + entropy on hostname BEFORE DNS resolution.
	// Prevents secret exfiltration via DNS queries for domains like
	// "sk-ant-xxxx.evil.com" where the subdomain encodes a secret.
	dlpResult, dlpWarns := s.checkDLP(parsed)
	dlpWarns = deduplicateWarnMatches(dlpWarns)
	if !dlpResult.Allowed {
		dlpResult.WarnMatches = dlpWarns
		s.emitDLPWarns(ctx, dlpWarns)
		return dlpResult
	}
	// Attach DLP warn matches to whatever result is returned from here on.
	// The defer fires on every return path, including blocks by later scanners.
	defer func() {
		result.WarnMatches = dlpWarns
		s.emitDLPWarns(ctx, dlpWarns)
	}()
	if result := s.checkEntropy(parsed); !result.Allowed {
		return result
	}

	// Subdomain entropy check — catches base64/hex encoded data in subdomains
	// (e.g., "aGVsbG8.evil.com" exfiltrating data via DNS queries).
	if result := s.checkSubdomainEntropy(hostname); !result.Allowed {
		return result
	}

	// SSRF protection — DNS resolution happens here, safe after DLP.
	// When active, core CIDRs are always included via mergedSSRFCIDRs()
	// so private ranges (10.x, 172.16.x, 192.168.x, loopback, link-local)
	// cannot be removed from the check set via config alone.
	if result := s.checkSSRF(ctx, hostname); !result.Allowed {
		return result
	}

	// Rate limit check (per-domain)
	if result := s.checkRateLimit(hostname); !result.Allowed {
		return result
	}

	// URL length check
	if s.maxURLLength > 0 && len(rawURL) > s.maxURLLength {
		return Result{
			Allowed: false,
			Reason:  fmt.Sprintf("URL length %d exceeds maximum %d", len(rawURL), s.maxURLLength),
			Scanner: ScannerLength,
			Score:   0.8,
		}
	}

	// Data budget check (per-domain sliding window)
	if result := s.checkDataBudget(hostname); !result.Allowed {
		return result
	}

	// Final context check: catch cancellations that arrived during in-memory
	// scanning (blocklist, DLP, entropy) before returning an allow verdict.
	if ctx.Err() != nil {
		return Result{
			Allowed: false,
			Reason:  "request context cancelled",
			Scanner: ScannerContext,
			Score:   1.0,
		}
	}

	return Result{Allowed: true, Scanner: ScannerAll, Score: 0.0}
}

// parseAlternativeIP decodes non-standard IP address notations that
// net.ParseIP does not handle: hex (0x7f000001), octal (0177.0.0.1),
// decimal integer (2130706433), and mixed-radix dotted notation.
// Attackers use these to bypass SSRF checks that only recognize
// standard dotted-decimal. Returns nil if the hostname is not an
// alternative IP notation.
func parseAlternativeIP(hostname string) net.IP {
	hostname = strings.TrimSpace(hostname)
	if hostname == "" {
		return nil
	}

	// Dotted notation with possible hex/octal octets (e.g., 0177.0.0.1, 0x7f.0.0.1).
	if strings.Contains(hostname, ".") {
		parts := strings.Split(hostname, ".")
		if len(parts) != 4 {
			return nil
		}
		octets := make([]byte, 4)
		for i, part := range parts {
			val, err := strconv.ParseUint(part, 0, 16) // base 0: auto-detect hex/octal/decimal; 16 bits max per octet
			if err != nil || val > 255 {
				return nil
			}
			octets[i] = byte(val)
		}
		// Only return if at least one octet used non-standard notation.
		// Standard dotted-decimal is already handled by net.ParseIP.
		hasNonStandard := false
		for _, part := range parts {
			if strings.HasPrefix(part, "0x") || strings.HasPrefix(part, "0X") ||
				(len(part) > 1 && part[0] == '0' && part != "0") {
				hasNonStandard = true
				break
			}
		}
		if !hasNonStandard {
			return nil
		}
		return net.IPv4(octets[0], octets[1], octets[2], octets[3])
	}

	// Single integer notation: hex (0x7f000001), octal (017700000001),
	// or decimal (2130706433). Represents the full 32-bit IPv4 address.
	val, err := strconv.ParseUint(hostname, 0, 32) // base 0: auto-detect; 32 bits for full IPv4
	if err != nil {
		return nil
	}
	return net.IPv4(byte(val>>24), byte(val>>16&0xFF), byte(val>>8&0xFF), byte(val&0xFF))
}

// checkSSRF blocks requests to internal/private IP ranges.
// When no internal CIDRs are configured (nil slice), SSRF protection is disabled.
// To block loopback, link-local, etc., include those CIDRs in config.Internal.
// When SSRF IS active, core CIDRs are always included in the check set.
func (s *Scanner) checkSSRF(ctx context.Context, hostname string) Result {
	// Check context before the SSRF-disabled fast path so cancelled requests
	// don't slip through when internalCIDRs is empty.
	if ctx.Err() != nil {
		return Result{
			Allowed: false,
			Reason:  "request context cancelled",
			Scanner: ScannerContext,
			Score:   1.0,
		}
	}
	if len(s.internalCIDRs) == 0 {
		return Result{Allowed: true}
	}

	// When SSRF is active, merge core CIDRs so private ranges can never
	// be removed from the check set via config alone.
	allCIDRs := s.mergedSSRFCIDRs()

	// Decode non-standard IP notations (hex, octal, decimal integer) BEFORE
	// DNS resolution. Attackers use 0x7f000001, 0177.0.0.1, or 2130706433
	// to reach 127.0.0.1 without net.ParseIP recognizing it. If the hostname
	// decodes to a valid IP, check CIDRs directly and skip DNS.
	if altIP := parseAlternativeIP(hostname); altIP != nil {
		if v4 := altIP.To4(); v4 != nil {
			altIP = v4
		}
		for _, cidr := range allCIDRs {
			if cidr.Contains(altIP) {
				return Result{
					Allowed: false,
					Reason:  fmt.Sprintf("SSRF blocked: %s decodes to internal IP %s", hostname, altIP),
					Scanner: ScannerSSRF,
					Score:   1.0,
				}
			}
		}
		// Non-standard IP that doesn't match internal CIDRs — allow.
		return Result{Allowed: true}
	}

	// Resolve hostname to IP for SSRF check.
	// Fail closed: if we can't resolve DNS, we can't verify the IP is safe.
	dnsCtx, dnsCancel := context.WithTimeout(ctx, 5*time.Second) // 5s: DNS resolution ceiling; inherits caller cancellation
	defer dnsCancel()
	ips, err := net.DefaultResolver.LookupHost(dnsCtx, hostname)
	if err != nil {
		return Result{
			Allowed: false,
			Reason:  fmt.Sprintf("SSRF check failed: DNS resolution error for %s: %v", hostname, err),
			Scanner: ScannerSSRF,
			Score:   1.0,
		}
	}

	// Trusted domains bypass the internal-IP CIDR check. All other scanners
	// (DLP, blocklist, entropy) still apply — only the RFC1918 resolution
	// check is skipped. This lets operators allowlist internal services
	// (e.g., local inference servers) without disabling SSRF protection globally.
	if s.IsTrustedDomain(hostname) {
		return Result{Allowed: true}
	}

	for _, ipStr := range ips {
		// Strip IPv6 zone ID (e.g. "::1%eth0" → "::1"). Zone IDs cause
		// net.ParseIP to return nil, silently skipping the CIDR check.
		if idx := strings.Index(ipStr, "%"); idx != -1 {
			ipStr = ipStr[:idx]
		}
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}
		// Normalize IPv4-mapped IPv6 (::ffff:x.x.x.x) to 4-byte form.
		if v4 := ip.To4(); v4 != nil {
			ip = v4
		}

		// Check against internal CIDRs (core + config)
		for _, cidr := range allCIDRs {
			if cidr.Contains(ip) {
				// IP allowlist exemption: operator explicitly trusts this range.
				if s.IsIPAllowlisted(ip) {
					continue
				}
				r := Result{
					Allowed: false,
					Reason:  fmt.Sprintf("SSRF blocked: %s resolves to internal IP %s", hostname, ipStr),
					Scanner: ScannerSSRF,
					Score:   1.0,
				}
				// If the domain is in api_allowlist, this is a config
				// mismatch (not a real attack). Provide a specific hint
				// and classify so adaptive enforcement doesn't escalate.
				if s.IsInAPIAllowlist(hostname) {
					if net.ParseIP(hostname) != nil {
						// Raw IP literal: trusted_domains rejects IPs, so
						// point operators at ssrf.ip_allowlist instead.
						r.Hint = fmt.Sprintf("add %q to ssrf.ip_allowlist to allow this internal IP", ipStr)
					} else {
						r.Hint = fmt.Sprintf("add %q to trusted_domains to allow internal IP resolution", hostname)
					}
					r.Class = ClassConfigMismatch
				}
				return r
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
		Scanner: ScannerAllowlist,
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
				Scanner: ScannerBlocklist,
				Score:   1.0,
			}
		}
	}
	return Result{Allowed: true}
}

// checkCRLF detects CRLF injection sequences in URLs. CR+LF bytes in a URL
// enable HTTP header injection at the target server. Go's http library rejects
// raw \r\n in requests, but we detect encoded variants (%0d%0a, double-encoded)
// for defense-in-depth visibility.
//
// Fragments are excluded: they are never sent to the upstream server, so CRLF
// in a fragment cannot inject headers.
func checkCRLF(rawURL string) Result {
	// Strip fragment — it never reaches the server.
	if idx := strings.IndexByte(rawURL, '#'); idx != -1 {
		rawURL = rawURL[:idx]
	}
	lower := strings.ToLower(rawURL)

	// Check for encoded CRLF pair: %0d%0a (the primary attack vector).
	if strings.Contains(lower, "%0d%0a") {
		return Result{
			Allowed: false,
			Reason:  "CRLF injection sequence in URL",
			Scanner: ScannerCRLF,
			Score:   0.9,
		}
	}

	// Check for double-encoded CRLF pair: %250d%250a.
	if strings.Contains(lower, "%250d%250a") {
		return Result{
			Allowed: false,
			Reason:  "double-encoded CRLF injection sequence in URL",
			Scanner: ScannerCRLF,
			Score:   0.9,
		}
	}

	// Check for bare encoded LF or CR. Some servers (e.g., Node.js HTTP
	// parsers) accept a bare LF as a header terminator, so %0a alone is
	// enough to inject headers without a preceding %0d.
	if strings.Contains(lower, "%0a") || strings.Contains(lower, "%0d") {
		return Result{
			Allowed: false,
			Reason:  "encoded CR or LF in URL",
			Scanner: ScannerCRLF,
			Score:   0.9,
		}
	}

	// Check for double-encoded bare LF or CR: %250a, %250d.
	if strings.Contains(lower, "%250a") || strings.Contains(lower, "%250d") {
		return Result{
			Allowed: false,
			Reason:  "double-encoded CR or LF in URL",
			Scanner: ScannerCRLF,
			Score:   0.9,
		}
	}

	// Check for raw CR or LF bytes (should not appear in URLs).
	if strings.ContainsAny(rawURL, "\r\n") {
		return Result{
			Allowed: false,
			Reason:  "raw CRLF bytes in URL",
			Scanner: ScannerCRLF,
			Score:   0.9,
		}
	}

	return Result{Allowed: true}
}

// checkPathTraversal detects directory traversal sequences in URL paths.
// Target servers are responsible for path safety, but detecting traversal
// provides defense-in-depth and visibility into potential attacks.
func checkPathTraversal(parsed *url.URL) Result {
	// Check the raw path to catch encoded variants. url.Parse decodes %2e
	// to '.' in Path but preserves encoding in RawPath (when it differs).
	rawPath := parsed.RawPath
	if rawPath == "" {
		rawPath = parsed.Path
	}
	lowerPath := strings.ToLower(rawPath)

	// Detect ".." as a path segment in raw and encoded forms.
	// Match segment-bounded traversal: /<dotdot><sep> or trailing /<dotdot>,
	// where sep is / \ %2f %5c and dots may be encoded as %2e.
	dotdots := []string{"..", "%2e.", ".%2e", "%2e%2e"}
	seps := []string{"/", "\\", "%2f", "%5c"}

	for _, dd := range dotdots {
		for _, left := range seps {
			for _, right := range seps {
				// <left><dd><right>  e.g. /../, %2f..%5c, \..%2f
				if strings.Contains(lowerPath, left+dd+right) {
					return Result{Allowed: false, Reason: "path traversal sequence in URL", Scanner: ScannerPathTraversal, Score: 0.7}
				}
			}
			// <left><dd> at end of path — no trailing separator
			if strings.HasSuffix(lowerPath, left+dd) {
				return Result{Allowed: false, Reason: "path traversal sequence in URL", Scanner: ScannerPathTraversal, Score: 0.7}
			}
		}
	}

	// Double-encoded variants: %252e%252e bounded by separators.
	if strings.Contains(lowerPath, "/%252e%252e/") ||
		strings.Contains(lowerPath, "/%252e%252e%252f") ||
		strings.HasSuffix(lowerPath, "/%252e%252e") {
		return Result{
			Allowed: false,
			Reason:  "double-encoded path traversal in URL",
			Scanner: ScannerPathTraversal,
			Score:   0.7,
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
			Scanner: ScannerRateLimit,
			Score:   0.7,
			Class:   ClassProtective,
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

// decodedResult pairs decoded text with the encoding that produced it.
type decodedResult struct {
	text     string
	encoding string
}

// Encoding labels for decoded results.
const (
	encodingHex    = "hex"
	encodingBase64 = "base64"
	encodingBase32 = "base32"
)

// hexPrefixReplacer strips two-char hex prefix notations (\x, \X, 0x, 0X).
// Package-level to avoid repeated construction on every normalizeHex call.
var hexPrefixReplacer = strings.NewReplacer(`\x`, "", `\X`, "", "0x", "", "0X", "")

// normalizeHex strips common hex-notation delimiters so that delimiter-separated
// hex strings can be decoded by hex.DecodeString. Handles:
//   - \x / \X prefix notation: \x73\x6b → 736b
//   - 0x / 0X prefix notation: 0x73 0x6b → 736b
//   - Colon-separated:         73:6b     → 736b
//   - Space-separated:         73 6b     → 736b
//   - Hyphen-separated:        73-6b     → 736b
//   - Comma-separated:         73,6b     → 736b
//
// Returns "" if the result is not valid hex (odd length or non-hex chars).
func normalizeHex(s string) string {
	if len(s) < 4 {
		return ""
	}

	// Strip two-char prefix sequences first (\x, 0x).
	// Must happen before single-char delimiter stripping to avoid
	// leaving stray 'x' characters from partially-matched patterns.
	out := hexPrefixReplacer.Replace(s)

	// Strip single-char delimiters.
	out = strings.Map(func(r rune) rune {
		switch r {
		case ':', ' ', '-', ',':
			return -1
		default:
			return r
		}
	}, out)

	// Validate: must be even-length, non-empty, and pure hex.
	if len(out) == 0 || len(out)%2 != 0 {
		return ""
	}
	for _, c := range out {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return ""
		}
	}
	return out
}

// hexByteSep formats a contiguous hex string with a separator between each byte
// pair. Used by matchSecretEncodings to generate delimiter-separated variants
// of known secrets for substring matching.
// Example: hexByteSep("736b2d", ":") returns "73:6b:2d".
func hexByteSep(hexStr, sep string) string {
	if len(hexStr) < 4 || len(hexStr)%2 != 0 {
		return hexStr
	}
	var b strings.Builder
	b.Grow(len(hexStr) + (len(hexStr)/2-1)*len(sep))
	for i := 0; i < len(hexStr); i += 2 {
		if i > 0 {
			b.WriteString(sep)
		}
		b.WriteString(hexStr[i : i+2])
	}
	return b.String()
}

// hexBytePrefix formats a contiguous hex string with a prefix before each byte pair.
// Example: hexBytePrefix("736b2d", `\x`) returns `\x73\x6b\x2d`.
func hexBytePrefix(hexStr, prefix string) string {
	if len(hexStr) < 2 || len(hexStr)%2 != 0 {
		return hexStr
	}
	var b strings.Builder
	b.Grow(len(hexStr) + (len(hexStr)/2)*len(prefix))
	for i := 0; i < len(hexStr); i += 2 {
		b.WriteString(prefix)
		b.WriteString(hexStr[i : i+2])
	}
	return b.String()
}

// decodeEncodings tries hex, base64, and base32 decoding on a string and returns
// any successfully decoded variants with encoding labels. Used by checkDLP to
// catch encoded secrets in query parameters (e.g. ?key=736b2d616e742d... is
// hex-encoded sk-ant-...). Mirrors the encoding checks in ScanTextForDLP.
func decodeEncodings(s string) []decodedResult {
	var out []decodedResult
	if decoded, err := hex.DecodeString(s); err == nil && len(decoded) > 0 {
		out = append(out, decodedResult{string(decoded), encodingHex})
	} else if normalized := normalizeHex(s); normalized != "" {
		// Delimiter-separated hex (e.g., 73:6b:2d, \x73\x6b, 0x736b).
		if decoded, err := hex.DecodeString(normalized); err == nil && len(decoded) > 0 {
			out = append(out, decodedResult{string(decoded), encodingHex})
		}
	}
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.URLEncoding,
		base64.RawStdEncoding, base64.RawURLEncoding,
	} {
		if decoded, err := enc.DecodeString(s); err == nil && len(decoded) > 0 {
			out = append(out, decodedResult{string(decoded), encodingBase64})
		}
	}
	if decoded, err := base32.StdEncoding.DecodeString(s); err == nil && len(decoded) > 0 {
		out = append(out, decodedResult{string(decoded), encodingBase32})
	}
	return out
}

// checkDLP runs DLP regex patterns against the full URL string including hostname.
// Scanning the full URL catches secrets encoded in subdomains (e.g., sk-proj-xxx.evil.com)
// and secrets split across query parameters. Iterative URL decoding
// prevents multi-layer encoding bypass.
func (s *Scanner) checkDLP(parsed *url.URL) (Result, []WarnMatch) {
	// Canary check is deferred to after DLP pattern evaluation (below).
	// DLP patterns provide more specific attribution ("aws_access_key" vs
	// "Canary Token"). Canary is the safety net for synthetic tokens that
	// DLP patterns don't cover. Both are evaluated — DLP wins if it matches.

	var warnMatches []WarnMatch

	// parsed.Path is already URL-decoded by Go's url.Parse.
	// For query strings, iteratively decode to catch multi-layer encoding.
	decodedQuery := IterativeDecode(parsed.RawQuery)

	targets := []string{
		parsed.String(), // full URL — catches secrets in hostname/subdomains
		parsed.Path,
		decodedQuery,
	}

	// Also check decoded query keys and values individually.
	// Noise-strip each value to catch dot-separated keys (e.g. "s.k.-.a.n.t.-..." → "sk-ant-...").
	// Try hex/base64/base32 decoding to catch encoded secrets
	// (e.g. ?key=736b2d616e742d... is hex-encoded sk-ant-...).
	for key, values := range parsed.Query() {
		decodedKey := IterativeDecode(key)
		targets = append(targets, decodedKey)
		for _, d := range decodeEncodings(decodedKey) {
			targets = append(targets, d.text)
		}
		if stripped := stripURLNoise(decodedKey); stripped != decodedKey {
			targets = append(targets, stripped)
		}
		for _, v := range values {
			decoded := IterativeDecode(v)
			targets = append(targets, decoded)
			for _, d := range decodeEncodings(decoded) {
				targets = append(targets, d.text)
			}
			if stripped := stripURLNoise(decoded); stripped != decoded {
				targets = append(targets, stripped)
			}
		}
	}

	// Also apply iterative decode to the raw path for double-encoded path segments.
	decodedPath := IterativeDecode(parsed.RawPath)
	if decodedPath != "" && decodedPath != parsed.Path {
		targets = append(targets, decodedPath)
	}

	// Try hex/base64/base32 decoding on path segments to catch encoded secrets
	// in URL paths (e.g. /73732d616e742d... is hex-encoded sk-ant-...).
	// Path is already URL-decoded by Go's url.Parse, so we decode the segments directly.
	for _, segment := range strings.Split(parsed.Path, "/") {
		if len(segment) >= 10 { // minimum viable encoded secret length
			for _, d := range decodeEncodings(segment) {
				targets = append(targets, d.text)
			}
		}
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
		cleaned := normalize.ForDLP(target)
		for _, idx := range s.dlpPreFilter.patternsToCheck(cleaned) {
			p := s.dlpPatterns[idx]
			if p.matches(cleaned) {
				// Skip pattern if the destination domain is explicitly exempted.
				if len(p.exemptDomains) > 0 && matchesDomainList(parsed.Hostname(), p.exemptDomains) {
					continue
				}
				if p.warn {
					warnMatches = append(warnMatches, WarnMatch{
						PatternName: p.name,
						Severity:    p.severity,
					})
					continue
				}
				return Result{
					Allowed: false,
					Reason:  fmt.Sprintf("DLP match: %s (%s)", p.name, p.severity),
					Scanner: ScannerDLP,
					Score:   1.0,
				}, warnMatches
			}
		}
	}

	// Subsequence scan: try ordered combinations of query values (size 2-4)
	// to catch secrets split across params with junk values interleaved.
	// E.g., "?a=sk-&x=junk&b=ant-&y=junk&c=api03-&z=junk&d=AAAA..." —
	// combination (0,2,4,6) reconstructs "sk-ant-api03-AAAA...".
	subResult, subWarns := s.querySubsequenceDLP(parsed.RawQuery, parsed.Hostname())
	warnMatches = append(warnMatches, subWarns...)
	if !subResult.Allowed {
		return subResult, warnMatches
	}

	// Seed phrase detection on seed-safe candidates only.
	// NOT on dot-collapsed or noise-stripped text (creates synthetic word runs).
	// Covers: query values, path, hostname labels (pre-DNS exfil), path segments.
	if s.seedEnabled {
		seedTargets := []string{parsed.Path, decodedQuery}
		// Individual query values: raw decoded + encoding variants (base64/hex/base32).
		for _, values := range parsed.Query() {
			for _, v := range values {
				decoded := IterativeDecode(v)
				seedTargets = append(seedTargets, decoded)
				for _, d := range decodeEncodings(decoded) {
					seedTargets = append(seedTargets, d.text)
				}
			}
		}
		// Ordered query-value concatenation with spaces: catches seed phrases
		// split across params (e.g., ?w1=abandon&w2=abandon&...&w12=about).
		// orderedQueryConcat joins without separators (for regex DLP), so we
		// build a space-separated version for seed word tokenization.
		if parsed.RawQuery != "" && strings.Contains(parsed.RawQuery, "&") {
			var seedConcat strings.Builder
			for i, pair := range strings.Split(parsed.RawQuery, "&") {
				_, value, _ := strings.Cut(pair, "=")
				if value != "" {
					if i > 0 {
						seedConcat.WriteByte(' ')
					}
					seedConcat.WriteString(IterativeDecode(value))
				}
			}
			seedTargets = append(seedTargets, seedConcat.String())
		}
		// Decoded path segments: base64/hex/base32 encoded seed phrases in path.
		for _, seg := range strings.Split(parsed.Path, "/") {
			if len(seg) < 20 {
				continue
			}
			for _, d := range decodeEncodings(IterativeDecode(seg)) {
				seedTargets = append(seedTargets, d.text)
			}
		}
		// Hostname labels: catch seed words as subdomain labels
		// (e.g., "abandon.abandon.abandon...evil.com" exfils via DNS).
		// Join labels with spaces so the tokenizer sees them as words.
		hostname := parsed.Hostname()
		if strings.Contains(hostname, ".") {
			seedTargets = append(seedTargets, strings.ReplaceAll(hostname, ".", " "))
		}
		// Path segments: catch seed words as path components
		// (e.g., "/abandon/abandon/abandon/.../about").
		if strings.Contains(parsed.Path, "/") {
			seedTargets = append(seedTargets, strings.ReplaceAll(parsed.Path, "/", " "))
		}
		for _, target := range seedTargets {
			if target == "" {
				continue
			}
			if matches := seedprotect.Detect(target, s.seedMinWords, s.seedVerifyChecksum); len(matches) > 0 {
				return Result{
					Allowed: false,
					Reason:  "DLP match: BIP-39 Seed Phrase (critical)",
					Scanner: ScannerDLP,
					Score:   1.0,
				}, warnMatches
			}
		}
	}

	// Check for environment variable leaks
	if result := s.checkSecretsInURL(s.envSecrets, parsed, "environment variable leak detected"); !result.Allowed {
		return result, warnMatches
	}

	// Check for known file secret leaks
	if result := s.checkSecretsInURL(s.fileSecrets, parsed, "known secret leak detected"); !result.Allowed {
		return result, warnMatches
	}

	return Result{Allowed: true}, deduplicateWarnMatches(warnMatches)
}

// querySubsequenceDLP checks ordered subsequences (combinations) of query
// parameter values for DLP pattern matches. Catches secrets split across
// multiple parameters with arbitrary junk values interleaved between fragments.
// Tries subsequences of size 2-4 for URLs with 3-20 query params.
// Cost: O(n^4) worst case, bounded at ~6k combinations for n=20.
func (s *Scanner) querySubsequenceDLP(rawQuery, hostname string) (Result, []WarnMatch) {
	if rawQuery == "" || !strings.Contains(rawQuery, "&") {
		return Result{Allowed: true}, nil
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
		return Result{Allowed: true}, nil
	}
	// Cap to first 20 values to bound combinatorial cost (O(n^4)).
	if n > 20 {
		values = values[:20]
		n = 20
	}

	var warnMatches []WarnMatch
	for size := 2; size <= 4 && size <= n; size++ {
		result, warns := s.checkDLPCombinations(values, n, size, hostname)
		warnMatches = append(warnMatches, warns...)
		if !result.Allowed {
			return result, warnMatches
		}
	}

	return Result{Allowed: true}, warnMatches
}

// checkDLPCombinations generates all ordered combinations of the given size
// from the values slice and checks each concatenation against DLP patterns.
func (s *Scanner) checkDLPCombinations(values []string, n, size int, hostname string) (Result, []WarnMatch) {
	var warnMatches []WarnMatch
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

		cleaned := normalize.ForDLP(concat)

		for _, idx := range s.dlpPreFilter.patternsToCheck(cleaned) {
			p := s.dlpPatterns[idx]
			if p.matches(cleaned) {
				if len(p.exemptDomains) > 0 && matchesDomainList(hostname, p.exemptDomains) {
					continue
				}
				if p.warn {
					warnMatches = append(warnMatches, WarnMatch{
						PatternName: p.name,
						Severity:    p.severity,
					})
					continue
				}
				return Result{
					Allowed: false,
					Reason:  fmt.Sprintf("DLP match: %s (%s)", p.name, p.severity),
					Scanner: ScannerDLP,
					Score:   1.0,
				}, warnMatches
			}
		}

		if !nextCombination(indices, n) {
			break
		}
	}

	return Result{Allowed: true}, warnMatches
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

// emitDLPWarns calls the instance warn hook for each warn match if set.
func (s *Scanner) emitDLPWarns(ctx context.Context, matches []WarnMatch) {
	if len(matches) == 0 || s.dlpWarnHook == nil {
		return
	}
	for _, m := range matches {
		s.dlpWarnHook(ctx, m.PatternName, m.Severity)
	}
}

// deduplicateWarnMatches removes duplicate warn matches by pattern name.
func deduplicateWarnMatches(matches []WarnMatch) []WarnMatch {
	if len(matches) <= 1 {
		return matches
	}
	seen := make(map[string]struct{}, len(matches))
	out := make([]WarnMatch, 0, len(matches))
	for _, m := range matches {
		if _, ok := seen[m.PatternName]; !ok {
			seen[m.PatternName] = struct{}{}
			out = append(out, m)
		}
	}
	return out
}

// checkSecretsInURL scans a URL for leaked secrets (env vars or file-based).
// It URL-decodes, strips control chars, and checks all encoded forms of each secret.
func (s *Scanner) checkSecretsInURL(secrets []string, parsed *url.URL, reasonPrefix string) Result {
	if len(secrets) == 0 {
		return Result{Allowed: true}
	}

	fullURL := normalize.StripControlChars(parsed.String())
	decodedURL := normalize.StripControlChars(IterativeDecode(fullURL))
	texts := []string{fullURL, decodedURL}
	lowerTexts := []string{strings.ToLower(fullURL), strings.ToLower(decodedURL)}

	for _, secret := range secrets {
		if matched, enc := matchSecretEncodings(secret, texts, lowerTexts); matched {
			reason := reasonPrefix
			if enc != "" {
				reason += " (" + enc + "-encoded)"
			}
			return Result{Allowed: false, Reason: reason, Scanner: ScannerDLP, Score: 1.0}
		}
	}
	// Canary fallback: if no DLP pattern matched, check canary tokens.
	// This runs last so DLP patterns get attribution priority.
	if matches := s.scanCanaryText(parsed.String()); len(matches) > 0 {
		m := matches[0]
		reason := fmt.Sprintf("DLP match: %s (%s)", m.PatternName, m.Severity)
		if m.Encoded != "" {
			reason += " [" + m.Encoded + "]"
		}
		return Result{Allowed: false, Reason: reason, Scanner: ScannerDLP, Score: 1.0}
	}

	return Result{Allowed: true}
}

// containsAny returns true if needle appears in any of the haystacks.
func containsAny(needle string, haystacks ...string) bool {
	for _, h := range haystacks {
		if strings.Contains(h, needle) {
			return true
		}
	}
	return false
}

// matchSecretEncodings checks all encoded forms of a secret against the given texts.
// texts are for case-sensitive checks; lowerTexts (pre-lowercased) are for hex comparison.
// Returns (true, encoding) on first match. Encoding is "" for raw, or "base64",
// "base64url", "hex", "base32" for encoded forms.
func matchSecretEncodings(secret string, texts, lowerTexts []string) (bool, string) {
	// Raw match.
	if containsAny(secret, texts...) {
		return true, ""
	}

	// Base64 standard (padded + unpadded).
	b64Std := base64.StdEncoding.EncodeToString([]byte(secret))
	b64StdNoPad := strings.TrimRight(b64Std, "=")
	if containsAny(b64Std, texts...) ||
		(b64StdNoPad != b64Std && containsAny(b64StdNoPad, texts...)) {
		return true, encodingBase64
	}

	// Base64 URL-safe (padded + unpadded).
	b64URL := base64.URLEncoding.EncodeToString([]byte(secret))
	b64URLNoPad := strings.TrimRight(b64URL, "=")
	if (b64URL != b64Std && containsAny(b64URL, texts...)) ||
		(b64URLNoPad != b64StdNoPad && containsAny(b64URLNoPad, texts...)) {
		return true, "base64url"
	}

	// Hex (case-insensitive via pre-lowered texts).
	hexEnc := hex.EncodeToString([]byte(secret))
	if containsAny(hexEnc, lowerTexts...) {
		return true, encodingHex
	}

	// Delimiter-separated hex variants for env/file secret detection.
	// Matches all formats that normalizeHex can strip.
	colonHex := hexByteSep(hexEnc, ":")
	spaceHex := hexByteSep(hexEnc, " ")
	hyphenHex := hexByteSep(hexEnc, "-")
	commaHex := hexByteSep(hexEnc, ",")
	bsxHex := hexBytePrefix(hexEnc, `\x`)
	zxHex := hexBytePrefix(hexEnc, "0x")
	if containsAny(colonHex, lowerTexts...) ||
		containsAny(spaceHex, lowerTexts...) ||
		containsAny(hyphenHex, lowerTexts...) ||
		containsAny(commaHex, lowerTexts...) ||
		containsAny(bsxHex, lowerTexts...) ||
		containsAny(zxHex, lowerTexts...) {
		return true, encodingHex
	}

	// Base32 standard (padded + unpadded).
	b32Std := base32.StdEncoding.EncodeToString([]byte(secret))
	b32NoPad := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte(secret))
	if containsAny(b32Std, texts...) ||
		(b32NoPad != b32Std && containsAny(b32NoPad, texts...)) {
		return true, encodingBase32
	}

	return false, ""
}

// nonSecretEnvNames lists environment variable names that are never secrets.
// These are well-known system/shell/runtime variables whose values (paths,
// locale strings, color codes) routinely exceed the length and entropy
// thresholds but carry zero secret content. Skipping them prevents false
// positives when agents legitimately send values like $PWD in tool arguments.
var nonSecretEnvNames = map[string]struct{}{
	// Working directory and paths
	"PWD": {}, "OLDPWD": {}, "HOME": {}, "PATH": {},
	"TMPDIR": {}, "TEMP": {}, "TMP": {},
	// POSIX "last command" variable — bash sets $_ to the absolute path
	// of the previously executed command. High-entropy binary path leaks
	// into scans whenever the parent shell ran something like
	// /usr/local/bin/go test. Not a secret, never has been.
	"_": {},
	// User identity (public, not secret)
	"USER": {}, "LOGNAME": {}, "USERNAME": {}, "HOSTNAME": {}, "HOST": {},
	// Shell and terminal
	"SHELL": {}, "SHLVL": {}, "TERM": {}, "TERM_PROGRAM": {},
	"COLORTERM": {}, "COLORFGBG": {},
	// Locale
	"LANG": {}, "LANGUAGE": {},
	// Display
	"DISPLAY": {}, "WAYLAND_DISPLAY": {},
	// Editor
	"EDITOR": {}, "VISUAL": {}, "PAGER": {}, "LESS": {},
	// Color codes (LS_COLORS is often very long and high-entropy)
	"LS_COLORS": {}, "LSCOLORS": {},
	// D-Bus / SSH agent (socket paths, not credentials)
	"DBUS_SESSION_BUS_ADDRESS": {}, "SSH_AUTH_SOCK": {},
	// Language runtimes (paths, not secrets)
	"GOPATH": {}, "GOROOT": {}, "GOBIN": {},
	"PYTHONPATH": {}, "PYTHONHOME": {}, "NODE_PATH": {},
	"MANPATH": {}, "INFOPATH": {},
	// Prompt strings
	"PS1": {}, "PS2": {}, "PS3": {}, "PS4": {},
	// Windows equivalents (matched case-insensitively via ToUpper)
	"USERPROFILE": {}, "APPDATA": {}, "LOCALAPPDATA": {},
	"PROGRAMFILES": {}, "PROGRAMDATA": {},
	"SYSTEMROOT": {}, "WINDIR": {}, "COMSPEC": {},
	"COMPUTERNAME": {}, "PATHEXT": {}, "SESSIONNAME": {},
}

// nonSecretEnvPrefixes lists prefixes for env var names that are never secrets.
// Matched against the uppercased variable name (case-insensitive).
var nonSecretEnvPrefixes = []string{
	"LC_",  // LC_ALL, LC_CTYPE, LC_MESSAGES, etc.
	"XDG_", // XDG_DATA_HOME, XDG_RUNTIME_DIR, etc.
}

// isNonSecretEnvName returns true if the environment variable name is a
// well-known non-secret variable that should be excluded from leak detection.
// Comparison is case-insensitive: on Windows, env var names like "Path" and
// "UserProfile" are common mixed-case variants of the uppercase originals.
func isNonSecretEnvName(name string) bool {
	upper := strings.ToUpper(name)
	if _, ok := nonSecretEnvNames[upper]; ok {
		return true
	}
	for _, prefix := range nonSecretEnvPrefixes {
		if strings.HasPrefix(upper, prefix) {
			return true
		}
	}
	return false
}

// extractEnvSecrets filters environment variables for likely secrets.
// Returns values >= minLen chars with Shannon entropy >3.0.
// Skips well-known non-secret variable names (PWD, PATH, HOME, etc.)
// to avoid false positives on paths and locale strings.
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

		name := parts[0]
		value := parts[1]

		// Skip well-known non-secret variables (paths, locale, shell config).
		if isNonSecretEnvName(name) {
			continue
		}

		if len(value) < minLen {
			continue
		}

		if ShannonEntropy(value) > minEntropy {
			secrets = append(secrets, value)
		}
	}

	return secrets
}

// dedupSecrets removes duplicates from fileSecrets: both against envSecrets
// (preventing double-scanning) and within fileSecrets itself.
func dedupSecrets(fileSecrets, envSecrets []string) []string {
	existing := make(map[string]struct{}, len(envSecrets)+len(fileSecrets))
	for _, s := range envSecrets {
		existing[s] = struct{}{}
	}
	var result []string
	for _, s := range fileSecrets {
		if _, ok := existing[s]; !ok {
			existing[s] = struct{}{}
			result = append(result, s)
		}
	}
	return result
}

// LoadSecretsFile reads explicit secret values from a file, one per line.
// Lines starting with # (after optional whitespace) are comments.
// Blank lines, null-byte lines, and lines below minLen are skipped.
// Max 4096 bytes per line, max 1000 entries.
func LoadSecretsFile(path string, minLen int) ([]string, error) {
	f, err := os.Open(filepath.Clean(path))
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
	// Buffer must exceed maxLineLen so bufio.ErrTooLong cannot fire for any
	// line the explicit len(line) > maxLineLen guard would skip.
	const scanBufMax = maxLineLen*2 + 4096
	sc.Buffer(make([]byte, 0, scanBufMax), scanBufMax)

	for sc.Scan() {
		lineNum++
		line := sc.Text()

		// Strip UTF-8 BOM from first line.
		if first {
			line = strings.TrimPrefix(line, "\xef\xbb\xbf")
			first = false
		}

		// Strip leading and trailing whitespace/tabs/CR.
		line = strings.TrimSpace(line)

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
// Domains listed in subdomain_entropy_exclusions skip path entropy checks only
// (APIs that use high-entropy subdomains often embed tokens in URL paths too).
// Query entropy is always checked regardless of exclusions.
func (s *Scanner) checkEntropy(parsed *url.URL) Result {
	if s.entropyThreshold <= 0 {
		return Result{Allowed: true}
	}

	excluded := s.isExcludedFromSubdomainEntropy(parsed.Hostname())

	// Check path segments (skipped for excluded domains).
	if !excluded {
		for _, segment := range strings.Split(parsed.Path, "/") {
			if len(segment) >= s.entropyMinLen {
				entropy := ShannonEntropy(segment)
				if entropy > s.entropyThreshold {
					return Result{
						Allowed: false,
						Reason:  fmt.Sprintf("high entropy path segment (%.2f > %.2f threshold)", entropy, s.entropyThreshold),
						Scanner: ScannerEntropy,
						Score:   math.Min(entropy/8.0, 1.0), // normalize to 0-1
					}
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
					Scanner: ScannerEntropy,
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
						Scanner: ScannerEntropy,
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
			Scanner: ScannerDataBudget,
			Score:   0.8,
		}
	}
	return Result{Allowed: true}
}

// subdomainMinLabelLen is the minimum subdomain label length to check.
// Short labels (www, api, cdn) are normal and should not be flagged.
const subdomainMinLabelLen = 8

// checkSubdomainEntropy flags hostnames where subdomain labels contain
// high-entropy data, indicating base64/hex exfiltration via DNS queries.
// Only checks hostnames with 3+ labels (at least one subdomain beyond base domain).
// Excludes domains listed in subdomainExclusions (e.g., RunPod, cloud services
// that use high-entropy subdomains for legitimate purposes).
// Uses a separate threshold from query parameter entropy because subdomains
// have different baseline entropy — hex labels at 3.5-4.0 are suspicious
// in subdomains but common in query parameters.
func (s *Scanner) checkSubdomainEntropy(hostname string) Result {
	if s.subdomainEntropyThreshold <= 0 {
		return Result{Allowed: true}
	}

	// Skip IP addresses
	if net.ParseIP(hostname) != nil {
		return Result{Allowed: true}
	}

	// Skip domains on the exclusion list (exact match or wildcard suffix)
	if s.isExcludedFromSubdomainEntropy(hostname) {
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
		if entropy > s.subdomainEntropyThreshold {
			return Result{
				Allowed: false,
				Reason:  fmt.Sprintf("high entropy subdomain label %q (%.2f > %.2f threshold)", label, entropy, s.subdomainEntropyThreshold),
				Scanner: ScannerSubdomainEntropy,
				Score:   math.Min(entropy/8.0, 1.0),
			}
		}
	}

	return Result{Allowed: true}
}

// matchesDomainList checks if the hostname matches any entry in a domain list.
// Supports exact hostnames and wildcard prefixes (*.example.com matches
// any subdomain of example.com, including example.com itself).
// All comparisons are case-insensitive with trailing-dot normalization.
func matchesDomainList(hostname string, domains []string) bool {
	host := strings.ToLower(strings.TrimSuffix(hostname, "."))
	for _, pattern := range domains {
		// Defensive: patterns should already be normalized by config.Validate(),
		// but we re-normalize here as defense-in-depth for security-sensitive matching.
		p := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(pattern), "."))
		if p == "" {
			continue
		}
		// Wildcard prefix: *.example.com matches sub.example.com and example.com
		if strings.HasPrefix(p, "*.") {
			suffix := p[1:] // ".example.com"
			base := p[2:]   // "example.com"
			if host == base || strings.HasSuffix(host, suffix) {
				return true
			}
			continue
		}
		// Exact match
		if host == p {
			return true
		}
	}
	return false
}

// isExcludedFromSubdomainEntropy checks if the hostname matches any subdomain
// entropy exclusion rule.
func (s *Scanner) isExcludedFromSubdomainEntropy(hostname string) bool {
	return matchesDomainList(hostname, s.subdomainExclusions)
}

// baseDomain returns the registrable domain (eTLD+1) for budget tracking,
// stripping subdomains to prevent bypass via subdomain rotation.
// Uses the Mozilla Public Suffix List via golang.org/x/net/publicsuffix,
// which correctly handles ccTLDs (co.uk, com.au, gov.uk, etc.).
// IP addresses and single-label hosts are returned as-is.
func baseDomain(hostname string) string {
	if net.ParseIP(hostname) != nil {
		return hostname
	}
	etld1, err := publicsuffix.EffectiveTLDPlusOne(hostname)
	if err != nil {
		// Fallback for single-label hosts (localhost, etc.)
		return hostname
	}
	return etld1
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
