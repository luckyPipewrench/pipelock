// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/normalize"
)

// Core scanner constants. These label values flow into metrics and audit logs.
const (
	ScannerCoreDLP      = "core_dlp"
	ScannerCoreSSRF     = "core_ssrf"
	ScannerCoreResponse = "core_response"
)

// CoreDLPCount returns the number of immutable core DLP patterns.
func CoreDLPCount() int { return len(coreDLPPatternDefs()) }

// CoreResponseCount returns the number of immutable core response patterns.
func CoreResponseCount() int { return len(coreResponsePatternDefs()) }

// coreDLPPattern defines a single immutable DLP pattern compiled into the binary.
// These patterns represent the safety floor — they CANNOT be disabled by any
// config field (include_defaults, response_scanning.enabled, etc.).
type coreDLPPattern struct {
	name     string
	regex    string
	severity string
}

// coreResponsePattern defines a single immutable response scanning pattern.
type coreResponsePattern struct {
	name  string
	regex string
}

// coreDLPPatternDefs returns the immutable core DLP patterns.
// Decision rule: "Would you be ashamed if this got through?"
//
// These patterns are the absolute minimum safety floor. They detect
// credential types where a false negative is catastrophic — leaked
// cloud keys, source control tokens, and cryptographic material.
func coreDLPPatternDefs() []coreDLPPattern {
	return []coreDLPPattern{
		// Cloud provider credentials — names match config.Defaults() exactly.
		{
			name:     "AWS Access ID",
			regex:    `(AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16,}`,
			severity: "critical",
		},
		{
			name:     "AWS Secret Key",
			regex:    `(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY|secret.?access.?key|SecretAccessKey)\s*["'=:\s]{1,5}\s*[A-Za-z0-9/+=]{40}`,
			severity: "critical",
		},
		{
			name:     "GCP Service Account Key",
			regex:    `"type"\s*:\s*"service_account"`,
			severity: "critical",
		},

		// Source control tokens
		{
			name:     "GitHub Token",
			regex:    `gh[pousr]_[A-Za-z0-9_]{36,}`,
			severity: "critical",
		},
		{
			name:     "GitHub Fine-Grained PAT",
			regex:    `github_pat_[a-zA-Z0-9_]{36,}`,
			severity: "critical",
		},
		{
			name:     "GitLab PAT",
			regex:    `glpat-[a-zA-Z0-9\-_]{20,}`,
			severity: "critical",
		},

		// Messaging platform tokens
		{
			name:     "Slack Token",
			regex:    `xox[bpras]-[0-9a-zA-Z-]{15,}`,
			severity: "critical",
		},

		// Cryptographic material
		{
			name:     "Private Key Header",
			regex:    `-----BEGIN\s+(RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----`,
			severity: "critical",
		},
	}
}

// coreResponsePatternDefs returns the immutable core response scanning patterns.
// These are the highest-confidence prompt injection signatures where a false
// negative means an agent gets hijacked.
func coreResponsePatternDefs() []coreResponsePattern {
	return []coreResponsePattern{
		{
			name:  "Prompt Injection",
			regex: `(?i)(ignore|disregard|forget|abandon)[-,;:.\s]+\s*(?:all\s+\w+\s+|\w+\s+all\s+|all\s+|\w+\s+)?(previous|prior|above|earlier)\s+(\w+\s+)?(instructions|prompts|rules|context|directives|constraints|policies|guardrails)`,
		},
		{
			name:  "System Override",
			regex: `(?im)^\s*system\s*:`,
		},
		{
			name:  "Role Override",
			regex: `(?i)you\s+are\s+(now\s+)?(a\s+)?((?-i:\bDAN\b)|evil|unrestricted|jailbroken|unfiltered)`,
		},
		{
			name:  "Hidden Instruction",
			regex: `(?i)(do\s+not\s+(reveal|tell|show|display|mention)\s+this\s+to\s+the\s+user|hidden\s+instruction|invisible\s+to\s+(the\s+)?user|the\s+user\s+(cannot|must\s+not|should\s+not)\s+see\s+this)`,
		},
		{
			name:  "Credential Solicitation",
			regex: `(?is)\b(send|provide|paste|return|include|supply|submit|share)\b.{0,80}\b(password|passwd|token|api[_ -]?key|secret|credential|private[_ -]?key|ssh[_ -]?key|session[_ -]?cookie)\b`,
		},
		{
			name:  "Credential Path Directive",
			regex: `(?is)\b(read|get|fetch|retrieve|cat|copy|extract|open)\b.{0,80}(\.ssh[/\\]|\.aws[/\\]credentials|\.env\b|\.npmrc\b|\.pypirc\b|\.netrc\b|\bid_rsa\b|\bid_ed25519\b|\bkubeconfig\b|/etc/passwd\b|/etc/shadow\b)`,
		},
		{
			name:  "Covert Action Directive",
			regex: `(?is)(secretly|silently|covertly|quietly|without\s+(?:the\s+user\s+)?(?:knowing|noticing|seeing))[,;:]?\s+.{0,40}\b(execut\w*|run|call|invoke|send|fetch|curl|wget|download|upload|post)\b`,
		},
		{
			name:  "Instruction Boundary",
			regex: `(<\|(?:endoftext|im_start|im_end|system|end_header_id|begin_of_text)\|>|\[/?INST\]|<\|(?:user|assistant)\|>|<<SYS>>)`,
		},
	}
}

// coreInternalCIDRDefs returns the private/reserved IPv4 ranges that the core
// SSRF scanner always blocks. These ranges are checked regardless of the
// user's config.Internal setting.
func coreInternalCIDRDefs() []string {
	return []string{
		"0.0.0.0/8",      // "this" network (RFC 1122)
		"127.0.0.0/8",    // loopback (RFC 1122)
		"10.0.0.0/8",     // private class A (RFC 1918)
		"172.16.0.0/12",  // private class B (RFC 1918)
		"192.168.0.0/16", // private class C (RFC 1918)
		"169.254.0.0/16", // link-local / cloud metadata (RFC 3927)
		"100.64.0.0/10",  // carrier-grade NAT (RFC 6598)
		"::1/128",        // IPv6 loopback
		"fc00::/7",       // IPv6 unique local
		"fe80::/10",      // IPv6 link-local
	}
}

// compiledCoreScanner holds pre-compiled core patterns. Initialized once
// in initCoreScanner and stored on the Scanner struct.
type compiledCoreScanner struct {
	dlpPatterns                []*compiledPattern
	dlpPreFilter               *dlpPreFilter
	responsePatterns           []*compiledPattern
	responsePreFilter          *responsePreFilter
	responseOptSpacePatterns   []*compiledPattern
	responseOptSpacePreFilter  *responsePreFilter
	responseVowelFoldPatterns  []*compiledPattern
	responseVowelFoldPreFilter *responsePreFilter
	internalCIDRs              []*net.IPNet
}

// initCoreScanner compiles all core patterns and CIDRs. Called once from
// scanner.New(). Panics on invalid patterns (these are compile-time constants,
// so invalid patterns are programming errors caught in CI).
func initCoreScanner() *compiledCoreScanner {
	cs := &compiledCoreScanner{}

	// Compile core DLP patterns.
	for _, p := range coreDLPPatternDefs() {
		pattern := p.regex
		if !strings.HasPrefix(pattern, "(?i)") {
			pattern = "(?i)" + pattern
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			panic(fmt.Sprintf("BUG: core DLP pattern %q failed to compile: %v", p.name, err))
		}
		cs.dlpPatterns = append(cs.dlpPatterns, &compiledPattern{
			name:     p.name,
			re:       re,
			severity: p.severity,
		})
	}
	cs.dlpPreFilter = newDLPPreFilter(cs.dlpPatterns)

	// Compile core response patterns with all variant passes.
	for _, p := range coreResponsePatternDefs() {
		re, err := regexp.Compile(p.regex)
		if err != nil {
			panic(fmt.Sprintf("BUG: core response pattern %q failed to compile: %v", p.name, err))
		}
		cs.responsePatterns = append(cs.responsePatterns, &compiledPattern{
			name: p.name,
			re:   re,
		})

		// Optional-whitespace variant: \s+ → \s*
		optRegex := strings.ReplaceAll(p.regex, `\s+`, `\s*`)
		optRegex = strings.ReplaceAll(optRegex, `[-,;:.\s]+`, `[-,;:.\s]*`)
		if optRegex != p.regex {
			if optRe, optErr := regexp.Compile(optRegex); optErr == nil {
				cs.responseOptSpacePatterns = append(cs.responseOptSpacePatterns, &compiledPattern{
					name: p.name,
					re:   optRe,
				})
			}
		}

		// Vowel-folded variant for confusable-vowel attacks.
		vfRegex := p.regex
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
		if vfRegex != p.regex {
			if vfRe, vfErr := regexp.Compile(vfRegex); vfErr == nil {
				cs.responseVowelFoldPatterns = append(cs.responseVowelFoldPatterns, &compiledPattern{
					name: p.name,
					re:   vfRe,
				})
			}
		}
	}

	// Build response pre-filters.
	if len(cs.responsePatterns) > 0 {
		cs.responsePreFilter = newResponsePreFilter(cs.responsePatterns)
	}
	if len(cs.responseOptSpacePatterns) > 0 {
		cs.responseOptSpacePreFilter = newResponsePreFilter(cs.responseOptSpacePatterns)
	}
	if len(cs.responseVowelFoldPatterns) > 0 {
		cs.responseVowelFoldPreFilter = newResponsePreFilter(cs.responseVowelFoldPatterns)
	}

	// Parse core internal CIDRs.
	for _, cidr := range coreInternalCIDRDefs() {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(fmt.Sprintf("BUG: core internal CIDR %q failed to parse: %v", cidr, err))
		}
		cs.internalCIDRs = append(cs.internalCIDRs, ipNet)
	}

	return cs
}

// ScanCoreResponse runs core response patterns against content. This runs
// regardless of ResponseScanning.Enabled — the safety floor is non-negotiable.
// Returns matches found by core patterns only; the caller should run the main
// response scanner separately if enabled.
func (s *Scanner) ScanCoreResponse(ctx context.Context, content string) []ResponseMatch {
	if s.core == nil {
		return nil
	}
	if ctx != nil && ctx.Err() != nil {
		return []ResponseMatch{{
			PatternName: "context_canceled",
			MatchText:   ctx.Err().Error(),
		}}
	}

	original := content
	content = normalize.ForMatching(content)

	// Primary pass.
	if matches := matchPatternsPreFiltered(s.core.responsePreFilter, s.core.responsePatterns, content); len(matches) > 0 {
		return matches
	}

	// Secondary: replace invisible chars with spaces.
	spaced := normalize.ForMatching(normalize.ReplaceInvisibleWithSpace(original))
	if spaced != content {
		if matches := matchPatternsPreFiltered(s.core.responsePreFilter, s.core.responsePatterns, spaced); len(matches) > 0 {
			return matches
		}
	}

	// Tertiary: leetspeak normalization.
	leeted := normalize.Leetspeak(content)
	if leeted != content {
		if matches := matchPatternsPreFiltered(s.core.responsePreFilter, s.core.responsePatterns, leeted); len(matches) > 0 {
			return matches
		}
	}

	// Quaternary: optional-whitespace matching.
	if len(s.core.responseOptSpacePatterns) > 0 {
		if matches := matchPatternsPreFiltered(s.core.responseOptSpacePreFilter, s.core.responseOptSpacePatterns, content); len(matches) > 0 {
			return matches
		}
	}

	// Quinary: vowel-folded matching.
	if len(s.core.responseVowelFoldPatterns) > 0 {
		folded := normalize.FoldVowels(content)
		if folded != content {
			if matches := matchPatternsPreFiltered(s.core.responseVowelFoldPreFilter, s.core.responseVowelFoldPatterns, folded); len(matches) > 0 {
				return matches
			}
		}
	}

	// Senary: base64/hex decode pass for encoded injection payloads.
	if hasEncodedRun(content) {
		if matches := s.matchDecodedCoreResponse(content); len(matches) > 0 {
			return matches
		}
	}

	return nil
}

// matchDecodedCoreResponse tries base64/hex decoding content and checks the
// decoded result against core response patterns. Entry point for the senary pass.
func (s *Scanner) matchDecodedCoreResponse(content string) []ResponseMatch {
	return s.matchDecodedCoreResponseRecursive(content, 0)
}

// matchDecodedCoreResponseRecursive is the recursive implementation of
// matchDecodedCoreResponse. Mirrors the main scanner's matchDecodedResponseRecursive
// but uses only core response patterns.
func (s *Scanner) matchDecodedCoreResponseRecursive(content string, depth int) []ResponseMatch {
	if depth >= responseDecodeMaxDepth {
		return nil
	}

	// Strategy 1: whole-content decode (strip whitespace first).
	stripped := strings.Map(func(r rune) rune {
		if r == ' ' || r == '\n' || r == '\r' || r == '\t' {
			return -1
		}
		return r
	}, content)

	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.URLEncoding,
		base64.RawStdEncoding, base64.RawURLEncoding,
	} {
		if decoded, err := enc.DecodeString(stripped); err == nil && len(decoded) > 0 {
			d := string(decoded)
			normalized := normalize.ForMatching(d)
			if matches := matchPatternsPreFiltered(s.core.responsePreFilter, s.core.responsePatterns, normalized); len(matches) > 0 {
				return matches
			}
			if matches := s.matchDecodedCoreResponseRecursive(d, depth+1); len(matches) > 0 {
				return matches
			}
		}
	}
	if decoded, err := hex.DecodeString(stripped); err == nil && len(decoded) > 0 {
		d := string(decoded)
		normalized := normalize.ForMatching(d)
		if matches := matchPatternsPreFiltered(s.core.responsePreFilter, s.core.responsePatterns, normalized); len(matches) > 0 {
			return matches
		}
		if matches := s.matchDecodedCoreResponseRecursive(d, depth+1); len(matches) > 0 {
			return matches
		}
	}

	// Strategy 2: segment-level decode.
	segments := extractEncodedRuns(content, minSegmentDecodeLen)
	for _, seg := range segments {
		for _, enc := range []*base64.Encoding{
			base64.StdEncoding, base64.URLEncoding,
			base64.RawStdEncoding, base64.RawURLEncoding,
		} {
			if decoded, err := enc.DecodeString(seg); err == nil && len(decoded) > 0 && isPrintableText(decoded) {
				d := string(decoded)
				normalized := normalize.ForMatching(d)
				if matches := matchPatternsPreFiltered(s.core.responsePreFilter, s.core.responsePatterns, normalized); len(matches) > 0 {
					return matches
				}
				if matches := s.matchDecodedCoreResponseRecursive(d, depth+1); len(matches) > 0 {
					return matches
				}
			}
		}
		if decoded, err := hex.DecodeString(seg); err == nil && len(decoded) > 0 && isPrintableText(decoded) {
			d := string(decoded)
			normalized := normalize.ForMatching(d)
			if matches := matchPatternsPreFiltered(s.core.responsePreFilter, s.core.responsePatterns, normalized); len(matches) > 0 {
				return matches
			}
			if matches := s.matchDecodedCoreResponseRecursive(d, depth+1); len(matches) > 0 {
				return matches
			}
		}
	}

	return nil
}

// scanCoreDLP runs core DLP patterns against text. Returns matches found by
// core patterns only.
func (s *Scanner) scanCoreDLP(text string) []TextDLPMatch {
	if s.core == nil || len(s.core.dlpPatterns) == 0 {
		return nil
	}

	cleaned := normalize.ForDLP(text)
	var matches []TextDLPMatch

	for _, idx := range s.core.dlpPreFilter.patternsToCheck(cleaned) {
		p := s.core.dlpPatterns[idx]
		if p.matches(cleaned) {
			matches = append(matches, TextDLPMatch{
				PatternName: p.name,
				Severity:    p.severity,
			})
		}
	}

	// URL-decoded variant.
	if decoded := IterativeDecode(cleaned); decoded != cleaned {
		matches = append(matches, s.matchCoreDLPPatterns(decoded, "url")...)
	}

	// Subdomain dot-collapse.
	if strings.Contains(cleaned, ".") {
		dotless := strings.ReplaceAll(cleaned, ".", "")
		if dotless != cleaned {
			matches = append(matches, s.matchCoreDLPPatterns(dotless, "subdomain")...)
		}
	}

	// Recursive encoding decode: try base64, hex, base32 and re-check
	// core DLP patterns on decoded content. Catches base64(secret), hex(secret).
	matches = append(matches, s.decodeAndMatchCoreRecursive(cleaned, 0)...)

	return deduplicateMatches(matches)
}

// matchCoreDLPPatterns runs core DLP regex patterns against text with encoding tag.
func (s *Scanner) matchCoreDLPPatterns(text, encoding string) []TextDLPMatch {
	text = normalize.ForDLP(text)
	var matches []TextDLPMatch
	for _, idx := range s.core.dlpPreFilter.patternsToCheck(text) {
		p := s.core.dlpPatterns[idx]
		if p.matches(text) {
			matches = append(matches, TextDLPMatch{
				PatternName: p.name,
				Severity:    p.severity,
				Encoded:     encoding,
			})
		}
	}
	return matches
}

// decodeAndMatchCoreRecursive tries base64, hex, and base32 decoding, runs core
// DLP patterns on decoded content, then recurses on the decoded result to catch
// multi-layer chains (e.g., base64(hex(secret))). Mirrors the main scanner's
// decodeAndMatchRecursive but uses only core DLP patterns.
func (s *Scanner) decodeAndMatchCoreRecursive(text string, depth int) []TextDLPMatch {
	if depth >= maxDecodeDepth {
		return nil
	}

	var matches []TextDLPMatch

	// Try base64 decoding (padded and unpadded variants).
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.URLEncoding,
		base64.RawStdEncoding, base64.RawURLEncoding,
	} {
		if decoded, err := enc.DecodeString(text); err == nil && len(decoded) > 0 {
			d := string(decoded)
			matches = append(matches, s.matchCoreDLPPatterns(d, "base64")...)
			matches = append(matches, s.decodeAndMatchCoreRecursive(d, depth+1)...)
		}
	}

	// Try hex decoding (raw and delimiter-stripped).
	if decoded, err := hex.DecodeString(text); err == nil && len(decoded) > 0 {
		d := string(decoded)
		matches = append(matches, s.matchCoreDLPPatterns(d, "hex")...)
		matches = append(matches, s.decodeAndMatchCoreRecursive(d, depth+1)...)
	} else if normalized := normalizeHex(text); normalized != "" {
		if decoded, err := hex.DecodeString(normalized); err == nil && len(decoded) > 0 {
			d := string(decoded)
			matches = append(matches, s.matchCoreDLPPatterns(d, "hex")...)
			matches = append(matches, s.decodeAndMatchCoreRecursive(d, depth+1)...)
		}
	}

	// Try base32 decoding.
	if decoded, err := base32.StdEncoding.DecodeString(text); err == nil && len(decoded) > 0 {
		d := string(decoded)
		matches = append(matches, s.matchCoreDLPPatterns(d, "base32")...)
		matches = append(matches, s.decodeAndMatchCoreRecursive(d, depth+1)...)
	}

	return matches
}

// isCoreCIDRBlocked checks whether an IP falls within any core internal CIDR.
// This check always runs, even if the user's config.Internal is empty.
func (s *Scanner) isCoreCIDRBlocked(ip net.IP) bool {
	if s.core == nil {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	for _, cidr := range s.core.internalCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// mergedSSRFCIDRs returns core CIDRs combined with user-configured CIDRs.
// Core CIDRs come first so they're checked before config CIDRs. Duplicate
// ranges are acceptable — net.IPNet.Contains is cheap and the total count is small.
func (s *Scanner) mergedSSRFCIDRs() []*net.IPNet {
	if s.core == nil {
		return s.internalCIDRs
	}
	if len(s.internalCIDRs) == 0 {
		return s.core.internalCIDRs
	}
	merged := make([]*net.IPNet, 0, len(s.core.internalCIDRs)+len(s.internalCIDRs))
	merged = append(merged, s.core.internalCIDRs...)
	merged = append(merged, s.internalCIDRs...)
	return merged
}

// checkCoreSSRFLiteral blocks requests to literal private IP addresses when
// SSRF config is disabled (cfg.Internal is nil). This provides the same
// immutable floor for SSRF as core DLP and core response scanning.
//
// When SSRF IS active (cfg.Internal non-nil), the normal checkSSRF path
// already includes core CIDRs via mergedSSRFCIDRs() and provides richer
// diagnostics (hints, config mismatch classification). This function only
// serves as the safety net for the disabled case.
//
// Only checks IP literals (standard dotted-decimal, hex, octal, decimal
// integer). Hostname-based SSRF (where DNS resolves to a private IP) remains
// config-gated because it requires DNS resolution.
//
// Respects ssrf.ip_allowlist so operators can explicitly permit specific
// internal IPs (e.g., sidecar communication, test servers).
func (s *Scanner) checkCoreSSRFLiteral(hostname string) Result {
	if s.core == nil {
		return Result{Allowed: true}
	}

	// When SSRF is active, checkSSRF handles everything (including core
	// CIDRs via mergedSSRFCIDRs). Only fire here as the safety net.
	if len(s.internalCIDRs) > 0 {
		return Result{Allowed: true}
	}

	// Normalize hostname for IP parsing:
	// - Strip IPv6 zone ID (e.g. "::1%eth0" → "::1") which causes
	//   net.ParseIP to return nil.
	// - url.URL.Hostname() already strips brackets from "[::1]".
	clean := hostname
	if idx := strings.Index(clean, "%"); idx != -1 {
		clean = clean[:idx]
	}

	// Try standard dotted-decimal / IPv6 first.
	ip := net.ParseIP(clean)

	// Try alternative IP notations (hex, octal, decimal integer).
	if ip == nil {
		ip = parseAlternativeIP(clean)
	}

	if ip == nil {
		return Result{Allowed: true} // hostname, not IP literal
	}

	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}

	// Operator override: ip_allowlist exempts specific ranges.
	if s.IsIPAllowlisted(ip) {
		return Result{Allowed: true}
	}

	if s.isCoreCIDRBlocked(ip) {
		r := Result{
			Allowed: false,
			Reason:  fmt.Sprintf("core SSRF: %s is a private/internal IP address", hostname),
			Scanner: ScannerCoreSSRF,
			Score:   1.0,
		}
		// If the IP is in api_allowlist, this is a config mismatch (operator
		// intended to allow it) rather than a real attack. Classify so
		// adaptive enforcement doesn't escalate, and hint toward ip_allowlist.
		if s.IsInAPIAllowlist(clean) {
			cidr := ip.String() + "/128"
			if ip.To4() != nil {
				cidr = ip.String() + "/32"
			}
			r.Hint = fmt.Sprintf("add %q to ssrf.ip_allowlist to allow this internal IP", cidr)
			r.Class = ClassConfigMismatch
		}
		return r
	}

	return Result{Allowed: true}
}

// checkCoreDLP runs core DLP patterns against a parsed URL. Mirrors the main
// checkDLP flow but uses only core patterns. Core findings are FINAL.
func (s *Scanner) checkCoreDLP(parsed *url.URL) Result {
	if s.core == nil || len(s.core.dlpPatterns) == 0 {
		return Result{Allowed: true}
	}

	decodedQuery := IterativeDecode(parsed.RawQuery)
	targets := []string{
		parsed.String(),
		parsed.Path,
		decodedQuery,
	}

	// Individual query keys and values (decoded + encoding variants).
	for key, values := range parsed.Query() {
		decodedKey := IterativeDecode(key)
		targets = append(targets, decodedKey)
		if stripped := stripURLNoise(decodedKey); stripped != decodedKey {
			targets = append(targets, stripped)
		}
		for _, v := range values {
			decoded := IterativeDecode(v)
			targets = append(targets, decoded)
			if stripped := stripURLNoise(decoded); stripped != decoded {
				targets = append(targets, stripped)
			}
		}
	}

	// Dot-collapse hostname.
	if hostname := parsed.Hostname(); strings.Contains(hostname, ".") {
		targets = append(targets, strings.ReplaceAll(hostname, ".", ""))
	}

	// Noise-stripped path.
	if stripped := stripURLNoise(parsed.Path); stripped != parsed.Path {
		targets = append(targets, stripped)
	}

	// Double-encoded raw path.
	decodedPath := IterativeDecode(parsed.RawPath)
	if decodedPath != "" && decodedPath != parsed.Path {
		targets = append(targets, decodedPath)
	}

	// Path segment decoding (hex/base64/base32).
	for _, segment := range strings.Split(parsed.Path, "/") {
		if len(segment) >= 10 {
			for _, d := range decodeEncodings(segment) {
				targets = append(targets, d.text)
			}
		}
	}

	// Ordered query-value concatenation (catches secrets split across params).
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
		cleaned := normalize.ForDLP(target)
		for _, idx := range s.core.dlpPreFilter.patternsToCheck(cleaned) {
			p := s.core.dlpPatterns[idx]
			if p.matches(cleaned) {
				return Result{
					Allowed: false,
					Reason:  fmt.Sprintf("core DLP match: %s (%s)", p.name, p.severity),
					Scanner: ScannerCoreDLP,
					Score:   1.0,
				}
			}
		}
	}

	// Subsequence scan: try ordered combinations of query values to catch
	// secrets split across params with junk values interleaved.
	if result := s.querySubsequenceCoreDLP(parsed.RawQuery); !result.Allowed {
		return result
	}

	return Result{Allowed: true}
}

// querySubsequenceCoreDLP checks ordered combinations of query values against
// core DLP patterns. Mirrors the main scanner's querySubsequenceDLP.
func (s *Scanner) querySubsequenceCoreDLP(rawQuery string) Result {
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
	if n > 20 {
		values = values[:20]
		n = 20
	}
	for size := 2; size <= 4 && size <= n; size++ {
		if result := s.checkCoreDLPCombinations(values, n, size); !result.Allowed {
			return result
		}
	}
	return Result{Allowed: true}
}

// checkCoreDLPCombinations tries all ordered combinations of query values
// of the given size against core DLP patterns.
func (s *Scanner) checkCoreDLPCombinations(values []string, n, size int) Result {
	indices := make([]int, size)
	for i := range indices {
		indices[i] = i
	}
	for {
		var concat strings.Builder
		for _, idx := range indices {
			concat.WriteString(values[idx])
		}
		combined := concat.String()
		cleaned := normalize.ForDLP(combined)
		for _, idx := range s.core.dlpPreFilter.patternsToCheck(cleaned) {
			p := s.core.dlpPatterns[idx]
			if p.matches(cleaned) {
				return Result{
					Allowed: false,
					Reason:  fmt.Sprintf("core DLP match: %s (%s)", p.name, p.severity),
					Scanner: ScannerCoreDLP,
					Score:   1.0,
				}
			}
		}
		// Advance to next combination in lexicographic order.
		i := size - 1
		for i >= 0 && indices[i] == n-size+i {
			i--
		}
		if i < 0 {
			break
		}
		indices[i]++
		for j := i + 1; j < size; j++ {
			indices[j] = indices[j-1] + 1
		}
	}
	return Result{Allowed: true}
}

// CorePatternCount returns the number of core DLP + response patterns.
// Used by diagnostics and health checks.
func (s *Scanner) CorePatternCount() (dlp, response int) {
	if s.core == nil {
		return 0, 0
	}
	return len(s.core.dlpPatterns), len(s.core.responsePatterns)
}
