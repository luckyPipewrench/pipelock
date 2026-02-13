package scanner

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"strings"

	"golang.org/x/text/unicode/norm"
)

// TextDLPMatch describes a single DLP pattern match in arbitrary text.
type TextDLPMatch struct {
	PatternName string `json:"pattern_name"`
	Severity    string `json:"severity"`
	Encoded     string `json:"encoded,omitempty"` // "", "base64", "hex", "base32", "env", "url", "subdomain"
}

// TextDLPResult describes the outcome of scanning text for DLP patterns.
type TextDLPResult struct {
	Clean   bool           `json:"clean"`
	Matches []TextDLPMatch `json:"matches,omitempty"`
}

// ScanTextForDLP checks arbitrary text for DLP pattern matches and env secret leaks.
// Unlike checkDLP (which operates on URLs), this method works on raw text strings
// from MCP tool arguments. It applies zero-width stripping, NFKC normalization,
// and checks encoded variants (base64, hex, base32) of the text for patterns.
func (s *Scanner) ScanTextForDLP(text string) TextDLPResult {
	if len(s.dlpPatterns) == 0 && len(s.envSecrets) == 0 {
		return TextDLPResult{Clean: true}
	}

	// Normalize: strip zero-width chars and apply NFKC.
	cleaned := stripZeroWidth(text)
	cleaned = norm.NFKC.String(cleaned)

	var matches []TextDLPMatch

	// Check raw text against DLP patterns (before URL decoding).
	// This catches secrets that aren't URL-encoded.
	for _, p := range s.dlpPatterns {
		if p.re.MatchString(cleaned) {
			matches = append(matches, TextDLPMatch{
				PatternName: p.name,
				Severity:    p.severity,
			})
		}
	}

	// Iterative URL-decode and re-check DLP patterns (catches %2D → - etc.).
	// Uses iterativeDecode (up to 3 rounds) to defeat double/triple encoding.
	if decoded := iterativeDecode(cleaned); decoded != cleaned {
		matches = append(matches, s.matchDLPPatterns(decoded, "url")...)
	}

	// Dot-collapse check: catches secrets split across DNS subdomains
	// (e.g. "sk-ant-api03.AABBCCDD.EEFFGGHH.evil.com" → "sk-ant-api03AABBCCDDEEFFGGHH...").
	// Only applied when text contains dots that could be subdomain separators.
	if strings.Contains(cleaned, ".") {
		dotless := strings.ReplaceAll(cleaned, ".", "")
		if dotless != cleaned {
			matches = append(matches, s.matchDLPPatterns(dotless, "subdomain")...)
		}
	}

	// Try base64 decoding the text and check decoded content.
	// Check both padded and unpadded variants (attackers often strip padding).
	for _, enc := range []struct {
		e *base64.Encoding
	}{
		{base64.StdEncoding},
		{base64.URLEncoding},
		{base64.RawStdEncoding},
		{base64.RawURLEncoding},
	} {
		if decoded, err := enc.e.DecodeString(cleaned); err == nil && len(decoded) > 0 {
			matches = append(matches, s.matchDLPPatterns(string(decoded), "base64")...)
		}
	}

	// Try hex decoding.
	if decoded, err := hex.DecodeString(cleaned); err == nil && len(decoded) > 0 {
		matches = append(matches, s.matchDLPPatterns(string(decoded), "hex")...)
	}

	// Try base32 decoding.
	if decoded, err := base32.StdEncoding.DecodeString(cleaned); err == nil && len(decoded) > 0 {
		matches = append(matches, s.matchDLPPatterns(string(decoded), "base32")...)
	}

	// Check for env secret leaks (raw + encoded forms).
	matches = append(matches, s.checkEnvLeakText(cleaned)...)

	// Deduplicate matches by pattern name + encoding.
	matches = deduplicateMatches(matches)

	if len(matches) == 0 {
		return TextDLPResult{Clean: true}
	}
	return TextDLPResult{Clean: false, Matches: matches}
}

// matchDLPPatterns runs DLP regex patterns against text, tagging matches with encoding.
// Strips null bytes and zero-width chars from decoded text before matching, since
// URL/base64/hex decoding can reintroduce them after the initial stripZeroWidth pass.
func (s *Scanner) matchDLPPatterns(text, encoding string) []TextDLPMatch {
	text = stripZeroWidth(text)
	var matches []TextDLPMatch
	for _, p := range s.dlpPatterns {
		if p.re.MatchString(text) {
			matches = append(matches, TextDLPMatch{
				PatternName: p.name,
				Severity:    p.severity,
				Encoded:     encoding,
			})
		}
	}
	return matches
}

// checkEnvLeakText checks text for environment variable secret values.
// Checks raw text and common encoded forms (base64, hex, base32).
func (s *Scanner) checkEnvLeakText(text string) []TextDLPMatch {
	if len(s.envSecrets) == 0 {
		return nil
	}

	lowerText := strings.ToLower(text)
	var matches []TextDLPMatch

	for _, secret := range s.envSecrets {
		// Raw match.
		if strings.Contains(text, secret) {
			matches = append(matches, TextDLPMatch{
				PatternName: "Environment Variable Leak",
				Severity:    "critical",
				Encoded:     "env",
			})
			return matches // One env leak is enough to flag.
		}

		// Base64-encoded match (check both padded and unpadded).
		encoded := base64.StdEncoding.EncodeToString([]byte(secret))
		unpadded := strings.TrimRight(encoded, "=")
		if strings.Contains(text, encoded) || strings.Contains(text, unpadded) {
			matches = append(matches, TextDLPMatch{
				PatternName: "Environment Variable Leak",
				Severity:    "critical",
				Encoded:     "env",
			})
			return matches
		}

		// URL-safe base64 (check both padded and unpadded).
		encodedURL := base64.URLEncoding.EncodeToString([]byte(secret))
		unpaddedURL := strings.TrimRight(encodedURL, "=")
		if (encodedURL != encoded && strings.Contains(text, encodedURL)) ||
			(unpaddedURL != unpadded && strings.Contains(text, unpaddedURL)) {
			matches = append(matches, TextDLPMatch{
				PatternName: "Environment Variable Leak",
				Severity:    "critical",
				Encoded:     "env",
			})
			return matches
		}

		// Hex-encoded match.
		hexEncoded := hex.EncodeToString([]byte(secret))
		if strings.Contains(lowerText, hexEncoded) {
			matches = append(matches, TextDLPMatch{
				PatternName: "Environment Variable Leak",
				Severity:    "critical",
				Encoded:     "env",
			})
			return matches
		}

		// Base32-encoded match.
		b32 := base32.StdEncoding.EncodeToString([]byte(secret))
		if strings.Contains(text, b32) {
			matches = append(matches, TextDLPMatch{
				PatternName: "Environment Variable Leak",
				Severity:    "critical",
				Encoded:     "env",
			})
			return matches
		}
	}

	return nil
}

// deduplicateMatches removes duplicate matches with the same pattern name and encoding.
func deduplicateMatches(matches []TextDLPMatch) []TextDLPMatch {
	if len(matches) <= 1 {
		return matches
	}

	type key struct {
		name    string
		encoded string
	}
	seen := make(map[key]struct{}, len(matches))
	result := make([]TextDLPMatch, 0, len(matches))
	for _, m := range matches {
		k := key{name: m.PatternName, encoded: m.Encoded}
		if _, ok := seen[k]; !ok {
			seen[k] = struct{}{}
			result = append(result, m)
		}
	}
	return result
}
