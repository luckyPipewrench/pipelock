// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"mime"
	"net/url"
	"path"
	"strings"
)

// IsSuppressed checks if a finding with the given rule name and target path/URL
// matches any suppress entry. Supports exact match, glob (path.Match), directory
// prefix ("vendor/"), and basename glob ("*.txt" matches "dir/foo.txt").
func IsSuppressed(rule, target string, entries []SuppressEntry) bool {
	_, ok := SuppressedReason(rule, target, entries)
	return ok
}

// SuppressedReason returns the reason and true if the finding is suppressed,
// or ("", false) if not suppressed.
func SuppressedReason(rule, target string, entries []SuppressEntry) (string, bool) {
	if target == "" || len(entries) == 0 {
		return "", false
	}
	target = toSlash(target)
	for _, e := range entries {
		if !strings.EqualFold(e.Rule, rule) {
			continue
		}
		if matchesPath(target, e.Path) {
			return e.Reason, true
		}
	}
	return "", false
}

// matchesPath checks if target matches the given pattern.
func matchesPath(target, pattern string) bool {
	p := toSlash(pattern)
	if p == "" {
		return false
	}
	// Strip standard ports from both target and pattern so suppress
	// entries like "https://api.anthropic.com:443/*" match targets
	// without explicit ports, and vice versa.
	normalized := stripStandardPorts(target)
	p = stripStandardPorts(p)
	// Directory prefix: "vendor/" matches "vendor/foo/bar.go"
	if strings.HasSuffix(p, "/") {
		return strings.HasPrefix(normalized, p)
	}
	// Exact match (try both original and port-stripped).
	if normalized == p || target == p {
		return true
	}
	// Glob on full path.
	if matched, _ := path.Match(p, normalized); matched {
		return true
	}
	// Glob on basename (e.g., "*.txt" matches "dir/foo.txt").
	if matched, _ := path.Match(p, path.Base(normalized)); matched {
		return true
	}
	// Substring match for URL-style patterns containing "://".
	// Enables "*.anthropic.com*" to match "https://api.anthropic.com/v1/messages"
	// where path.Match fails because "*" doesn't cross "/" boundaries.
	if strings.Contains(p, "://") || (strings.Contains(p, ".") && strings.Contains(normalized, "://")) {
		if matchGlobSubstring(normalized, p) {
			return true
		}
	}
	// URL suffix match: pattern without leading slash matches URL path suffix.
	// e.g., "robots.txt" matches "https://example.com/robots.txt"
	if !strings.HasPrefix(p, "/") && strings.HasSuffix(normalized, "/"+p) {
		return true
	}
	return false
}

// stripStandardPorts removes :443 and :80 from URLs so suppress patterns
// don't need to account for explicit default ports. Uses net/url parsing
// to correctly identify the host:port boundary.
func stripStandardPorts(u string) string {
	if !strings.Contains(u, "://") {
		return u
	}
	parsed, err := url.Parse(u)
	if err != nil {
		return u
	}
	port := parsed.Port()
	if port == "443" || port == "80" {
		parsed.Host = parsed.Hostname()
		return parsed.String()
	}
	return u
}

// matchGlobSubstring does a simple glob match where "*" matches any character
// including "/". This is needed for URL patterns where path.Match's "*"
// (which stops at "/") is too restrictive.
func matchGlobSubstring(s, pattern string) bool {
	if pattern == "" {
		return false
	}
	// Convert glob to a simple check: split on "*" and verify all parts
	// appear in order in the string.
	parts := strings.Split(pattern, "*")
	if len(parts) == 0 {
		return false
	}
	idx := 0
	for i, part := range parts {
		if part == "" {
			continue
		}
		pos := strings.Index(s[idx:], part)
		if pos < 0 {
			return false
		}
		// First part must be a prefix if pattern doesn't start with "*".
		if i == 0 && !strings.HasPrefix(pattern, "*") && pos != 0 {
			return false
		}
		idx += pos + len(part)
	}
	// Last part must be a suffix if pattern doesn't end with "*".
	if !strings.HasSuffix(pattern, "*") {
		lastPart := parts[len(parts)-1]
		if lastPart != "" && !strings.HasSuffix(s, lastPart) {
			return false
		}
	}
	return true
}

// toSlash normalizes path separators to forward slashes.
func toSlash(s string) string {
	return strings.ReplaceAll(s, "\\", "/")
}

// SNIVerificationEnabled returns whether SNI verification is active.
// Defaults to true when not explicitly set.
func (f ForwardProxy) SNIVerificationEnabled() bool {
	if f.SNIVerification == nil {
		return true
	}
	return *f.SNIVerification
}

// EnforceEnabled returns whether blocking is enabled.
// Defaults to true when Enforce is nil (not set in config).
func (c *Config) EnforceEnabled() bool {
	return c.Enforce == nil || *c.Enforce
}

// ExplainBlocksEnabled returns whether block responses include hints.
// Defaults to false when ExplainBlocks is nil (opt-in only).
// Enabling this exposes scanner names and config field names in responses,
// which is useful for debugging but constitutes information disclosure.
func (c *Config) ExplainBlocksEnabled() bool {
	return c.ExplainBlocks != nil && *c.ExplainBlocks
}

// IsEnabled returns true if Sentry is enabled (nil defaults to true).
func (s *SentryConfig) IsEnabled() bool {
	return s.Enabled == nil || *s.Enabled
}

// EffectiveSampleRate returns the configured sample rate (nil defaults to 1.0).
func (s *SentryConfig) EffectiveSampleRate() float64 {
	if s.SampleRate == nil {
		return 1.0
	}
	return *s.SampleRate
}

// HasDoWFields returns true if any denial-of-wallet tracking field is set.
func (b *BudgetConfig) HasDoWFields() bool {
	return b.MaxToolCallsPerSession > 0 ||
		b.MaxConcurrentToolCalls > 0 ||
		b.MaxWallClockMinutes > 0 ||
		b.MaxRetriesPerTool > 0 ||
		b.MaxRetriesPerEndpoint > 0 ||
		b.LoopDetectionWindow > 0 ||
		b.FanOutLimit > 0
}

// ValidateDoW checks that dow_action is a recognized value.
func (b *BudgetConfig) ValidateDoW() error {
	switch b.DoWAction {
	case "", ActionBlock, ActionWarn:
		return nil
	default:
		return fmt.Errorf("invalid dow_action %q: must be block or warn", b.DoWAction)
	}
}

// IsEnabled reports whether the media policy is active. Defaults to true
// when the field is unset (security-preserving default).
func (m *MediaPolicy) IsEnabled() bool {
	return m.Enabled == nil || *m.Enabled
}

// ShouldStripImages reports whether all image responses should be rejected.
// Defaults to false when unset (allow images with metadata stripping).
func (m *MediaPolicy) ShouldStripImages() bool {
	return m.StripImages != nil && *m.StripImages
}

// ShouldStripAudio reports whether all audio responses should be rejected.
// Defaults to true when unset.
func (m *MediaPolicy) ShouldStripAudio() bool {
	return m.StripAudio == nil || *m.StripAudio
}

// ShouldStripVideo reports whether all video responses should be rejected.
// Defaults to true when unset.
func (m *MediaPolicy) ShouldStripVideo() bool {
	return m.StripVideo == nil || *m.StripVideo
}

// ShouldStripImageMetadata reports whether EXIF/XMP/IPTC should be removed
// from allowed images. Defaults to true when unset.
func (m *MediaPolicy) ShouldStripImageMetadata() bool {
	return m.StripImageMetadata == nil || *m.StripImageMetadata
}

// ShouldLogExposure reports whether media_exposure events should be emitted.
// Defaults to true when unset.
func (m *MediaPolicy) ShouldLogExposure() bool {
	return m.LogMediaExposure == nil || *m.LogMediaExposure
}

// EffectiveMaxImageBytes returns the active size limit, applying the default
// when the configured value is zero or negative.
func (m *MediaPolicy) EffectiveMaxImageBytes() int64 {
	if m.MaxImageBytes <= 0 {
		return DefaultMaxImageBytes
	}
	return m.MaxImageBytes
}

// EffectiveAllowedImageTypes returns the active image type whitelist,
// applying DefaultAllowedImageTypes when the configured list is empty.
// Entries are canonicalized (lowercased, whitespace-trimmed, parameters
// stripped) so validation and runtime matching can never disagree on
// ambiguous YAML forms like " image/png " or "image/jpeg; charset=binary".
// Canonicalizing at read time — not at Load() — keeps Config free of
// side-effect mutation and lets hot reload pick up whatever the operator
// changed without re-canonicalizing the stored struct.
func (m *MediaPolicy) EffectiveAllowedImageTypes() []string {
	if len(m.AllowedImageTypes) == 0 {
		return DefaultAllowedImageTypes
	}
	out := make([]string, 0, len(m.AllowedImageTypes))
	for _, raw := range m.AllowedImageTypes {
		if c := canonicalizeMediaTypeEntry(raw); c != "" {
			out = append(out, c)
		}
	}
	return out
}

// canonicalizeMediaTypeEntry parses a media type string (optionally with
// parameters) and returns the lowercase "type/subtype" portion with
// whitespace trimmed. Returns "" if the input is empty or unparseable
// enough that no media type can be recovered. Shared between validation
// and runtime matching so both paths compute the same canonical form.
func canonicalizeMediaTypeEntry(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	mt, _, err := mime.ParseMediaType(trimmed)
	if err != nil {
		// Fallback for malformed entries: strip any parameter suffix and
		// lowercase. If that still has no media-type shape, return empty
		// so the validator can reject it.
		if idx := strings.IndexByte(trimmed, ';'); idx >= 0 {
			trimmed = trimmed[:idx]
		}
		return strings.ToLower(strings.TrimSpace(trimmed))
	}
	return strings.ToLower(mt)
}

// ImageTypeAllowed reports whether a specific media type string passes the
// allowed-image-types filter. Comparison is canonicalized on both sides:
// the input media type has parameters stripped and is lowercased, and the
// stored allowlist is piped through EffectiveAllowedImageTypes so both
// sides share one canonical form. Returns false when StripImages is set
// (either explicitly or by the caller's pre-check); the explicit check
// here makes the method self-consistent for any future caller that
// forgets to gate on ShouldStripImages first.
func (m *MediaPolicy) ImageTypeAllowed(mediaType string) bool {
	if m.ShouldStripImages() {
		return false
	}
	mt := canonicalizeMediaTypeEntry(mediaType)
	if mt == "" {
		return false
	}
	for _, allowed := range m.EffectiveAllowedImageTypes() {
		if mt == allowed {
			return true
		}
	}
	return false
}

func ptrBool(v bool) *bool { return &v }

func ptrStr(v string) *string { return &v }
