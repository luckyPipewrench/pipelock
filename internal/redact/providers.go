// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package redact

import (
	"fmt"
	"net"
	"sort"
	"strings"
)

const (
	// ParserJSON is the provider parser that walks every string scalar in a
	// JSON document. Provider-specific parsers intentionally share this
	// implementation so redaction cannot depend on attacker-controlled field
	// placement.
	ParserJSON = "json"

	// ProviderGenericJSON is used when no provider profile matches. It keeps
	// unknown JSON providers fail-closed-and-redacted instead of depending on a
	// known-provider allowlist.
	ProviderGenericJSON = "generic-json"
)

// RequestMetadata identifies the upstream request enough to select a provider
// parser profile. Provider selection never suppresses scanning; it only
// chooses the parser implementation and labels the report.
type RequestMetadata struct {
	Host string
	Path string
}

// ProviderSpec describes a provider parser profile. Third-party providers can
// be configured by mapping host patterns and optional path prefixes to a
// parser. v1 supports the JSON scalar walker only.
type ProviderSpec struct {
	HostPatterns []string `yaml:"host_patterns"`
	PathPrefixes []string `yaml:"path_prefixes,omitempty"`
	Parser       string   `yaml:"parser,omitempty"`
}

type providerEntry struct {
	name string
	spec ProviderSpec
}

type providerMatch struct {
	entry        providerEntry
	hostExact    bool
	hostLength   int
	prefixLength int
}

// ProviderRegistry is an immutable provider parser registry.
type ProviderRegistry struct {
	entries []providerEntry
}

// DefaultProviderSpecs returns the built-in LLM provider parser profiles.
func DefaultProviderSpecs() map[string]ProviderSpec {
	return map[string]ProviderSpec{
		"anthropic": {
			HostPatterns: []string{"api.anthropic.com"},
			PathPrefixes: []string{"/v1/messages"},
			Parser:       ParserJSON,
		},
		"openai": {
			HostPatterns: []string{"api.openai.com"},
			PathPrefixes: []string{"/v1/chat/completions", "/v1/responses"},
			Parser:       ParserJSON,
		},
		"gemini": {
			HostPatterns: []string{"generativelanguage.googleapis.com", "*.generativelanguage.googleapis.com"},
			PathPrefixes: []string{"/v1/models/", "/v1beta/models/", "/v1alpha/models/"},
			Parser:       ParserJSON,
		},
	}
}

// NewProviderRegistry builds a registry from built-ins plus operator-defined
// profiles. Custom profiles with a built-in name override the built-in entry.
func NewProviderRegistry(custom map[string]ProviderSpec) (*ProviderRegistry, error) {
	merged := DefaultProviderSpecs()
	for name, spec := range custom {
		merged[name] = spec
	}

	names := make([]string, 0, len(merged))
	for name, spec := range merged {
		if err := validateProviderSpec(name, spec); err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	sort.Strings(names)

	entries := make([]providerEntry, 0, len(names))
	for _, name := range names {
		spec := merged[name]
		if spec.Parser == "" {
			spec.Parser = ParserJSON
		}
		entries = append(entries, providerEntry{name: name, spec: spec})
	}
	return &ProviderRegistry{entries: entries}, nil
}

// Match returns the most specific provider parser for meta, or the generic
// JSON parser if no provider profile matches.
func (r *ProviderRegistry) Match(meta RequestMetadata) (provider, parser string) {
	if r == nil {
		return ProviderGenericJSON, ParserJSON
	}
	host := canonicalHost(meta.Host)
	path := meta.Path
	if path == "" {
		path = "/"
	}

	var best *providerMatch
	for _, entry := range r.entries {
		hostExact, hostLength, ok := providerHostMatch(host, entry.spec.HostPatterns)
		if !ok {
			continue
		}
		prefixLength, ok := providerPathMatch(path, entry.spec.PathPrefixes)
		if !ok {
			continue
		}
		candidate := providerMatch{
			entry:        entry,
			hostExact:    hostExact,
			hostLength:   hostLength,
			prefixLength: prefixLength,
		}
		if best == nil || providerMatchLess(*best, candidate) {
			best = &candidate
		}
	}
	if best != nil {
		entry := best.entry
		parser := entry.spec.Parser
		if parser == "" {
			parser = ParserJSON
		}
		return entry.name, parser
	}
	return ProviderGenericJSON, ParserJSON
}

// RewriteRequestJSON selects the configured provider parser and rewrites body.
func RewriteRequestJSON(body []byte, m *Matcher, redactor *Redactor, lim Limits, meta RequestMetadata, registry *ProviderRegistry) ([]byte, *Report, error) {
	provider, parser := registry.Match(meta)
	if parser != ParserJSON {
		return nil, nil, newBlock(ReasonInternalError, redactor.Total(), "unsupported redaction provider parser "+parser)
	}
	out, report, err := RewriteJSON(body, m, redactor, lim)
	if err != nil {
		return nil, nil, err
	}
	report.Provider = provider
	report.Parser = parser
	return out, report, nil
}

func validateProviderSpec(name string, spec ProviderSpec) error {
	if !classNameRe.MatchString(name) {
		return fmt.Errorf("redact: provider %q must match [a-z0-9][a-z0-9_-]*", name)
	}
	parser := spec.Parser
	if parser == "" {
		parser = ParserJSON
	}
	if parser != ParserJSON {
		return fmt.Errorf("redact: provider %q parser %q is not supported", name, parser)
	}
	if len(spec.HostPatterns) == 0 {
		return fmt.Errorf("redact: provider %q must define at least one host_pattern", name)
	}
	for i, pattern := range spec.HostPatterns {
		if err := validateProviderHostPattern(pattern); err != nil {
			return fmt.Errorf("redact: provider %q host_patterns[%d] %q: %w", name, i, pattern, err)
		}
	}
	for i, prefix := range spec.PathPrefixes {
		if prefix == "" || !strings.HasPrefix(prefix, "/") || strings.ContainsAny(prefix, "?#") {
			return fmt.Errorf("redact: provider %q path_prefixes[%d] %q must be an absolute path prefix without query or fragment", name, i, prefix)
		}
	}
	return nil
}

func validateProviderHostPattern(pattern string) error {
	if pattern == "" {
		return fmt.Errorf("empty")
	}
	if strings.HasPrefix(pattern, "*.") {
		trimmed := strings.TrimPrefix(pattern, "*.")
		if strings.Contains(trimmed, "*") {
			return fmt.Errorf("wildcard is only supported as a leading *. prefix")
		}
		return validateHostEntry(trimmed)
	}
	if strings.Contains(pattern, "*") {
		return fmt.Errorf("wildcard is only supported as a leading *. prefix")
	}
	return validateHostEntry(pattern)
}

func providerMatchLess(a, b providerMatch) bool {
	if a.hostExact != b.hostExact {
		return !a.hostExact && b.hostExact
	}
	if a.prefixLength != b.prefixLength {
		return a.prefixLength < b.prefixLength
	}
	if a.hostLength != b.hostLength {
		return a.hostLength < b.hostLength
	}
	return a.entry.name > b.entry.name
}

func providerHostMatch(host string, patterns []string) (exact bool, length int, ok bool) {
	if host == "" {
		return false, 0, false
	}
	for _, pattern := range patterns {
		pattern = strings.ToLower(pattern)
		if pattern == host {
			if !ok || !exact || len(pattern) > length {
				exact = true
				length = len(pattern)
				ok = true
			}
			continue
		}
		if strings.HasPrefix(pattern, "*.") && strings.HasSuffix(host, pattern[1:]) {
			if !ok || (!exact && len(pattern) > length) {
				exact = false
				length = len(pattern)
				ok = true
			}
		}
	}
	return exact, length, ok
}

func providerPathMatch(path string, prefixes []string) (length int, ok bool) {
	if len(prefixes) == 0 {
		return 0, true
	}
	for _, prefix := range prefixes {
		if strings.HasPrefix(path, prefix) {
			if len(prefix) > length {
				length = len(prefix)
				ok = true
			}
		}
	}
	return length, ok
}

func canonicalHost(host string) string {
	host = strings.ToLower(host)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return host
}
