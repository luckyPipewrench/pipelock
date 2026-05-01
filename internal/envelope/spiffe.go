// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package envelope

import (
	"fmt"
	"net/url"
	"path"
	"strings"
)

const (
	ActorFormatLegacy = "legacy"
	ActorFormatSPIFFE = "spiffe"
)

// ParsedActor is the normalized shape of an envelope actor value.
type ParsedActor struct {
	Raw         string
	IsSPIFFE    bool
	TrustDomain string
	Workload    string
}

// ParseActor accepts legacy free-form actor strings and SPIFFE IDs. The
// permissive behavior is the v2.4 migration mode; callers that need the v2.5
// strict behavior can require ParsedActor.IsSPIFFE after parsing.
//
// SPIFFE-ID parsing follows SPIFFE-ID §2: trust domain must be a bare
// authority (no userinfo, no port), and the workload path must be
// canonical (no "." / ".." segments, no empty segments). Smuggled ports
// or path traversal would let an attacker bypass any actor allowlist
// that compares TrustDomain or Workload as opaque strings.
func ParseActor(raw string) (ParsedActor, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ParsedActor{}, fmt.Errorf("actor must not be empty")
	}
	if !strings.HasPrefix(strings.ToLower(trimmed), "spiffe://") {
		return ParsedActor{Raw: trimmed}, nil
	}

	u, err := url.Parse(trimmed)
	if err != nil {
		return ParsedActor{}, fmt.Errorf("parse SPIFFE actor: %w", err)
	}
	if u.Scheme != "spiffe" {
		return ParsedActor{}, fmt.Errorf("SPIFFE actor scheme must be spiffe")
	}
	if u.Host == "" {
		return ParsedActor{}, fmt.Errorf("SPIFFE actor trust domain must not be empty")
	}
	if u.User != nil {
		return ParsedActor{}, fmt.Errorf("SPIFFE actor must not include userinfo")
	}
	if u.Port() != "" {
		return ParsedActor{}, fmt.Errorf("SPIFFE actor trust domain must not include a port")
	}
	if u.Path == "" || u.Path == "/" {
		return ParsedActor{}, fmt.Errorf("SPIFFE actor workload path must not be empty")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return ParsedActor{}, fmt.Errorf("SPIFFE actor must not include query or fragment")
	}
	if !isCanonicalSPIFFEPath(u.Path) {
		return ParsedActor{}, fmt.Errorf("SPIFFE actor workload path must be canonical (no empty, %q, or %q segments)", ".", "..")
	}
	return ParsedActor{
		Raw:         trimmed,
		IsSPIFFE:    true,
		TrustDomain: strings.ToLower(u.Host),
		Workload:    u.EscapedPath(),
	}, nil
}

// isCanonicalSPIFFEPath returns true when p is already in canonical form:
// path.Clean leaves it unchanged AND it contains no empty, ".", or ".."
// segments. SPIFFE-ID §2.2.3 requires canonical paths so that allowlist
// checks comparing Workload as a string cannot be bypassed via traversal
// or empty-segment smuggling.
func isCanonicalSPIFFEPath(p string) bool {
	if p == "" || p[0] != '/' {
		return false
	}
	if path.Clean(p) != p {
		return false
	}
	for _, seg := range strings.Split(p[1:], "/") {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

// IsValidTrustDomain reports whether s is a syntactically valid SPIFFE
// trust domain — a non-empty DNS-shaped label with no scheme, slashes,
// userinfo, or port. Used by both spiffe.go (when parsing actor URIs)
// and config validation (when checking the operator-supplied
// trust_domain field).
func IsValidTrustDomain(s string) bool {
	if s == "" {
		return false
	}
	if strings.ContainsAny(s, "/\\@:?# ") {
		return false
	}
	// url.Parse on "spiffe://"+s lets us reuse the same parser the
	// runtime ParseActor uses. If the parser populates user/port, the
	// trust_domain is malformed.
	u, err := url.Parse("spiffe://" + s + "/x")
	if err != nil {
		return false
	}
	if u.Host == "" || u.User != nil || u.Port() != "" {
		return false
	}
	return strings.EqualFold(u.Host, s)
}

// FormatActor returns the wire actor for a newly emitted envelope.
func FormatActor(actor, actorFormat, trustDomain string) (string, error) {
	trimmed := strings.TrimSpace(actor)
	if trimmed == "" {
		trimmed = "anonymous"
	}
	switch strings.ToLower(strings.TrimSpace(actorFormat)) {
	case "", ActorFormatLegacy:
		return trimmed, nil
	case ActorFormatSPIFFE:
		if strings.HasPrefix(strings.ToLower(trimmed), "spiffe://") {
			if _, err := ParseActor(trimmed); err != nil {
				return "", err
			}
			return trimmed, nil
		}
		domain := strings.ToLower(strings.TrimSpace(trustDomain))
		if domain == "" {
			return "", fmt.Errorf("spiffe actor format requires trust_domain")
		}
		if !IsValidTrustDomain(domain) {
			return "", fmt.Errorf("spiffe actor format trust_domain %q is not a valid DNS-shaped label", trustDomain)
		}
		return "spiffe://" + domain + "/agent/" + escapeSPIFFEPathSegment(trimmed), nil
	default:
		return "", fmt.Errorf("unknown actor_format %q", actorFormat)
	}
}

func escapeSPIFFEPathSegment(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '.', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "anonymous"
	}
	return out
}
