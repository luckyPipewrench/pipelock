// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package reqpolicy implements Pipelock's request_policy layer: explicit,
// allow-by-default deny/warn safety rails on outbound HTTP API operations.
//
// It is independent of request_body_scanning and complementary to the
// learn-lock contract gate — it is neither a DLP scanner nor a behavioral
// allowlist. v1 matches on route only (host / effective method / normalized
// path / content type); GraphQL and JSON operation predicates are added in
// later phases. The Matcher precompiles rule regexes once at config (re)load;
// Evaluate is allocation-light and safe on the hot request path.
package reqpolicy

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// methodOverrideHeaders are the headers some frameworks honor to tunnel a
// different effective HTTP method through a POST. They must be resolved before
// route matching, or "POST + X-HTTP-Method-Override: DELETE" trivially bypasses
// a method-scoped rule.
var methodOverrideHeaders = []string{"X-HTTP-Method-Override", "X-Method-Override", "X-HTTP-Method"}

// maxUnescapeRounds bounds repeated percent-decoding during path normalization.
// Bounded so a crafted deeply-encoded path cannot spin the normalizer, while
// still collapsing multi-layer encodings (e.g. %252e%252e) that a downstream
// server would decode more than once and act on as a dot segment.
const maxUnescapeRounds = 5

// RequestMeta is the transport-neutral view of an outbound request that
// Evaluate needs. Transports build it once — after computing the effective
// method and normalizing the path — and pass it in.
type RequestMeta struct {
	Host        string // lowercased hostname, no port
	Method      string // effective HTTP method, uppercased
	Path        string // normalized request path
	ContentType string // media type only, lowercased, parameters stripped
	// Operations are the request's extracted API operations (e.g. via
	// ExtractGraphQL). A GraphQL rule predicate evaluates against these; an
	// empty slice means no inspectable operations, so a GraphQL predicate does
	// not match (fail-closed handling of parse errors / opaque requests is the
	// caller's responsibility, driven by on_parse_error / on_opaque_operation).
	Operations []RequestOperation
}

// Decision is the outcome of evaluating request policy against a request.
// A zero Decision (empty Action) means allow.
type Decision struct {
	Action   string // "" (allow), config.ActionWarn, or config.ActionBlock
	RuleName string // matched rule name; safe as a bounded metric/audit label
	Reason   string // operator-facing reason from the matched rule
	Shadow   bool   // matched rule is shadow: log the would-be action, do not enforce
}

// Matched reports whether the decision selected a rule (enforced or shadow).
func (d Decision) Matched() bool { return d.Action != "" }

// Enforced reports whether the decision should block/warn the live request.
// Shadow matches return false: they are logged but never enforced.
func (d Decision) Enforced() bool { return d.Action != "" && !d.Shadow }

type compiledRule struct {
	name         string
	action       string
	reason       string
	shadow       bool
	hosts        []string
	methods      map[string]struct{}
	pathPrefixes []string
	pathPatterns []*regexp.Regexp
	contentTypes map[string]struct{}
	graphql      *gqlPredicate
}

// Matcher holds the precompiled request_policy ruleset. Build one with
// NewMatcher at config (re)load and swap it atomically alongside the rest of
// the runtime config.
type Matcher struct {
	enabled bool
	rules   []compiledRule
}

// NewMatcher compiles cfg into a Matcher. It returns an error if any
// path_pattern fails to compile; callers run config validation first (which
// compiles the same patterns), so this is defense in depth. A nil cfg or a
// disabled section yields a Matcher that allows everything.
func NewMatcher(cfg *config.RequestPolicy) (*Matcher, error) {
	m := &Matcher{}
	if cfg == nil || !cfg.Enabled {
		return m, nil
	}
	m.enabled = true
	for i := range cfg.Rules {
		r := &cfg.Rules[i]
		cr := compiledRule{
			name:   r.Name,
			action: r.Action,
			reason: r.Reason,
			shadow: r.Shadow,
		}
		if len(r.Route.Hosts) > 0 {
			cr.hosts = make([]string, len(r.Route.Hosts))
			for j, h := range r.Route.Hosts {
				cr.hosts[j] = NormalizeHost(h)
			}
		}
		if len(r.Route.Methods) > 0 {
			cr.methods = make(map[string]struct{}, len(r.Route.Methods))
			for _, mth := range r.Route.Methods {
				cr.methods[strings.ToUpper(strings.TrimSpace(mth))] = struct{}{}
			}
		}
		for _, p := range r.Route.PathPatterns {
			re, err := regexp.Compile(p)
			if err != nil {
				return nil, fmt.Errorf("request_policy rule %q: invalid path_pattern %q: %w", r.Name, p, err)
			}
			cr.pathPatterns = append(cr.pathPatterns, re)
		}
		if len(r.Route.PathPrefixes) > 0 {
			cr.pathPrefixes = make([]string, len(r.Route.PathPrefixes))
			for j, p := range r.Route.PathPrefixes {
				cr.pathPrefixes[j] = NormalizePath(strings.TrimSpace(p))
			}
		}
		if len(r.Route.ContentTypes) > 0 {
			cr.contentTypes = make(map[string]struct{}, len(r.Route.ContentTypes))
			for _, ct := range r.Route.ContentTypes {
				cr.contentTypes[NormalizeContentType(ct)] = struct{}{}
			}
		}
		pred, err := compileGraphQLPredicate(r.GraphQL)
		if err != nil {
			return nil, fmt.Errorf("request_policy rule %q: invalid graphql predicate: %w", r.Name, err)
		}
		cr.graphql = pred
		m.rules = append(m.rules, cr)
	}
	return m, nil
}

// Evaluate runs meta against the ruleset and returns the strictest matching
// Decision. Block beats warn; among equal-strictness matches an enforced rule
// is preferred over a shadow rule so a real block is never masked by a shadow
// entry. Returns a zero Decision (allow) when nothing matches.
func (m *Matcher) Evaluate(meta RequestMeta) Decision {
	if m == nil || !m.enabled {
		return Decision{}
	}
	var best Decision
	for i := range m.rules {
		cr := &m.rules[i]
		if !cr.matches(meta) {
			continue
		}
		cand := Decision{Action: cr.action, RuleName: cr.name, Reason: cr.reason, Shadow: cr.shadow}
		if betterDecision(cand, best) {
			best = cand
		}
	}
	return best
}

// betterDecision reports whether cand should replace cur as the selected
// decision. Ordering: block > warn > none; within the same action, enforced
// (non-shadow) beats shadow.
func betterDecision(cand, cur Decision) bool {
	if delta := actionRank(cand.Action) - actionRank(cur.Action); delta != 0 {
		return delta > 0
	}
	if cand.Action == "" {
		return false
	}
	return !cand.Shadow && cur.Shadow
}

func actionRank(a string) int {
	switch a {
	case config.ActionBlock:
		return 2
	case config.ActionWarn:
		return 1
	default:
		return 0
	}
}

func (cr *compiledRule) matches(meta RequestMeta) bool {
	if len(cr.hosts) > 0 && !hostMatches(NormalizeHost(meta.Host), cr.hosts) {
		return false
	}
	if cr.methods != nil {
		if _, ok := cr.methods[strings.ToUpper(strings.TrimSpace(meta.Method))]; !ok {
			return false
		}
	}
	if !cr.pathMatches(NormalizePath(meta.Path)) {
		return false
	}
	if cr.contentTypes != nil {
		if _, ok := cr.contentTypes[NormalizeContentType(meta.ContentType)]; !ok {
			return false
		}
	}
	if cr.graphql != nil && !cr.graphql.matches(meta.Operations) {
		return false
	}
	return true
}

func (cr *compiledRule) pathMatches(p string) bool {
	if len(cr.pathPrefixes) == 0 && len(cr.pathPatterns) == 0 {
		return true
	}
	for _, pre := range cr.pathPrefixes {
		if strings.HasPrefix(p, pre) {
			return true
		}
	}
	for _, re := range cr.pathPatterns {
		if re.MatchString(p) {
			return true
		}
	}
	return false
}

// hostMatches reports whether host matches any pattern. Patterns are exact
// hosts or *.suffix wildcards (already lowercased/trim-dotted at compile time).
func hostMatches(host string, patterns []string) bool {
	host = NormalizeHost(host)
	for _, p := range patterns {
		if p == host {
			return true
		}
		if strings.HasPrefix(p, "*.") {
			// "*.example.com" matches the apex "example.com" and any subdomain.
			if host == p[2:] || strings.HasSuffix(host, p[1:]) {
				return true
			}
		}
	}
	return false
}

// EffectiveMethod returns the method a downstream server would act on,
// accounting for method-override headers. Only header-based overrides are
// resolved here; form-field (_method) overrides require a parsed body and are
// handled at the body hook. The result is uppercased.
//
// Caveat for the transport that builds RequestMeta: a valid override (e.g. GET)
// can "downgrade" a real POST when the upstream ignores the override header. To
// avoid evading a method-scoped deny rule that way, evaluate the ruleset
// against both the base method and the override and block if either matches,
// rather than trusting a single resolved method.
func EffectiveMethod(method string, headers http.Header) string {
	base := normalizeMethod(method)
	for _, h := range methodOverrideHeaders {
		if v := normalizeMethod(headers.Get(h)); isStandardMethod(v) {
			return v
		}
	}
	return base
}

func normalizeMethod(method string) string {
	return strings.ToUpper(strings.TrimSpace(method))
}

func isStandardMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut,
		http.MethodPatch, http.MethodDelete, http.MethodConnect,
		http.MethodOptions, http.MethodTrace:
		return true
	default:
		return false
	}
}

// NormalizeHost lowercases a host and strips a DNS trailing dot, optional URL
// scheme, and optional port. It is deliberately permissive because callers may
// hand over r.Host, URL.Host, or URL.String-derived values at different hook
// points.
func NormalizeHost(raw string) string {
	raw = strings.TrimSpace(strings.ToLower(raw))
	if raw == "" {
		return ""
	}
	if u, err := url.Parse(raw); err == nil && u.Host != "" {
		raw = u.Host
	}
	if h, _, err := net.SplitHostPort(raw); err == nil {
		raw = h
	}
	raw = strings.Trim(raw, "[]")
	return strings.TrimSuffix(raw, ".")
}

// NormalizePath canonicalizes a request path for stable route matching:
// repeated percent-decoding (bounded), per-segment removal of ;parameters, and
// dot-segment / double-slash collapsing. Case is preserved because path IDs are
// case-sensitive; rules needing case-insensitivity use a path_pattern.
func NormalizePath(raw string) string {
	if raw == "" {
		return "/"
	}
	// Drop any query/fragment that slipped in.
	if i := strings.IndexAny(raw, "?#"); i >= 0 {
		raw = raw[:i]
	}
	// Repeatedly percent-decode until stable or the round cap is hit, so a
	// multi-encoded ..%252e segment cannot hide from dot-segment removal.
	for r := 0; r < maxUnescapeRounds; r++ {
		dec, err := url.PathUnescape(raw)
		if err != nil || dec == raw {
			break
		}
		raw = dec
	}
	// Strip ;parameters from each segment.
	segs := strings.Split(raw, "/")
	for i, s := range segs {
		if j := strings.IndexByte(s, ';'); j >= 0 {
			segs[i] = s[:j]
		}
	}
	raw = strings.Join(segs, "/")
	// path.Clean collapses dot segments and double slashes but drops a trailing
	// slash, so restore it when the input had one.
	hadTrailingSlash := raw != "/" && strings.HasSuffix(raw, "/")
	cleaned := path.Clean(raw)
	if !strings.HasPrefix(cleaned, "/") {
		cleaned = "/" + cleaned
	}
	if hadTrailingSlash && cleaned != "/" {
		cleaned += "/"
	}
	return cleaned
}

// NormalizeContentType returns the lowercased media type with parameters
// (charset, boundary, etc.) stripped, matching how rules declare content_types.
func NormalizeContentType(ct string) string {
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	return strings.ToLower(strings.TrimSpace(ct))
}
