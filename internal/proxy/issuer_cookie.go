// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"hash/maphash"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/normalize"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"golang.org/x/net/publicsuffix"
)

const issuerCookieReceiptExtensionKey = "dlp_issuer_cookie_allow" // #nosec G101 -- receipt extension identifier

type issuerCookieAllowMetadata struct {
	Pattern     string `json:"pattern"`
	Surface     string `json:"surface"`
	Destination string `json:"destination"`
}

func (p *Proxy) recordIssuerCookieAllow(ctx audit.LogContext, pattern, target, requestID, agent, method string) {
	parsed, err := url.Parse(target)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" {
		return
	}
	destination := strings.ToLower(parsed.Hostname())
	if p.logger != nil {
		p.logger.LogDLPIssuerCookieAllow(ctx, pattern, destination)
	}
	metadata := issuerCookieAllowMetadata{Pattern: pattern, Surface: "header", Destination: destination}
	extension, err := json.Marshal(map[string]issuerCookieAllowMetadata{issuerCookieReceiptExtensionKey: metadata})
	if err != nil {
		return
	}
	p.emitCredentialAudienceReceipt(receipt.EmitOpts{
		ActionID: receipt.NewActionID(), Verdict: config.ActionAllow,
		Layer: issuerCookieReceiptExtensionKey, Pattern: pattern,
		Transport: "intercept", Method: method, Target: target,
		RequestID: requestID, Agent: agent, Extension: extension,
	})
}

// These ceilings bound the in-memory evidence window. Exhaustion disables
// allowances for the affected session rather than forgetting earlier input.
const (
	issuerCookieMaxAge          = 24 * time.Hour
	issuerCookieMinValueBytes   = 16
	issuerCookieMaxValueBytes   = 128
	issuerCookieMaxEntries      = 256
	issuerCookieMaxSessions     = 8
	issuerCookieMaxRequestBytes = 32 << 10
	issuerCookieMaxSeenBytes    = 4 << 20
	issuerCookieBloomBits       = 1 << 25
)

type issuerBoundCookieStore struct {
	mu       sync.Mutex
	key      [32]byte
	seedA    maphash.Seed
	seedB    maphash.Seed
	sessions map[string]*issuerCookieSession
	disabled bool
}

// A single atomic pointer ties the evidence window to its exact policy
// snapshot. A reload publishes a fresh store and cannot revive old cookies.
type issuerCookieRuntime struct {
	cfg   *config.Config
	store *issuerBoundCookieStore
}

func (p *Proxy) issuerCookieStore(cfg *config.Config, auth envelope.ActorAuth) *issuerBoundCookieStore {
	if p == nil || cfg == nil || !cfg.RequestBodyScanning.IssuerBoundSessionCookies || !auth.TrustedForIdentity() {
		return nil
	}
	runtime := p.issuerCookieRuntime.Load()
	if runtime == nil {
		return nil
	}
	return runtime.store
}

func (ic *InterceptContext) issuerCookieStore() *issuerBoundCookieStore {
	if ic == nil || ic.Proxy == nil || ic.Config == nil ||
		!ic.Config.RequestBodyScanning.IssuerBoundSessionCookies || !ic.ActorAuth.TrustedForIdentity() {
		return nil
	}
	runtime := ic.Proxy.issuerCookieRuntime.Load()
	if runtime == nil || (ic.IssuerRuntime != nil && ic.IssuerRuntime != runtime) ||
		(ic.IssuerRuntime == nil && runtime.cfg != ic.Config) {
		return nil
	}
	return runtime.store
}

func recordDeliveredIssuerCookies(ic *InterceptContext, request *http.Request, response *http.Response, delivered bool) {
	if ic == nil || request == nil || response == nil {
		return
	}
	store := ic.issuerCookieStore()
	if store == nil {
		return
	}
	store.observeResponse(sessionKeyFor(ic.Agent, ic.ClientIP, ic.ActorAuth), request.URL, response.Header, delivered, time.Now())
}

type issuerCookieSession struct {
	seen          []uint64
	observedBytes int
	tainted       bool
	entries       []issuerCookieEntry
	lastUsed      time.Time
}

type issuerCookieEntry struct {
	digest   [32]byte
	name     string
	host     string
	port     string
	domain   string
	hostOnly bool
	path     string
	secure   bool
	expires  time.Time
}

func newIssuerBoundCookieStore() *issuerBoundCookieStore {
	s := &issuerBoundCookieStore{
		seedA: maphash.MakeSeed(), seedB: maphash.MakeSeed(),
		sessions: make(map[string]*issuerCookieSession),
	}
	if _, err := rand.Read(s.key[:]); err != nil {
		s.disabled = true
	}
	return s
}

func (s *issuerBoundCookieStore) sessionLocked(id string, create bool, now time.Time) *issuerCookieSession {
	if s == nil || s.disabled || id == "" {
		return nil
	}
	if sess := s.sessions[id]; sess != nil {
		sess.lastUsed = now
		return sess
	}
	if !create {
		return nil
	}
	if len(s.sessions) >= issuerCookieMaxSessions {
		// Re-creating an evicted session would erase its outbound history and
		// permit a reflected value to look newly issued. Exhaustion disables
		// this allowance until reload instead.
		s.disabled = true
		s.sessions = nil
		return nil
	}
	sess := &issuerCookieSession{seen: make([]uint64, issuerCookieBloomBits/64), lastUsed: now}
	s.sessions[id] = sess
	return sess
}

// observeOutbound fingerprints every candidate substring in an observed
// request. Bloom collisions can only refuse an allowance. When bytes cannot
// be accounted for within the ceiling, the session stays fail-closed.
func (s *issuerBoundCookieStore) observeOutbound(id string, request []byte) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sess := s.sessionLocked(id, true, time.Now())
	if sess == nil || sess.tainted {
		return
	}
	if len(request) > issuerCookieMaxRequestBytes || sess.observedBytes > issuerCookieMaxSeenBytes-len(request) {
		sess.tainted = true
		sess.seen = nil
		sess.entries = nil
		return
	}
	sess.observedBytes += len(request)
	for start := range request {
		for end := start + issuerCookieMinValueBytes; end <= len(request) && end-start <= issuerCookieMaxValueBytes; end++ {
			a, b := maphash.Bytes(s.seedA, request[start:end]), maphash.Bytes(s.seedB, request[start:end])
			issuerBloomSet(sess.seen, a)
			issuerBloomSet(sess.seen, b)
		}
	}
}

func (s *issuerBoundCookieStore) taintSession(id string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess := s.sessionLocked(id, true, time.Now()); sess != nil {
		sess.tainted = true
		sess.seen = nil
		sess.entries = nil
	}
}

// observeHTTPRequest includes every client-controlled request component that
// can be forwarded by the HTTP proxy. An unread body invalidates the session.
func (s *issuerBoundCookieStore) observeHTTPRequest(id string, r *http.Request, target string, body []byte, bodyComplete bool) {
	if s == nil || r == nil || !bodyComplete {
		s.taintSession(id)
		return
	}
	s.observeOutbound(id, []byte(r.Method))
	s.observeOutbound(id, []byte(target))
	for _, headers := range []http.Header{r.Header, r.Trailer} {
		names := make([]string, 0, len(headers))
		for name := range headers {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			s.observeOutbound(id, []byte(name))
			for _, value := range headers[name] {
				s.observeOutbound(id, []byte(value))
			}
		}
	}
	s.observeOutbound(id, body)
}

func issuerBloomSet(bits []uint64, hash uint64) {
	index := hash % issuerCookieBloomBits
	bits[index/64] |= 1 << (index % 64)
}

func issuerBloomHas(bits []uint64, hash uint64) bool {
	index := hash % issuerCookieBloomBits
	return bits[index/64]&(1<<(index%64)) != 0
}

func (s *issuerBoundCookieStore) seenOutbound(sess *issuerCookieSession, value string) bool {
	return issuerBloomHas(sess.seen, maphash.String(s.seedA, value)) &&
		issuerBloomHas(sess.seen, maphash.String(s.seedB, value))
}

func (s *issuerBoundCookieStore) digest(name, value string) [32]byte {
	mac := hmac.New(sha256.New, s.key[:])
	_, _ = mac.Write([]byte(name))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(value))
	var out [32]byte
	copy(out[:], mac.Sum(nil))
	return out
}

func (s *issuerBoundCookieStore) observeResponse(id string, origin *url.URL, headers http.Header, delivered bool, now time.Time) {
	if s == nil || !delivered || origin == nil || origin.Scheme != "https" {
		return
	}
	host, port, ok := issuerCookieOrigin(origin)
	if !ok {
		return
	}
	response := &http.Response{Header: headers}
	s.mu.Lock()
	defer s.mu.Unlock()
	sess := s.sessionLocked(id, false, now)
	if sess == nil || sess.tainted {
		return
	}
	for _, cookie := range response.Cookies() {
		if len(cookie.Value) < issuerCookieMinValueBytes || len(cookie.Value) > issuerCookieMaxValueBytes ||
			strings.ContainsAny(cookie.Value, "\r\n\x00") || s.seenOutbound(sess, cookie.Value) || cookie.MaxAge < 0 {
			continue
		}
		domain, hostOnly, ok := issuerCookieDomain(host, cookie.Domain)
		if !ok {
			continue
		}
		path := cookie.Path
		if path == "" || path[0] != '/' {
			path = issuerCookieDefaultPath(origin.Path)
		}
		expires := now.Add(issuerCookieMaxAge)
		if cookie.MaxAge > 0 {
			if maxAgeExpiry := now.Add(time.Duration(cookie.MaxAge) * time.Second); maxAgeExpiry.Before(expires) {
				expires = maxAgeExpiry
			}
		} else if !cookie.Expires.IsZero() && cookie.Expires.Before(expires) {
			expires = cookie.Expires
		}
		if !expires.After(now) {
			continue
		}
		entry := issuerCookieEntry{
			digest: s.digest(cookie.Name, cookie.Value), name: cookie.Name,
			host: host, port: port, domain: domain, hostOnly: hostOnly,
			path: path, secure: cookie.Secure, expires: expires,
		}
		if len(sess.entries) >= issuerCookieMaxEntries {
			sess.entries = sess.entries[1:]
		}
		sess.entries = append(sess.entries, entry)
	}
}

func issuerCookieOrigin(u *url.URL) (host, port string, ok bool) {
	if u == nil || u.Scheme != "https" || u.User != nil || u.Hostname() == "" {
		return "", "", false
	}
	host = strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	port = u.Port()
	if port == "" {
		port = "443"
	}
	return host, port, host != ""
}

func issuerCookieDomain(host, attribute string) (domain string, hostOnly, ok bool) {
	if attribute == "" {
		return host, true, true
	}
	domain = strings.ToLower(strings.TrimPrefix(attribute, "."))
	if domain == "" || net.ParseIP(host) != nil || strings.HasSuffix(domain, ".") ||
		(host != domain && !strings.HasSuffix(host, "."+domain)) {
		return "", false, false
	}
	if suffix, _ := publicsuffix.PublicSuffix(domain); suffix == domain {
		return "", false, false
	}
	return domain, false, true
}

func issuerCookieDefaultPath(path string) string {
	last := strings.LastIndex(path, "/")
	if last <= 0 {
		return "/"
	}
	return path[:last]
}

func (s *issuerBoundCookieStore) allows(id string, target *url.URL, name, value string, now time.Time) bool {
	host, port, ok := issuerCookieOrigin(target)
	if !ok || s == nil || len(value) < issuerCookieMinValueBytes || len(value) > issuerCookieMaxValueBytes {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sess := s.sessionLocked(id, false, now)
	if sess == nil || sess.tainted {
		return false
	}
	digest := s.digest(name, value)
	for _, entry := range sess.entries {
		if entry.digest == digest && entry.name == name && entry.host == host && entry.port == port &&
			entry.expires.After(now) && issuerCookiePathMatches(entry.path, target.Path) {
			return true
		}
	}
	return false
}

func issuerCookiePathMatches(cookiePath, requestPath string) bool {
	return requestPath == cookiePath || (strings.HasPrefix(requestPath, cookiePath) &&
		(strings.HasSuffix(cookiePath, "/") || strings.HasPrefix(requestPath[len(cookiePath):], "/")))
}

type issuerCookieSpan struct{ start, end int }

// issuerCookieScanHeaders makes a scanning-only copy. The real request keeps
// its original Cookie header. Refuse the allowance when joined-header scanning
// or normalized/encoded match coordinates could conceal another finding.
func issuerCookieScanHeaders(ctx context.Context, headers http.Header, cfg *config.Config, sc *scanner.Scanner, store *issuerBoundCookieStore, session string, target *url.URL, now time.Time, onAllow func(string)) http.Header {
	if store == nil || cfg.RequestBodyScanning.HeaderMode != config.HeaderModeSensitive {
		return headers
	}
	for _, name := range cfg.RequestBodyScanning.SensitiveHeaders {
		if !strings.EqualFold(name, "Cookie") && len(headers.Values(name)) > 0 {
			return headers
		}
	}
	values := headers.Values("Cookie")
	if len(values) != 1 {
		return headers
	}
	raw := values[0]
	if normalize.ForDLP(raw) != raw {
		return headers
	}
	// A second cookie can produce a cross-boundary match that the scanner
	// deduplicates behind the first. Until every match span is retained, only
	// the single-cookie spelling has a provable value boundary.
	if strings.Count(raw, ";") != 0 {
		return headers
	}
	equals := strings.IndexByte(raw, '=')
	if equals < 1 {
		return headers
	}
	name := strings.TrimSpace(raw[:equals])
	valueStart := equals + 1
	for valueStart < len(raw) && raw[valueStart] == ' ' {
		valueStart++
	}
	valueEnd := len(raw)
	for valueEnd > valueStart && raw[valueEnd-1] == ' ' {
		valueEnd--
	}
	if name == "" || !store.allows(session, target, name, raw[valueStart:valueEnd], now) {
		return headers
	}
	allowedSpan := issuerCookieSpan{valueStart, valueEnd}
	result := sc.ScanTextForDLP(ctx, raw)
	if result.Clean || len(result.Matches) == 0 || len(result.InformationalMatches) > 0 {
		return headers
	}
	var patterns []string
	for _, match := range result.Matches {
		span := match.Span()
		if span.ViewLabel != scanner.ViewDLPNormalized || !issuerSpanWithin([]issuerCookieSpan{allowedSpan}, span.ByteStart, span.ByteEnd) {
			return headers
		}
		patterns = append(patterns, match.PatternName)
	}
	masked := []byte(raw)
	for i := allowedSpan.start; i < allowedSpan.end; i++ {
		masked[i] = '*'
	}
	copyHeaders := headers.Clone()
	copyHeaders.Set("Cookie", string(masked))
	for _, pattern := range patterns {
		if onAllow != nil {
			onAllow(pattern)
		}
	}
	return copyHeaders
}

func issuerSpanWithin(spans []issuerCookieSpan, start, end int) bool {
	for _, span := range spans {
		if start >= span.start && end <= span.end && end > start {
			return true
		}
	}
	return false
}
