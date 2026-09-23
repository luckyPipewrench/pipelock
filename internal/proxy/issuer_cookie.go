// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

const issuerCookieReceiptExtensionKey = "dlp_issuer_cookie_allow" // #nosec G101 -- receipt extension identifier

type issuerCookieAllowMetadata struct {
	Pattern     string `json:"pattern"`
	Cookie      string `json:"cookie"`
	Surface     string `json:"surface"`
	Destination string `json:"destination"`
}

// issuerCookieMaxLoggedName bounds the cookie name copied into audit records.
// The destination chose the name; the value is never recorded.
const issuerCookieMaxLoggedName = 256

func (p *Proxy) recordIssuerCookieAllow(ctx audit.LogContext, pattern, cookieName, target, requestID, agent, method string) {
	if len(cookieName) > issuerCookieMaxLoggedName {
		cookieName = cookieName[:issuerCookieMaxLoggedName]
	}
	parsed, err := url.Parse(target)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" {
		return
	}
	destination := strings.ToLower(parsed.Hostname())
	if p.logger != nil {
		p.logger.LogDLPIssuerCookieAllow(ctx, pattern, cookieName, destination)
	}
	metadata := issuerCookieAllowMetadata{Pattern: pattern, Cookie: cookieName, Surface: "header", Destination: destination}
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

// Limits come from the cookie specifications, not from observed traffic.
// RFC 6265 section 6.1 asks user agents to support cookies of at least 4096
// bytes (name, value and attributes together) and at least 3000 cookies in
// total. RFC 6265bis section 5.6 ignores an attribute value longer than 1024
// octets. The session ceiling bounds memory. Every eviction forgets an
// issuance, which can only return that cookie to ordinary header DLP.
const (
	issuerCookieMaxPairBytes  = 4096
	issuerCookieMaxAttrBytes  = 1024
	issuerCookieMaxEntries    = 3000
	issuerCookieMaxSessions   = 32
	issuerCookieMaxSetCookies = 256
)

// issuerBoundCookieStore remembers keyed digests of cookies that an
// intercepted HTTPS origin issued to one identity session. A remembered
// cookie pair is left out of header DLP only when the same session returns
// it to the exact issuing host and port over HTTPS. Returning a value to the
// origin that issued it discloses nothing that origin does not already hold.
type issuerBoundCookieStore struct {
	mu       sync.Mutex
	key      [32]byte
	sessions map[string]*issuerCookieSession
	disabled bool
}

// A single atomic pointer ties the evidence window to its exact policy
// snapshot. A reload publishes a fresh store and cannot revive old cookies.
type issuerCookieRuntime struct {
	cfg   *config.Config
	store *issuerBoundCookieStore
}

// issuerCookieEnabled reports whether a policy can produce issuance evidence.
// Only intercepted HTTPS responses are observed, so the allowance exists
// only where TLS interception and header DLP are both active.
func issuerCookieEnabled(cfg *config.Config) bool {
	return cfg != nil && cfg.RequestBodyScanning.IssuerBoundSessionCookies && cfg.TLSInterception.Enabled &&
		cfg.RequestBodyScanning.Enabled && cfg.RequestBodyScanning.ScanHeaders
}

func (ic *InterceptContext) issuerCookieStore() *issuerBoundCookieStore {
	if ic == nil || ic.Proxy == nil || !issuerCookieEnabled(ic.Config) || !ic.ActorAuth.TrustedForIdentity() {
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
	entries  []issuerCookieEntry
	lastUsed time.Time
}

// issuerCookieEntry holds no cookie name or value, only their keyed digest.
type issuerCookieEntry struct {
	digest  [32]byte
	host    string
	port    string
	path    string
	expires time.Time // zero means a session cookie
}

func newIssuerBoundCookieStore() *issuerBoundCookieStore {
	s := &issuerBoundCookieStore{sessions: make(map[string]*issuerCookieSession)}
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
		// Evicting the least recently used session forgets its issuances,
		// so its cookies receive ordinary header DLP again.
		var oldest string
		var oldestAt time.Time
		for key, sess := range s.sessions {
			if oldest == "" || sess.lastUsed.Before(oldestAt) {
				oldest, oldestAt = key, sess.lastUsed
			}
		}
		delete(s.sessions, oldest)
	}
	sess := &issuerCookieSession{lastUsed: now}
	s.sessions[id] = sess
	return sess
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

// issuerSetCookie is one Set-Cookie line reduced to what the allowance needs.
type issuerSetCookie struct {
	name, value, path string
	expires           time.Time
	expired           bool
}

// parseIssuerSetCookie follows the RFC 6265 section 5.2 algorithm for the
// name-value pair and the Max-Age, Expires and Path attributes. The name and
// value keep their wire spelling, including any quotes, because that is what
// a user agent returns. Anything the algorithm would ignore, or that exceeds
// the section 6.1 size, is not recorded and stays under ordinary DLP.
func parseIssuerSetCookie(line, defaultPath string, now time.Time) (issuerSetCookie, bool) {
	var c issuerSetCookie
	pair, attrs, _ := strings.Cut(line, ";")
	name, value, found := strings.Cut(pair, "=")
	if !found {
		return c, false
	}
	c.name, c.value = strings.Trim(name, " \t"), strings.Trim(value, " \t")
	if c.name == "" || len(c.name)+len(c.value) > issuerCookieMaxPairBytes || issuerCookieHasCTL(c.name+c.value) {
		return c, false
	}
	c.path = defaultPath
	maxAgeSet := false
	for attrs != "" {
		var attr string
		attr, attrs, _ = strings.Cut(attrs, ";")
		key, val, _ := strings.Cut(attr, "=")
		key, val = strings.Trim(key, " \t"), strings.Trim(val, " \t")
		if len(val) > issuerCookieMaxAttrBytes {
			continue
		}
		switch strings.ToLower(key) {
		case "max-age":
			if val == "" || (val[0] != '-' && (val[0] < '0' || val[0] > '9')) {
				continue
			}
			seconds, err := strconv.ParseInt(val, 10, 64)
			if err != nil {
				continue
			}
			maxAgeSet = true
			switch {
			case seconds <= 0:
				c.expired, c.expires = true, time.Time{}
			case seconds > int64(math.MaxInt64/time.Second):
				c.expired, c.expires = false, time.Time{}
			default:
				c.expired, c.expires = false, now.Add(time.Duration(seconds)*time.Second)
			}
		case "expires":
			if maxAgeSet {
				continue
			}
			at, err := http.ParseTime(val)
			if err != nil {
				continue
			}
			c.expired, c.expires = !at.After(now), at
		case "path":
			if val != "" && val[0] == '/' {
				c.path = val
			} else {
				c.path = defaultPath
			}
		}
	}
	return c, !c.expired
}

func issuerCookieHasCTL(s string) bool {
	for i := 0; i < len(s); i++ {
		if (s[i] < 0x20 && s[i] != '\t') || s[i] == 0x7f {
			return true
		}
	}
	return false
}

// observeResponse records cookies from a response delivered to the client.
// Domain attributes are deliberately ignored: the allowance binds to the
// exact issuing host, so a sibling host that a browser would also send a
// domain cookie to receives ordinary header DLP.
func (s *issuerBoundCookieStore) observeResponse(id string, origin *url.URL, headers http.Header, delivered bool, now time.Time) {
	if s == nil || !delivered {
		return
	}
	host, port, ok := issuerCookieOrigin(origin)
	if !ok {
		return
	}
	lines := headers.Values("Set-Cookie")
	if len(lines) == 0 {
		return
	}
	if len(lines) > issuerCookieMaxSetCookies {
		lines = lines[:issuerCookieMaxSetCookies]
	}
	defaultPath := issuerCookieDefaultPath(origin.Path)
	s.mu.Lock()
	defer s.mu.Unlock()
	var sess *issuerCookieSession
	for _, line := range lines {
		cookie, ok := parseIssuerSetCookie(line, defaultPath, now)
		if !ok {
			continue
		}
		if sess == nil {
			if sess = s.sessionLocked(id, true, now); sess == nil {
				return
			}
		}
		entry := issuerCookieEntry{
			digest: s.digest(cookie.name, cookie.value), host: host, port: port,
			path: cookie.path, expires: cookie.expires,
		}
		replaced := false
		for i := range sess.entries {
			old := &sess.entries[i]
			if old.digest == entry.digest && old.host == host && old.port == port && old.path == entry.path {
				*old = entry
				replaced = true
				break
			}
		}
		if replaced {
			continue
		}
		if len(sess.entries) >= issuerCookieMaxEntries {
			// Forget the oldest issuance; it returns to ordinary DLP.
			sess.entries = append(sess.entries[:0], sess.entries[1:]...)
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

// issuerCookieDefaultPath implements the RFC 6265 section 5.1.4 default-path.
func issuerCookieDefaultPath(path string) string {
	if path == "" || path[0] != '/' {
		return "/"
	}
	last := strings.LastIndex(path, "/")
	if last <= 0 {
		return "/"
	}
	return path[:last]
}

func (s *issuerBoundCookieStore) allows(id string, target *url.URL, name, value string, now time.Time) bool {
	host, port, ok := issuerCookieOrigin(target)
	if !ok || s == nil || len(name)+len(value) > issuerCookieMaxPairBytes {
		return false
	}
	requestPath := target.Path
	if requestPath == "" {
		requestPath = "/"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sess := s.sessionLocked(id, false, now)
	if sess == nil {
		return false
	}
	digest := s.digest(name, value)
	for _, entry := range sess.entries {
		if hmac.Equal(entry.digest[:], digest[:]) && entry.host == host && entry.port == port &&
			(entry.expires.IsZero() || entry.expires.After(now)) && issuerCookiePathMatches(entry.path, requestPath) {
			return true
		}
	}
	return false
}

// issuerCookiePathMatches implements the RFC 6265 section 5.1.4 path-match.
func issuerCookiePathMatches(cookiePath, requestPath string) bool {
	return requestPath == cookiePath || (strings.HasPrefix(requestPath, cookiePath) &&
		(strings.HasSuffix(cookiePath, "/") || strings.HasPrefix(requestPath[len(cookiePath):], "/")))
}

// issuerCookieAllowance names one returned cookie pair left out of header DLP
// and the patterns it would have matched. It never carries the value.
type issuerCookieAllowance struct {
	Name     string
	Patterns []string
}

// issuerCookieScanHeaders returns the headers header DLP should scan. The
// forwarded request is never modified. Each Cookie field is split into pairs
// by the RFC 6265 section 4.2.1 grammar; a pair this session received from
// the exact target origin is omitted, and every other pair, header and body
// byte is scanned unchanged.
func issuerCookieScanHeaders(ctx context.Context, headers http.Header, sc *scanner.Scanner, store *issuerBoundCookieStore, session string, target *url.URL, now time.Time) (http.Header, []issuerCookieAllowance) {
	if store == nil || target == nil {
		return headers, nil
	}
	var kept []string
	var allowances []issuerCookieAllowance
	var keys []string
	for key, fields := range headers {
		if !strings.EqualFold(key, "Cookie") {
			continue
		}
		keys = append(keys, key)
		for _, field := range fields {
			var remaining []string
			for _, raw := range strings.Split(field, ";") {
				pair := strings.Trim(raw, " \t")
				if pair == "" {
					continue
				}
				name, value, found := strings.Cut(pair, "=")
				name, value = strings.Trim(name, " \t"), strings.Trim(value, " \t")
				if !found || name == "" || !store.allows(session, target, name, value, now) {
					remaining = append(remaining, pair)
					continue
				}
				allowance := issuerCookieAllowance{Name: name}
				if sc != nil {
					for _, match := range sc.ScanTextForDLP(ctx, pair).Matches {
						allowance.Patterns = append(allowance.Patterns, match.PatternName)
					}
				}
				allowances = append(allowances, allowance)
			}
			if len(remaining) > 0 {
				kept = append(kept, strings.Join(remaining, "; "))
			}
		}
	}
	if len(allowances) == 0 {
		return headers, nil
	}
	scan := headers.Clone()
	for _, key := range keys {
		delete(scan, key)
	}
	if len(kept) > 0 {
		scan["Cookie"] = kept
	}
	return scan, allowances
}
