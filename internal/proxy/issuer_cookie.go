// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/publicsuffix"

	"github.com/luckyPipewrench/pipelock/internal/atomicfile"
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
	issuerCookieMaxStateBytes = 32 << 20
	issuerCookieStateVersion  = 1
	issuerCookieWriteInterval = 3 * time.Second
)

// issuerBoundCookieStore remembers keyed digests of cookies that an
// intercepted HTTPS origin issued to one identity session. A remembered
// cookie pair is left out of header DLP only when the same session returns
// it to the exact issuing host and port over HTTPS. Returning a value to the
// origin that issued it discloses nothing that origin does not already hold.
type issuerBoundCookieStore struct {
	mu        sync.Mutex
	key       [32]byte
	sessions  map[string]*issuerCookieSession
	disabled  bool
	path      string
	dirty     bool
	lastWrite time.Time
	timer     *time.Timer
	logError  func(error)
}

// A single atomic pointer ties requests to the current policy snapshot.
// An enabled reload retains the store; disabling a prerequisite resets it.
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
	digest [32]byte
	host   string
	port   string
	// domain is the cookie's Domain scope when the issuer set a valid one;
	// empty means a host-only cookie, returned only to host.
	domain  string
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

// issuerCookieStatePath follows the existing XDG state-home convention.
func issuerCookieStatePath() (string, error) {
	root := os.Getenv("XDG_STATE_HOME")
	if root == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		root = filepath.Join(home, ".local", "state")
	}
	if !filepath.IsAbs(root) {
		return "", errors.New("state home must be absolute")
	}
	return filepath.Join(root, "pipelock", "proxy", "issuer-cookies.json"), nil
}

type issuerCookieDisk struct {
	Version  int                       `json:"version"`
	Key      string                    `json:"key"`
	Sessions []issuerCookieDiskSession `json:"sessions"`
}
type issuerCookieDiskSession struct {
	ID       string                  `json:"id"`
	LastUsed time.Time               `json:"last_used"`
	Entries  []issuerCookieDiskEntry `json:"entries"`
}
type issuerCookieDiskEntry struct {
	Digest  string    `json:"digest"`
	Host    string    `json:"host"`
	Port    string    `json:"port"`
	Domain  string    `json:"domain,omitempty"`
	Path    string    `json:"path"`
	Expires time.Time `json:"expires"`
}

func (s *issuerBoundCookieStore) report(err error) {
	if err != nil && s.logError != nil {
		s.logError(err)
	}
}

func newPersistentIssuerCookieStore(logger *audit.Logger) *issuerBoundCookieStore {
	s := newIssuerBoundCookieStore()
	s.logError = func(err error) {
		if logger != nil {
			logger.LogError(audit.NewMethodLogContext("ISSUER_COOKIE"), err)
		}
	}
	path, err := issuerCookieStatePath()
	if err != nil {
		s.report(fmt.Errorf("issuer cookie state unavailable: %w", err))
		return s
	}
	s.path = path
	if err = s.load(time.Now()); err != nil {
		s.report(fmt.Errorf("issuer cookie state ignored: %w", err))
		// The generated key and empty map remain authoritative on any load error.
	}
	return s
}

func (s *issuerBoundCookieStore) load(now time.Time) error {
	if err := issuerCookieCheckDir(filepath.Dir(s.path)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	info, err := os.Lstat(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() > issuerCookieMaxStateBytes {
		return errors.New("state file type, permissions, or size invalid")
	}
	f, err := os.Open(filepath.Clean(s.path))
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	opened, err := f.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(info, opened) || opened.Mode().Perm() != 0o600 {
		return errors.New("issuer cookie state changed during open")
	}
	raw, err := io.ReadAll(io.LimitReader(f, issuerCookieMaxStateBytes+1))
	if err != nil {
		return err
	}
	if len(raw) > issuerCookieMaxStateBytes {
		return errors.New("state file exceeds limit")
	}
	var disk issuerCookieDisk
	if err = json.Unmarshal(raw, &disk); err != nil {
		return err
	}
	if disk.Version != issuerCookieStateVersion || len(disk.Sessions) > issuerCookieMaxSessions {
		return errors.New("unsupported or oversized issuer cookie state")
	}
	key, err := hex.DecodeString(disk.Key)
	if err != nil || len(key) != len(s.key) {
		return errors.New("invalid issuer cookie key")
	}
	loaded := make(map[string]*issuerCookieSession, len(disk.Sessions))
	for _, ds := range disk.Sessions {
		if ds.ID == "" || len(ds.ID) > 1024 || len(ds.Entries) > issuerCookieMaxEntries || loaded[ds.ID] != nil {
			return errors.New("invalid issuer cookie session")
		}
		sess := &issuerCookieSession{lastUsed: ds.LastUsed}
		for _, de := range ds.Entries {
			d, decodeErr := hex.DecodeString(de.Digest)
			if decodeErr != nil || len(d) != 32 || de.Host == "" || len(de.Host) > 253 || de.Port == "" || len(de.Port) > 5 ||
				de.Path == "" || len(de.Path) > issuerCookieMaxPairBytes || (de.Domain != "" && len(de.Domain) > 253) {
				return errors.New("invalid issuer cookie entry")
			}
			if !de.Expires.IsZero() && !de.Expires.After(now) {
				continue
			}
			var digest [32]byte
			copy(digest[:], d)
			sess.entries = append(sess.entries, issuerCookieEntry{digest: digest, host: de.Host, port: de.Port, domain: de.Domain, path: de.Path, expires: de.Expires})
		}
		if len(sess.entries) > 0 {
			loaded[ds.ID] = sess
		}
	}
	copy(s.key[:], key)
	s.sessions = loaded
	return nil
}

func issuerCookieCheckDir(dir string) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm()&^0o750 != 0 {
		return fmt.Errorf("issuer cookie state directory permissions invalid: %s", info.Mode().Perm())
	}
	return nil
}

func (s *issuerBoundCookieStore) flush(now time.Time, force bool) {
	if s == nil || s.path == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.path == "" || s.disabled {
		return
	}
	if s.timer != nil && force {
		s.timer.Stop()
		s.timer = nil
	}
	if !s.dirty && !force {
		return
	}
	if !force && !s.lastWrite.IsZero() && now.Sub(s.lastWrite) < issuerCookieWriteInterval {
		if s.timer == nil {
			s.timer = time.AfterFunc(issuerCookieWriteInterval-now.Sub(s.lastWrite), func() { s.flush(time.Now(), true) })
		}
		return
	}
	// Throttle failed writes as well as successful ones.
	s.lastWrite = now
	disk := issuerCookieDisk{Version: issuerCookieStateVersion, Key: hex.EncodeToString(s.key[:])}
	for id, sess := range s.sessions {
		ds := issuerCookieDiskSession{ID: id, LastUsed: sess.lastUsed}
		kept := sess.entries[:0]
		for _, entry := range sess.entries {
			if !entry.expires.IsZero() && !entry.expires.After(now) {
				continue
			}
			kept = append(kept, entry)
			ds.Entries = append(ds.Entries, issuerCookieDiskEntry{Digest: hex.EncodeToString(entry.digest[:]), Host: entry.host, Port: entry.port, Domain: entry.domain, Path: entry.path, Expires: entry.expires})
		}
		sess.entries = kept
		if len(kept) == 0 {
			delete(s.sessions, id)
		} else {
			disk.Sessions = append(disk.Sessions, ds)
		}
	}
	raw, err := json.Marshal(disk)
	if err != nil {
		s.invalidateStaleFile(err)
		return
	}
	if len(raw) > issuerCookieMaxStateBytes {
		s.invalidateStaleFile(errors.New("issuer cookie state exceeds limit"))
		return
	}
	dir := filepath.Dir(s.path)
	if err = os.MkdirAll(dir, 0o750); err == nil {
		err = issuerCookieCheckDir(dir)
	}
	if err == nil {
		err = atomicfile.Write(s.path, raw, 0o600)
	}
	if err != nil {
		s.invalidateStaleFile(fmt.Errorf("issuer cookie state write failed: %w", err))
		return
	}
	s.dirty = false
	s.lastWrite = now
}

// A prior snapshot can contain an entry evicted from memory. If the newer
// snapshot cannot be published, discard the prior one so restart scans it.
func (s *issuerBoundCookieStore) invalidateStaleFile(writeErr error) {
	s.report(writeErr)
	if err := os.Remove(s.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		s.report(fmt.Errorf("issuer cookie stale state removal failed: %w", err))
	}
}

func (s *issuerBoundCookieStore) retire() string {
	if s == nil {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.timer != nil {
		s.timer.Stop()
		s.timer = nil
	}
	path := s.path
	s.path = ""
	s.disabled = true
	return path
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
	domain            string
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
		case "domain":
			// RFC 6265 section 5.2.3: a leading dot is ignored and the
			// value is compared case-insensitively. The last Domain wins.
			c.domain = strings.ToLower(strings.TrimPrefix(val, "."))
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
// A cookie with no Domain attribute returns only to its issuing host. A Domain
// attribute is honoured the way a user agent honours it (RFC 6265 section 5.3
// steps 5 and 6): it must domain-match the issuing host, must not be a public
// suffix, and never applies to an IP-literal host; a cookie that fails those
// rules is one a browser would reject, so it is not recorded.
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
	changed := false
	defer func() {
		s.mu.Unlock()
		if changed {
			s.flush(now, false)
		}
	}()
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
		domain, ok := issuerCookieScope(host, cookie.domain)
		if !ok {
			continue
		}
		entry := issuerCookieEntry{
			digest: s.digest(cookie.name, cookie.value), host: host, port: port,
			domain: domain, path: cookie.path, expires: cookie.expires,
		}
		replaced := false
		for i := range sess.entries {
			old := &sess.entries[i]
			if old.digest == entry.digest && old.host == host && old.port == port && old.domain == entry.domain && old.path == entry.path {
				*old = entry
				replaced = true
				break
			}
		}
		if replaced {
			s.dirty = true
			changed = true
			continue
		}
		if len(sess.entries) >= issuerCookieMaxEntries {
			// Forget the oldest issuance; it returns to ordinary DLP.
			sess.entries = append(sess.entries[:0], sess.entries[1:]...)
		}
		sess.entries = append(sess.entries, entry)
		s.dirty = true
		changed = true
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

// issuerCookieScope validates a Set-Cookie Domain attribute against the
// issuing host per RFC 6265 section 5.3 steps 5 and 6. It returns the domain
// scope to record ("" for a host-only cookie) and false when a user agent
// would ignore the cookie. A Domain equal to a public suffix is accepted only
// when it equals the host itself, in which case the cookie is host-only.
func issuerCookieScope(host, domain string) (string, bool) {
	if domain == "" {
		return "", true
	}
	if suffix, _ := publicsuffix.PublicSuffix(domain); suffix == domain {
		return "", domain == host
	}
	if net.ParseIP(host) != nil {
		return "", false
	}
	if host != domain && !strings.HasSuffix(host, "."+domain) {
		return "", false
	}
	return domain, true
}

// issuerCookieHostMatches reports whether a request host is one the recorded
// cookie is sent to: the issuing host for a host-only cookie, otherwise any
// host that domain-matches the recorded Domain (RFC 6265 section 5.1.3).
func issuerCookieHostMatches(entry issuerCookieEntry, host string) bool {
	if entry.domain == "" {
		return entry.host == host
	}
	return host == entry.domain || strings.HasSuffix(host, "."+entry.domain)
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
		if hmac.Equal(entry.digest[:], digest[:]) && issuerCookieHostMatches(entry, host) && entry.port == port &&
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

// issuerCookieMaxBlockNames bounds the cookie names a block record carries.
const (
	issuerCookieMaxBlockNames = 16
	issuerCookieUnnamed       = "(unnamed)"
	issuerCookieRedactedName  = "(redacted)"
)

// loggableCookieName returns a pair's name for an audit record. A pair with
// no name, a name that itself carries a DLP match, or an overlong name is
// replaced by a placeholder, because a name is caller-controlled and could
// otherwise carry the value the block exists to keep out of logs.
func loggableCookieName(ctx context.Context, pair string, sc *scanner.Scanner) string {
	name, _, found := strings.Cut(pair, "=")
	name = strings.Trim(name, " \t")
	switch {
	case !found || name == "":
		return issuerCookieUnnamed
	case len(name) > issuerCookieMaxLoggedName || len(sc.ScanTextForDLP(ctx, name).Matches) > 0:
		return issuerCookieRedactedName
	}
	return name
}

// cookieNamesWithDLPMatch names the scanned Cookie pairs that each carry a
// DLP match, so an operator can tell which cookie a header block came from.
// It reports names only, never values.
func cookieNamesWithDLPMatch(ctx context.Context, headers http.Header, sc *scanner.Scanner) []string {
	if sc == nil {
		return nil
	}
	var names []string
	for key, fields := range headers {
		if !strings.EqualFold(key, "Cookie") {
			continue
		}
		for _, field := range fields {
			for _, raw := range strings.Split(field, ";") {
				pair := strings.Trim(raw, " \t")
				if pair == "" {
					continue
				}
				if len(sc.ScanTextForDLP(ctx, pair).Matches) == 0 {
					continue
				}
				names = append(names, loggableCookieName(ctx, pair, sc))
				if len(names) == issuerCookieMaxBlockNames {
					return names
				}
			}
		}
	}
	return names
}
