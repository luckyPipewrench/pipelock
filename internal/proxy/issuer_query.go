// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"golang.org/x/net/html/charset"
)

const issuerQueryReceiptExtensionKey = "entropy_issuer_query_allow"

// issuerQueryKind records how a value came to be issued, so the receipt for an
// allowance says which rule admitted it.
type issuerQueryKind string

const (
	// issuerQueryObserved: the host in the URL served the value itself.
	issuerQueryObserved issuerQueryKind = "observed_issuer"
	// issuerQueryOAuthRedirect: an OAuth authorization server redirected to a
	// redirect_uri on another host that the same session had declared to it.
	issuerQueryOAuthRedirect issuerQueryKind = "declared_oauth_redirect"
)

// issuerQueryMaxRedirects bounds the OAuth redirect_uri declarations kept per
// session. A session runs few authorization flows at once; evicting an old
// declaration only returns that flow's callback to the ordinary entropy gate.
const issuerQueryMaxRedirects = 64

type issuerQueryEntry struct {
	digest [32]byte
	kind   issuerQueryKind
}

type issuerQueryStore struct {
	mu       sync.Mutex
	key      [32]byte
	sessions map[string][]issuerQueryEntry
	// redirects holds keyed digests of (authorization server origin,
	// redirect_uri origin and path) pairs declared by the session.
	redirects map[string][][32]byte
	// paths holds keyed digests of the URL paths a response served from its
	// own origin linked to. They live apart from values so a page that links
	// to hundreds of assets cannot push a paging token out of its list.
	paths map[string][][32]byte
	// documents holds keyed digests of the origins that served the session an
	// HTML document. A request's page-origin value is accepted only for an
	// origin in this list, so a header the agent wrote cannot name one.
	documents map[string][][32]byte
	used      map[string]time.Time
	disabled  bool
}

func newIssuerQueryStore() *issuerQueryStore {
	return newIssuerQueryStoreWithReader(rand.Reader)
}

func newIssuerQueryStoreWithReader(reader io.Reader) *issuerQueryStore {
	s := &issuerQueryStore{
		sessions:  make(map[string][]issuerQueryEntry),
		redirects: make(map[string][][32]byte),
		paths:     make(map[string][][32]byte),
		documents: make(map[string][][32]byte),
		used:      make(map[string]time.Time),
	}
	if _, err := io.ReadFull(reader, s.key[:]); err != nil {
		s.disabled = true
	}
	return s
}

func (ic *InterceptContext) issuerQueryStore() *issuerQueryStore {
	if ic == nil || ic.Proxy == nil || !issuerCookieEnabled(ic.Config) || !ic.stateTrusted() {
		return nil
	}
	runtime := ic.Proxy.issuerCookieRuntime.Load()
	if runtime == nil || (ic.IssuerRuntime != nil && ic.IssuerRuntime != runtime) ||
		(ic.IssuerRuntime == nil && runtime.cfg != ic.Config) {
		return nil
	}
	return runtime.query
}

// digest binds the scheme as well as host, port and path. The origin check
// already admits only https, so the scheme field is defense in depth against
// that check ever widening.
func (s *issuerQueryStore) digest(scheme, host, port, path, name, value string) [32]byte {
	return s.digestFields(scheme, host, port, path, name, value)
}

func (s *issuerQueryStore) digestFields(fields ...string) [32]byte {
	// Each field is written as its byte length then its raw bytes, so the
	// tuple is unambiguous and byte-exact: no field boundary can be forged,
	// and invalid UTF-8 is hashed as-is rather than normalized.
	mac := hmac.New(sha256.New, s.key[:])
	var size [8]byte
	for _, field := range fields {
		binary.BigEndian.PutUint64(size[:], uint64(len(field)))
		_, _ = mac.Write(size[:])
		_, _ = mac.Write([]byte(field))
	}
	var out [32]byte
	copy(out[:], mac.Sum(nil))
	return out
}

func issuerQueryPath(target *url.URL) string {
	if path := target.EscapedPath(); path != "" {
		return path
	}
	return "/"
}

// admitSessionLocked makes room for a session that holds no evidence yet by
// evicting the least recently used session, across values and declarations.
func (s *issuerQueryStore) admitSessionLocked(session string) {
	if _, exists := s.used[session]; exists || len(s.used) < issuerCookieMaxSessions {
		return
	}
	var oldest string
	for id, used := range s.used {
		if oldest == "" || used.Before(s.used[oldest]) {
			oldest = id
		}
	}
	delete(s.sessions, oldest)
	delete(s.redirects, oldest)
	delete(s.paths, oldest)
	delete(s.documents, oldest)
	delete(s.used, oldest)
}

func (s *issuerQueryStore) remember(session string, target *url.URL, name, value string, now time.Time) {
	s.rememberKind(session, target, name, value, issuerQueryObserved, now)
}

func (s *issuerQueryStore) rememberKind(session string, target *url.URL, name, value string, kind issuerQueryKind, now time.Time) {
	if s == nil || s.disabled || session == "" || len(name)+len(value) > issuerCookieMaxPairBytes {
		return
	}
	host, port, ok := issuerCookieOrigin(target)
	if !ok {
		return
	}
	digest := s.digest(strings.ToLower(target.Scheme), host, port, issuerQueryPath(target), name, value)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.admitSessionLocked(session)
	entries := s.sessions[session]
	for _, entry := range entries {
		if hmac.Equal(entry.digest[:], digest[:]) {
			s.used[session] = now
			return
		}
	}
	if len(entries) >= issuerCookieMaxEntries {
		entries = entries[1:]
	}
	s.sessions[session] = append(entries, issuerQueryEntry{digest: digest, kind: kind})
	s.used[session] = now
}

func (s *issuerQueryStore) allows(session string, target *url.URL, name, value string) bool {
	_, ok := s.match(session, target, name, value)
	return ok
}

// match reports whether the session was issued this exact value for this
// target, and by which rule.
func (s *issuerQueryStore) match(session string, target *url.URL, name, value string) (issuerQueryKind, bool) {
	if s == nil || s.disabled || session == "" || len(name)+len(value) > issuerCookieMaxPairBytes {
		return "", false
	}
	host, port, ok := issuerCookieOrigin(target)
	if !ok {
		return "", false
	}
	digest := s.digest(strings.ToLower(target.Scheme), host, port, issuerQueryPath(target), name, value)
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, entry := range s.sessions[session] {
		if hmac.Equal(entry.digest[:], digest[:]) {
			s.used[session] = time.Now()
			return entry.kind, true
		}
	}
	return "", false
}

// pathDigest binds one escaped URL path to the scheme, host and port that
// served the link. The leading tag keeps it apart from a value digest.
func (s *issuerQueryStore) pathDigest(target *url.URL) ([32]byte, bool) {
	host, port, ok := issuerCookieOrigin(target)
	if !ok {
		return [32]byte{}, false
	}
	path := issuerQueryPath(target)
	if len(path) > issuerCookieMaxPairBytes {
		return [32]byte{}, false
	}
	return s.digestFields("url_path", strings.ToLower(target.Scheme), host, port, path), true
}

// rememberPath records that the origin in target linked to target's exact
// path, so a later request for that same path on that same origin is a link the
// origin issued rather than a path the agent composed.
func (s *issuerQueryStore) rememberPath(session string, target *url.URL, now time.Time) {
	if s == nil || s.disabled || session == "" {
		return
	}
	digest, ok := s.pathDigest(target)
	if !ok {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.admitSessionLocked(session)
	issued := s.paths[session]
	for _, existing := range issued {
		if hmac.Equal(existing[:], digest[:]) {
			s.used[session] = now
			return
		}
	}
	if len(issued) >= issuerCookieMaxEntries {
		issued = issued[1:]
	}
	s.paths[session] = append(issued, digest)
	s.used[session] = now
}

// pathIssued reports whether the session saw the origin in target link to
// target's exact path.
func (s *issuerQueryStore) pathIssued(session string, target *url.URL) bool {
	if s == nil || s.disabled || session == "" {
		return false
	}
	digest, ok := s.pathDigest(target)
	if !ok {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.paths[session] {
		if hmac.Equal(existing[:], digest[:]) {
			s.used[session] = time.Now()
			return true
		}
	}
	return false
}

// documentDigest binds one origin. The leading tag keeps it apart from the
// other digests.
func (s *issuerQueryStore) documentDigest(origin *url.URL) ([32]byte, bool) {
	host, port, ok := issuerCookieOrigin(origin)
	if !ok {
		return [32]byte{}, false
	}
	return s.digestFields("html_document_origin", strings.ToLower(origin.Scheme), host, port), true
}

// rememberDocument records that the session received an HTML document from the
// origin of target.
func (s *issuerQueryStore) rememberDocument(session string, target *url.URL, now time.Time) {
	if s == nil || s.disabled || session == "" {
		return
	}
	digest, ok := s.documentDigest(target)
	if !ok {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.admitSessionLocked(session)
	served := s.documents[session]
	for _, existing := range served {
		if hmac.Equal(existing[:], digest[:]) {
			s.used[session] = now
			return
		}
	}
	if len(served) >= issuerCookieMaxEntries {
		served = served[1:]
	}
	s.documents[session] = append(served, digest)
	s.used[session] = now
}

// documentServed reports whether the session received an HTML document from
// the origin of target.
func (s *issuerQueryStore) documentServed(session string, target *url.URL) bool {
	if s == nil || s.disabled || session == "" {
		return false
	}
	digest, ok := s.documentDigest(target)
	if !ok {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.documents[session] {
		if hmac.Equal(existing[:], digest[:]) {
			s.used[session] = time.Now()
			return true
		}
	}
	return false
}

// redirectDigest binds an authorization server origin to one redirect_uri
// origin and path. The leading tag and the field count keep it apart from a
// value digest.
func (s *issuerQueryStore) redirectDigest(server, redirect *url.URL) ([32]byte, bool) {
	serverHost, serverPort, ok := issuerCookieOrigin(server)
	if !ok {
		return [32]byte{}, false
	}
	redirectHost, redirectPort, ok := issuerCookieOrigin(redirect)
	if !ok {
		return [32]byte{}, false
	}
	return s.digestFields("oauth_redirect_uri",
		strings.ToLower(server.Scheme), serverHost, serverPort,
		strings.ToLower(redirect.Scheme), redirectHost, redirectPort, issuerQueryPath(redirect)), true
}

// declareRedirect records that the session asked the authorization server at
// server's origin to return to redirect.
func (s *issuerQueryStore) declareRedirect(session string, server, redirect *url.URL, now time.Time) {
	if s == nil || s.disabled || session == "" {
		return
	}
	digest, ok := s.redirectDigest(server, redirect)
	if !ok {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.admitSessionLocked(session)
	declared := s.redirects[session]
	for _, existing := range declared {
		if hmac.Equal(existing[:], digest[:]) {
			s.used[session] = now
			return
		}
	}
	if len(declared) >= issuerQueryMaxRedirects {
		declared = declared[1:]
	}
	s.redirects[session] = append(declared, digest)
	s.used[session] = now
}

// redirectDeclared reports whether the session declared redirect to the
// authorization server at server's origin.
func (s *issuerQueryStore) redirectDeclared(session string, server, redirect *url.URL) bool {
	if s == nil || s.disabled || session == "" {
		return false
	}
	digest, ok := s.redirectDigest(server, redirect)
	if !ok {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.redirects[session] {
		if hmac.Equal(existing[:], digest[:]) {
			return true
		}
	}
	return false
}

// oauthCrossHostPermitted applies oauthCrossHostAllowed to both the request's
// configuration and the one the live issuer runtime was built from. A CONNECT
// captures them separately, so a reload between the two can pair an old
// permissive configuration with a newer runtime; either one blocking wins.
func (ic *InterceptContext) oauthCrossHostPermitted() bool {
	if ic == nil || !oauthCrossHostAllowed(ic.Config) {
		return false
	}
	if ic.Proxy != nil {
		if runtime := ic.Proxy.issuerCookieRuntime.Load(); runtime != nil && !oauthCrossHostAllowed(runtime.cfg) {
			return false
		}
	}
	return true
}

// oauthCrossHostAllowed reports whether cross-host OAuth issuance may run.
// A server that echoes request-body data into a redirect can carry that data
// to another host in a URL. While request-body content entropy only warns,
// the agent could send the same data straight to that host, so the hop adds
// nothing. When the operator blocks body content entropy, the hop would be the
// way around that block, so cross-host values keep the ordinary URL gate.
func oauthCrossHostAllowed(cfg *config.Config) bool {
	return cfg != nil && cfg.RequestBodyScanning.ContentEntropyAction != config.ActionBlock
}

// The query parameters a cross-host OAuth hop may carry past the entropy gate.
// Any other parameter on the same redirect keeps the ordinary gate, so a
// server cannot ride a qualifying redirect to exempt an arbitrary value.
var (
	// The authorization response (RFC 6749 section 4.1.2) and the issuer
	// identifier that accompanies it (RFC 9207).
	oauthCallbackParams = map[string]bool{"code": true, "state": true, "iss": true}
	// The client-generated values of an authorization request (RFC 6749
	// section 4.1.1, OpenID Connect Core section 3.1.2.1). code_challenge has
	// its own shape-based relief and client_id is not a generated value.
	oauthAuthorizeParams = map[string]bool{"state": true, "nonce": true}
)

// oauthCrossHostHop reports whether a redirect from one origin to another is
// an OAuth authorization-code hop whose values the redirecting server issued,
// and returns the query parameters that hop may carry:
//   - the client sending the browser to an authorization server, when the
//     authorization request's redirect_uri is on the client's own origin, so
//     the client issued the values and asked for the code to come back to it;
//   - the authorization server returning to the exact redirect_uri origin and
//     path that this session declared to that server.
func oauthCrossHostHop(store *issuerQueryStore, session string, from, to *url.URL) (map[string]bool, bool) {
	if store.redirectDeclared(session, from, to) {
		return oauthCallbackParams, true
	}
	redirect, ok := oauthRedirectDeclaration(to)
	if !ok {
		return nil, false
	}
	fromHost, fromPort, fromOK := issuerCookieOrigin(from)
	redirectHost, redirectPort, redirectOK := issuerCookieOrigin(redirect)
	if fromOK && redirectOK && fromHost == redirectHost && fromPort == redirectPort {
		return oauthAuthorizeParams, true
	}
	return nil, false
}

// oauthRedirectDeclaration returns the redirect_uri of an OAuth authorization
// request carried in a URL query (RFC 6749 section 4.1.1): a response_type
// that includes "code", a client_id and an absolute redirect_uri, each exactly
// once, as section 3.1 requires. The redirect_uri must be https with no
// userinfo and no fragment (section 3.1.2).
func oauthRedirectDeclaration(request *url.URL) (*url.URL, bool) {
	if request == nil || request.RawQuery == "" {
		return nil, false
	}
	// ParseQuery refuses a ";" separator, so an ambiguous query declares
	// nothing.
	query, err := url.ParseQuery(request.RawQuery)
	if err != nil {
		return nil, false
	}
	responseType, clientID, redirectURI := query["response_type"], query["client_id"], query["redirect_uri"]
	if len(responseType) != 1 || len(clientID) != 1 || clientID[0] == "" || len(redirectURI) != 1 {
		return nil, false
	}
	// response_type is a space-delimited list (RFC 6749 section 3.1.1), so a
	// hybrid "code id_token" request also returns a code.
	hasCode := false
	for _, token := range strings.Split(responseType[0], " ") {
		if token == "code" {
			hasCode = true
		}
	}
	if !hasCode {
		return nil, false
	}
	redirect, err := url.Parse(redirectURI[0])
	if err != nil || !redirect.IsAbs() || redirect.Fragment != "" || strings.Contains(redirectURI[0], "#") {
		return nil, false
	}
	if _, _, ok := issuerCookieOrigin(redirect); !ok {
		return nil, false
	}
	return redirect, true
}

// issuerQueryMaxDepth bounds JSON nesting walked for issued links; the
// earlier tree walk stopped at the same depth.
const issuerQueryMaxDepth = 33

func recordDeliveredIssuerQuery(ic *InterceptContext, response *http.Response, body []byte, delivered bool) {
	if !delivered || ic == nil || response == nil || response.Request == nil || response.Request.URL == nil {
		return
	}
	store := ic.issuerQueryStore()
	if store == nil {
		return
	}
	issuerHost, issuerPort, ok := issuerCookieOrigin(response.Request.URL)
	if !ok {
		return
	}
	session := sessionKeyFor(ic.Config, ic.Agent, ic.ClientIP, ic.ActorAuth)
	// An OAuth authorization request names where the code must go. Record the
	// declaration only once the request was allowed and its response
	// delivered, which is the only way this function is reached.
	if redirect, declared := oauthRedirectDeclaration(response.Request.URL); declared {
		store.declareRedirect(session, response.Request.URL, redirect, time.Now())
	}
	remaining := issuerCookieMaxSetCookies
	// Path evidence has its own budget so a listing with many same-origin
	// paths cannot exhaust the one that records query values (a paging token
	// that follows them).
	pathRemaining := issuerCookieMaxSetCookies
	// base is what a relative reference resolves against: the response URL,
	// or an HTML document's own <base href> when it names the same origin.
	base := response.Request.URL
	// observe records the URL a response carried. linkAttr marks a value the
	// document itself declares to be a URL (an HTML link attribute), so a
	// bare relative reference is a link. A JSON string is only a link when it
	// has a scheme or starts with a single slash; otherwise any word the
	// server returned would resolve to a path it never issued.
	observe := func(value string, redirectHop, linkAttr bool) {
		candidate, err := url.Parse(value)
		if err != nil {
			return
		}
		pathIssued := linkAttr || candidate.IsAbs() ||
			(strings.HasPrefix(value, "/") && !strings.HasPrefix(value, "//"))
		if candidate.RawQuery == "" && !pathIssued {
			return
		}
		if !candidate.IsAbs() {
			// Resolve any relative reference ("/x?a", "x?a", "?a") against the
			// response URL; the origin check below then rejects anything that
			// resolved to another host, including a "//host" reference.
			candidate = base.ResolveReference(candidate)
		}
		host, port, valid := issuerCookieOrigin(candidate)
		if !valid {
			return
		}
		kind := issuerQueryObserved
		var allowed map[string]bool // nil: every parameter, for same-host values
		if host != issuerHost || port != issuerPort {
			// A value may cross to another host only on a redirect that is
			// one of the two OAuth authorization-code hops.
			if !redirectHop || !ic.oauthCrossHostPermitted() || candidate.RawQuery == "" {
				return
			}
			names, hop := oauthCrossHostHop(store, session, response.Request.URL, candidate)
			if !hop {
				return
			}
			kind = issuerQueryOAuthRedirect
			allowed = names
		} else if pathIssued && pathRemaining > 0 {
			// Only the origin's own link counts: a cross-host redirect above
			// returned before this point and issues no path.
			store.rememberPath(session, candidate, time.Now())
			pathRemaining--
		}
		for name, values := range candidate.Query() {
			if allowed != nil && !allowed[name] {
				continue
			}
			for _, queryValue := range values {
				if remaining == 0 {
					return
				}
				store.rememberKind(session, candidate, name, queryValue, kind, time.Now())
				remaining--
			}
		}
	}
	// A redirect issues its target in the Location header, usually with an
	// empty body: an authorization server hands out an OAuth state value
	// exactly this way. The same origin check applies, so a redirect to
	// another host issues nothing unless it is a declared OAuth callback.
	if response.StatusCode >= 300 && response.StatusCode < 400 {
		if location := response.Header.Get("Location"); location != "" {
			observe(location, true, false)
		}
	}
	if len(body) == 0 {
		return
	}
	mediaType := strings.ToLower(strings.TrimSpace(strings.Split(response.Header.Get("Content-Type"), ";")[0]))
	if mediaType == "text/html" || mediaType == "application/xhtml+xml" {
		// The agent received a document from this origin, so a later request
		// may name it as the page it is embedded in.
		store.rememberDocument(session, response.Request.URL, time.Now())
		if !asciiTransparentDocument(body, response.Header.Get("Content-Type")) {
			// Links and base are read from the raw bytes as UTF-8. Under an
			// encoding that does not keep ASCII markup as-is (UTF-16, or one
			// with shift states such as ISO-2022-JP), a browser may decode
			// different URLs, so the document issues no link at all.
			return
		}
		links, baseHref, baseKnown := htmlLinksAndBase(body, remaining)
		if mediaType == "application/xhtml+xml" {
			// XHTML is parsed as XML, not by the HTML algorithm that found
			// this base, so its base is not known.
			baseKnown = false
		}
		docBase, usable := sameOriginBase(response.Request.URL, baseHref)
		for _, link := range links {
			if !baseKnown || !usable {
				// The browser resolves this document's relative links
				// against a base Pipelock cannot honor, or cannot see, so
				// only an absolute link names the URL it will request.
				if ref, err := url.Parse(link); err != nil || !ref.IsAbs() {
					continue
				}
			}
			base = docBase
			observe(link, false, true)
		}
		return
	}
	if mediaType != "application/json" && !strings.HasSuffix(mediaType, "+json") {
		return
	}
	// Walk the JSON as a token stream rather than decoding it into generic
	// maps and slices, which would cost several times the body size on every
	// intercepted JSON response. json.Valid keeps the old rule that a body
	// which is not valid JSON issues nothing.
	if !json.Valid(body) {
		return
	}
	// Only string VALUES issue links. An object key is not a value the
	// server handed out, so keys are skipped. Each open container records
	// whether it is an object and, if so, whether its next string is a key.
	type jsonLevel struct{ object, expectKey bool }
	decoder := json.NewDecoder(bytes.NewReader(body))
	var levels []jsonLevel
	// valueDone marks the current object's pending value as consumed, so
	// its next string is a key again.
	valueDone := func() {
		if n := len(levels); n > 0 && levels[n-1].object {
			levels[n-1].expectKey = true
		}
	}
	for remaining > 0 {
		token, err := decoder.Token()
		if err != nil {
			return
		}
		switch t := token.(type) {
		case json.Delim:
			switch t {
			case '{', '[':
				levels = append(levels, jsonLevel{object: t == '{', expectKey: t == '{'})
				if len(levels) > issuerQueryMaxDepth {
					return
				}
			default:
				levels = levels[:len(levels)-1]
				valueDone()
			}
		case string:
			if n := len(levels); n > 0 && levels[n-1].object && levels[n-1].expectKey {
				levels[n-1].expectKey = false
				continue
			}
			observe(t, false, false)
			valueDone()
		default:
			valueDone()
		}
	}
}

// lateMetaCharset matches a <meta> charset declaration, which a browser can
// act on after its 1024-byte prescan by re-decoding the document.
var lateMetaCharset = regexp.MustCompile(`(?i)<meta[^>]*charset`)

// asciiTransparentDocument reports whether a browser decodes this HTML so that
// its ASCII markup reads the same as the raw bytes: UTF-8 or windows-1252,
// the WHATWG fallback. A declared encoding (BOM or Content-Type) is taken at
// its word. A guessed one is trusted only when nothing in the body lets a
// browser decide differently: an escape byte (ISO-2022-JP detection), a NUL
// byte (UTF-16 without a BOM), or a charset declaration past the prescan.
func asciiTransparentDocument(body []byte, contentType string) bool {
	_, name, certain := charset.DetermineEncoding(body, contentType)
	if name != "utf-8" && name != "windows-1252" {
		return false
	}
	if certain {
		return true
	}
	if bytes.IndexByte(body, 0x1b) >= 0 || bytes.IndexByte(body, 0) >= 0 {
		return false
	}
	const prescan = 1024
	return len(body) <= prescan || !lateMetaCharset.Match(body[prescan:])
}

// sameOriginBase returns the URL an HTML document's relative references
// resolve against: its <base href> resolved against the response URL. usable
// is false when the base is unparseable or names another origin. The browser
// then resolves relative links against that other base, so falling back to
// the response URL would credit this origin with paths it never linked; the
// caller must skip relative links instead.
func sameOriginBase(responseURL *url.URL, href string) (*url.URL, bool) {
	if href == "" {
		return responseURL, true
	}
	ref, err := url.Parse(href)
	if err != nil {
		return nil, false
	}
	resolved := responseURL.ResolveReference(ref)
	host, port, ok := issuerCookieOrigin(resolved)
	responseHost, responsePort, responseOK := issuerCookieOrigin(responseURL)
	// issuerCookieOrigin admits only https, so a matching host and port is a
	// matching origin.
	if !ok || !responseOK || host != responseHost || port != responsePort {
		return nil, false
	}
	return resolved, true
}

// recordIssuerQueryAllow records an issuer-query allow. cfg is the request's
// config snapshot; under require_receipts every path that cannot durably
// record the allow returns an error the caller must treat as fail-closed.
// With require_receipts off it always returns nil (best-effort).
func (p *Proxy) recordIssuerQueryAllow(cfg *config.Config, ctx audit.LogContext, target, requestID, agent, method string, kind issuerQueryKind, selected ...receipt.EmitOpts) error {
	requireReceipts := cfg != nil && cfg.FlightRecorder.RequireReceipts
	fail := func(err error) error {
		if requireReceipts {
			return err
		}
		return nil
	}
	if p == nil {
		return fail(errCredentialAudienceReceiptEmitterUnavailable)
	}
	parsed, err := url.Parse(target)
	if err != nil {
		return fail(fmt.Errorf("issuer query allow target: %w", err))
	}
	if p.logger != nil {
		p.logger.LogIssuerQueryAllow(ctx, strings.ToLower(parsed.Hostname()))
	}
	if kind != issuerQueryOAuthRedirect && kind != issuerQueryPageOrigin {
		kind = issuerQueryObserved
	}
	safeTarget := parsed.Scheme + "://" + parsed.Host + parsed.EscapedPath()
	extension := []byte(`{"entropy_issuer_query_allow":"` + string(kind) + `"}`)
	var shard receipt.EmitOpts
	if len(selected) > 0 {
		shard = selected[0]
	}
	emitErr := p.emitCredentialAudienceReceipt(cfg, withReceiptShard(receipt.EmitOpts{
		ActionID: receipt.NewActionID(), Verdict: config.ActionAllow,
		Layer: issuerQueryReceiptExtensionKey, Pattern: issuerQueryReceiptExtensionKey,
		Transport: "intercept", Method: method, Target: safeTarget,
		RequestID: requestID, Agent: agent, Extension: extension,
	}, shard))
	if emitErr != nil {
		return fail(emitErr)
	}
	return nil
}
