// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"crypto/hmac"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
)

// A server-issued ID is an opaque object identifier an origin returned in a
// JSON response, such as a mail filter or message ID, that the agent then
// names as one segment of a URL path back to that same origin. The path
// entropy gate reads such an ID as a possible payload. It is relieved for one
// segment only when the origin introduced the value: the exact string never
// appeared in anything this session sent to that origin. A string the agent
// sent and the origin stored and returned is a reflection, not an issue, so
// it stays scored.
//
// Evidence is in-memory and session-bound like the rest of the issuer store.
// A session whose sent traffic cannot be fully read stops minting IDs, so a
// value can never be admitted because Pipelock failed to see it go out.

const (
	issuerQueryServerID issuerQueryKind = "server_issued_id"

	// An ID shorter than this is never scored as high entropy, and a longer
	// one is not a plausible object identifier.
	issuerServerIDMinLen = 16
	issuerServerIDMaxLen = 512
	// issuerServerIDMaxPerResponse bounds the IDs one response can mint.
	issuerServerIDMaxPerResponse = 512
	// issuerSentMaxEntries bounds the sent-token digests kept per session.
	// Evicting one would let that token be minted later, so a full set stops
	// minting for the session instead.
	issuerSentMaxEntries = 8192
	// issuerSentMaxTokensPerRequest bounds the tokens one request records. A
	// request over the bound marks the session unreadable.
	issuerSentMaxTokensPerRequest = 4096
	// issuerUnreadableMaxSessions bounds the sessions remembered as having
	// incomplete sent history. Past it the whole store stops minting.
	issuerUnreadableMaxSessions = 4096
	// issuerSentAllMaxEntries bounds the sent digests kept across all
	// sessions. Past it the whole store stops minting.
	issuerSentAllMaxEntries = 1 << 17
)

// issuerServerIDShaped reports whether value can be one whole URL path
// segment naming an object: unreserved characters plus the base64 padding
// and plus signs some providers keep in IDs. No separator, escape or space
// can occur, so the value is the segment exactly as written and as decoded.
func issuerServerIDShaped(value string) bool {
	if len(value) < issuerServerIDMinLen || len(value) > issuerServerIDMaxLen {
		return false
	}
	for i := 0; i < len(value); i++ {
		if !issuerServerIDByte(value[i]) {
			return false
		}
	}
	return true
}

func issuerServerIDByte(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	}
	switch c {
	case '-', '_', '.', '~', '=', '+':
		return true
	}
	return false
}

// issuerSentTokens splits text into maximal runs of ID characters and keeps
// those long enough to be minted. Every way a value could later come back as
// an ID is a run of these characters, so recording runs covers the value
// whatever surrounds it.
func issuerSentTokens(text string, emit func(string) bool) bool {
	start := -1
	for i := 0; i < len(text); i++ {
		if issuerServerIDByte(text[i]) {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 {
			if !emitSentRun(text[start:i], emit) {
				return false
			}
			start = -1
		}
	}
	if start >= 0 {
		return emitSentRun(text[start:], emit)
	}
	return true
}

// emitSentRun records one maximal run, and each side of every "=" in it:
// "=" is an ID character (base64 padding) and also the form key/value
// separator, so "payload=<value>" must record <value> on its own.
func emitSentRun(run string, emit func(string) bool) bool {
	if len(run) >= issuerServerIDMinLen && !emit(run) {
		return false
	}
	if strings.IndexByte(run, '=') >= 0 {
		for _, part := range strings.Split(run, "=") {
			if len(part) >= issuerServerIDMinLen && part != run && !emit(part) {
				return false
			}
		}
	}
	return true
}

// sentDigest binds a sent token to the host alone. A value sent to a host over
// any scheme or port has reached that host, so it must never mint as an ID
// the host issued, whatever port the ID is later used on.
func (s *issuerQueryStore) sentDigest(target *url.URL, value string) ([32]byte, bool) {
	host := strings.ToLower(strings.TrimSuffix(target.Hostname(), "."))
	if host == "" {
		return [32]byte{}, false
	}
	return s.digestFields("sent_host", host, value), true
}

func (s *issuerQueryStore) originDigest(tag string, target *url.URL, value string) ([32]byte, bool) {
	host, port, ok := issuerCookieOrigin(target)
	if !ok {
		return [32]byte{}, false
	}
	return s.digestFields(tag, strings.ToLower(target.Scheme), host, port, value), true
}

// taintSentLocked stops minting for a session whose outgoing traffic could
// not be fully recorded.
func (s *issuerQueryStore) taintSentLocked(session string) {
	delete(s.ids, session)
	if s.sentUnreadable[session] {
		return
	}
	if len(s.sentUnreadable) >= issuerUnreadableMaxSessions {
		s.mintDisabled = true
		return
	}
	s.sentUnreadable[session] = true
}

// mintBlockedLocked reports whether the session may not mint or use IDs.
func (s *issuerQueryStore) mintBlockedLocked(session string) bool {
	return s.mintDisabled || s.sentUnreadable[session]
}

// recordSent records every token a request carries to its origin: path
// segments, query keys and values, and the body, both raw and decoded. A
// body that was sent but not buffered, or a request over the bound, marks the
// session unreadable.
func (s *issuerQueryStore) recordSent(session string, target *url.URL, header http.Header, body []byte, bodyKnown bool, now time.Time) {
	if s == nil || s.disabled || session == "" || target == nil {
		return
	}
	// issuerCookieOrigin rejects userinfo so a user:pass@host URL cannot
	// impersonate another origin. The client still sends that userinfo, as
	// Basic auth, to the host. Record against the host with the userinfo
	// removed, and record the user and password as sent text.
	originTarget := target
	if target.User != nil {
		stripped := *target
		stripped.User = nil
		originTarget = &stripped
	}
	if scheme := strings.ToLower(originTarget.Scheme); (scheme != "https" && scheme != "http") || originTarget.Hostname() == "" {
		return
	}
	var texts []string
	texts = append(texts, target.EscapedPath(), target.Path)
	if user := target.User; user != nil {
		texts = appendFormLike(texts, user.Username())
		if password, ok := user.Password(); ok {
			texts = appendFormLike(texts, password)
		}
	}
	texts = appendFormLike(texts, target.RawQuery)
	for name, values := range header {
		texts = append(texts, name)
		for _, value := range values {
			texts = appendFormLike(texts, value)
		}
	}
	if len(body) > 0 {
		texts = appendFormLike(texts, string(body))
	}

	var digests [][32]byte
	overflow := false
	for _, text := range texts {
		complete := issuerSentTokens(text, func(token string) bool {
			if len(digests) >= issuerSentMaxTokensPerRequest {
				overflow = true
				return false
			}
			if digest, ok := s.sentDigest(originTarget, token); ok {
				digests = append(digests, digest)
			}
			return true
		})
		if !complete {
			break
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.admitSessionLocked(session)
	s.used[session] = now
	if !bodyKnown || overflow {
		s.taintSentLocked(session)
		return
	}
	sent := s.sent[session]
	if sent == nil {
		sent = make(map[[32]byte]struct{})
		s.sent[session] = sent
	}
	for _, digest := range digests {
		// Every session's sends count: a value one agent handed a host must
		// not mint as an ID that host issued to another agent.
		if _, exists := s.sentAll[digest]; !exists {
			if len(s.sentAll) >= issuerSentAllMaxEntries {
				s.mintDisabled = true
			} else {
				s.sentAll[digest] = struct{}{}
			}
		}
		if _, exists := sent[digest]; exists {
			continue
		}
		if len(sent) >= issuerSentMaxEntries {
			s.taintSentLocked(session)
			return
		}
		sent[digest] = struct{}{}
	}
}

// lenientUnescape percent-decodes every valid %XX escape and keeps any
// malformed one as written, so one bad escape cannot hide the rest. plus
// selects whether "+" also decodes to a space, as in a form body.
func lenientUnescape(text string, plus bool) string {
	if strings.IndexByte(text, '%') < 0 && (!plus || strings.IndexByte(text, '+') < 0) {
		return text
	}
	var b strings.Builder
	b.Grow(len(text))
	for i := 0; i < len(text); i++ {
		c := text[i]
		if c == '%' && i+2 < len(text) && isHex(text[i+1]) && isHex(text[i+2]) {
			b.WriteByte(unhex(text[i+1])<<4 | unhex(text[i+2]))
			i += 2
			continue
		}
		if c == '+' && plus {
			b.WriteByte(' ')
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func unhex(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	default:
		return c - 'A' + 10
	}
}

// appendFormLike adds text as written, leniently percent-decoded both with
// and without "+" as a space, and each key and value of it read as
// "&"/";"-separated form pairs, decoded the same way. Any of those forms may
// be the one an origin stores and returns.
func appendFormLike(texts []string, text string) []string {
	staged := []string{text, lenientUnescape(text, false), lenientUnescape(text, true)}
	for _, pair := range strings.FieldsFunc(text, func(r rune) bool { return r == '&' || r == ';' }) {
		key, value, _ := strings.Cut(pair, "=")
		for _, part := range []string{key, value} {
			staged = append(staged, lenientUnescape(part, false), lenientUnescape(part, true))
		}
	}
	// Identical copies (a body with no escapes) are one text. Walking each
	// copy would count the same tokens against the per-request cap.
	seen := make(map[string]struct{}, len(staged))
	for _, form := range staged {
		if _, ok := seen[form]; ok {
			continue
		}
		seen[form] = struct{}{}
		texts = append(texts, form)
		texts = appendJSONStringsIfValid(texts, form)
	}
	return texts
}

// appendJSONStringsIfValid walks text when it is a JSON value. A form field,
// query value or header often carries a JSON object whose strings are escaped;
// the raw token scan cannot see through those escapes.
func appendJSONStringsIfValid(texts []string, text string) []string {
	if text == "" || !json.Valid([]byte(text)) {
		return texts
	}
	return appendJSONStrings(texts, []byte(text))
}

// appendJSONStrings adds every string key and value of a JSON body, decoded,
// so an escape sequence in the body cannot hide a token from the raw scan.
func appendJSONStrings(texts []string, body []byte) []string {
	if !json.Valid(body) {
		return texts
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	for {
		token, err := decoder.Token()
		if err != nil {
			return texts
		}
		if s, ok := token.(string); ok {
			texts = append(texts, s)
		}
	}
}

// mintServerID records value as an ID the origin in target issued, unless
// the session sent that exact value to the origin or its sent traffic is
// unreadable.
func (s *issuerQueryStore) mintServerID(session string, target *url.URL, value string, now time.Time) {
	if s == nil || s.disabled || session == "" || !issuerServerIDShaped(value) {
		return
	}
	if _, _, ok := issuerCookieOrigin(target); !ok {
		return
	}
	sentDigest, ok := s.sentDigest(target, value)
	if !ok {
		return
	}
	idDigest, _ := s.originDigest("server_id", target, value)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.mintBlockedLocked(session) {
		return
	}
	if _, reflectedAny := s.sentAll[sentDigest]; reflectedAny {
		return
	}
	if _, reflected := s.sent[session][sentDigest]; reflected {
		return
	}
	s.admitSessionLocked(session)
	issued := s.ids[session]
	for _, existing := range issued {
		if hmac.Equal(existing[:], idDigest[:]) {
			s.used[session] = now
			return
		}
	}
	if len(issued) >= issuerCookieMaxEntries {
		issued = issued[1:]
	}
	s.ids[session] = append(issued, idDigest)
	s.used[session] = now
}

// serverIDIssued reports whether the origin in target issued segment to the
// session as an ID.
func (s *issuerQueryStore) serverIDIssued(session string, target *url.URL, segment string) bool {
	if s == nil || s.disabled || session == "" || !issuerServerIDShaped(segment) {
		return false
	}
	digest, ok := s.originDigest("server_id", target, segment)
	if !ok {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.mintBlockedLocked(session) {
		return false
	}
	for _, existing := range s.ids[session] {
		if hmac.Equal(existing[:], digest[:]) {
			s.used[session] = time.Now()
			return true
		}
	}
	return false
}

// recordIssuerRequestSent records what an allowed request is about to send
// upstream. It runs before forwarding, so a response to a later request can
// never mint a value this request carried, even when the two overlap.
func recordIssuerRequestSent(ic *InterceptContext, r *http.Request, body []byte) {
	if ic == nil || r == nil || r.URL == nil {
		return
	}
	store := ic.issuerQueryStore()
	if store == nil {
		// A tunnel pinned to the pre-reload runtime still forwards. The live
		// store is the one later requests mint from, so the send is recorded
		// there instead of looking like the session never made it.
		store = ic.issuerQueryStoreIgnoringSnapshot()
	}
	if store == nil {
		return
	}
	bodyKnown := body != nil || r.Body == nil || r.Body == http.NoBody
	session := sessionKeyFor(ic.Config, ic.Agent, ic.ClientIP, ic.ActorAuth)
	store.recordSent(session, r.URL, r.Header, body, bodyKnown, time.Now())
}

// issuerQueryStoreIgnoringSnapshot returns the live query store when this
// request's pinned runtime no longer matches it. The feature check reads the
// live configuration, not the request's: a tunnel opened while the feature
// was off can still forward after a reload turns it on, and its sends must be
// recorded where later requests mint. An untrusted actor or a missing proxy
// still returns nil. The result is only ever used to record sends.
func (ic *InterceptContext) issuerQueryStoreIgnoringSnapshot() *issuerQueryStore {
	if ic == nil || ic.Proxy == nil || !ic.stateTrusted() {
		return nil
	}
	runtime := ic.Proxy.issuerCookieRuntime.Load()
	if runtime == nil || runtime.query == nil || runtime.query.disabled || !issuerCookieEnabled(runtime.cfg) {
		return nil
	}
	skewed := ic.IssuerRuntime != nil && ic.IssuerRuntime != runtime
	if ic.IssuerRuntime == nil && runtime.cfg != ic.Config {
		skewed = true
	}
	if !skewed {
		return nil
	}
	return runtime.query
}

// issuerStoreForUnmediatedSend returns the live issuer store whatever
// configuration snapshot the caller holds. A send that does not pass through
// TLS interception can still reach an origin the store holds IDs for, so it
// must be recorded or taint the session even when the snapshots differ.
func (p *Proxy) issuerStoreForUnmediatedSend() *issuerQueryStore {
	if p == nil {
		return nil
	}
	runtime := p.issuerCookieRuntime.Load()
	if runtime == nil {
		return nil
	}
	return runtime.query
}

// recordIssuerForwardSent records a plain-HTTP forward-proxy request as sent.
// A body Pipelock did not buffer stops minting for the session.
func (p *Proxy) recordIssuerForwardSent(cfg *config.Config, agent, clientIP string, actorAuth envelope.ActorAuth, r *http.Request, body []byte) {
	store := p.issuerStoreForUnmediatedSend()
	if store == nil || r == nil || r.URL == nil {
		return
	}
	bodyKnown := body != nil || r.Body == nil || r.Body == http.NoBody
	store.recordSent(sessionKeyFor(cfg, agent, clientIP, actorAuth), r.URL, r.Header, body, bodyKnown, time.Now())
}

// recordIssuerFetchSent records a /fetch request's URL as sent. It carries no
// body, so its tokens are complete.
func (p *Proxy) recordIssuerFetchSent(cfg *config.Config, agent, clientIP string, actorAuth envelope.ActorAuth, target *url.URL) {
	store := p.issuerStoreForUnmediatedSend()
	if store == nil || target == nil {
		return
	}
	store.recordSent(sessionKeyFor(cfg, agent, clientIP, actorAuth), target, nil, nil, true, time.Now())
}

// taintIssuerSessionForStream marks a session whose traffic now includes a
// stream Pipelock does not record token by token, such as WebSocket frames.
func (p *Proxy) taintIssuerSessionForStream(cfg *config.Config, agent, clientIP string, actorAuth envelope.ActorAuth) {
	store := p.issuerStoreForUnmediatedSend()
	if store == nil || store.disabled {
		return
	}
	session := sessionKeyFor(cfg, agent, clientIP, actorAuth)
	if session == "" {
		return
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	store.taintSentLocked(session)
}
