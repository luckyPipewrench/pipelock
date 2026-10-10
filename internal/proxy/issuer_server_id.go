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
	for i := 0; i <= len(text); i++ {
		if i < len(text) && issuerServerIDByte(text[i]) {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 {
			if run := text[start:i]; len(run) >= issuerServerIDMinLen {
				if !emit(run) {
					return false
				}
			}
			start = -1
		}
	}
	return true
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
	s.sentUnreadable[session] = true
	delete(s.ids, session)
}

// recordSent records every token a request carries to its origin: path
// segments, query keys and values, and the body, both raw and decoded. A
// body that was sent but not buffered, or a request over the bound, marks the
// session unreadable.
func (s *issuerQueryStore) recordSent(session string, target *url.URL, body []byte, bodyKnown bool, now time.Time) {
	if s == nil || s.disabled || session == "" || target == nil {
		return
	}
	if _, _, ok := issuerCookieOrigin(target); !ok {
		return
	}
	var texts []string
	texts = append(texts, target.EscapedPath(), target.Path, target.RawQuery)
	if decoded, err := url.QueryUnescape(target.RawQuery); err == nil {
		texts = append(texts, decoded)
	}
	for key, values := range target.Query() {
		texts = append(texts, key)
		texts = append(texts, values...)
	}
	if len(body) > 0 {
		raw := string(body)
		texts = append(texts, raw)
		if decoded, err := url.QueryUnescape(raw); err == nil {
			texts = append(texts, decoded)
		}
		texts = appendJSONStrings(texts, body)
	}

	var digests [][32]byte
	overflow := false
	for _, text := range texts {
		complete := issuerSentTokens(text, func(token string) bool {
			if len(digests) >= issuerSentMaxTokensPerRequest {
				overflow = true
				return false
			}
			if digest, ok := s.originDigest("sent", target, token); ok {
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
	sentDigest, ok := s.originDigest("sent", target, value)
	if !ok {
		return
	}
	idDigest, _ := s.originDigest("server_id", target, value)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sentUnreadable[session] {
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
	if s.sentUnreadable[session] {
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
		return
	}
	bodyKnown := body != nil || r.Body == nil || r.Body == http.NoBody || r.ContentLength == 0
	session := sessionKeyFor(ic.Config, ic.Agent, ic.ClientIP, ic.ActorAuth)
	store.recordSent(session, r.URL, body, bodyKnown, time.Now())
}
