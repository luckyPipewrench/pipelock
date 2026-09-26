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
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

const issuerQueryReceiptExtensionKey = "entropy_issuer_query_allow"

type issuerQueryEntry struct {
	digest [32]byte
}

type issuerQueryStore struct {
	mu       sync.Mutex
	key      [32]byte
	sessions map[string][]issuerQueryEntry
	used     map[string]time.Time
	disabled bool
}

func newIssuerQueryStore() *issuerQueryStore {
	return newIssuerQueryStoreWithReader(rand.Reader)
}

func newIssuerQueryStoreWithReader(reader io.Reader) *issuerQueryStore {
	s := &issuerQueryStore{sessions: make(map[string][]issuerQueryEntry), used: make(map[string]time.Time)}
	if _, err := io.ReadFull(reader, s.key[:]); err != nil {
		s.disabled = true
	}
	return s
}

func (ic *InterceptContext) issuerQueryStore() *issuerQueryStore {
	if ic == nil || ic.Proxy == nil || !issuerCookieEnabled(ic.Config) || !ic.ActorAuth.TrustedForIdentity() {
		return nil
	}
	runtime := ic.Proxy.issuerCookieRuntime.Load()
	if runtime == nil || (ic.IssuerRuntime != nil && ic.IssuerRuntime != runtime) ||
		(ic.IssuerRuntime == nil && runtime.cfg != ic.Config) {
		return nil
	}
	return runtime.query
}

func (s *issuerQueryStore) digest(host, port, path, name, value string) [32]byte {
	// Each field is written as its byte length then its raw bytes, so the
	// tuple is unambiguous and byte-exact: no field boundary can be forged,
	// and invalid UTF-8 is hashed as-is rather than normalized.
	mac := hmac.New(sha256.New, s.key[:])
	var size [8]byte
	for _, field := range [...]string{host, port, path, name, value} {
		binary.BigEndian.PutUint64(size[:], uint64(len(field)))
		_, _ = mac.Write(size[:])
		_, _ = mac.Write([]byte(field))
	}
	var out [32]byte
	copy(out[:], mac.Sum(nil))
	return out
}

func (s *issuerQueryStore) remember(session string, target *url.URL, name, value string, now time.Time) {
	if s == nil || s.disabled || session == "" || len(name)+len(value) > issuerCookieMaxPairBytes {
		return
	}
	host, port, ok := issuerCookieOrigin(target)
	if !ok {
		return
	}
	path := target.EscapedPath()
	if path == "" {
		path = "/"
	}
	digest := s.digest(host, port, path, name, value)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.sessions[session]; !exists && len(s.sessions) >= issuerCookieMaxSessions {
		var oldest string
		for id, used := range s.used {
			if oldest == "" || used.Before(s.used[oldest]) {
				oldest = id
			}
		}
		delete(s.sessions, oldest)
		delete(s.used, oldest)
	}
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
	s.sessions[session] = append(entries, issuerQueryEntry{digest: digest})
	s.used[session] = now
}

func (s *issuerQueryStore) allows(session string, target *url.URL, name, value string) bool {
	if s == nil || s.disabled || session == "" || len(name)+len(value) > issuerCookieMaxPairBytes {
		return false
	}
	host, port, ok := issuerCookieOrigin(target)
	if !ok {
		return false
	}
	path := target.EscapedPath()
	if path == "" {
		path = "/"
	}
	digest := s.digest(host, port, path, name, value)
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, entry := range s.sessions[session] {
		if hmac.Equal(entry.digest[:], digest[:]) {
			s.used[session] = time.Now()
			return true
		}
	}
	return false
}

// issuerQueryMaxDepth bounds JSON nesting walked for issued links; the
// earlier tree walk stopped at the same depth.
const issuerQueryMaxDepth = 33

func recordDeliveredIssuerQuery(ic *InterceptContext, response *http.Response, body []byte, delivered bool) {
	if !delivered || ic == nil || response == nil || response.Request == nil || response.Request.URL == nil || len(body) == 0 {
		return
	}
	store := ic.issuerQueryStore()
	if store == nil {
		return
	}
	mediaType := strings.ToLower(strings.TrimSpace(strings.Split(response.Header.Get("Content-Type"), ";")[0]))
	if mediaType != "application/json" && !strings.HasSuffix(mediaType, "+json") {
		return
	}
	issuerHost, issuerPort, ok := issuerCookieOrigin(response.Request.URL)
	if !ok {
		return
	}
	// Walk the JSON as a token stream rather than decoding it into generic
	// maps and slices, which would cost several times the body size on every
	// intercepted JSON response. json.Valid keeps the old rule that a body
	// which is not valid JSON issues nothing.
	if !json.Valid(body) {
		return
	}
	session := sessionKeyFor(ic.Agent, ic.ClientIP, ic.ActorAuth)
	remaining := issuerCookieMaxSetCookies
	observe := func(value string) {
		candidate, err := url.Parse(value)
		if err != nil || candidate.RawQuery == "" {
			return
		}
		if !candidate.IsAbs() {
			// Resolve any relative reference ("/x?a", "x?a", "?a") against the
			// response URL; the origin check below then rejects anything that
			// resolved to another host, including a "//host" reference.
			candidate = response.Request.URL.ResolveReference(candidate)
		}
		host, port, valid := issuerCookieOrigin(candidate)
		if !valid || host != issuerHost || port != issuerPort {
			return
		}
		for name, values := range candidate.Query() {
			for _, queryValue := range values {
				if remaining == 0 {
					return
				}
				store.remember(session, candidate, name, queryValue, time.Now())
				remaining--
			}
		}
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
			observe(t)
			valueDone()
		default:
			valueDone()
		}
	}
}

func (p *Proxy) recordIssuerQueryAllow(ctx audit.LogContext, target, requestID, agent, method string) {
	if p == nil {
		return
	}
	parsed, err := url.Parse(target)
	if err != nil {
		return
	}
	if p.logger != nil {
		p.logger.LogIssuerQueryAllow(ctx, strings.ToLower(parsed.Hostname()))
	}
	safeTarget := parsed.Scheme + "://" + parsed.Host + parsed.EscapedPath()
	extension := []byte(`{"entropy_issuer_query_allow":"observed_issuer"}`)
	p.emitCredentialAudienceReceipt(receipt.EmitOpts{
		ActionID: receipt.NewActionID(), Verdict: config.ActionAllow,
		Layer: issuerQueryReceiptExtensionKey, Pattern: issuerQueryReceiptExtensionKey,
		Transport: "intercept", Method: method, Target: safeTarget,
		RequestID: requestID, Agent: agent, Extension: extension,
	})
}
