// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package livechat holds the transport-agnostic access and abuse controls for
// the public "live chat" playground: an invite-code gate, fail-closed safety
// limits (rate, concurrency, time, size), and the HTTP/SSE server that wires
// them to a contained live run.
//
// Everything here is fail-closed by construction: no token, no session; over
// any cap, refuse rather than run unbounded compute; if a control cannot be
// established, deny. The package deliberately holds NO agent secrets — it only
// gates who may start a contained demo session.
package livechat

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Gate errors. Every one results in a refused session — the gate never fails
// open. They are distinguished so the server can return the right status code
// and audit reason without leaking which code (if any) was tried.
var (
	// ErrGateClosed means the gate cannot issue sessions at all: it has no
	// signing secret or no invite codes configured. The default state of an
	// unconfigured gate is closed, not open.
	ErrGateClosed = errors.New("livechat: gate closed (no secret or no codes configured)")
	// ErrUnknownCode is returned when a presented invite code is not registered.
	ErrUnknownCode = errors.New("livechat: unknown invite code")
	// ErrCodeExhausted is returned when a code's session budget is used up.
	ErrCodeExhausted = errors.New("livechat: invite code exhausted")
	// ErrTokenMalformed is returned when a session token cannot be parsed.
	ErrTokenMalformed = errors.New("livechat: malformed session token")
	// ErrBadSignature is returned when a token's HMAC does not verify.
	ErrBadSignature = errors.New("livechat: invalid session token signature")
	// ErrTokenExpired is returned when a token is past its expiry.
	ErrTokenExpired = errors.New("livechat: session token expired")
)

// minSecretLen is the minimum acceptable signing-secret length. 32 bytes is the
// output size of SHA-256 / one HMAC-SHA256 block half; shorter secrets weaken
// the token MAC.
const minSecretLen = 32

// minTokenTTL / maxTokenTTL bound the session-token lifetime. Tokens are
// short-lived bearer credentials; an excessively long TTL widens the replay
// window, and a zero/negative TTL would mint already-dead tokens.
const (
	minTokenTTL = 30 * time.Second
	maxTokenTTL = 30 * time.Minute
)

// SessionClaims is the verified content of a session token. It binds a session
// to the code that minted it (by opaque id, never the code itself) and to a
// validity window.
type SessionClaims struct {
	SessionID string    `json:"sid"`
	CodeID    string    `json:"cid"`
	IssuedAt  time.Time `json:"iat"`
	ExpiresAt time.Time `json:"exp"`
}

// CodeSpec registers one invite code with the gate.
type CodeSpec struct {
	// Code is the secret string handed to an attendee. It is never stored in
	// the clear; the gate keys on its SHA-256.
	Code string
	// ID is a non-secret label for the code, surfaced in claims and audit. If
	// empty, a short hash-derived id is used.
	ID string
	// MaxSessions caps how many sessions this code may mint. A value <= 0 means
	// unlimited — a deliberate operator choice; the server is expected to pass a
	// finite cap for public exposure.
	MaxSessions int
}

// GateConfig configures a Gate.
type GateConfig struct {
	// Secret signs session tokens. Must be at least minSecretLen bytes.
	Secret []byte
	// Codes are the registered invite codes. An empty set means the gate is
	// closed (fail-closed).
	Codes []CodeSpec
	// TokenTTL is the session-token lifetime. Clamped to [minTokenTTL, maxTokenTTL].
	TokenTTL time.Duration
	// Now overrides the clock for tests. Defaults to time.Now.
	Now func() time.Time
}

type codeState struct {
	id        string
	maxIssued int // <= 0 means unlimited
	issued    int
}

// Gate validates invite codes and issues/verifies short-lived session tokens.
// It is safe for concurrent use.
type Gate struct {
	secret []byte
	ttl    time.Duration
	now    func() time.Time

	mu          sync.Mutex
	codes       map[[32]byte]*codeState
	redemptions map[string]*codeState
}

// NewGate builds a Gate. It returns an error (so the caller fails closed at
// startup) when the secret is too short. A gate with zero codes is constructed
// successfully but is "closed": every Redeem returns ErrGateClosed.
func NewGate(cfg GateConfig) (*Gate, error) {
	if len(cfg.Secret) < minSecretLen {
		return nil, fmt.Errorf("livechat: gate secret must be >= %d bytes, got %d", minSecretLen, len(cfg.Secret))
	}
	ttl := cfg.TokenTTL
	if ttl < minTokenTTL {
		ttl = minTokenTTL
	}
	if ttl > maxTokenTTL {
		ttl = maxTokenTTL
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	g := &Gate{
		secret:      append([]byte(nil), cfg.Secret...),
		ttl:         ttl,
		now:         now,
		codes:       make(map[[32]byte]*codeState, len(cfg.Codes)),
		redemptions: make(map[string]*codeState),
	}
	for _, c := range cfg.Codes {
		if c.Code == "" {
			continue // a blank code is ignored, never a wildcard
		}
		sum := sha256.Sum256([]byte(c.Code))
		id := c.ID
		if id == "" {
			id = defaultCodeID(g.secret, c.Code)
		}
		g.codes[sum] = &codeState{id: id, maxIssued: c.MaxSessions}
	}
	return g, nil
}

func defaultCodeID(secret []byte, code string) string {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte("pipelock-livechat-code-id\x00"))
	m.Write([]byte(code))
	sum := m.Sum(nil)
	return "code-" + base64.RawURLEncoding.EncodeToString(sum[:9])
}

// Open reports whether the gate can currently mint any session (has at least
// one configured code). Used for readiness/diagnostics, not as an auth check.
func (g *Gate) Open() bool {
	if g == nil {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.codes) > 0
}

// Redeem validates an invite code and, on success, mints a signed session
// token. It enforces the per-code session budget atomically. Fail-closed: any
// problem returns an error and no token.
func (g *Gate) Redeem(code, sessionID string) (token string, claims SessionClaims, err error) {
	if g == nil {
		return "", SessionClaims{}, ErrGateClosed
	}
	sum := sha256.Sum256([]byte(code))

	g.mu.Lock()
	if len(g.codes) == 0 {
		g.mu.Unlock()
		return "", SessionClaims{}, ErrGateClosed
	}
	st, ok := g.codes[sum]
	if !ok {
		g.mu.Unlock()
		return "", SessionClaims{}, ErrUnknownCode
	}
	if st.maxIssued > 0 && st.issued >= st.maxIssued {
		g.mu.Unlock()
		return "", SessionClaims{}, ErrCodeExhausted
	}
	st.issued++
	codeID := st.id
	g.mu.Unlock()

	now := g.now().UTC()
	claims = SessionClaims{
		SessionID: sessionID,
		CodeID:    codeID,
		IssuedAt:  now,
		ExpiresAt: now.Add(g.ttl),
	}
	token, err = g.sign(claims)
	if err != nil {
		// Refund the budget: the session never started.
		g.mu.Lock()
		if st.issued > 0 {
			st.issued--
		}
		g.mu.Unlock()
		return "", SessionClaims{}, err
	}
	g.mu.Lock()
	if sessionID != "" {
		g.redemptions[sessionID] = st
	}
	g.mu.Unlock()
	return token, claims, nil
}

// Commit marks a redeemed token as having started a real session. After this
// point the invite budget is intentionally consumed. It is safe to call more
// than once.
func (g *Gate) Commit(claims SessionClaims) {
	if g == nil || claims.SessionID == "" {
		return
	}
	g.mu.Lock()
	delete(g.redemptions, claims.SessionID)
	g.mu.Unlock()
}

// Refund returns a just-redeemed session to its invite-code budget when the
// server refuses before a live session is installed. It is idempotent: only a
// redemption still tracked by this gate can be refunded.
func (g *Gate) Refund(claims SessionClaims) {
	if g == nil || claims.SessionID == "" {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	st := g.redemptions[claims.SessionID]
	if st == nil {
		return
	}
	if st.issued > 0 {
		st.issued--
	}
	delete(g.redemptions, claims.SessionID)
}

// Validate parses and verifies a session token, returning its claims. It checks
// the HMAC in constant time and rejects expired tokens. Fail-closed on any
// error.
func (g *Gate) Validate(token string) (SessionClaims, error) {
	if g == nil {
		return SessionClaims{}, ErrGateClosed
	}
	payloadB64, sigB64, ok := splitToken(token)
	if !ok {
		return SessionClaims{}, ErrTokenMalformed
	}
	payload, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return SessionClaims{}, ErrTokenMalformed
	}
	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return SessionClaims{}, ErrTokenMalformed
	}
	want := g.mac([]byte(payloadB64))
	if subtle.ConstantTimeCompare(sig, want) != 1 {
		return SessionClaims{}, ErrBadSignature
	}
	var claims SessionClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return SessionClaims{}, ErrTokenMalformed
	}
	if claims.SessionID == "" || claims.ExpiresAt.IsZero() {
		return SessionClaims{}, ErrTokenMalformed
	}
	if !g.now().UTC().Before(claims.ExpiresAt) {
		return SessionClaims{}, ErrTokenExpired
	}
	return claims, nil
}

func (g *Gate) sign(claims SessionClaims) (string, error) {
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("livechat: marshal claims: %w", err)
	}
	payloadB64 := base64.RawURLEncoding.EncodeToString(payload)
	sig := g.mac([]byte(payloadB64))
	return payloadB64 + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func (g *Gate) mac(msg []byte) []byte {
	m := hmac.New(sha256.New, g.secret)
	m.Write(msg)
	return m.Sum(nil)
}

// splitToken splits "payload.sig" on the single separating dot. It rejects
// tokens without exactly one dot.
func splitToken(token string) (payload, sig string, ok bool) {
	dot := -1
	for i := 0; i < len(token); i++ {
		if token[i] == '.' {
			if dot != -1 {
				return "", "", false // more than one dot
			}
			dot = i
		}
	}
	if dot <= 0 || dot >= len(token)-1 {
		return "", "", false
	}
	return token[:dot], token[dot+1:], true
}

// NewRandomCode returns a URL-safe random invite code with the given number of
// random bytes (a typical 18 yields a 24-char code). Used by the server to mint
// codes when the operator does not supply their own.
func NewRandomCode(nBytes int) (string, error) {
	if nBytes < 8 {
		nBytes = 8
	}
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("livechat: generate code: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// NewSecret returns a fresh random gate-signing secret of minSecretLen bytes.
func NewSecret() ([]byte, error) {
	b := make([]byte, minSecretLen)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("livechat: generate secret: %w", err)
	}
	return b, nil
}
