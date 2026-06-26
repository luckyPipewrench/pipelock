// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package broker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	defaultTurnstileVerifyURL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
	maxTurnstileTokenBytes    = 2048
	defaultSeenTokenTTL       = 5 * time.Minute
	defaultSeenTokenMax       = 10000
	// DefaultTurnstileMaxAge is the default maximum age for a Turnstile
	// challenge_ts before the verifier rejects it.
	DefaultTurnstileMaxAge = 5 * time.Minute
	// DefaultFailedTokenTTL bounds how long a just-failed token is fast-rejected
	// to dampen Siteverify retry amplification during provider trouble. It is
	// short so a genuinely valid token blocked by a transient upstream error can
	// be retried soon after.
	DefaultFailedTokenTTL = 30 * time.Second
)

// HumanVerifier validates a browser proof before the broker leases a VM.
type HumanVerifier interface {
	Verify(ctx context.Context, token, remoteIP string) error
}

// ErrTokenAlreadyUsed is returned when a Turnstile token has already been
// submitted, preventing a replay-race where two concurrent session requests
// use the same human-solve proof to lease two VMs.
var ErrTokenAlreadyUsed = errors.New("turnstile token already used")

// SeenTokens is a mutex-guarded set of recently verified Turnstile tokens.
// It prevents replay-race attacks where two concurrent requests submit the
// same token before the upstream Siteverify endpoint detects the duplicate.
// Expired entries are lazily evicted on insert, capping growth.
//
// Tokens are recorded ONLY after a successful upstream verification. A failed
// token does not poison the cache and cannot cause self-DoS by filling it with
// junk entries.
type SeenTokens struct {
	mu  sync.Mutex
	m   map[string]time.Time // token → expiry
	ttl time.Duration
	max int
	now func() time.Time
}

// NewSeenTokens creates a seen-token set. A zero ttl uses defaultSeenTokenTTL.
// The now function is injectable for deterministic tests; nil uses time.Now.
func NewSeenTokens(ttl time.Duration, now func() time.Time) *SeenTokens {
	if ttl <= 0 {
		ttl = defaultSeenTokenTTL
	}
	if now == nil {
		now = time.Now
	}
	return &SeenTokens{
		m:   make(map[string]time.Time),
		ttl: ttl,
		max: defaultSeenTokenMax,
		now: now,
	}
}

// IsSeen returns true if the token is in the cache and not expired.
func (s *SeenTokens) IsSeen(token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	exp, exists := s.m[token]
	return exists && now.Before(exp)
}

// MarkSeen records a token as consumed after a successful verification.
// Returns false if the cache is full (fail-closed).
func (s *SeenTokens) MarkSeen(token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()

	// Lazy eviction of expired entries to cap growth.
	for k, exp := range s.m {
		if !now.Before(exp) {
			delete(s.m, k)
		}
	}

	if len(s.m) >= s.max {
		return false
	}
	if exp, exists := s.m[token]; exists && now.Before(exp) {
		return false
	}
	s.m[token] = now.Add(s.ttl)
	return true
}

// CheckAndMark atomically checks whether a token has been seen. If not, it
// marks it and returns true (proceed). If already present and not expired, it
// returns false (reject). Expired entries for other tokens are lazily evicted.
//
// Deprecated: use IsSeen + MarkSeen for the post-verify record pattern.
// Retained for backward compatibility with tests that exercise the old API.
func (s *SeenTokens) CheckAndMark(token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()

	// Lazy eviction of expired entries to cap growth.
	for k, exp := range s.m {
		if !now.Before(exp) {
			delete(s.m, k)
		}
	}

	if exp, exists := s.m[token]; exists && now.Before(exp) {
		return false
	}
	if len(s.m) >= s.max {
		return false
	}
	s.m[token] = now.Add(s.ttl)
	return true
}

// ReplayGuardVerifier wraps a HumanVerifier with broker-side token replay
// prevention. A token is recorded as consumed ONLY after a successful
// upstream verification, so an attacker spraying invalid tokens cannot
// poison the cache and self-DoS legitimate users. Concurrent identical
// tokens are serialized by singleflight to prevent double-lease during the
// upstream network call.
type ReplayGuardVerifier struct {
	Inner HumanVerifier
	Seen  *SeenTokens
	// Failed, when non-nil, is a short-TTL negative cache of tokens whose
	// upstream verification just failed. It dampens Siteverify retry
	// amplification (a client resubmitting the same bad token during provider
	// trouble) without permanently poisoning the token: after the short TTL a
	// genuinely valid token can be retried.
	Failed *SeenTokens

	mu       sync.Mutex
	inflight map[string]chan struct{} // token → done channel
	waitHook func()                   // test hook called when a waiter observes an in-flight token
}

// Verify rejects already-seen tokens, deduplicates in-flight concurrent
// identical tokens, delegates to the inner verifier, and records successful
// tokens in the seen cache.
func (v *ReplayGuardVerifier) Verify(ctx context.Context, token, remoteIP string) error {
	trimmed := strings.TrimSpace(token)
	if trimmed == "" {
		return errors.New("turnstile token is required")
	}
	if len(trimmed) > maxTurnstileTokenBytes {
		return errors.New("turnstile token is too long")
	}

	// Serialize concurrent identical tokens so only one reaches the network.
	// The second concurrent caller waits for the first to finish, then checks
	// the seen cache: if the first succeeded the token is consumed and the
	// second is rejected, preserving the one-use invariant.
	for {
		// Reject already-verified (consumed) tokens.
		if v.Seen.IsSeen(trimmed) {
			return ErrTokenAlreadyUsed
		}

		// Fast-reject a token that just failed upstream, so a client resubmitting a
		// bad token during provider trouble does not amplify Siteverify calls.
		if v.Failed != nil && v.Failed.IsSeen(trimmed) {
			return errTurnstileRejected
		}

		v.mu.Lock()
		if v.inflight == nil {
			v.inflight = make(map[string]chan struct{})
		}
		if ch, ok := v.inflight[trimmed]; ok {
			waitHook := v.waitHook
			v.mu.Unlock()
			if waitHook != nil {
				waitHook()
			}
			// Another goroutine is verifying this token. Wait, then loop back
			// through the replay/negative-cache/inflight gates. If the leader
			// failed without populating Failed, exactly one waiter may become the
			// next leader; the rest keep waiting instead of all hitting upstream.
			select {
			case <-ch:
				continue
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		ch := make(chan struct{})
		v.inflight[trimmed] = ch
		v.mu.Unlock()
		defer func() {
			v.mu.Lock()
			delete(v.inflight, trimmed)
			close(ch)
			v.mu.Unlock()
		}()
		break
	}

	err := v.Inner.Verify(ctx, trimmed, remoteIP)
	if err != nil {
		// Failed verification: do NOT record in the (permanent) seen cache so the
		// token is not poisoned for a potentially valid future use. Record it in
		// the short-TTL negative cache to dampen immediate retry amplification.
		if v.Failed != nil {
			v.Failed.MarkSeen(trimmed)
		}
		return err
	}

	// Successful: record as consumed so replays are rejected.
	if !v.Seen.MarkSeen(trimmed) {
		// Cache full — fail closed to prevent replay.
		return ErrTokenAlreadyUsed
	}
	return nil
}

// TurnstileVerifier validates Cloudflare Turnstile tokens via Siteverify.
type TurnstileVerifier struct {
	Secret    string
	VerifyURL string
	Client    *http.Client

	// ExpectedHostname validates the Siteverify response hostname field.
	// When non-empty, the challenge must have been solved on this hostname.
	// Public deployments SHOULD set this to prevent cross-site token reuse.
	ExpectedHostname string

	// ExpectedAction validates the Siteverify response action field.
	// When non-empty, the challenge must carry this action label.
	// Public deployments SHOULD set this to prevent cross-form token reuse.
	ExpectedAction string

	// MaxAge rejects challenges solved more than this duration ago.
	// Zero disables freshness checking. Default: 5 minutes (set via flag).
	// When set, a missing or unparseable challenge_ts fails closed.
	MaxAge time.Duration

	// Now is an injectable clock for deterministic tests. Nil uses time.Now.
	Now func() time.Time
}

type turnstileResponse struct {
	Success     bool     `json:"success"`
	ErrorCodes  []string `json:"error-codes"`
	Hostname    string   `json:"hostname"`
	Action      string   `json:"action"`
	ChallengeTS string   `json:"challenge_ts"`
}

// errTurnstileRejected is the generic client-facing error for any post-success
// validation failure. The specific check that failed is intentionally NOT
// disclosed to prevent an attacker from iterating on hostname/action/timing.
var errTurnstileRejected = errors.New("turnstile rejected token")

func (v TurnstileVerifier) Verify(ctx context.Context, token, remoteIP string) error {
	trimmedSecret := strings.TrimSpace(v.Secret)
	if trimmedSecret == "" {
		return errors.New("turnstile secret is empty")
	}
	trimmedToken := strings.TrimSpace(token)
	if trimmedToken == "" {
		return errors.New("turnstile token is required")
	}
	if len(trimmedToken) > maxTurnstileTokenBytes {
		return errors.New("turnstile token is too long")
	}
	endpoint := strings.TrimSpace(v.VerifyURL)
	if endpoint == "" {
		endpoint = defaultTurnstileVerifyURL
	}
	client := v.Client
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	form := url.Values{
		"secret":   {trimmedSecret},
		"response": {trimmedToken},
	}
	if strings.TrimSpace(remoteIP) != "" {
		form.Set("remoteip", strings.TrimSpace(remoteIP))
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("build turnstile verify request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("verify turnstile token: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("verify turnstile token: status %d", resp.StatusCode)
	}
	var out turnstileResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64*1024)).Decode(&out); err != nil {
		return fmt.Errorf("decode turnstile response: %w", err)
	}
	if !out.Success {
		if len(out.ErrorCodes) > 0 {
			return fmt.Errorf("turnstile rejected token: %s", strings.Join(out.ErrorCodes, ","))
		}
		return errTurnstileRejected
	}

	// Post-success response validation: hostname, action, and freshness.
	// Fail closed with a generic error — never disclose which check failed.
	if v.ExpectedHostname != "" && !strings.EqualFold(out.Hostname, v.ExpectedHostname) {
		return errTurnstileRejected
	}
	if v.ExpectedAction != "" && out.Action != v.ExpectedAction {
		return errTurnstileRejected
	}
	if v.MaxAge > 0 {
		if out.ChallengeTS == "" {
			// Missing timestamp with freshness enforcement — fail closed.
			return errTurnstileRejected
		}
		ts, parseErr := time.Parse(time.RFC3339, out.ChallengeTS)
		if parseErr != nil {
			// Unparseable timestamp — fail closed.
			return errTurnstileRejected
		}
		now := v.Now
		if now == nil {
			now = time.Now
		}
		if now().Sub(ts) > v.MaxAge {
			return errTurnstileRejected
		}
	}

	return nil
}
