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
)

// HumanVerifier validates a browser proof before the broker leases a VM.
type HumanVerifier interface {
	Verify(ctx context.Context, token, remoteIP string) error
}

// ErrTokenAlreadyUsed is returned when a Turnstile token has already been
// submitted, preventing a replay-race where two concurrent session requests
// use the same human-solve proof to lease two VMs.
var ErrTokenAlreadyUsed = errors.New("turnstile token already used")

// SeenTokens is a mutex-guarded set of recently submitted Turnstile tokens.
// It prevents replay-race attacks where two concurrent requests submit the
// same token before the upstream Siteverify endpoint detects the duplicate.
// Expired entries are lazily evicted on insert, capping growth.
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

// CheckAndMark atomically checks whether a token has been seen. If not, it
// marks it and returns true (proceed). If already present and not expired, it
// returns false (reject). Expired entries for other tokens are lazily evicted.
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
// prevention. The seen-token check runs BEFORE the upstream Siteverify call,
// so a replayed token never reaches the network.
type ReplayGuardVerifier struct {
	Inner HumanVerifier
	Seen  *SeenTokens
}

// Verify rejects already-seen tokens before delegating to the inner verifier.
func (v *ReplayGuardVerifier) Verify(ctx context.Context, token, remoteIP string) error {
	trimmed := strings.TrimSpace(token)
	if trimmed == "" {
		return errors.New("turnstile token is required")
	}
	if len(trimmed) > maxTurnstileTokenBytes {
		return errors.New("turnstile token is too long")
	}
	if !v.Seen.CheckAndMark(trimmed) {
		return ErrTokenAlreadyUsed
	}
	return v.Inner.Verify(ctx, trimmed, remoteIP)
}

// TurnstileVerifier validates Cloudflare Turnstile tokens via Siteverify.
type TurnstileVerifier struct {
	Secret    string
	VerifyURL string
	Client    *http.Client
}

type turnstileResponse struct {
	Success    bool     `json:"success"`
	ErrorCodes []string `json:"error-codes"`
}

func (v TurnstileVerifier) Verify(ctx context.Context, token, remoteIP string) error {
	secret := strings.TrimSpace(v.Secret)
	if secret == "" {
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
		"secret":   {secret},
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
		return errors.New("turnstile rejected token")
	}
	return nil
}
