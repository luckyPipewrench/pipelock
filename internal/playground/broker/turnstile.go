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
	"time"
)

const (
	defaultTurnstileVerifyURL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
	maxTurnstileTokenBytes    = 2048
)

// HumanVerifier validates a browser proof before the broker leases a VM.
type HumanVerifier interface {
	Verify(ctx context.Context, token, remoteIP string) error
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
	token = strings.TrimSpace(token)
	if token == "" {
		return errors.New("turnstile token is required")
	}
	if len(token) > maxTurnstileTokenBytes {
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
		"response": {token},
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
