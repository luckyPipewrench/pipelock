// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/proxy"
)

// Default timeout for admin API calls. Admin API operations are
// lightweight (no bodies beyond tier transitions) so a short timeout
// keeps the CLI snappy when the server is unreachable.
const defaultClientTimeout = 10 * time.Second

// httpClientInterface is the subset of *http.Client the session client
// actually uses. Extracted so tests can substitute an httptest round-
// tripper or a fake with no network.
type httpClientInterface interface {
	Do(req *http.Request) (*http.Response, error)
}

// Client is the thin HTTP client wrapping the admin API. It holds the
// resolved endpoint (URL + bearer token) and a *http.Client with a
// default timeout. Callers create one per command invocation via
// newClient and discard it when done.
type Client struct {
	base  string
	token string
	http  httpClientInterface
}

// newClient builds a session admin API client from the resolved endpoint
// with the default http.Client timeout. Use newClientWithHTTP when a
// test needs to inject a custom round tripper.
func newClient(ep endpoint) *Client {
	return newClientWithHTTP(ep, &http.Client{Timeout: defaultClientTimeout})
}

// newClientWithHTTP builds a session admin API client with an explicit
// httpClientInterface. Tests use this to inject an httptest-backed
// round tripper or a stub that records the calls it receives. Trailing
// slashes on the base URL are stripped so `http://host:9090/` and
// `http://host:9090` produce identical admin API request paths — leaving
// them in would route `/api/v1/sessions` to `//api/v1/sessions` which
// the admin router does not recognize.
func newClientWithHTTP(ep endpoint, c httpClientInterface) *Client {
	return &Client{
		base:  strings.TrimRight(ep.URL, "/"),
		token: ep.Token,
		http:  c,
	}
}

// listResponse mirrors the server-side anonymous struct returned by
// HandleList so callers can decode into a typed value.
type listResponse struct {
	Sessions []proxy.SessionSnapshot `json:"sessions"`
	Count    int                     `json:"count"`
}

// airlockResponse mirrors the server-side airlockResponse struct. Kept
// local so this package does not import unexported proxy types.
type airlockResponse struct {
	Key          string `json:"key"`
	PreviousTier string `json:"previous_tier"`
	NewTier      string `json:"new_tier"`
	Changed      bool   `json:"changed"`
}

// List fetches /api/v1/sessions. When tier is non-empty, it is passed as
// a ?tier= query parameter and the server filters the results.
func (c *Client) List(ctx context.Context, tier string) (listResponse, error) {
	target := c.base + "/api/v1/sessions"
	if tier != "" {
		target += "?tier=" + url.QueryEscape(tier)
	}
	var resp listResponse
	if err := c.do(ctx, http.MethodGet, target, nil, &resp); err != nil {
		return listResponse{}, err
	}
	return resp, nil
}

// Inspect fetches /api/v1/sessions/{key} and decodes the SessionDetail.
func (c *Client) Inspect(ctx context.Context, key string) (proxy.SessionDetail, error) {
	target := c.base + "/api/v1/sessions/" + url.PathEscape(key)
	var detail proxy.SessionDetail
	if err := c.do(ctx, http.MethodGet, target, nil, &detail); err != nil {
		return proxy.SessionDetail{}, err
	}
	return detail, nil
}

// Explain fetches /api/v1/sessions/{key}/explain.
func (c *Client) Explain(ctx context.Context, key string) (proxy.SessionExplanation, error) {
	target := c.base + "/api/v1/sessions/" + url.PathEscape(key) + "/explain"
	var exp proxy.SessionExplanation
	if err := c.do(ctx, http.MethodGet, target, nil, &exp); err != nil {
		return proxy.SessionExplanation{}, err
	}
	return exp, nil
}

// Release posts /api/v1/sessions/{key}/airlock with the target tier so
// ForceSetTier drops the session into that tier. Operators use this to
// recover soft-quarantined sessions once the incident is resolved.
func (c *Client) Release(ctx context.Context, key, tier string) (airlockResponse, error) {
	target := c.base + "/api/v1/sessions/" + url.PathEscape(key) + "/airlock"
	body, err := json.Marshal(map[string]string{"tier": tier})
	if err != nil {
		return airlockResponse{}, fmt.Errorf("marshal release body: %w", err)
	}
	var resp airlockResponse
	if err := c.do(ctx, http.MethodPost, target, bytes.NewReader(body), &resp); err != nil {
		return airlockResponse{}, err
	}
	return resp, nil
}

// Terminate posts /api/v1/sessions/{key}/terminate.
func (c *Client) Terminate(ctx context.Context, key string) (proxy.SessionTerminateResult, error) {
	target := c.base + "/api/v1/sessions/" + url.PathEscape(key) + "/terminate"
	var resp proxy.SessionTerminateResult
	if err := c.do(ctx, http.MethodPost, target, nil, &resp); err != nil {
		return proxy.SessionTerminateResult{}, err
	}
	return resp, nil
}

// do performs the HTTP call with bearer auth, decodes the JSON response
// into out, and returns a typed APIError for non-2xx statuses so the
// caller can map each class to a distinct exit code.
func (c *Client) do(ctx context.Context, method, target string, body io.Reader, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("request %s %s: %w", method, target, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		apiErr := &APIError{
			Method:     method,
			URL:        target,
			StatusCode: resp.StatusCode,
			RetryAfter: resp.Header.Get("Retry-After"),
		}
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
		apiErr.Body = string(bytes.TrimSpace(raw))
		return apiErr
	}

	if out == nil {
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		if errors.Is(err, io.EOF) {
			// Empty body on 200 is acceptable when the caller didn't
			// request a typed value — do returns above when out is nil.
			return fmt.Errorf("empty response body from %s %s", method, target)
		}
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

// APIError is returned for any non-2xx admin API response. Carries the
// HTTP status, Retry-After header (when present), and the response body
// so the caller can propagate the server's error message back to the
// operator without guessing at shape.
type APIError struct {
	Method     string
	URL        string
	StatusCode int
	RetryAfter string
	Body       string
}

func (e *APIError) Error() string {
	if e.RetryAfter != "" {
		return fmt.Sprintf("%s %s: HTTP %d (Retry-After: %s): %s", e.Method, e.URL, e.StatusCode, e.RetryAfter, e.Body)
	}
	return fmt.Sprintf("%s %s: HTTP %d: %s", e.Method, e.URL, e.StatusCode, e.Body)
}

// IsNotFound reports whether err is an APIError with 404 status.
func IsNotFound(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusNotFound
}

// IsUnauthorized reports whether err is an APIError with 401 status.
func IsUnauthorized(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusUnauthorized
}

// IsRateLimited reports whether err is an APIError with 429 status.
func IsRateLimited(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusTooManyRequests
}
