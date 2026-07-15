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

	"github.com/luckyPipewrench/pipelock/internal/contract"
	"github.com/luckyPipewrench/pipelock/internal/proxy"
)

// Default timeout for admin API calls. Admin API operations are
// lightweight (no bodies beyond tier transitions) so a short timeout
// keeps the CLI snappy when the server is unreachable.
const (
	defaultClientTimeout   = 10 * time.Second
	maxClientResponseBytes = 1 << 20
)

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
// `http://host:9090` produce identical admin API request paths - leaving
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

func (c *Client) AdaptiveStatus(ctx context.Context) (proxy.AdaptiveStatus, error) {
	target := c.base + "/api/v1/adaptive/status"
	var resp proxy.AdaptiveStatus
	if err := c.do(ctx, http.MethodGet, target, nil, &resp); err != nil {
		return proxy.AdaptiveStatus{}, err
	}
	return resp, nil
}

func (c *Client) AdaptiveFlush(ctx context.Context) (proxy.AdaptiveFlushResult, error) {
	target := c.base + "/api/v1/adaptive/flush"
	var resp proxy.AdaptiveFlushResult
	if err := c.do(ctx, http.MethodPost, target, nil, &resp); err != nil {
		return proxy.AdaptiveFlushResult{}, err
	}
	return resp, nil
}

func (c *Client) AdaptiveWhoami(ctx context.Context) (proxy.AdaptiveWhoami, error) {
	target := c.base + "/api/v1/adaptive/whoami"
	var resp proxy.AdaptiveWhoami
	if err := c.do(ctx, http.MethodGet, target, nil, &resp); err != nil {
		return proxy.AdaptiveWhoami{}, err
	}
	return resp, nil
}

func (c *Client) BaselineList(ctx context.Context) (proxy.BaselineListResponse, error) {
	target := c.base + "/api/v1/baseline"
	var resp proxy.BaselineListResponse
	if err := c.do(ctx, http.MethodGet, target, nil, &resp); err != nil {
		return proxy.BaselineListResponse{}, err
	}
	return resp, nil
}

func (c *Client) BaselineShow(ctx context.Context, agent string) (proxy.BaselineProfile, error) {
	target := c.base + "/api/v1/baseline/" + url.PathEscape(agent)
	var resp proxy.BaselineProfile
	if err := c.do(ctx, http.MethodGet, target, nil, &resp); err != nil {
		return proxy.BaselineProfile{}, err
	}
	return resp, nil
}

func (c *Client) BaselineRatify(ctx context.Context, agent string) (proxy.BaselineRatifyResult, error) {
	target := c.base + "/api/v1/baseline/" + url.PathEscape(agent) + "/ratify"
	var resp proxy.BaselineRatifyResult
	if err := c.do(ctx, http.MethodPost, target, nil, &resp); err != nil {
		return proxy.BaselineRatifyResult{}, err
	}
	return resp, nil
}

func (c *Client) BaselineForget(ctx context.Context, agent string) (proxy.BaselineForgetResult, error) {
	target := c.base + "/api/v1/baseline/" + url.PathEscape(agent) + "/forget"
	var resp proxy.BaselineForgetResult
	if err := c.do(ctx, http.MethodPost, target, nil, &resp); err != nil {
		return proxy.BaselineForgetResult{}, err
	}
	return resp, nil
}

// DeferredList fetches the pending held (deferred) actions from the operator
// admin API.
func (c *Client) DeferredList(ctx context.Context) (proxy.DeferredListResponse, error) {
	target := c.base + "/api/v1/deferred"
	var resp proxy.DeferredListResponse
	if err := c.do(ctx, http.MethodGet, target, nil, &resp); err != nil {
		return proxy.DeferredListResponse{}, err
	}
	return resp, nil
}

// DeferredApprove approves a held action by defer id. The action only opens if
// its rule permits approval; otherwise the server resolves it closed and the
// returned FinalDecision reports the actual (block) outcome.
func (c *Client) DeferredApprove(ctx context.Context, deferID string) (proxy.DeferredResolveResult, error) {
	return c.deferredResolve(ctx, deferID, "approve")
}

// DeferredDeny denies a held action by defer id, resolving it closed (blocked).
func (c *Client) DeferredDeny(ctx context.Context, deferID string) (proxy.DeferredResolveResult, error) {
	return c.deferredResolve(ctx, deferID, "deny")
}

func (c *Client) deferredResolve(ctx context.Context, deferID, action string) (proxy.DeferredResolveResult, error) {
	target := c.base + "/api/v1/deferred/" + url.PathEscape(deferID) + "/" + action
	var resp proxy.DeferredResolveResult
	if err := c.do(ctx, http.MethodPost, target, nil, &resp); err != nil {
		return proxy.DeferredResolveResult{}, err
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
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxClientResponseBytes+1))
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if len(raw) > maxClientResponseBytes {
		return fmt.Errorf("response exceeds %d bytes", maxClientResponseBytes)
	}
	if err := contract.DecodeStrictJSON(raw, out); err != nil {
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

// errorPath returns just the request path (plus raw query) for display.
// The scheme and host are stripped so error strings never leak where the
// admin API is actually running - operators often paste error output into
// tickets, chat, or logs that are less trusted than the endpoint itself.
// Falls back to the raw URL when url.Parse cannot recover a Path (which
// should not happen in practice, since the client always constructs
// target URLs from a validated base, but keeps the error useful in the
// degenerate case instead of returning an empty string).
func (e *APIError) errorPath() string {
	if e.URL == "" {
		return ""
	}
	parsed, err := url.Parse(e.URL)
	if err != nil || parsed.Path == "" {
		return e.URL
	}
	path := parsed.Path
	if parsed.RawQuery != "" {
		path += "?" + parsed.RawQuery
	}
	return path
}

func (e *APIError) Error() string {
	display := e.errorPath()
	if e.RetryAfter != "" {
		return fmt.Sprintf("%s %s: HTTP %d (Retry-After: %s): %s", e.Method, display, e.StatusCode, e.RetryAfter, e.Body)
	}
	return fmt.Sprintf("%s %s: HTTP %d: %s", e.Method, display, e.StatusCode, e.Body)
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
