// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanapi

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/policy"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// Scan kind identifiers accepted by the API.
const (
	KindURL             = "url"
	KindDLP             = "dlp"
	KindPromptInjection = "prompt_injection"
	KindToolCall        = "tool_call"
)

// Decision values returned in the response.
const (
	DecisionAllow = "allow"
	DecisionDeny  = "deny"
)

// Status values returned in the response.
const (
	StatusCompleted = "completed"
	StatusError     = "error"
)

// validKinds defines the accepted scan kind values.
var validKinds = map[string]bool{
	KindURL:             true,
	KindDLP:             true,
	KindPromptInjection: true,
	KindToolCall:        true,
}

// Default limits applied when config values are zero.
const (
	defaultMaxBody        int64 = 1 << 20 // 1MB
	defaultRPM                  = 600
	defaultBurst                = 50
	defaultScanTimeout          = 5 * time.Second
	defaultURLLimit             = 8192
	defaultTextLimit            = 512 * 1024 // 512KB
	defaultContentLimit         = 512 * 1024
	defaultArgumentsLimit       = 512 * 1024
)

// Handler serves POST /api/v1/scan requests.
type Handler struct {
	cfg          *config.Config
	scanner      *scanner.Scanner
	policyCfg    *policy.Config
	metrics      *metrics.Metrics
	version      string
	killSwitchFn func() bool // returns true when kill switch is active

	// Per-token rate limiters.
	mu       sync.Mutex
	limiters map[string]*rate.Limiter
}

// NewHandler creates a Scan API handler.
func NewHandler(
	cfg *config.Config,
	sc *scanner.Scanner,
	policyCfg *policy.Config,
	m *metrics.Metrics,
	version string,
) *Handler {
	return &Handler{
		cfg:       cfg,
		scanner:   sc,
		policyCfg: policyCfg,
		metrics:   m,
		version:   version,
		limiters:  make(map[string]*rate.Limiter),
	}
}

// SetKillSwitchFn sets the function that checks kill switch state.
func (h *Handler) SetKillSwitchFn(fn func() bool) {
	h.killSwitchFn = fn
}

// ServeHTTP handles POST /api/v1/scan.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		h.writeError(w, http.StatusMethodNotAllowed, "", "method_not_allowed", "Only POST is accepted", false)
		return
	}

	// Auth: extract and validate bearer token.
	token := extractBearerToken(r)
	if token == "" || !h.validToken(token) {
		h.writeError(w, http.StatusUnauthorized, "", "unauthorized", "Missing or invalid bearer token", false)
		return
	}

	// Rate limit: per-token token bucket.
	if !h.allowRequest(token) {
		w.Header().Set("Retry-After", "1")
		h.writeError(w, http.StatusTooManyRequests, "", "rate_limited", "Rate limit exceeded for this token", true)
		return
	}

	// Kill switch check.
	if h.killSwitchFn != nil && h.killSwitchFn() {
		h.writeError(w, http.StatusServiceUnavailable, "", "kill_switch_active", "All scanning suspended by kill switch", false)
		return
	}

	// Body size limit.
	maxBody := h.cfg.ScanAPI.MaxBodyBytes
	if maxBody <= 0 {
		maxBody = defaultMaxBody
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "", "read_error", "Failed to read request body", false)
		return
	}
	if int64(len(body)) > maxBody {
		h.writeError(w, http.StatusBadRequest, "", "body_too_large",
			fmt.Sprintf("Request body exceeds %d bytes", maxBody), false)
		return
	}

	// Parse request with strict decoding (reject unknown fields).
	var req Request
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "", "invalid_json",
			fmt.Sprintf("Invalid request: %v", err), false)
		return
	}

	// Validate kind (post-parse: kind is available for error responses).
	if !validKinds[req.Kind] {
		h.writeError(w, http.StatusBadRequest, req.Kind, "invalid_kind",
			fmt.Sprintf("Unknown kind %q. Valid: url, dlp, prompt_injection, tool_call", req.Kind), false)
		return
	}

	// Check if kind is enabled.
	if !h.kindEnabled(req.Kind) {
		h.writeError(w, http.StatusBadRequest, req.Kind, "kind_disabled",
			fmt.Sprintf("Kind %q is disabled on this server", req.Kind), false)
		return
	}

	// Validate per-kind input fields.
	if err := h.validateInput(req.Kind, &req.Input); err != nil {
		h.writeError(w, http.StatusBadRequest, req.Kind, "invalid_input", err.Error(), false)
		return
	}

	// Execute scan with timeout.
	scanTimeout := defaultScanTimeout
	if h.cfg.ScanAPI.Timeouts.Scan != "" {
		if d, parseErr := time.ParseDuration(h.cfg.ScanAPI.Timeouts.Scan); parseErr == nil {
			scanTimeout = d
		}
	}

	start := time.Now()
	ctx, cancel := context.WithTimeout(r.Context(), scanTimeout)
	defer cancel()

	resp, status := h.executeScan(ctx, &req)

	resp.DurationMS = time.Since(start).Milliseconds()
	resp.EngineVersion = h.version
	if req.Context != nil && req.Context.RequestID != "" {
		resp.RequestID = req.Context.RequestID
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(resp)
}

func (h *Handler) validToken(token string) bool {
	for _, t := range h.cfg.ScanAPI.Auth.BearerTokens {
		if subtle.ConstantTimeCompare([]byte(token), []byte(t)) == 1 {
			return true
		}
	}
	return false
}

func (h *Handler) allowRequest(token string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()

	lim, ok := h.limiters[token]
	if !ok {
		rpm := h.cfg.ScanAPI.RateLimit.RequestsPerMinute
		if rpm <= 0 {
			rpm = defaultRPM
		}
		burst := h.cfg.ScanAPI.RateLimit.Burst
		if burst <= 0 {
			burst = defaultBurst
		}
		lim = rate.NewLimiter(rate.Every(time.Minute/time.Duration(rpm)), burst)
		h.limiters[token] = lim
	}
	return lim.Allow()
}

func (h *Handler) kindEnabled(kind string) bool {
	switch kind {
	case KindURL:
		return h.cfg.ScanAPI.Kinds.URL
	case KindDLP:
		return h.cfg.ScanAPI.Kinds.DLP
	case KindPromptInjection:
		return h.cfg.ScanAPI.Kinds.PromptInjection
	case KindToolCall:
		return h.cfg.ScanAPI.Kinds.ToolCall
	default:
		return false
	}
}

func (h *Handler) validateInput(kind string, input *Input) error {
	switch kind {
	case KindURL:
		if input.URL == "" {
			return fmt.Errorf("input.url is required for kind %q", KindURL)
		}
		if len(input.URL) > h.fieldLimit(h.cfg.ScanAPI.FieldLimits.URL, defaultURLLimit) {
			return fmt.Errorf("input.url exceeds field limit")
		}
	case KindDLP:
		if input.Text == "" {
			return fmt.Errorf("input.text is required for kind %q", KindDLP)
		}
		if len(input.Text) > h.fieldLimit(h.cfg.ScanAPI.FieldLimits.Text, defaultTextLimit) {
			return fmt.Errorf("input.text exceeds field limit")
		}
	case KindPromptInjection:
		if input.Content == "" {
			return fmt.Errorf("input.content is required for kind %q", KindPromptInjection)
		}
		if len(input.Content) > h.fieldLimit(h.cfg.ScanAPI.FieldLimits.Content, defaultContentLimit) {
			return fmt.Errorf("input.content exceeds field limit")
		}
	case KindToolCall:
		if input.ToolName == "" {
			return fmt.Errorf("input.tool_name is required for kind %q", KindToolCall)
		}
		if len(input.Arguments) > h.fieldLimit(h.cfg.ScanAPI.FieldLimits.Arguments, defaultArgumentsLimit) {
			return fmt.Errorf("input.arguments exceeds field limit")
		}
	}
	return nil
}

func (h *Handler) fieldLimit(configured, defaultVal int) int {
	if configured > 0 {
		return configured
	}
	return defaultVal
}

func extractBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(auth) > len(prefix) && auth[:len(prefix)] == prefix {
		return auth[len(prefix):]
	}
	return ""
}

func (h *Handler) writeError(w http.ResponseWriter, status int, kind, code, message string, retryable bool) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	resp := Response{
		Status:        StatusError,
		Kind:          kind, // may be empty for pre-parse errors (401, body too large)
		ScanID:        generateScanID(),
		EngineVersion: h.version,
		Errors: []APIError{
			{Code: code, Message: message, Retryable: retryable},
		},
	}
	_ = json.NewEncoder(w).Encode(resp)
}
