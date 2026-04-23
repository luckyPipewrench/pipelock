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
	"net/url"
	"strconv"
	"strings"
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

// Error codes used in API error responses and metrics labels.
const (
	errorCodeUnknown              = "unknown"
	errorCodeScanDeadlineExceeded = "scan_deadline_exceeded"
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
	configFn     func() *config.Config
	scannerFn    func() *scanner.Scanner
	policyCfgFn  func() *policy.Config

	// Per-token rate limiters.
	mu       sync.Mutex
	limiters map[string]scanAPITokenLimiter
}

type scanAPITokenLimiter struct {
	limiter *rate.Limiter
	rpm     int
	burst   int
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
		limiters:  make(map[string]scanAPITokenLimiter),
	}
}

// SetKillSwitchFn sets the function that checks kill switch state.
func (h *Handler) SetKillSwitchFn(fn func() bool) {
	h.killSwitchFn = fn
}

// SetRuntimeGetters wires live config/scanner/policy access for long-lived
// listeners so hot reloads take effect without rebuilding the handler.
func (h *Handler) SetRuntimeGetters(
	configFn func() *config.Config,
	scannerFn func() *scanner.Scanner,
	policyCfgFn func() *policy.Config,
) {
	h.configFn = configFn
	h.scannerFn = scannerFn
	h.policyCfgFn = policyCfgFn
}

// ServeHTTP handles POST /api/v1/scan.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.metrics.IncrScanAPIInflight()
	defer h.metrics.DecrScanAPIInflight()

	cfg := h.currentConfig()
	if cfg == nil {
		h.writeError(w, http.StatusInternalServerError, "", "config_unavailable", "Scan API configuration unavailable", true)
		return
	}

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		h.writeError(w, http.StatusMethodNotAllowed, "", "method_not_allowed", "Only POST is accepted", false)
		return
	}

	// Auth: extract and validate bearer token.
	token := extractBearerToken(r)
	if token == "" || !h.validTokenFor(token, cfg) {
		h.writeError(w, http.StatusUnauthorized, "", "unauthorized", "Missing or invalid bearer token", false)
		return
	}

	// Rate limit: per-token token bucket.
	if !h.allowRequestFor(token, cfg) {
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
	maxBody := cfg.ScanAPI.MaxBodyBytes
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
	// Reject trailing data after JSON object (concatenated payloads).
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		h.writeError(w, http.StatusBadRequest, "", "invalid_json",
			"Invalid request: trailing data after JSON object", false)
		return
	}

	// Validate kind (post-parse: kind is available for error responses).
	if !validKinds[req.Kind] {
		h.writeError(w, http.StatusBadRequest, req.Kind, "invalid_kind",
			fmt.Sprintf("Unknown kind %q. Valid: url, dlp, prompt_injection, tool_call", req.Kind), false)
		return
	}

	// Check if kind is enabled.
	if !h.kindEnabledFor(req.Kind, cfg) {
		h.writeError(w, http.StatusBadRequest, req.Kind, "kind_disabled",
			fmt.Sprintf("Kind %q is disabled on this server", req.Kind), false)
		return
	}

	// Validate per-kind input fields.
	if err := h.validateInputFor(req.Kind, &req.Input, cfg); err != nil {
		h.writeError(w, http.StatusBadRequest, req.Kind, "invalid_input", err.Error(), false)
		return
	}

	// Execute scan with timeout.
	scanTimeout := defaultScanTimeout
	if cfg.ScanAPI.Timeouts.Scan != "" {
		if d, parseErr := time.ParseDuration(cfg.ScanAPI.Timeouts.Scan); parseErr == nil {
			scanTimeout = d
		}
	}

	start := time.Now()
	ctx, cancel := context.WithTimeout(r.Context(), scanTimeout)
	defer cancel()

	resp, status := h.executeScan(ctx, &req)

	elapsed := time.Since(start)
	resp.DurationMS = elapsed.Milliseconds()
	resp.EngineVersion = h.version
	if req.Context != nil && req.Context.RequestID != "" {
		resp.RequestID = req.Context.RequestID
	}

	// Record Prometheus metrics.
	h.metrics.ObserveScanAPIDuration(req.Kind, elapsed)
	decision := resp.Decision
	if decision == "" {
		decision = StatusError
	}
	h.metrics.RecordScanAPIRequest(req.Kind, decision, strconv.Itoa(status))
	for _, f := range resp.Findings {
		h.metrics.RecordScanAPIFinding(req.Kind, f.Scanner, f.Severity)
	}
	if resp.Status == StatusError {
		code := errorCodeUnknown
		if len(resp.Errors) > 0 {
			code = resp.Errors[0].Code
		}
		h.metrics.RecordScanAPIError(req.Kind, code)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(resp)
}

func (h *Handler) validTokenFor(token string, cfg *config.Config) bool {
	if cfg == nil {
		return false
	}
	tokenBytes := []byte(token)
	match := 0
	for _, t := range cfg.ScanAPI.Auth.BearerTokens {
		match |= subtle.ConstantTimeCompare(tokenBytes, []byte(t))
	}
	return match == 1
}

func (h *Handler) allowRequestFor(token string, cfg *config.Config) bool {
	if cfg == nil {
		return false
	}
	h.mu.Lock()
	defer h.mu.Unlock()

	rpm := cfg.ScanAPI.RateLimit.RequestsPerMinute
	if rpm <= 0 {
		rpm = defaultRPM
	}
	burst := cfg.ScanAPI.RateLimit.Burst
	if burst <= 0 {
		burst = defaultBurst
	}

	lim, ok := h.limiters[token]
	if !ok || lim.rpm != rpm || lim.burst != burst {
		lim = scanAPITokenLimiter{
			limiter: rate.NewLimiter(rate.Every(time.Minute/time.Duration(rpm)), burst),
			rpm:     rpm,
			burst:   burst,
		}
		h.limiters[token] = lim
	}
	return lim.limiter.Allow()
}

func (h *Handler) kindEnabled(kind string) bool {
	return h.kindEnabledFor(kind, h.currentConfig())
}

func (h *Handler) kindEnabledFor(kind string, cfg *config.Config) bool {
	if cfg == nil {
		return false
	}
	switch kind {
	case KindURL:
		return cfg.ScanAPI.Kinds.URL
	case KindDLP:
		return cfg.ScanAPI.Kinds.DLP
	case KindPromptInjection:
		return cfg.ScanAPI.Kinds.PromptInjection
	case KindToolCall:
		return cfg.ScanAPI.Kinds.ToolCall
	default:
		return false
	}
}

func (h *Handler) validateInputFor(kind string, input *Input, cfg *config.Config) error {
	if cfg == nil {
		return fmt.Errorf("scan configuration unavailable")
	}
	switch kind {
	case KindURL:
		if input.URL == "" {
			return fmt.Errorf("input.url is required for kind %q", KindURL)
		}
		if len(input.URL) > h.fieldLimit(cfg.ScanAPI.FieldLimits.URL, defaultURLLimit) {
			return fmt.Errorf("input.url exceeds field limit")
		}
		// Full semantic validation: scheme must be http/https and host must be present.
		// Rejects bare schemes ("https://"), non-HTTP schemes, and schemeless strings.
		parsed, parseErr := url.Parse(input.URL)
		if parseErr != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
			return fmt.Errorf("input.url must be a valid http:// or https:// URL with a host")
		}
	case KindDLP:
		if input.Text == "" {
			return fmt.Errorf("input.text is required for kind %q", KindDLP)
		}
		if len(input.Text) > h.fieldLimit(cfg.ScanAPI.FieldLimits.Text, defaultTextLimit) {
			return fmt.Errorf("input.text exceeds field limit")
		}
	case KindPromptInjection:
		if input.Content == "" {
			return fmt.Errorf("input.content is required for kind %q", KindPromptInjection)
		}
		if len(input.Content) > h.fieldLimit(cfg.ScanAPI.FieldLimits.Content, defaultContentLimit) {
			return fmt.Errorf("input.content exceeds field limit")
		}
	case KindToolCall:
		if input.ToolName == "" {
			return fmt.Errorf("input.tool_name is required for kind %q", KindToolCall)
		}
		if len(input.Arguments) > h.fieldLimit(cfg.ScanAPI.FieldLimits.Arguments, defaultArgumentsLimit) {
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
	// RFC 7235: auth-scheme is a case-insensitive token.
	// Accept "Bearer", "bearer", "BEARER", etc.
	const prefixLen = len("Bearer ")
	if len(auth) > prefixLen && strings.EqualFold(auth[:prefixLen], "Bearer ") {
		return auth[prefixLen:]
	}
	return ""
}

func (h *Handler) writeError(w http.ResponseWriter, status int, kind, code, message string, retryable bool) {
	// Normalize invalid kind to prevent unbounded Prometheus label cardinality.
	metricKind := kind
	if metricKind != "" && !validKinds[metricKind] {
		metricKind = errorCodeUnknown
	}
	h.metrics.RecordScanAPIError(metricKind, code)
	h.metrics.RecordScanAPIRequest(metricKind, StatusError, strconv.Itoa(status))

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

func (h *Handler) currentConfig() *config.Config {
	if h.configFn != nil {
		return h.configFn()
	}
	return h.cfg
}

func (h *Handler) currentScanner() *scanner.Scanner {
	if h.scannerFn != nil {
		return h.scannerFn()
	}
	return h.scanner
}

func (h *Handler) currentPolicyCfg() *policy.Config {
	if h.policyCfgFn != nil {
		return h.policyCfgFn()
	}
	return h.policyCfg
}
