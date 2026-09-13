// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package killswitch

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/authlimit"
	"github.com/luckyPipewrench/pipelock/internal/jsonscan"
)

const (
	apiRateLimitWindow = time.Minute
	apiRateLimitMax    = 10
)

// APIHandler handles HTTP requests to the kill switch API.
type APIHandler struct {
	ctrl *Controller

	mu          sync.Mutex
	reqCount    int
	windowStart time.Time

	// authFailures bounds presented-but-invalid bearer tokens per client
	// address. The authenticated request budget above is consumed only by
	// valid requests, so without this a wrong guess was free.
	authFailures *authlimit.Limiter
}

// NewAPIHandler creates an API handler for the given controller.
func NewAPIHandler(ctrl *Controller) *APIHandler {
	return &APIHandler{
		ctrl:         ctrl,
		windowStart:  time.Now(),
		authFailures: authlimit.NewDefault(),
	}
}

// authenticate enforces bearer authentication for both API endpoints. It
// returns false after writing the response when the request must not proceed.
//
// Order matters and is deliberate: a presented token first reserves one
// evaluation slot for the client address, atomically, and is compared only if
// a slot was free. A spent budget is refused BEFORE the compare, so a guesser
// gets no oracle from the refusal and a parallel burst cannot outrun the
// count. A request that presents no token is rejected but not counted. A valid
// token releases the address's reservations.
func (h *APIHandler) authenticate(w http.ResponseWriter, r *http.Request) (*runtime, bool) {
	rt := h.ctrl.cfg.Load()
	if rt.apiToken == "" {
		// No token configured - API disabled
		http.Error(w, "kill switch API not configured (no api_token)", http.StatusServiceUnavailable)
		return nil, false
	}
	token := extractBearerToken(r)
	if token == "" {
		w.Header().Set("WWW-Authenticate", `Bearer realm="pipelock"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return nil, false
	}
	clientKey := authlimit.ClientKey(r)
	if allowed, retry := h.authFailures.Admit(clientKey); !allowed {
		authlimit.Refuse(w, retry)
		return nil, false
	}
	if subtle.ConstantTimeCompare([]byte(token), []byte(rt.apiToken)) != 1 {
		w.Header().Set("WWW-Authenticate", `Bearer realm="pipelock"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return nil, false
	}
	h.authFailures.Reset(clientKey)
	return rt, true
}

// HandleToggle handles POST /api/v1/killswitch.
// Request body: {"active": true} or {"active": false}
// Requires Bearer token authentication matching config api_token.
func (h *APIHandler) HandleToggle(w http.ResponseWriter, r *http.Request) {
	// Method check
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	rt, ok := h.authenticate(w, r)
	if !ok {
		return
	}

	// Rate limit
	if !h.checkRateLimit() {
		w.Header().Set("Retry-After", "60")
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	// Parse request body (strict: reject unknown fields)
	var req struct {
		Active *bool `json:"active"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1024)
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid request body: %v", err), http.StatusBadRequest)
		return
	}
	if err := jsonscan.RejectDuplicateKeys(raw); err != nil {
		http.Error(w, fmt.Sprintf("invalid request body: %v", err), http.StatusBadRequest)
		return
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("invalid request body: %v", err), http.StatusBadRequest)
		return
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		http.Error(w, "request body must contain exactly one JSON object", http.StatusBadRequest)
		return
	}
	if req.Active == nil {
		http.Error(w, `missing required field "active"`, http.StatusBadRequest)
		return
	}

	// Apply
	h.ctrl.SetAPI(*req.Active)

	// Response
	w.Header().Set("Content-Type", "application/json")
	resp := struct {
		Active  bool   `json:"active"`
		Source  string `json:"source"`
		Message string `json:"message,omitempty"`
	}{
		Active: *req.Active,
		Source: "api",
	}
	if *req.Active {
		resp.Message = rt.message
	}
	_ = json.NewEncoder(w).Encode(resp)
}

// HandleStatus handles GET /api/v1/killswitch/status.
// Returns the current state of each activation source.
func (h *APIHandler) HandleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	rt, ok := h.authenticate(w, r)
	if !ok {
		return
	}

	sources := h.ctrl.Sources()
	anyActive := false
	for _, v := range sources {
		if v {
			anyActive = true
			break
		}
	}

	w.Header().Set("Content-Type", "application/json")
	resp := struct {
		Active  bool            `json:"active"`
		Sources map[string]bool `json:"sources"`
		Message string          `json:"message,omitempty"`
	}{
		Active:  anyActive,
		Sources: sources,
	}
	if anyActive {
		resp.Message = rt.message
	}
	_ = json.NewEncoder(w).Encode(resp)
}

// checkRateLimit implements a simple fixed-window rate limiter.
func (h *APIHandler) checkRateLimit() bool {
	h.mu.Lock()
	defer h.mu.Unlock()

	now := time.Now()
	if now.Sub(h.windowStart) > apiRateLimitWindow {
		h.reqCount = 0
		h.windowStart = now
	}
	h.reqCount++
	return h.reqCount <= apiRateLimitMax
}

// extractBearerToken extracts the token from an Authorization: Bearer header.
func extractBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(auth) > len(prefix) && auth[:len(prefix)] == prefix {
		return auth[len(prefix):]
	}
	return ""
}
