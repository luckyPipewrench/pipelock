package killswitch

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
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
}

// NewAPIHandler creates an API handler for the given controller.
func NewAPIHandler(ctrl *Controller) *APIHandler {
	return &APIHandler{
		ctrl:        ctrl,
		windowStart: time.Now(),
	}
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

	// Auth check
	rt := h.ctrl.cfg.Load()
	if rt.apiToken == "" {
		// No token configured — API disabled
		http.Error(w, "kill switch API not configured (no api_token)", http.StatusServiceUnavailable)
		return
	}

	token := extractBearerToken(r)
	if token == "" || subtle.ConstantTimeCompare([]byte(token), []byte(rt.apiToken)) != 1 {
		w.Header().Set("WWW-Authenticate", `Bearer realm="pipelock"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
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
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("invalid request body: %v", err), http.StatusBadRequest)
		return
	}
	if dec.More() {
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

	// Auth check (same token)
	rt := h.ctrl.cfg.Load()
	if rt.apiToken == "" {
		http.Error(w, "kill switch API not configured (no api_token)", http.StatusServiceUnavailable)
		return
	}

	token := extractBearerToken(r)
	if token == "" || subtle.ConstantTimeCompare([]byte(token), []byte(rt.apiToken)) != 1 {
		w.Header().Set("WWW-Authenticate", `Bearer realm="pipelock"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
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
