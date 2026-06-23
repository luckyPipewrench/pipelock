// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package broker

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/playground/livechat"
)

const (
	defaultInternalPort = 8080
	defaultReapInterval = 5 * time.Second
	maxBrokerBodyBytes  = 64 * 1024
	vmInviteCodeBytes   = 18

	envVMInviteCode = "PLAYGROUND_CODE"

	// defaultVMReadyTimeout bounds the broker's whole VM session-create retry
	// window. A freshly leased VM reports "started" (Firecracker booted) before it
	// serves, and crosses TWO fail-closed containment proofs (six 2s egress probes
	// each): the boot-gate proof in the entrypoint, then a per-session proof inside
	// the session-create handler itself. So the connection is refused for several
	// seconds, and the eventual session-create request then blocks for the
	// per-session proof (~12s) before responding. This budget covers both with
	// headroom; the whole window — not each attempt — is bounded, so a legitimately
	// slow session-create is never cancelled mid-proof.
	defaultVMReadyTimeout = 60 * time.Second
	// vmReadyPollInterval is the wait between VM session-create attempts while the
	// VM server is not yet accepting connections.
	vmReadyPollInterval = 500 * time.Millisecond
)

// ServerConfig configures the public playground broker HTTP front door.
type ServerConfig struct {
	// Leases owns VM lifecycle and the global machine concurrency cap. Required.
	Leases *LeaseManager
	// Gate validates public invite codes before a VM is leased. Required.
	Gate *livechat.Gate
	// HumanVerifier validates a browser proof before invite-code redemption and
	// VM lease. Nil disables this gate for private/Access-gated deployments.
	HumanVerifier HumanVerifier
	// IPRate and CodeRate apply to session creation and proxied session routes.
	IPRate   livechat.RateConfig
	CodeRate livechat.RateConfig
	// Daily budgets are charged on session creation, in the required order:
	// per-IP, per-code, global. A later failure refunds every budget charged in
	// that request.
	PerIPDailyBudget   int
	PerCodeDailyBudget int
	GlobalDailyBudget  int
	// SessionEnv is layered into each per-VM lease along with the generated
	// single-use VM invite code. It carries operator-provided per-session secret
	// values such as PLAYGROUND_MODEL_KEY and PLAYGROUND_ORCHESTRATOR_KEY.
	SessionEnv map[string]string
	// InternalPort is the VM server port. Zero uses 8080.
	InternalPort int
	// DeadlineGrace extends the VM-reported session expiry before the broker
	// reaps the lease. Negative values are rejected.
	DeadlineGrace time.Duration
	// ReapInterval controls the background expired-lease sweep. Zero uses a
	// conservative default.
	ReapInterval time.Duration
	// HTTPClient is used for the initial VM session-create request. Nil uses the
	// default client.
	HTTPClient *http.Client
	// VMReadyTimeout bounds how long the broker retries the VM session-create
	// while the freshly leased VM is still completing its fail-closed containment
	// proof and not yet listening. Zero uses defaultVMReadyTimeout.
	VMReadyTimeout time.Duration
	// TrustForwardedFor reads client IP from X-Forwarded-For. Only set behind a
	// trusted proxy.
	TrustForwardedFor bool
	// AllowOrigin sets Access-Control-Allow-Origin. Empty disables CORS headers.
	AllowOrigin string
}

// Server is the broker HTTP front door. It is safe for concurrent use.
type Server struct {
	cfg      ServerConfig
	ipRate   *livechat.RateLimiter
	codeRate *livechat.RateLimiter
	perIP    *livechat.KeyedDailyBudget
	perCode  *livechat.KeyedDailyBudget
	global   *livechat.DailyBudget
	client   *http.Client

	vmReadyTimeout time.Duration

	killed atomic.Bool

	mu       sync.Mutex
	tokens   map[string]*tokenLease
	bySess   map[string]string
	starts   []time.Time
	closed   bool
	reapDone chan struct{}
}

type tokenLease struct {
	token      string
	sessionKey string
	lease      *Lease
	deadline   time.Time
}

type sessionRequest struct {
	Code           string `json:"code"`
	TurnstileToken string `json:"turnstile_token,omitempty"`
}

type vmSessionResponse struct {
	Token     string `json:"token"`
	SessionID string `json:"session_id"`
	ExpiresAt string `json:"expires_at"`
	State     string `json:"state"`
}

type messageRequest struct {
	Token   string `json:"token"`
	Message string `json:"message"`
}

// NewServer validates cfg, starts the expiry reaper, and returns a broker
// server. A missing gate or lease manager fails closed at startup.
func NewServer(cfg ServerConfig) (*Server, error) {
	if cfg.Leases == nil {
		return nil, errors.New("broker: ServerConfig.Leases is required")
	}
	if cfg.Gate == nil {
		return nil, errors.New("broker: ServerConfig.Gate is required")
	}
	if cfg.DeadlineGrace < 0 {
		return nil, errors.New("broker: DeadlineGrace must be >= 0")
	}
	for _, c := range []struct {
		name string
		v    int
	}{
		{"PerIPDailyBudget", cfg.PerIPDailyBudget},
		{"PerCodeDailyBudget", cfg.PerCodeDailyBudget},
		{"GlobalDailyBudget", cfg.GlobalDailyBudget},
	} {
		if c.v < 0 {
			return nil, fmt.Errorf("broker: %s must be >= 0", c.name)
		}
	}
	if cfg.InternalPort == 0 {
		cfg.InternalPort = defaultInternalPort
	}
	if cfg.ReapInterval <= 0 {
		cfg.ReapInterval = defaultReapInterval
	}
	client := cfg.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	vmReadyTimeout := cfg.VMReadyTimeout
	if vmReadyTimeout <= 0 {
		vmReadyTimeout = defaultVMReadyTimeout
	}
	s := &Server{
		cfg:            cfg,
		ipRate:         livechat.NewRateLimiter(cfg.IPRate),
		codeRate:       livechat.NewRateLimiter(cfg.CodeRate),
		perIP:          livechat.NewKeyedDailyBudget(cfg.PerIPDailyBudget, 0),
		perCode:        livechat.NewKeyedDailyBudget(cfg.PerCodeDailyBudget, 0),
		global:         livechat.NewDailyBudget(cfg.GlobalDailyBudget),
		client:         client,
		vmReadyTimeout: vmReadyTimeout,
		tokens:         make(map[string]*tokenLease),
		bySess:         make(map[string]string),
		reapDone:       make(chan struct{}),
	}
	go s.reapLoop()
	return s, nil
}

// Handler returns the broker's public /api/live/* routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(livechat.RouteSession, s.handleSession)
	mux.HandleFunc(livechat.RouteStream, s.handleStream)
	mux.HandleFunc(livechat.RouteMessage, s.handleMessage)
	mux.HandleFunc(livechat.RouteBundle, s.handleBundle)
	mux.HandleFunc(livechat.RouteHealth, s.handleHealth)
	return mux
}

// Close releases every active lease and stops the background reaper.
func (s *Server) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	close(s.reapDone)
	bindings := make([]*tokenLease, 0, len(s.tokens))
	for _, binding := range s.tokens {
		bindings = append(bindings, binding)
	}
	s.tokens = make(map[string]*tokenLease)
	s.bySess = make(map[string]string)
	s.mu.Unlock()

	for _, binding := range bindings {
		s.cfg.Leases.Release(context.Background(), binding.sessionKey)
	}
}

// Kill refuses new sessions/messages and releases every active lease.
func (s *Server) Kill() {
	s.killed.Store(true)
	s.releaseAll()
}

// Resume clears the kill switch for future sessions.
func (s *Server) Resume() {
	s.killed.Store(false)
}

// Killed reports whether the broker emergency stop is active.
func (s *Server) Killed() bool {
	return s.killed.Load()
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	s.setCORS(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodGet {
		writeBrokerErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeBrokerJSON(w, http.StatusOK, map[string]any{
		"ok":                         s.cfg.Gate.Open() && s.global.Open() && !s.killed.Load(),
		"in_use":                     s.cfg.Leases.ActiveLeases(),
		"capacity":                   s.cfg.Leases.cfg.Concurrency.Cap(),
		"budget_remaining":           s.global.Remaining(),
		"killed":                     s.killed.Load(),
		"session_starts_last_minute": s.sessionStartsSince(time.Now(), time.Minute),
	})
}

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	s.setCORS(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPost {
		writeBrokerErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	ip := s.clientIP(r)
	if !s.ipRate.Allow("ip:" + ip) {
		writeBrokerErr(w, http.StatusTooManyRequests, "rate limited")
		return
	}
	if s.killed.Load() {
		writeBrokerErr(w, http.StatusServiceUnavailable, "the demo is paused")
		return
	}

	var body sessionRequest
	if err := decodeBrokerJSON(r, &body); err != nil {
		writeBrokerErr(w, http.StatusBadRequest, "bad request")
		return
	}
	if body.Code == "" {
		writeBrokerErr(w, http.StatusForbidden, "invite code rejected")
		return
	}
	if s.cfg.HumanVerifier != nil {
		// Turnstile remoteip must be the exact client address, not the /64
		// abuse bucket, so token-to-IP binding stays correct.
		if err := s.cfg.HumanVerifier.Verify(r.Context(), body.TurnstileToken, s.clientIPExact(r)); err != nil {
			writeBrokerErr(w, http.StatusForbidden, "human verification required")
			return
		}
	}
	codeLimiterKey := "code:" + codeKey(body.Code)
	if !s.codeRate.Allow(codeLimiterKey) {
		writeBrokerErr(w, http.StatusTooManyRequests, "rate limited")
		return
	}

	sessionKey, err := newBrokerSessionKey()
	if err != nil {
		writeBrokerErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	_, claims, err := s.cfg.Gate.Redeem(body.Code, sessionKey)
	if err != nil {
		writeBrokerErr(w, gateStatus(err), "invite code rejected")
		return
	}

	var rollback []func()
	undo := func() {
		for i := len(rollback) - 1; i >= 0; i-- {
			rollback[i]()
		}
	}
	rollback = append(rollback, func() { s.cfg.Gate.Refund(claims) })

	ipBudgetKey := "ip:" + ip
	codeBudgetKey := "code:" + claims.CodeID
	if !s.perIP.Charge(ipBudgetKey, 1) {
		undo()
		writeBrokerErr(w, http.StatusTooManyRequests, "daily limit reached for your address")
		return
	}
	rollback = append(rollback, func() { s.perIP.Refund(ipBudgetKey, 1) })

	if !s.perCode.Charge(codeBudgetKey, 1) {
		undo()
		writeBrokerErr(w, http.StatusTooManyRequests, "daily limit reached for this code")
		return
	}
	rollback = append(rollback, func() { s.perCode.Refund(codeBudgetKey, 1) })

	if !s.global.Charge(1) {
		undo()
		writeBrokerErr(w, http.StatusServiceUnavailable, "daily limit reached, the demo is paused until tomorrow")
		return
	}
	rollback = append(rollback, func() { s.global.Refund(1) })

	vmCode, err := livechat.NewRandomCode(vmInviteCodeBytes)
	if err != nil {
		undo()
		writeBrokerErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	sessionEnv := mergeEnv(s.cfg.SessionEnv, map[string]string{envVMInviteCode: vmCode})
	lease, err := s.cfg.Leases.Lease(r.Context(), sessionKey, sessionEnv)
	if err != nil {
		undo()
		if errors.Is(err, ErrAtCapacity) {
			writeBrokerErr(w, http.StatusServiceUnavailable, "at capacity, try again")
			return
		}
		writeBrokerErr(w, http.StatusServiceUnavailable, "session could not be started")
		return
	}

	resp, expiresAt, err := s.createVMSession(r.Context(), lease, vmCode)
	if err != nil {
		s.cfg.Leases.Release(context.WithoutCancel(r.Context()), sessionKey)
		undo()
		writeBrokerErr(w, http.StatusServiceUnavailable, "session could not be started")
		return
	}
	if resp.Token == "" || resp.SessionID == "" || expiresAt.IsZero() {
		s.cfg.Leases.Release(context.WithoutCancel(r.Context()), sessionKey)
		undo()
		writeBrokerErr(w, http.StatusServiceUnavailable, "session could not be started")
		return
	}

	deadline := expiresAt.Add(s.cfg.DeadlineGrace)
	if time.Until(deadline) <= 0 {
		s.cfg.Leases.Release(context.WithoutCancel(r.Context()), sessionKey)
		undo()
		writeBrokerErr(w, http.StatusServiceUnavailable, "session expired before start")
		return
	}
	if !s.registerToken(resp.Token, &tokenLease{token: resp.Token, sessionKey: sessionKey, lease: lease, deadline: deadline}) {
		s.cfg.Leases.Release(context.WithoutCancel(r.Context()), sessionKey)
		undo()
		writeBrokerErr(w, http.StatusServiceUnavailable, "session could not be started")
		return
	}
	s.cfg.Gate.Commit(claims)
	s.recordSessionStart(time.Now())
	writeBrokerJSON(w, http.StatusOK, resp)
}

func (s *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	s.setCORS(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodGet {
		writeBrokerErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !s.ipRate.Allow("ip:" + s.clientIP(r)) {
		writeBrokerErr(w, http.StatusTooManyRequests, "rate limited")
		return
	}
	binding := s.lookupToken(r.URL.Query().Get("token"))
	if binding == nil {
		writeBrokerErr(w, http.StatusNotFound, "session not found")
		return
	}
	s.proxy(w, r, binding, true)
}

func (s *Server) handleMessage(w http.ResponseWriter, r *http.Request) {
	s.setCORS(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPost {
		writeBrokerErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !s.ipRate.Allow("ip:" + s.clientIP(r)) {
		writeBrokerErr(w, http.StatusTooManyRequests, "rate limited")
		return
	}
	if s.killed.Load() {
		writeBrokerErr(w, http.StatusServiceUnavailable, "the demo is paused")
		return
	}
	body, token, err := readMessageToken(w, r)
	if err != nil {
		// http.MaxBytesReader sets the response to 413 automatically for
		// oversize bodies. For other parse errors, respond 400.
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			writeBrokerErr(w, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		writeBrokerErr(w, http.StatusBadRequest, "bad request")
		return
	}
	binding := s.lookupToken(token)
	if binding == nil {
		writeBrokerErr(w, http.StatusNotFound, "session not found")
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	s.proxy(w, r, binding, false)
}

func (s *Server) handleBundle(w http.ResponseWriter, r *http.Request) {
	s.setCORS(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodGet {
		writeBrokerErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !s.ipRate.Allow("ip:" + s.clientIP(r)) {
		writeBrokerErr(w, http.StatusTooManyRequests, "rate limited")
		return
	}
	token := r.URL.Query().Get("token")
	binding := s.lookupToken(token)
	if binding == nil {
		writeBrokerErr(w, http.StatusNotFound, "session not found")
		return
	}
	rec := &statusRecorder{ResponseWriter: w}
	s.proxy(rec, r, binding, false)
	if rec.status == http.StatusOK {
		s.releaseToken(context.WithoutCancel(r.Context()), token)
	}
}

func (s *Server) createVMSession(ctx context.Context, lease *Lease, code string) (vmSessionResponse, time.Time, error) {
	target, err := s.targetURL(lease, livechat.RouteSession)
	if err != nil {
		return vmSessionResponse{}, time.Time{}, err
	}
	reqBody, err := json.Marshal(sessionRequest{Code: code})
	if err != nil {
		return vmSessionResponse{}, time.Time{}, fmt.Errorf("broker: marshal vm session request: %w", err)
	}

	// A leased VM reports "started" (Firecracker booted) before its in-process
	// server is listening: it proves containment first. Retry the session-create
	// through that window, but ONLY while the connection itself fails — a
	// pre-response transport error means the request never reached the VM server,
	// so no session was minted and the VM's single-use invite code is untouched
	// (safe to retry). The first HTTP response, success or error status, ends the
	// retry: the server answered and may have consumed the code, so retrying it
	// could double-spend or mask a real rejection.
	//
	// The whole window is bounded by readyCtx, NOT each attempt: the eventual
	// session-create request legitimately blocks for the per-session containment
	// proof (~12s), and must not be cancelled mid-proof. A connection-refused
	// returns immediately regardless, so refused attempts still retry promptly.
	readyCtx, cancel := context.WithTimeout(ctx, s.vmReadyTimeout)
	defer cancel()
	var lastErr error
	for {
		resp, expiresAt, retryable, attemptErr := s.attemptVMSession(readyCtx, target.String(), reqBody)
		if attemptErr == nil {
			return resp, expiresAt, nil
		}
		if !retryable {
			return vmSessionResponse{}, time.Time{}, attemptErr
		}
		lastErr = attemptErr
		if readyCtx.Err() != nil {
			if errors.Is(readyCtx.Err(), context.DeadlineExceeded) && ctx.Err() == nil {
				return vmSessionResponse{}, time.Time{}, fmt.Errorf("broker: vm server not ready within %s: %w", s.vmReadyTimeout, lastErr)
			}
			return vmSessionResponse{}, time.Time{}, readyCtx.Err()
		}
		select {
		case <-readyCtx.Done():
		case <-time.After(vmReadyPollInterval):
		}
	}
}

// attemptVMSession performs one VM session-create round trip. retryable reports
// whether the failure was a pre-response transport error (the request never
// reached the VM server, so no session was minted): such failures are safe to
// retry while the VM finishes its fail-closed containment proof. Any received
// HTTP response — success or error status — is non-retryable.
func (s *Server) attemptVMSession(ctx context.Context, target string, reqBody []byte) (resp vmSessionResponse, expiresAt time.Time, retryable bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(reqBody))
	if err != nil {
		return vmSessionResponse{}, time.Time{}, false, fmt.Errorf("broker: build vm session request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	httpResp, err := s.client.Do(req)
	if err != nil {
		// No HTTP response was received: the VM is not yet accepting connections
		// (still proving containment). Retryable — the readyCtx deadline in the
		// caller bounds the overall wait.
		return vmSessionResponse{}, time.Time{}, true, fmt.Errorf("broker: create vm session: %w", err)
	}
	defer func() { _ = httpResp.Body.Close() }()

	respBody, err := io.ReadAll(io.LimitReader(httpResp.Body, maxBrokerBodyBytes))
	if err != nil {
		return vmSessionResponse{}, time.Time{}, false, fmt.Errorf("broker: read vm session response: %w", err)
	}
	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		return vmSessionResponse{}, time.Time{}, false, fmt.Errorf("broker: vm session status %d", httpResp.StatusCode)
	}
	var vmResp vmSessionResponse
	if err := json.Unmarshal(respBody, &vmResp); err != nil {
		return vmSessionResponse{}, time.Time{}, false, fmt.Errorf("broker: parse vm session response: %w", err)
	}
	parsedExpiry, err := time.Parse(time.RFC3339, vmResp.ExpiresAt)
	if err != nil {
		return vmSessionResponse{}, time.Time{}, false, fmt.Errorf("broker: parse vm session expiry: %w", err)
	}
	return vmResp, parsedExpiry, false, nil
}

func (s *Server) proxy(w http.ResponseWriter, r *http.Request, binding *tokenLease, stream bool) {
	target, err := s.targetURL(binding.lease, r.URL.Path)
	if err != nil {
		writeBrokerErr(w, http.StatusServiceUnavailable, "session proxy unavailable")
		return
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	if stream {
		proxy.FlushInterval = -1
	}
	proxy.ErrorHandler = func(rw http.ResponseWriter, _ *http.Request, _ error) {
		writeBrokerErr(rw, http.StatusBadGateway, "session proxy unavailable")
	}
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.URL.Path = r.URL.Path
		req.URL.RawPath = r.URL.RawPath
		req.URL.RawQuery = r.URL.RawQuery
		req.Host = target.Host
	}
	proxy.ServeHTTP(w, r)
}

func (s *Server) targetURL(lease *Lease, path string) (*url.URL, error) {
	if lease == nil || lease.Machine == nil {
		return nil, errors.New("broker: missing lease machine")
	}
	host, err := targetHost(lease.Machine.PrivateIP, s.cfg.InternalPort)
	if err != nil {
		return nil, err
	}
	return &url.URL{Scheme: "http", Host: host, Path: path}, nil
}

func targetHost(privateIP string, port int) (string, error) {
	if strings.TrimSpace(privateIP) == "" {
		return "", errors.New("broker: machine private ip is empty")
	}
	if strings.Contains(privateIP, "://") {
		return "", errors.New("broker: machine private ip must be a host or host:port, not a URL")
	}
	if _, _, err := net.SplitHostPort(privateIP); err == nil {
		return privateIP, nil
	}
	if port <= 0 {
		port = defaultInternalPort
	}
	return net.JoinHostPort(strings.Trim(privateIP, "[]"), strconv.Itoa(port)), nil
}

func (s *Server) registerToken(token string, binding *tokenLease) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	// Re-check the kill switch under the lock. Kill() stores killed=true before
	// releaseAll() snapshots the token map, so a session-create that was in flight
	// during a pause (blocked in VM boot, past the early killed check) must refuse
	// to register here, or its VM survives the pause: a fail-open emergency stop.
	// Mirrors the inner livechat server's pre-insert kill recheck.
	if s.killed.Load() {
		return false
	}
	if _, exists := s.tokens[token]; exists {
		return false
	}
	s.tokens[token] = binding
	s.bySess[binding.sessionKey] = token
	return true
}

func (s *Server) lookupToken(token string) *tokenLease {
	if token == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tokens[token]
}

func (s *Server) releaseToken(ctx context.Context, token string) {
	s.mu.Lock()
	binding := s.tokens[token]
	if binding != nil {
		delete(s.tokens, token)
		delete(s.bySess, binding.sessionKey)
	}
	s.mu.Unlock()
	if binding == nil {
		return
	}
	s.cfg.Leases.Release(ctx, binding.sessionKey)
}

func (s *Server) releaseAll() {
	s.mu.Lock()
	tokens := make([]string, 0, len(s.tokens))
	for token := range s.tokens {
		tokens = append(tokens, token)
	}
	s.mu.Unlock()
	for _, token := range tokens {
		s.releaseToken(context.Background(), token)
	}
}

func (s *Server) recordSessionStart(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneStartsLocked(now, time.Minute)
	s.starts = append(s.starts, now)
}

func (s *Server) sessionStartsSince(now time.Time, window time.Duration) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneStartsLocked(now, window)
	return len(s.starts)
}

func (s *Server) pruneStartsLocked(now time.Time, window time.Duration) {
	cutoff := now.Add(-window)
	keep := 0
	for _, started := range s.starts {
		if started.After(cutoff) {
			s.starts[keep] = started
			keep++
		}
	}
	for i := keep; i < len(s.starts); i++ {
		s.starts[i] = time.Time{}
	}
	s.starts = s.starts[:keep]
}

func (s *Server) reapLoop() {
	ticker := time.NewTicker(s.cfg.ReapInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.reapExpired(time.Now())
		case <-s.reapDone:
			return
		}
	}
}

func (s *Server) reapExpired(now time.Time) {
	var expired []string
	s.mu.Lock()
	for token, binding := range s.tokens {
		if !binding.deadline.After(now) {
			expired = append(expired, token)
		}
	}
	s.mu.Unlock()
	for _, token := range expired {
		s.releaseToken(context.Background(), token)
	}
}

func (s *Server) setCORS(w http.ResponseWriter) {
	if s.cfg.AllowOrigin != "" {
		w.Header().Set("Access-Control-Allow-Origin", s.cfg.AllowOrigin)
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Vary", "Origin")
	}
}

func (s *Server) clientIP(r *http.Request) string {
	return livechat.ClientIP(r, s.cfg.TrustForwardedFor)
}

func (s *Server) clientIPExact(r *http.Request) string {
	return livechat.ClientIPExact(r, s.cfg.TrustForwardedFor)
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.ResponseWriter.Write(b)
}

func (r *statusRecorder) Flush() {
	if flusher, ok := r.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (r *statusRecorder) Unwrap() http.ResponseWriter {
	return r.ResponseWriter
}

func readMessageToken(w http.ResponseWriter, r *http.Request) ([]byte, string, error) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBrokerBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, "", fmt.Errorf("broker: read message request: %w", err)
	}
	var req messageRequest
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return nil, "", err
	}
	return body, req.Token, nil
}

func decodeBrokerJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, maxBrokerBodyBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	var extra struct{}
	if err := dec.Decode(&extra); err != io.EOF {
		return errors.New("broker: request body must contain exactly one JSON object")
	}
	return nil
}

func writeBrokerJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeBrokerErr(w http.ResponseWriter, status int, msg string) {
	writeBrokerJSON(w, status, map[string]string{"error": msg})
}

func gateStatus(err error) int {
	if errors.Is(err, livechat.ErrGateClosed) {
		return http.StatusServiceUnavailable
	}
	return http.StatusForbidden
}

func codeKey(code string) string {
	sum := sha256.Sum256([]byte(code))
	return hex.EncodeToString(sum[:])
}

func newBrokerSessionKey() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("broker: generate session key: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}
