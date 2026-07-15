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

	"github.com/luckyPipewrench/pipelock/internal/jsonscan"
	"github.com/luckyPipewrench/pipelock/internal/playground"
	"github.com/luckyPipewrench/pipelock/internal/playground/livechat"
)

const (
	defaultInternalPort = 8080
	defaultReapInterval = 5 * time.Second
	maxBrokerBodyBytes  = 64 * 1024
	vmInviteCodeBytes   = 18

	envVMInviteCode = "PLAYGROUND_CODE"

	// maxArtifactBytes caps the per-artifact size of the raw sealed bundle the
	// broker will cache. The bundle is signed JSON/tar.gz; 16 MiB is generous.
	maxArtifactBytes = 16 << 20 // 16 MiB

	// maxKitBytes caps the per-artifact size of a verify kit (os != ""), which
	// bundles a platform verifier binary alongside the signed run and is much
	// larger than the raw bundle. Kept separate so a future notarized/universal
	// build cannot silently exceed the bundle cap and fail on one platform only.
	maxKitBytes = 64 << 20 // 64 MiB

	// maxArtifactCacheEntries bounds the total number of cached artifacts to
	// prevent unbounded memory growth. A single session can hold up to four
	// entries (the raw bundle plus a per-OS verify kit each), so this is sized
	// well above the global daily session budget to keep a traffic spike from
	// evicting one visitor's artifact before they re-download within the cache
	// TTL. Each entry is capped at maxArtifactBytes, bounding worst-case memory.
	maxArtifactCacheEntries = 256

	// maxArtifactCacheBytes bounds the total resident size of all cached
	// artifacts independent of the entry count, so many concurrent large verify
	// kits cannot exhaust memory. The oldest entries are evicted to stay under it.
	maxArtifactCacheBytes = 512 << 20 // 512 MiB

	// artifactFetchTimeout bounds a single detached artifact fetch so a stalled
	// VM cannot pin a goroutine, memory, or the per-token in-flight counter.
	artifactFetchTimeout = 90 * time.Second

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
	// WarmPool is the optional pre-created VM pool. When set, handleSession
	// tries to acquire a warm VM before falling back to the synchronous
	// Lease() create path. Nil disables warm-pool handout.
	WarmPool *Pool
	// Gate validates public invite codes before a VM is leased. Required.
	Gate *livechat.Gate
	// DefaultCode, when non-empty, is the invite code used when a session request
	// arrives with no code. It MUST be one of the Gate's configured codes, and is
	// only safe to set when a human gate (Turnstile or Cloudflare Access) protects
	// session creation — the caller (main) enforces that. Empty means a code is
	// always required. It is never sent to clients.
	DefaultCode string
	// TurnstileSitekey is the PUBLIC Cloudflare Turnstile site key, reported via
	// /health so the viewer can render the widget. Empty means no Turnstile
	// widget (Access-gated or unsafe-no-gate deploy). The secret is held by
	// HumanVerifier, never here.
	TurnstileSitekey string
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

	// bundleCache holds sealed artifacts so re-downloads and kit-then-raw
	// flows survive VM teardown. Keyed by (token, os).
	bundleCache *artifactCache

	mu       sync.Mutex
	tokens   map[string]*tokenLease
	bySess   map[string]string
	starts   []time.Time
	closed   bool
	reapDone chan struct{}

	// bundleInflight counts in-flight bundle-download requests per token, and
	// bundleSealed records tokens whose artifact is durably cached. Together
	// they hold the VM until every concurrent download for a token finishes, so
	// a fast variant (raw bundle, a double-click, a second tab) cannot
	// release/destroy the VM while another variant is still being fetched. Both
	// are guarded by mu.
	bundleInflight map[string]int
	bundleSealed   map[string]bool
	bundleFailed   map[string]bool
	// fetchMu serializes concurrent identical (token, os) cache misses so only
	// one request reads a full artifact from the VM into memory. Entries are
	// removed after the last waiter leaves so long-running brokers cannot grow
	// one lock per historical session. Guarded by mu.
	fetchMu map[artifactCacheKey]*artifactFetchLock
}

type tokenLease struct {
	token      string
	sessionKey string
	lease      *Lease
	deadline   time.Time
}

// artifactCacheKey identifies a cached artifact by session token and OS
// variant (empty string = the raw .tar.gz bundle).
type artifactCacheKey struct {
	token string
	os    string
}

type artifactFetchLock struct {
	mu   sync.Mutex
	refs int
}

// artifactCacheEntry holds a single sealed artifact served to visitors.
type artifactCacheEntry struct {
	body               []byte
	contentType        string
	contentDisposition string
	insertedAt         time.Time
}

// artifactCache is a bounded in-memory cache for sealed session artifacts,
// keyed by (token, os). It survives VM teardown so re-downloads and kit-then-
// raw flows work after the VM is destroyed.
type artifactCache struct {
	mu       sync.Mutex
	entries  map[artifactCacheKey]*artifactCacheEntry
	ttl      time.Duration
	curBytes int64
}

func newArtifactCache(ttl time.Duration) *artifactCache {
	return &artifactCache{
		entries: make(map[artifactCacheKey]*artifactCacheEntry),
		ttl:     ttl,
	}
}

// evictLocked removes an entry and decrements the byte total. Caller holds mu.
// It is safe to call inside a range over c.entries (Go permits delete-on-range).
func (c *artifactCache) evictLocked(key artifactCacheKey) {
	if e, ok := c.entries[key]; ok {
		c.curBytes -= int64(len(e.body))
		delete(c.entries, key)
	}
}

// get returns the cached artifact for the key, or nil if absent/expired.
func (c *artifactCache) get(key artifactCacheKey) *artifactCacheEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok {
		return nil
	}
	if time.Since(e.insertedAt) > c.ttl {
		c.evictLocked(key)
		return nil
	}
	return e
}

// put stores an artifact, evicting expired entries first and then the oldest
// entries until both the entry-count cap AND the total-byte budget are
// satisfied. The byte budget bounds worst-case memory regardless of how many
// large verify kits are cached at once.
func (c *artifactCache) put(key artifactCacheKey, e *artifactCacheEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// Replace any existing entry for this key (adjust the byte total).
	c.evictLocked(key)
	// Evict expired entries.
	now := time.Now()
	for k, v := range c.entries {
		if now.Sub(v.insertedAt) > c.ttl {
			c.evictLocked(k)
		}
	}
	// Evict the oldest entries until within both the entry and byte budgets.
	newBytes := int64(len(e.body))
	for len(c.entries) >= maxArtifactCacheEntries ||
		(len(c.entries) > 0 && c.curBytes+newBytes > maxArtifactCacheBytes) {
		var oldestKey artifactCacheKey
		var oldestTime time.Time
		first := true
		for k, v := range c.entries {
			if first || v.insertedAt.Before(oldestTime) {
				oldestKey, oldestTime, first = k, v.insertedAt, false
			}
		}
		if first {
			break
		}
		c.evictLocked(oldestKey)
	}
	c.entries[key] = e
	c.curBytes += newBytes
}

// len returns the number of entries (for testing).
func (c *artifactCache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// bytesLen returns the tracked total cached bytes (for testing).
func (c *artifactCache) bytesLen() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.curBytes
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
	// The artifact cache TTL covers the session TTL plus generous grace for
	// re-downloads. 10 minutes is safe: cached bytes are the visitor-facing
	// signed artifact (offline-verifiable), not secrets.
	const artifactCacheTTL = 10 * time.Minute
	s := &Server{
		cfg:            cfg,
		ipRate:         livechat.NewRateLimiter(cfg.IPRate),
		codeRate:       livechat.NewRateLimiter(cfg.CodeRate),
		perIP:          livechat.NewKeyedDailyBudget(cfg.PerIPDailyBudget, 0),
		perCode:        livechat.NewKeyedDailyBudget(cfg.PerCodeDailyBudget, 0),
		global:         livechat.NewDailyBudget(cfg.GlobalDailyBudget),
		client:         client,
		vmReadyTimeout: vmReadyTimeout,
		bundleCache:    newArtifactCache(artifactCacheTTL),
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

// Kill refuses new sessions/messages, releases every active lease, and drains
// the warm pool (so a killed broker holds no standing compute/spend and does not
// keep replenishing warm VMs).
func (s *Server) Kill() {
	s.killed.Store(true)
	s.releaseAll()
	if s.cfg.WarmPool != nil {
		s.cfg.WarmPool.Pause(context.Background())
	}
}

// Resume clears the kill switch for future sessions and re-enables warm-pool
// refill.
func (s *Server) Resume() {
	s.killed.Store(false)
	if s.cfg.WarmPool != nil {
		s.cfg.WarmPool.Resume()
	}
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
		// code_required is false when a server-side DefaultCode is configured
		// (Access-gated deploys): the viewer then auto-starts instead of
		// prompting for an invite code.
		"code_required": s.cfg.DefaultCode == "",
		// turnstile_sitekey is the public site key (empty if no Turnstile gate);
		// the viewer renders the widget and sends turnstile_token when present.
		"turnstile_sitekey": s.cfg.TurnstileSitekey,
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
	// An empty client code falls back to the configured DefaultCode. DefaultCode is
	// only ever set when a human gate (Turnstile or Cloudflare Access) protects
	// session creation, so the human proof — not the invite-code prompt — is the
	// public authorization step. The default code is server-side only (never
	// embedded in client JS). When no DefaultCode is configured, an empty code is
	// still rejected.
	code := body.Code
	if code == "" {
		code = s.cfg.DefaultCode
	}
	if code == "" {
		writeBrokerErr(w, http.StatusUnauthorized, "invite code rejected")
		return
	}
	if !s.global.Open() {
		writeBrokerErr(w, http.StatusServiceUnavailable, "daily limit reached, the demo is paused until tomorrow")
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
	sessionKey, err := newBrokerSessionKey()
	if err != nil {
		writeBrokerErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	_, claims, err := s.cfg.Gate.Redeem(code, sessionKey)
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

	codeLimiterKey := "code:" + claims.CodeID
	if !s.codeRate.Allow(codeLimiterKey) {
		undo()
		writeBrokerErr(w, http.StatusTooManyRequests, "rate limited")
		return
	}

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

	// Try the warm pool first for instant handout; fall through to the
	// synchronous create path if the pool is empty or disabled.
	//
	// INVARIANT 3: a visitor NEVER fails because the pool is empty.
	var lease *Lease
	var vmCode string
	if s.cfg.WarmPool != nil {
		if wm, wc, wRelease, ok := s.cfg.WarmPool.Acquire(); ok {
			vmCode = wc
			adopted, adoptErr := s.cfg.Leases.AdoptWarm(sessionKey, wm, wRelease)
			if adoptErr != nil {
				// Adoption failed (e.g. duplicate key race). Tear down the warm VM
				// through the quarantine-on-failure path so a FAILED destroy keeps
				// the slot held and the VM tracked (still reaper-protected) rather
				// than releasing the slot and forgetting a still-alive VM.
				// AbortHandoff clears the in-flight handoff marker itself.
				s.cfg.WarmPool.AbortHandoff(r.Context(), wm, wRelease, "adopt failed")
			} else {
				lease = adopted
				// Machine is now an active lease (protected by ActiveMachineIDs);
				// clear the in-flight handoff marker. Closes the reaper TOCTOU
				// window opened by Acquire.
				s.cfg.WarmPool.FinishHandoff(wm.ID)
			}
		}
	}
	if lease == nil {
		// Cold path: mint a fresh vmCode, create a VM synchronously.
		var codeErr error
		vmCode, codeErr = livechat.NewRandomCode(vmInviteCodeBytes)
		if codeErr != nil {
			undo()
			writeBrokerErr(w, http.StatusInternalServerError, "internal error")
			return
		}
		sessionEnv := mergeEnv(s.cfg.SessionEnv, map[string]string{envVMInviteCode: vmCode})
		var leaseErr error
		lease, leaseErr = s.cfg.Leases.Lease(r.Context(), sessionKey, sessionEnv)
		if leaseErr != nil {
			undo()
			if errors.Is(leaseErr, ErrAtCapacity) {
				writeBrokerErr(w, http.StatusServiceUnavailable, "at capacity, try again")
				return
			}
			writeBrokerErr(w, http.StatusServiceUnavailable, "session could not be started")
			return
		}
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
	queryToken := r.URL.Query().Get("token")
	osParam := r.URL.Query().Get("os")
	if osParam != "" {
		normalized, err := playground.ParseVerifyKitOS(osParam)
		if err != nil {
			writeBrokerErr(w, http.StatusBadRequest, "unsupported verify kit")
			return
		}
		osParam = string(normalized)
	}

	// Cache HIT: serve the cached artifact without touching the VM. This
	// makes re-downloads and kit-then-raw flows work after VM teardown.
	cacheKey := artifactCacheKey{token: queryToken, os: osParam}
	if cached := s.bundleCache.get(cacheKey); cached != nil {
		w.Header().Set("Content-Type", cached.contentType)
		w.Header().Set("Content-Disposition", cached.contentDisposition)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(cached.body)
		return
	}

	// Cache MISS: the VM must still be alive to fetch the artifact.
	binding := s.lookupToken(queryToken)
	if binding == nil {
		writeBrokerErr(w, http.StatusNotFound, "session not found")
		return
	}

	// Mark this request in-flight for the token so a concurrent download of a
	// different variant (raw bundle + OS kit, a double-click, two tabs, browser
	// prefetch/retry) cannot release/destroy the VM while another fetch is still
	// running. The VM is released only when the LAST in-flight request for the
	// token finishes AND an artifact has been durably sealed into the cache.
	s.bundleEnter(queryToken)
	defer func() {
		if s.bundleLeave(queryToken) {
			s.releaseToken(context.WithoutCancel(r.Context()), queryToken)
		}
	}()

	// Coalesce concurrent identical (token, os) misses so only ONE request reads
	// a full artifact from the VM into memory; the others serialize on this
	// per-variant lock and then read the cache the leader populated.
	fm := s.bundleFetchLock(cacheKey)
	defer s.bundleFetchUnlock(cacheKey, fm)
	if cached := s.bundleCache.get(cacheKey); cached != nil {
		w.Header().Set("Content-Type", cached.contentType)
		w.Header().Set("Content-Disposition", cached.contentDisposition)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(cached.body)
		return
	}

	// Detach the fetch from request cancellation so a client disconnect mid-fetch
	// cannot abort populating the durable cache, but bound it with a hard timeout
	// so a stalled VM cannot pin a goroutine or the in-flight counter forever.
	fetchCtx, cancelFetch := context.WithTimeout(context.WithoutCancel(r.Context()), artifactFetchTimeout)
	defer cancelFetch()

	// Fetch the requested artifact variant from the VM.
	fetched, fetchErr := s.fetchVMArtifact(fetchCtx, binding.lease, queryToken, osParam)
	if fetchErr != nil {
		// Propagate without sealing so the VM is retained for retry.
		s.bundleMarkFailed(queryToken)
		writeBrokerErr(w, http.StatusBadGateway, "session proxy unavailable")
		return
	}
	if fetched.status != http.StatusOK {
		// Non-200 from the VM (e.g. 503 seal failure): propagate and do NOT
		// seal. The visitor can retry while the VM still lives.
		s.bundleMarkFailed(queryToken)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(fetched.status)
		_, _ = w.Write(fetched.body)
		return
	}

	// Store the successfully fetched artifact in the cache and mark the token
	// sealed so the VM may be released once all in-flight requests finish.
	s.bundleCache.put(cacheKey, &artifactCacheEntry{
		body:               fetched.body,
		contentType:        fetched.contentType,
		contentDisposition: fetched.contentDisposition,
		insertedAt:         time.Now(),
	})

	// Also prefetch the raw bundle (os="") into the cache so a later
	// raw-bundle download succeeds even after the VM is gone.
	sealToken := true
	if osParam != "" {
		rawKey := artifactCacheKey{token: queryToken, os: ""}
		if s.bundleCache.get(rawKey) == nil {
			if raw, rawErr := s.fetchVMArtifact(fetchCtx, binding.lease, queryToken, ""); rawErr == nil && raw.status == http.StatusOK {
				s.bundleCache.put(rawKey, &artifactCacheEntry{
					body:               raw.body,
					contentType:        raw.contentType,
					contentDisposition: raw.contentDisposition,
					insertedAt:         time.Now(),
				})
			} else {
				sealToken = false
				s.bundleMarkFailed(queryToken)
			}
		}
	}
	if sealToken {
		s.bundleSeal(queryToken)
	}

	// Serve the fetched artifact to the client. VM release happens in the
	// deferred bundleLeave once the last in-flight request for the token ends.
	w.Header().Set("Content-Type", fetched.contentType)
	w.Header().Set("Content-Disposition", fetched.contentDisposition)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(fetched.body)
}

// bundleEnter records a handleBundle request as in-flight for the token so the
// VM is not released while a concurrent artifact fetch for the same token is
// still running.
func (s *Server) bundleEnter(token string) {
	s.mu.Lock()
	if s.bundleInflight == nil {
		s.bundleInflight = make(map[string]int)
	}
	s.bundleInflight[token]++
	s.mu.Unlock()
}

// bundleFetchLock locks the per-(token, os) mutex used to coalesce concurrent
// identical cache misses so only one request fetches the artifact from the VM.
// The returned lock must be released with bundleFetchUnlock.
func (s *Server) bundleFetchLock(key artifactCacheKey) *artifactFetchLock {
	s.mu.Lock()
	if s.fetchMu == nil {
		s.fetchMu = make(map[artifactCacheKey]*artifactFetchLock)
	}
	m := s.fetchMu[key]
	if m == nil {
		m = &artifactFetchLock{}
		s.fetchMu[key] = m
	}
	m.refs++
	s.mu.Unlock()
	m.mu.Lock()
	return m
}

func (s *Server) bundleFetchUnlock(key artifactCacheKey, m *artifactFetchLock) {
	m.mu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	m.refs--
	if m.refs == 0 && s.fetchMu[key] == m {
		delete(s.fetchMu, key)
	}
}

// bundleSeal records that an artifact for the token has been durably cached, so
// the VM may be released once all in-flight requests finish.
func (s *Server) bundleSeal(token string) {
	s.mu.Lock()
	if s.bundleSealed == nil {
		s.bundleSealed = make(map[string]bool)
	}
	s.bundleSealed[token] = true
	s.mu.Unlock()
}

func (s *Server) bundleMarkFailed(token string) {
	s.mu.Lock()
	if s.bundleFailed == nil {
		s.bundleFailed = make(map[string]bool)
	}
	s.bundleFailed[token] = true
	s.mu.Unlock()
}

// bundleLeave decrements the in-flight count for the token. It returns true if
// this was the last in-flight request, an artifact was sealed, and no concurrent
// artifact fetch failed, meaning the caller should release the VM now. If any
// fetch in the wave failed, the VM is retained for retry and the reaper reclaims
// it at TTL. This preserves the "try another variant / retry the failed
// download" path instead of letting one successful variant tear down the VM
// behind a concurrent failed one.
func (s *Server) bundleLeave(token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bundleInflight[token]--
	if s.bundleInflight[token] > 0 {
		return false
	}
	delete(s.bundleInflight, token)
	sealed := s.bundleSealed[token]
	failed := s.bundleFailed[token]
	delete(s.bundleFailed, token)
	if failed {
		return false
	}
	delete(s.bundleSealed, token)
	return sealed
}

// vmArtifact holds the result of a direct bounded GET to the VM's bundle route.
type vmArtifact struct {
	status             int
	body               []byte
	contentType        string
	contentDisposition string
}

// fetchVMArtifact makes a bounded HTTP GET to the VM's bundle endpoint and
// reads the full response body into memory. It does NOT use the streaming
// reverse proxy because the broker needs the complete body to cache it.
func (s *Server) fetchVMArtifact(ctx context.Context, lease *Lease, vmToken, osParam string) (vmArtifact, error) {
	target, err := s.targetURL(lease, livechat.RouteBundle)
	if err != nil {
		return vmArtifact{}, err
	}
	q := target.Query()
	q.Set("token", vmToken)
	if osParam != "" {
		q.Set("os", osParam)
	}
	target.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return vmArtifact{}, fmt.Errorf("broker: build bundle request: %w", err)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return vmArtifact{}, fmt.Errorf("broker: fetch bundle: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Verify kits (os != "") bundle a platform verifier binary and are far
	// larger than the raw bundle, so they get a separate, higher cap.
	sizeCap := int64(maxArtifactBytes)
	if osParam != "" {
		sizeCap = int64(maxKitBytes)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, sizeCap+1))
	if err != nil {
		return vmArtifact{}, fmt.Errorf("broker: read bundle body: %w", err)
	}
	if int64(len(body)) > sizeCap {
		return vmArtifact{}, fmt.Errorf("broker: bundle body exceeds %d bytes", sizeCap)
	}

	return vmArtifact{
		status:             resp.StatusCode,
		body:               body,
		contentType:        resp.Header.Get("Content-Type"),
		contentDisposition: resp.Header.Get("Content-Disposition"),
	}, nil
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

	respBody, err := io.ReadAll(io.LimitReader(httpResp.Body, maxBrokerBodyBytes+1))
	if err != nil {
		return vmSessionResponse{}, time.Time{}, false, fmt.Errorf("broker: read vm session response: %w", err)
	}
	if len(respBody) > maxBrokerBodyBytes {
		return vmSessionResponse{}, time.Time{}, false, fmt.Errorf("broker: vm session response exceeds %d bytes", maxBrokerBodyBytes)
	}
	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		return vmSessionResponse{}, time.Time{}, false, fmt.Errorf("broker: vm session status %d", httpResp.StatusCode)
	}
	if err := jsonscan.RejectDuplicateKeys(respBody); err != nil {
		return vmSessionResponse{}, time.Time{}, false, fmt.Errorf("broker: parse vm session response: %w", err)
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
	// An invite-code redemption failure is an authentication problem (a bad or
	// spent code), distinct from the human-verification gate (403). Returning
	// 401 lets the viewer tell the visitor to fix their code rather than retry
	// the human check.
	return http.StatusUnauthorized
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
