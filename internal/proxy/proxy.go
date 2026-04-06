// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package proxy implements the Pipelock fetch proxy HTTP server.
// The fetch proxy runs in an unprivileged zone with NO access to secrets.
// It receives URL requests from the agent, scans them, fetches content,
// and returns extracted text.
package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	readability "github.com/go-shiori/go-readability"
	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/capture"
	"github.com/luckyPipewrench/pipelock/internal/certgen"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/decide"
	"github.com/luckyPipewrench/pipelock/internal/edition"
	"github.com/luckyPipewrench/pipelock/internal/hitl"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
	"github.com/luckyPipewrench/pipelock/internal/mcp"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/session"
	"github.com/luckyPipewrench/pipelock/internal/shield"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

// contextKey is used for storing per-request values in context.
type contextKey int

const (
	ctxKeyClientIP contextKey = iota
	ctxKeyRequestID
	ctxKeyAgent
	ctxKeyAgentConfig  // per-agent resolved config for redirect scanning
	ctxKeyAgentScanner // per-agent resolved scanner for redirect scanning
)

const (
	schemeHTTP  = "http"
	schemeHTTPS = "https"

	// maxCEESessions bounds memory used by fragment tracking across all sessions.
	// 10,000 sessions at 64KB each = ~640MB worst case. In practice, most
	// deployments have <100 concurrent sessions.
	maxCEESessions = 10000
)

// requestCounter provides monotonic request IDs.
var requestCounter atomic.Uint64

// Regex patterns for extracting content from HTML hiding spots that
// readability strips (comments, script bodies, style bodies). We scan
// only these extracted fragments for injection, not the full HTML markup,
// to avoid false positives on legitimate HTML tags and attributes.
var (
	reHTMLComment   = regexp.MustCompile(`(?s)<!--(.*?)-->`)
	reScriptBody    = regexp.MustCompile(`(?si)<script[^>]*>(.*?)</script>`)
	reStyleBody     = regexp.MustCompile(`(?si)<style[^>]*>(.*?)</style>`)
	reHiddenElement = regexp.MustCompile(`(?si)<[a-z][a-z0-9]*\b` +
		`(?:[^>]*?(?:display\s*:\s*none|visibility\s*:\s*hidden)|[^>]*?\shidden)` +
		`[^>]*>(.*?)</`)
)

// extractHiddenContent pulls text from HTML elements that readability
// strips: comments, script bodies, and style bodies. Returns the
// concatenated text from these hiding spots (empty if none found).
func extractHiddenContent(html string) string {
	var b strings.Builder
	for _, m := range reHTMLComment.FindAllStringSubmatch(html, -1) {
		b.WriteString(m[1])
		b.WriteByte('\n')
	}
	for _, m := range reScriptBody.FindAllStringSubmatch(html, -1) {
		b.WriteString(m[1])
		b.WriteByte('\n')
	}
	for _, m := range reStyleBody.FindAllStringSubmatch(html, -1) {
		b.WriteString(m[1])
		b.WriteByte('\n')
	}
	for _, m := range reHiddenElement.FindAllStringSubmatch(html, -1) {
		b.WriteString(m[1])
		b.WriteByte('\n')
	}
	return b.String()
}

// requestMeta extracts the client IP (port stripped) and a unique request ID
// from the incoming request. Used by all proxy handler paths.
func requestMeta(r *http.Request) (clientIP, requestID string) {
	clientIP = r.RemoteAddr
	if host, _, err := net.SplitHostPort(clientIP); err == nil {
		clientIP = host
	}
	requestID = fmt.Sprintf("req-%d", requestCounter.Add(1))
	return
}

// Version is set at build time via ldflags.
var Version = "0.1.0-dev"

// editionSnapshot wraps an Edition for atomic pointer storage.
type editionSnapshot struct{ edition.Edition }

// Proxy is the Pipelock fetch proxy server.
type Proxy struct {
	cfgPtr            atomic.Pointer[config.Config]
	scannerPtr        atomic.Pointer[scanner.Scanner]
	editionPtr        atomic.Pointer[editionSnapshot]
	sessionMgrPtr     atomic.Pointer[SessionManager]         // nil when profiling disabled
	certCachePtr      atomic.Pointer[certgen.CertCache]      // nil when TLS interception disabled
	entropyTrackerPtr atomic.Pointer[scanner.EntropyTracker] // nil when entropy budget disabled
	fragmentBufferPtr atomic.Pointer[scanner.FragmentBuffer] // nil when fragment reassembly disabled
	logger            *audit.Logger
	metrics           *metrics.Metrics
	ks                *killswitch.Controller
	ksAPI             *killswitch.APIHandler
	sessionAPI        *SessionAPIHandler
	dialer            *net.Dialer
	client            *http.Client
	tlsTransport      *http.Transport // shared Transport for TLS interception upstream connections
	server            *http.Server
	agentServers      []*http.Server // per-agent listeners (managed by CLI)
	startTime         time.Time
	reloadMu          sync.Mutex // serializes Reload calls
	approver          *hitl.Approver
	a2aCardBaseline   *mcp.CardBaseline // Agent Card drift detection across requests
	captureObs        capture.CaptureObserver
	recorder          *recorder.Recorder              // flight recorder for tamper-evident evidence (nil = disabled)
	receiptEmitterPtr atomic.Pointer[receipt.Emitter] // action receipt emitter (nil = disabled)
	receiptKeyPath    string                          // active signing key path, for reload comparison
	shieldEngine      *shield.Engine                  // browser shield HTML/JS rewriter (nil = not initialized)
	frozenTools       *FrozenToolRegistry             // frozen tool inventories for airlock hard tier
}

// Option configures optional Proxy behavior.
type Option func(*Proxy)

// WithApprover sets a HITL approver for the "ask" response scanning action.
func WithApprover(a *hitl.Approver) Option {
	return func(p *Proxy) { p.approver = a }
}

// WithKillSwitch sets the emergency deny-all kill switch controller.
func WithKillSwitch(ks *killswitch.Controller) Option {
	return func(p *Proxy) { p.ks = ks }
}

// WithKillSwitchAPI sets the kill switch API handler for registering routes.
func WithKillSwitchAPI(api *killswitch.APIHandler) Option {
	return func(p *Proxy) { p.ksAPI = api }
}

// WithCaptureObserver sets the policy capture observer for recording verdicts
// at each proxy scanning stage. Pass nil to disable capture (NopObserver is
// used by default).
func WithCaptureObserver(obs capture.CaptureObserver) Option {
	return func(p *Proxy) { p.captureObs = obs }
}

// WithRecorder sets the flight recorder for tamper-evident evidence logging.
// When non-nil, the proxy records enforcement decisions to the hash-chained
// evidence log. Pass nil to disable (default).
func WithRecorder(rec *recorder.Recorder) Option {
	return func(p *Proxy) { p.recorder = rec }
}

// WithReceiptEmitter sets the action receipt emitter. When non-nil, the proxy
// emits signed action receipts for every enforcement decision to the flight
// recorder. Pass nil to disable (default).
func WithReceiptEmitter(e *receipt.Emitter) Option {
	return func(p *Proxy) { p.receiptEmitterPtr.Store(e) }
}

// WithReceiptKeyPath sets the initial signing key path for reload comparison.
// Must match the key used to construct the emitter passed to WithReceiptEmitter
// so that reload can detect key rotation.
func WithReceiptKeyPath(path string) Option {
	return func(p *Proxy) { p.receiptKeyPath = path }
}

// FetchResponse is the JSON response returned by the /fetch endpoint.
type FetchResponse struct {
	URL         string `json:"url"`
	Agent       string `json:"agent,omitempty"`
	StatusCode  int    `json:"status_code,omitempty"`
	ContentType string `json:"content_type,omitempty"`
	Title       string `json:"title,omitempty"`
	Content     string `json:"content,omitempty"`
	Error       string `json:"error,omitempty"`
	Blocked     bool   `json:"blocked"`
	BlockReason string `json:"block_reason,omitempty"`
	Hint        string `json:"hint,omitempty"`
}

// New creates a new fetch proxy from config.
func New(cfg *config.Config, logger *audit.Logger, sc *scanner.Scanner, m *metrics.Metrics, opts ...Option) (*Proxy, error) {
	p := &Proxy{
		logger:          logger,
		metrics:         m,
		startTime:       time.Now(),
		a2aCardBaseline: mcp.NewCardBaseline(1000), // 1000-entry LRU for Agent Card drift detection
	}
	for _, opt := range opts {
		opt(p)
	}
	if p.captureObs == nil {
		p.captureObs = capture.NopObserver{}
	}
	p.cfgPtr.Store(cfg)
	p.scannerPtr.Store(sc)

	// Build edition (agent registry in enterprise, noop in OSS).
	ed, edErr := edition.NewEditionFunc(cfg, sc)
	if edErr != nil {
		return nil, fmt.Errorf("edition init: %w", edErr)
	}
	p.editionPtr.Store(&editionSnapshot{ed})

	if cfg.SessionProfiling.Enabled {
		var adaptiveCfg *config.AdaptiveEnforcement
		if cfg.AdaptiveEnforcement.Enabled {
			adaptiveCfg = &cfg.AdaptiveEnforcement
		}
		smOpts := SessionManagerOptions{Logger: logger}
		if cfg.Airlock.Enabled {
			smOpts.AirlockCfg = &cfg.Airlock
		}
		sm := NewSessionManager(&cfg.SessionProfiling, adaptiveCfg, m, smOpts)
		if cfg.BehavioralBaseline.Enabled {
			_ = sm.EnableBaseline(&cfg.BehavioralBaseline) // validated at Load time
		}
		p.sessionMgrPtr.Store(sm)
	}

	// Initialize shield engine and frozen tool registry.
	p.shieldEngine = shield.NewEngine(cfg.BrowserShield.TrackingDomains)
	p.frozenTools = NewFrozenToolRegistry()

	p.setupCEE(&cfg.CrossRequestDetection)

	// Create session admin API handler when an API token is configured.
	// Mirrors the kill switch env-var override: PIPELOCK_KILLSWITCH_API_TOKEN
	// takes precedence over the YAML value.
	apiToken := cfg.KillSwitch.APIToken
	if envToken := os.Getenv(killswitch.EnvAPIToken); envToken != "" {
		apiToken = envToken
	}
	if apiToken != "" {
		p.sessionAPI = NewSessionAPIHandler(
			&p.sessionMgrPtr,
			&p.entropyTrackerPtr,
			&p.fragmentBufferPtr,
			m,
			logger,
			apiToken,
		)
	}

	p.dialer = &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	transport := &http.Transport{
		DialContext:           p.ssrfSafeDialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: time.Duration(cfg.FetchProxy.TimeoutSeconds) * time.Second,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
	}

	p.client = &http.Client{
		Transport: transport,
		Timeout:   time.Duration(cfg.FetchProxy.TimeoutSeconds) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects (max 5)")
			}
			originalURL := via[0].URL.String()
			redirectURL := req.URL.String()
			clientIP, _ := req.Context().Value(ctxKeyClientIP).(string)
			requestID, _ := req.Context().Value(ctxKeyRequestID).(string)
			agentName, _ := req.Context().Value(ctxKeyAgent).(string)
			logger.LogRedirect(originalURL, redirectURL, clientIP, requestID, agentName, len(via))
			// Scan redirect URL with the per-agent scanner when available.
			// Handlers attach the resolved agent config/scanner to the
			// request context so redirect enforcement matches the agent
			// profile, not the global default. Falls back to the global
			// config/scanner for backward compatibility (pre-agent paths).
			currentCfg, _ := req.Context().Value(ctxKeyAgentConfig).(*config.Config)
			if currentCfg == nil {
				currentCfg = p.cfgPtr.Load()
			}
			currentScanner, _ := req.Context().Value(ctxKeyAgentScanner).(*scanner.Scanner)
			if currentScanner == nil {
				currentScanner = p.scannerPtr.Load()
			}
			result := currentScanner.Scan(req.Context(), redirectURL)
			if !result.Allowed {
				actx := audit.LogContext{
					Method:    req.Method,
					URL:       redirectURL,
					ClientIP:  clientIP,
					RequestID: requestID,
					Agent:     agentName,
				}
				if currentCfg.EnforceEnabled() {
					logger.LogBlocked(actx, "redirect", fmt.Sprintf("redirect from %s blocked: %s", originalURL, result.Reason))
					return fmt.Errorf("redirect blocked: %s", result.Reason)
				}
				logger.LogAnomaly(actx, result.Scanner, fmt.Sprintf("redirect from %s: %s", originalURL, result.Reason), result.Score)
			}
			return nil
		},
	}

	p.tlsTransport = newTLSInterceptTransport(p.ssrfSafeDialContext, m.RecordTLSHandshake, nil)

	return p, nil
}

// recordDecision writes an enforcement verdict to the flight recorder if enabled.
// Uses Record (not RecordDecision) so entries are hash-chained without requiring
// an Ed25519 signing key. Checkpoints are still signed when sign_checkpoints is
// enabled. Errors are logged but never block the proxy hot path.
func (p *Proxy) recordDecision(verdict, layer, pattern, transport, requestID string) {
	if p.recorder == nil {
		return
	}

	summary := verdict + ": " + layer
	if pattern != "" {
		summary += " (" + pattern + ")"
	}

	_ = p.recorder.Record(recorder.Entry{
		SessionID: "proxy",
		Type:      "decision",
		Transport: transport,
		Summary:   summary,
		Detail: map[string]string{
			"verdict":    verdict,
			"layer":      layer,
			"pattern":    pattern,
			"request_id": requestID,
		},
	})
}

// emitReceipt creates and records a signed action receipt for a proxy decision.
// Safe to call when the emitter is nil (no-op). The call is synchronous
// through the recorder mutex — same cost as recordDecision. Errors are logged
// but not propagated.
func (p *Proxy) emitReceipt(opts receipt.EmitOpts) {
	e := p.receiptEmitterPtr.Load()
	if e == nil {
		return
	}
	if err := e.Emit(opts); err != nil {
		p.logger.LogError(audit.LogContext{RequestID: opts.RequestID}, err)
	}
}

// reloadReceiptEmitter handles receipt emitter lifecycle on config reload.
// Creates a new emitter if a signing key appears, updates the config hash
// if the emitter exists, or nils it if the key is removed. Must be called
// under reloadMu.
func (p *Proxy) reloadReceiptEmitter(cfg *config.Config) {
	keyPath := cfg.FlightRecorder.SigningKeyPath

	if keyPath == "" {
		// No signing key configured — disable receipts if they were on.
		p.receiptEmitterPtr.Store(nil)
		p.receiptKeyPath = ""
		return
	}

	// Always reload the key file to detect both path changes and
	// in-place content changes (key rotation at the same path).
	if p.recorder == nil {
		return
	}

	privKey, err := signing.LoadPrivateKeyFile(filepath.Clean(keyPath))
	if err != nil {
		// Failure is non-fatal: log and keep the prior emitter (if any) so
		// receipts continue with the old key rather than going dark entirely.
		if p.logger != nil {
			p.logger.LogError(audit.LogContext{Method: "RELOAD"}, fmt.Errorf("loading receipt signing key: %w", err))
		}
		return
	}

	p.receiptEmitterPtr.Store(receipt.NewEmitter(receipt.EmitterConfig{
		Recorder:   p.recorder,
		PrivKey:    privKey,
		ConfigHash: cfg.Hash(),
		Principal:  "local",
		Actor:      "pipelock",
	}))
	p.receiptKeyPath = keyPath
}

// CurrentConfig returns the currently active config. Used for reload comparison.
func (p *Proxy) CurrentConfig() *config.Config {
	return p.cfgPtr.Load()
}

// ConfigPtr returns the atomic config pointer. Used by the reverse proxy
// handler to share the same config and receive hot-reload updates.
func (p *Proxy) ConfigPtr() *atomic.Pointer[config.Config] {
	return &p.cfgPtr
}

// ScannerPtr returns the atomic scanner pointer. Used by the reverse proxy
// handler to share the same scanner and receive hot-reload updates.
func (p *Proxy) ScannerPtr() *atomic.Pointer[scanner.Scanner] {
	return &p.scannerPtr
}

// SessionMgrPtr returns the atomic pointer to the session manager.
// Used by run.go to construct the session API handler for the dedicated port.
func (p *Proxy) SessionMgrPtr() *atomic.Pointer[SessionManager] {
	return &p.sessionMgrPtr
}

// EntropyTrackerPtr returns the atomic pointer to the entropy tracker.
// Used by run.go to construct the session API handler for the dedicated port.
func (p *Proxy) EntropyTrackerPtr() *atomic.Pointer[scanner.EntropyTracker] {
	return &p.entropyTrackerPtr
}

// FragmentBufferPtr returns the atomic pointer to the fragment buffer.
// Used by run.go to construct the session API handler for the dedicated port.
func (p *Proxy) FragmentBufferPtr() *atomic.Pointer[scanner.FragmentBuffer] {
	return &p.fragmentBufferPtr
}

// Reload atomically swaps the config and scanner for hot-reload support.
// The old scanner is closed to release its rate limiter goroutine.
// Session manager lifecycle is toggled when session_profiling.enabled changes.
//
// Note: HTTP client timeouts, transport settings, and server listen address
// are set at construction in New()/Start() and are NOT updated by Reload.
// Only config values read per-request (mode, enforce, user-agent, blocklists,
// DLP patterns, response scanning, etc.) take effect immediately.
func (p *Proxy) Reload(cfg *config.Config, sc *scanner.Scanner) {
	p.reloadMu.Lock()
	defer p.reloadMu.Unlock()

	// Build new edition BEFORE swapping config/scanner.
	// If this fails, keep all existing state unchanged (fail-safe).
	oldSnap := p.editionPtr.Load()
	newEd, edErr := oldSnap.Reload(cfg, sc)
	if edErr != nil {
		p.logger.LogError(audit.LogContext{Method: "RELOAD"}, fmt.Errorf("edition rebuild failed, keeping old config: %w", edErr))
		sc.Close() // caller-allocated scanner must be closed since we're not using it
		return
	}

	// Receipt emitter lifecycle: create on first signing key appearance,
	// update config hash on existing, nil on key removal. Must run BEFORE
	// config swap so receipts always reflect the policy that governed the
	// decision. Without this ordering, requests racing with reload could
	// get signed with the previous policy hash.
	p.reloadReceiptEmitter(cfg)

	oldCfg := p.cfgPtr.Load()
	p.cfgPtr.Store(cfg)
	old := p.scannerPtr.Swap(sc)

	if old != nil {
		old.Close()
	}

	if oldSnap := p.editionPtr.Swap(&editionSnapshot{newEd}); oldSnap != nil {
		oldSnap.Close()
	}

	// Toggle session manager lifecycle on config change.
	var adaptiveCfg *config.AdaptiveEnforcement
	if cfg.AdaptiveEnforcement.Enabled {
		adaptiveCfg = &cfg.AdaptiveEnforcement
	}
	var airlockCfg *config.Airlock
	if cfg.Airlock.Enabled {
		airlockCfg = &cfg.Airlock
	}
	wasEnabled := oldCfg.SessionProfiling.Enabled
	isEnabled := cfg.SessionProfiling.Enabled
	if !wasEnabled && isEnabled {
		smOpts := SessionManagerOptions{Logger: p.logger, AirlockCfg: airlockCfg}
		sm := NewSessionManager(&cfg.SessionProfiling, adaptiveCfg, p.metrics, smOpts)
		if cfg.BehavioralBaseline.Enabled {
			_ = sm.EnableBaseline(&cfg.BehavioralBaseline)
		}
		p.sessionMgrPtr.Store(sm)
	} else if wasEnabled && !isEnabled {
		if old := p.sessionMgrPtr.Swap(nil); old != nil {
			old.Close()
		}
	} else if wasEnabled && isEnabled {
		// Config values changed while profiling stays enabled — update in place
		// so TTL/capacity thresholds take effect without losing session state.
		if sm := p.sessionMgrPtr.Load(); sm != nil {
			sm.UpdateConfig(&cfg.SessionProfiling, adaptiveCfg, airlockCfg)
		}
	}

	// Toggle CEE components on config change. Build new components before
	// swapping to avoid a nil window where concurrent requests bypass CEE.
	// Entropy/fragment data is lost on reload, which is acceptable for short
	// sliding windows (typically 5 min).
	newET, newFB := p.buildCEE(&cfg.CrossRequestDetection)
	if oldET := p.entropyTrackerPtr.Swap(newET); oldET != nil {
		oldET.Close()
	}
	if oldFB := p.fragmentBufferPtr.Swap(newFB); oldFB != nil {
		oldFB.Close()
	}
	p.updateCEEStats()

	// Receipt emitter hash is updated by reloadReceiptEmitter above.
	// No separate UpdateConfigHash needed — emitter is always (re)created
	// with the current cfg.Hash() when a signing key is configured.
}

// LoadCertCache creates or replaces the cert cache based on current config.
// Called at startup and on hot-reload when TLS interception config changes.
func (p *Proxy) LoadCertCache(cfg *config.Config) error {
	if !cfg.TLSInterception.Enabled {
		p.certCachePtr.Store(nil)
		return nil
	}
	certPath, keyPath, resolveErr := cfg.ResolveCAPath()
	if resolveErr != nil {
		return fmt.Errorf("load TLS CA: %w", resolveErr)
	}
	ca, caKey, err := certgen.LoadCA(certPath, keyPath)
	if err != nil {
		return fmt.Errorf("load TLS CA: %w (run 'pipelock tls init' to generate)", err)
	}
	ttl, _ := time.ParseDuration(cfg.TLSInterception.CertTTL) // already validated
	cache := certgen.NewCertCache(ca, caKey, ttl, cfg.TLSInterception.CertCacheSize)
	p.certCachePtr.Store(cache)
	return nil
}

// Close releases resources owned by the proxy (session manager goroutine,
// agent registry scanners). Safe to call multiple times. Does not stop the
// HTTP server — use context cancellation in Start() for that.
// RegisterAgentServer adds an externally-managed agent server to the
// proxy's shutdown list. Called by the CLI layer after binding agent
// listeners, so Start()'s shutdown goroutine can gracefully stop them.
func (p *Proxy) RegisterAgentServer(srv *http.Server) {
	p.agentServers = append(p.agentServers, srv)
}

// ShutdownAgentServers gracefully shuts down all registered agent servers.
// Used by the license expiry watchdog to unbind per-agent listeners when
// the enterprise license expires at runtime.
func (p *Proxy) ShutdownAgentServers() {
	for _, srv := range p.agentServers {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = srv.Shutdown(ctx)
		cancel()
	}
}

// buildCEE creates entropy tracker and fragment buffer based on the config.
// Returns nil for disabled components. Called from setupCEE and Reload.
func (p *Proxy) buildCEE(ceeCfg *config.CrossRequestDetection) (*scanner.EntropyTracker, *scanner.FragmentBuffer) {
	var et *scanner.EntropyTracker
	var fb *scanner.FragmentBuffer
	if ceeCfg.Enabled {
		if ceeCfg.EntropyBudget.Enabled {
			et = scanner.NewEntropyTracker(
				ceeCfg.EntropyBudget.BitsPerWindow,
				ceeCfg.EntropyBudget.WindowMinutes*60, // minutes to seconds
			)
		}
		if ceeCfg.FragmentReassembly.Enabled {
			fb = scanner.NewFragmentBuffer(
				ceeCfg.FragmentReassembly.MaxBufferBytes,
				maxCEESessions,
				ceeCfg.FragmentReassembly.WindowMinutes*60, // minutes to seconds
			)
		}
	}
	return et, fb
}

// setupCEE creates and stores entropy tracker and fragment buffer based on
// the cross-request detection config. Called from New() at startup.
func (p *Proxy) setupCEE(ceeCfg *config.CrossRequestDetection) {
	et, fb := p.buildCEE(ceeCfg)
	p.entropyTrackerPtr.Store(et)
	p.fragmentBufferPtr.Store(fb)
	p.updateCEEStats()
}

// updateCEEStats registers a callback so CEE state is available through the
// /stats endpoint. The callback reads atomic pointers, so it captures the
// proxy reference once and queries current state on each /stats request.
func (p *Proxy) updateCEEStats() {
	p.metrics.SetCEEStatsFunc(func() metrics.CEEStats {
		var stats metrics.CEEStats
		if et := p.entropyTrackerPtr.Load(); et != nil {
			stats.EntropyTrackerActive = true
		}
		if fb := p.fragmentBufferPtr.Load(); fb != nil {
			stats.FragmentBufferActive = true
			stats.FragmentBufferBytes = fb.TotalBufferBytes()
		}
		return stats
	})
}

func (p *Proxy) Close() {
	if sm := p.sessionMgrPtr.Load(); sm != nil {
		sm.Close()
	}
	if sc := p.scannerPtr.Load(); sc != nil {
		sc.Close()
	}
	if snap := p.editionPtr.Load(); snap != nil {
		snap.Close()
	}
	if et := p.entropyTrackerPtr.Load(); et != nil {
		et.Close()
	}
	if fb := p.fragmentBufferPtr.Load(); fb != nil {
		fb.Close()
	}
	if p.tlsTransport != nil {
		p.tlsTransport.CloseIdleConnections()
	}
}

// SessionStore returns the proxy's session store for sharing with MCP transports.
// Returns nil when session profiling is disabled.
func (p *Proxy) SessionStore() session.Store {
	if sm := p.sessionMgrPtr.Load(); sm != nil {
		return sm.AsStore()
	}
	return nil
}

// resolveAgent returns the ResolvedAgent for the given profile name.
// Delegates to the current Edition's LookupProfile.
func (p *Proxy) resolveAgent(profile string) *edition.ResolvedAgent {
	resolved, _ := p.editionPtr.Load().LookupProfile(profile)
	return resolved
}

// knownProfiles returns a set of profile names from the current edition.
// Used by proxy-local agent resolution for bounded-cardinality metrics.
func (p *Proxy) knownProfiles() map[string]bool {
	return p.editionPtr.Load().KnownProfiles()
}

// resolveAgentFromRequest delegates to the Edition's ResolveAgent.
// The Edition handles context override, CIDR, header/query, and fallback.
func (p *Proxy) resolveAgentFromRequest(r *http.Request) (*edition.ResolvedAgent, edition.AgentIdentity) {
	return p.editionPtr.Load().ResolveAgent(r.Context(), r)
}

// Edition returns the current active Edition.
func (p *Proxy) Edition() edition.Edition {
	return p.editionPtr.Load().Edition
}

// Ports returns the per-agent listener port mappings from the current edition.
func (p *Proxy) Ports() map[string]string {
	return p.editionPtr.Load().Ports()
}

// newTLSInterceptTransport creates a shared http.Transport for TLS interception
// upstream connections. Pools TCP+TLS connections across CONNECT tunnels to the
// same host, avoiding per-tunnel connection setup overhead. Pass nil rootCAs to
// use the system default trust store.
func newTLSInterceptTransport(
	ssrfDial func(ctx context.Context, network, addr string) (net.Conn, error),
	recordHandshake func(stage string, d time.Duration),
	rootCAs *x509.CertPool,
) *http.Transport {
	return &http.Transport{
		DialTLSContext: func(dialCtx context.Context, network, addr string) (net.Conn, error) {
			// Use SSRF-safe dialer for the TCP connection to prevent
			// DNS rebinding TOCTOU between the scanner check and dial.
			rawConn, dialErr := ssrfDial(dialCtx, network, addr)
			if dialErr != nil {
				return nil, dialErr
			}
			host, _, _ := net.SplitHostPort(addr)
			// Layer TLS on top of the SSRF-validated TCP connection.
			tlsCfg := &tls.Config{
				ServerName: host,
				RootCAs:    rootCAs,
				NextProtos: []string{"h2", "http/1.1"},
				MinVersion: tls.VersionTLS12,
			}
			start := time.Now()
			tlsUpstream := tls.Client(rawConn, tlsCfg)
			if err := tlsUpstream.HandshakeContext(dialCtx); err != nil {
				_ = rawConn.Close()
				return nil, err
			}
			recordHandshake("upstream", time.Since(start))
			return tlsUpstream, nil
		},
		ForceAttemptHTTP2:  true, // required with custom DialTLSContext for h2
		DisableCompression: true, // force identity encoding for scanning
		MaxIdleConns:       100,  // pool up to 100 idle connections across all hosts
		IdleConnTimeout:    90 * time.Second,
	}
}

// recordSessionActivity handles session profiling, adaptive signals, and anomaly
// detection for any proxy handler. The agent parameter enables per-agent session
// isolation (key becomes "agent|clientIP"); pass "" when agent is unavailable.
// When deferClean is true, the RecordClean call is skipped even for a clean URL
// scan result; the caller is responsible for calling it after all scanning is
// complete (fetch uses this to avoid decaying score before header DLP, CEE, and
// response scanning have run).
// Returns a SessionResult with Blocked set when the request should be rejected
// due to a session anomaly in block mode, and Level set to the current
// escalation level for downstream use by UpgradeAction().
func (p *Proxy) recordSessionActivity(clientIP, agent, hostname, requestID string, result scanner.Result, cfg *config.Config, log *audit.Logger, deferClean bool) SessionResult {
	sm := p.sessionMgrPtr.Load()
	if sm == nil || !cfg.SessionProfiling.Enabled {
		return SessionResult{}
	}

	// Build session key: agent|clientIP when agent is known, else just clientIP.
	key := clientIP
	if agent != "" && agent != agentAnonymous {
		key = agent + "|" + clientIP
	}

	sess := sm.GetOrCreate(key)

	// On-entry de-escalation: recover sessions stuck at block_all.
	if changed, fromLabel, toLabel := trySessionRecovery(sess, &cfg.AdaptiveEnforcement, p.metrics); changed {
		if log != nil {
			log.LogAdaptiveEscalation(key, fromLabel, toLabel, clientIP, requestID, sess.ThreatScore())
		}
	}

	anomalies := sess.RecordRequest(hostname, &cfg.SessionProfiling)

	// IP-level domain tracking: catches header rotation attacks where the
	// agent identity changes per request but the source IP stays the same.
	ipAnomalies := sm.RecordIPDomain(clientIP, hostname, &cfg.SessionProfiling)
	anomalies = append(anomalies, ipAnomalies...)

	// Record adaptive signals (only when adaptive enforcement is enabled).
	if cfg.AdaptiveEnforcement.Enabled {
		adaptiveCfg := cfg.AdaptiveEnforcement
		ep := decide.EscalationParams{
			Threshold: adaptiveCfg.EscalationThreshold,
			Logger:    log,
			Metrics:   p.metrics,
			Session:   key,
			ClientIP:  clientIP,
			RequestID: requestID,
		}
		if result.IsProtective() {
			// Score-neutral: no escalation signal, no clean decay.
			// A rate-limited request proves nothing about threat posture.
		} else if result.IsConfigMismatch() {
			// Bounded signal: config-mismatch blocks (SSRF on an
			// allowlisted domain) are not real attacks, but repeated
			// probing should still accumulate a weak signal so the
			// session isn't completely invisible to adaptive scoring.
			if decide.RecordSignal(sess, session.SignalNearMiss, ep) {
				sess.SetBlockAll(decide.UpgradeAction("", sess.EscalationLevel(), &adaptiveCfg) == config.ActionBlock)
			}
		} else if !result.Allowed {
			if decide.RecordSignal(sess, session.SignalBlock, ep) {
				// Update block_all flag so RecordRequest stops refreshing lastActivity.
				sess.SetBlockAll(decide.UpgradeAction("", sess.EscalationLevel(), &adaptiveCfg) == config.ActionBlock)
			}
		} else if result.Score > 0 {
			if decide.RecordSignal(sess, session.SignalNearMiss, ep) {
				sess.SetBlockAll(decide.UpgradeAction("", sess.EscalationLevel(), &adaptiveCfg) == config.ActionBlock)
			}
		} else if !deferClean {
			// Skip RecordClean when the caller defers it to the end of the
			// request lifecycle (fetch), so that later scanning stages (header
			// DLP, CEE, response) can still raise a finding before decay fires.
			sess.RecordClean(adaptiveCfg.DecayPerCleanRequest)
		}
	}

	level := sess.EscalationLevel()

	// Airlock auto-triggers: map adaptive escalation levels to airlock tiers.
	// Only fires when airlock is enabled. sess is already *SessionState from
	// SessionManager.GetOrCreate, so Airlock() is directly accessible.
	if cfg.Airlock.Enabled {
		targetTier := ""
		switch session.EscalationLabel(level) {
		case "elevated":
			targetTier = cfg.Airlock.Triggers.OnElevated
		case "high":
			targetTier = cfg.Airlock.Triggers.OnHigh
		case "critical":
			targetTier = cfg.Airlock.Triggers.OnCritical
		}
		if targetTier != "" && targetTier != config.AirlockTierNone {
			if changed, from, to := sess.Airlock().SetTier(targetTier); changed {
				if log != nil {
					log.LogAirlockEnter(key, to, "adaptive_"+session.EscalationLabel(level), clientIP, requestID)
				}
				if p.metrics != nil {
					p.metrics.RecordAirlockTransition(from, to, "adaptive")
				}
			}
		}
	}

	for _, a := range anomalies {
		log.LogSessionAnomaly(key, a.Type, a.Detail, clientIP, requestID, a.Score)
		p.metrics.RecordSessionAnomaly(a.Type)

		if cfg.SessionProfiling.AnomalyAction == config.ActionBlock && cfg.EnforceEnabled() {
			return SessionResult{Blocked: true, Detail: fmt.Sprintf("session anomaly: %s", a.Detail), Level: level}
		}
	}

	return SessionResult{Level: level}
}

// applyShield runs the Browser Shield rewriter on a response body when enabled
// and the hostname is not exempt. Handles max_shield_bytes, oversize_action, and
// exempt_domains config knobs. Returns the (possibly rewritten) body.
// applyShield runs Browser Shield rewriting on a response body. Returns the
// (possibly rewritten) body and a blocked flag. When blocked is true, the
// caller must return 403 to the client (oversize response with block action).
func (p *Proxy) applyShield(body []byte, contentType, hostname string, respHeaders http.Header, cfg *config.Config, actx audit.LogContext, clientIP, requestID, transport string) ([]byte, bool) {
	if p.shieldEngine == nil || !cfg.BrowserShield.Enabled {
		return body, false
	}

	// Exempt domains: skip shield entirely.
	if isShieldExempt(hostname, cfg.BrowserShield.ExemptDomains) {
		p.metrics.RecordShieldSkipped("exempt_domain")
		return body, false
	}

	// Max shield bytes: enforce oversize action.
	if cfg.BrowserShield.MaxShieldBytes > 0 && len(body) > cfg.BrowserShield.MaxShieldBytes {
		p.metrics.RecordShieldSkipped("oversize")
		switch cfg.BrowserShield.OversizeAction {
		case config.ShieldOversizeScanHead:
			// Rewrite only the head; append the unshielded tail so the full
			// response body is returned intact.
			head := p.runShieldPipeline(body[:cfg.BrowserShield.MaxShieldBytes], contentType, respHeaders, cfg, actx, clientIP, requestID, transport)
			return append(head, body[cfg.BrowserShield.MaxShieldBytes:]...), false
		case config.ShieldOversizeWarn:
			p.logger.LogAnomaly(actx, "shield_oversize", fmt.Sprintf("response body %d bytes exceeds max_shield_bytes %d", len(body), cfg.BrowserShield.MaxShieldBytes), 0)
			return body, false
		default: // block: fail-closed, return 403
			p.logger.LogBlocked(actx, "shield_oversize", fmt.Sprintf("response body %d bytes exceeds max_shield_bytes %d (action: block)", len(body), cfg.BrowserShield.MaxShieldBytes))
			return nil, true
		}
	}

	return p.runShieldPipeline(body, contentType, respHeaders, cfg, actx, clientIP, requestID, transport), false
}

// runShieldPipeline applies the shield detection and rewrite pipeline to body bytes.
func (p *Proxy) runShieldPipeline(body []byte, contentType string, respHeaders http.Header, cfg *config.Config, actx audit.LogContext, clientIP, requestID, transport string) []byte {
	shieldStart := time.Now()
	prefixLen := len(body)
	if prefixLen > 512 {
		prefixLen = 512
	}
	pipeline := shield.DetectPipeline(contentType, body[:prefixLen])
	if pipeline == shield.PipelineNone {
		return body
	}
	// Extract CSP nonce from response headers (preferred over body extraction).
	headerNonce := shield.ExtractCSPNonce(respHeaders)
	shieldResult := p.shieldEngine.RewriteWithNonce(string(body), pipeline, &cfg.BrowserShield, headerNonce)
	if shieldResult.Rewritten {
		body = []byte(shieldResult.Content)
		if shieldResult.ExtensionHits > 0 {
			p.metrics.RecordShieldRewrite("extension", transport)
			p.logger.LogShieldRewrite("extension", shieldResult.ExtensionHits, transport, actx.URL, clientIP, requestID)
		}
		if shieldResult.TrackingHits > 0 {
			p.metrics.RecordShieldRewrite("tracking", transport)
			p.logger.LogShieldRewrite("tracking", shieldResult.TrackingHits, transport, actx.URL, clientIP, requestID)
		}
		if shieldResult.TrapHits > 0 {
			p.metrics.RecordShieldRewrite("trap", transport)
			p.logger.LogShieldRewrite("trap", shieldResult.TrapHits, transport, actx.URL, clientIP, requestID)
		}
		if shieldResult.ShimInjected {
			p.metrics.RecordShieldShimInjected(transport)
		}
	}
	p.metrics.RecordShieldLatency(transport, time.Since(shieldStart))
	return body
}

// runShieldPipelineShared is the shared Browser Shield pipeline usable by
// both Proxy and ReverseProxyHandler. Extracts CSP nonce from response
// headers and runs the full rewrite + metrics pipeline.
func runShieldPipelineShared(engine *shield.Engine, body []byte, contentType string, respHeaders http.Header, cfg *config.BrowserShield, m *metrics.Metrics, transport string) []byte {
	prefixLen := len(body)
	if prefixLen > 512 {
		prefixLen = 512
	}
	pipeline := shield.DetectPipeline(contentType, body[:prefixLen])
	if pipeline == shield.PipelineNone {
		return body
	}
	headerNonce := shield.ExtractCSPNonce(respHeaders)
	shieldResult := engine.RewriteWithNonce(string(body), pipeline, cfg, headerNonce)
	if shieldResult.Rewritten {
		body = []byte(shieldResult.Content)
		if shieldResult.ExtensionHits > 0 {
			m.RecordShieldRewrite("extension", transport)
		}
		if shieldResult.TrackingHits > 0 {
			m.RecordShieldRewrite("tracking", transport)
		}
		if shieldResult.TrapHits > 0 {
			m.RecordShieldRewrite("trap", transport)
		}
		if shieldResult.ShimInjected {
			m.RecordShieldShimInjected(transport)
		}
	}
	return body
}

// ShieldEngine returns the proxy's browser shield engine for sharing with
// other handlers (e.g., reverse proxy). Returns nil when shield is not initialized.
// FrozenTools returns the frozen tool registry for MCP airlock enforcement.
func (p *Proxy) FrozenTools() *FrozenToolRegistry {
	return p.frozenTools
}

func (p *Proxy) ShieldEngine() *shield.Engine {
	return p.shieldEngine
}

// isShieldExempt checks whether a hostname is in the browser shield exempt list.
func isShieldExempt(hostname string, exempts []string) bool {
	for _, d := range exempts {
		if strings.EqualFold(hostname, d) {
			return true
		}
	}
	return false
}

// ssrfSafeDialContext resolves DNS and validates all IPs against internal
// CIDRs before connecting. Prevents DNS rebinding SSRF where an attacker
// returns a safe IP during scanning but a private IP at connection time.
// Used by both the HTTP client transport and CONNECT tunnel dialing.
// Trusted domains (from config.trusted_domains) bypass the internal-IP check.
func (p *Proxy) ssrfSafeDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("ssrfSafeDialContext: split addr %q: %w", addr, err)
	}

	// If the host is already an IP, check it and dial directly.
	// IsTrustedDomain rejects IP literals, so raw IPs are always
	// subject to SSRF blocking regardless of trusted_domains config.
	if ip := net.ParseIP(host); ip != nil {
		// Normalize IPv4-mapped IPv6 (::ffff:x.x.x.x) to 4-byte form,
		// consistent with the DNS resolution path below.
		if v4 := ip.To4(); v4 != nil {
			ip = v4
		}
		if currentSc := p.scannerPtr.Load(); currentSc.IsInternalIP(ip) && !currentSc.IsIPAllowlisted(ip) {
			return nil, fmt.Errorf("SSRF blocked: connection to internal IP %s", host)
		}
		return p.dialer.DialContext(ctx, network, addr)
	}

	// Resolve DNS and validate every IP before connecting.
	ips, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("ssrfSafeDialContext: DNS lookup %q: %w", host, err)
	}

	if len(ips) == 0 {
		return nil, fmt.Errorf("SSRF blocked: DNS returned no addresses for %s", host)
	}

	currentSc := p.scannerPtr.Load()
	isTrusted := currentSc.IsTrustedDomain(host)
	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return nil, fmt.Errorf("SSRF blocked: unparseable IP %q from DNS for %s", ipStr, host)
		}
		// Normalize IPv4-mapped IPv6 (::ffff:x.x.x.x) to 4-byte form.
		if v4 := ip.To4(); v4 != nil {
			ip = v4
		}
		if currentSc.IsInternalIP(ip) {
			if isTrusted || currentSc.IsIPAllowlisted(ip) {
				// Trusted domain or IP-allowlisted address — allow.
				// The scanner-level checkSSRF handles the authoritative
				// allow/deny decision and logging.
				continue
			}
			return nil, fmt.Errorf("SSRF blocked: %s resolves to internal IP %s", host, ipStr)
		}
	}

	// Connect to the first validated IP.
	return p.dialer.DialContext(ctx, network, net.JoinHostPort(ips[0], port))
}

// buildHandler wraps a ServeMux to intercept CONNECT and absolute-URI forward
// proxy requests before falling through to the mux. Used by Start() and tests.
func (p *Proxy) buildHandler(mux *http.ServeMux) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Kill switch: deny all requests when active (except exempt endpoints/IPs).
		if p.ks != nil {
			if d := p.ks.IsActiveHTTP(r); d.Active {
				clientIP, _ := requestMeta(r)
				p.logger.LogKillSwitchDeny(schemeHTTP, r.URL.Path, d.Source, d.Message, clientIP)
				p.metrics.RecordKillSwitchDenial(schemeHTTP, r.URL.Path)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusServiceUnavailable)
				_ = json.NewEncoder(w).Encode(map[string]string{
					"error":   "kill_switch_active",
					"message": d.Message,
				})
				return
			}
		}

		if r.Method == http.MethodConnect {
			if !p.cfgPtr.Load().ForwardProxy.Enabled {
				http.Error(w, "CONNECT not supported", http.StatusMethodNotAllowed)
				return
			}
			p.handleConnect(w, r)
			return
		}
		if r.URL.IsAbs() && r.URL.Host != "" {
			if !p.cfgPtr.Load().ForwardProxy.Enabled {
				http.Error(w, "forward proxy not enabled", http.StatusMethodNotAllowed)
				return
			}
			p.handleForwardHTTP(w, r)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

// sessionAPIRouter dispatches /api/v1/sessions/{key}/* requests to the
// appropriate session API handler based on the trailing path segment.
func (p *Proxy) sessionAPIRouter(w http.ResponseWriter, r *http.Request) {
	path := r.URL.EscapedPath()
	switch {
	case killswitch.IsSessionActionPath(path, "airlock"):
		p.sessionAPI.HandleAirlock(w, r)
	case killswitch.IsSessionActionPath(path, "reset"):
		p.sessionAPI.HandleReset(w, r)
	default:
		http.NotFound(w, r)
	}
}

// buildMux constructs the route multiplexer for the proxy. Used by both
// Start() and Handler() to ensure route registration is not duplicated.
func (p *Proxy) buildMux() *http.ServeMux {
	cfg := p.cfgPtr.Load()

	mux := http.NewServeMux()
	mux.HandleFunc("/fetch", p.handleFetch)
	mux.HandleFunc("/ws", p.handleWebSocket)
	mux.HandleFunc("/health", p.handleHealth)
	// Register metrics/stats only when NOT running on a separate port.
	if cfg.MetricsListen == "" {
		mux.Handle("/metrics", p.metrics.PrometheusHandler())
		mux.HandleFunc("/stats", p.metrics.StatsHandler())
	}
	// Register kill switch API routes only when the API is NOT running on a
	// separate port.
	if p.ksAPI != nil && cfg.KillSwitch.APIListen == "" {
		mux.HandleFunc("/api/v1/killswitch", p.ksAPI.HandleToggle)
		mux.HandleFunc("/api/v1/killswitch/status", p.ksAPI.HandleStatus)
	}
	// Register session admin API routes only when NOT on a separate port.
	if p.sessionAPI != nil && cfg.KillSwitch.APIListen == "" {
		mux.HandleFunc("/api/v1/sessions", p.sessionAPI.HandleList)
		mux.HandleFunc("/api/v1/sessions/", p.sessionAPIRouter)
	}
	return mux
}

// Handler returns the composed HTTP handler for the proxy, including
// CONNECT interception and kill switch checks. Useful for testing with
// httptest.NewServer and for embedding the proxy in other servers.
func (p *Proxy) Handler() http.Handler {
	return p.buildHandler(p.buildMux())
}

// Start starts the fetch proxy HTTP server. It blocks until the context
// is cancelled or the server encounters a fatal error.
func (p *Proxy) Start(ctx context.Context) error {
	cfg := p.cfgPtr.Load()

	handler := p.buildHandler(p.buildMux())

	// CONNECT tunnels and WebSocket connections need to live beyond any single
	// write timeout. When forward proxy or WebSocket proxy is enabled,
	// WriteTimeout is set to 0 (unlimited) because http.Server enforces it
	// per-connection, not per-handler. Long-lived connections would be killed
	// prematurely. This also affects /fetch, /health, /metrics, and /stats on
	// the same listener. Those endpoints remain protected by: the
	// http.Client.Timeout on outbound fetches, the ReadHeaderTimeout
	// (slowloris), and the response size cap (MaxResponseMB). Per-connection
	// lifetime is enforced by max_tunnel_seconds / max_connection_seconds and
	// idle_timeout_seconds.
	writeTimeout := time.Duration(cfg.FetchProxy.TimeoutSeconds+10) * time.Second
	if cfg.ForwardProxy.Enabled || cfg.WebSocketProxy.Enabled {
		writeTimeout = 0
	}

	p.server = &http.Server{
		Addr:    cfg.FetchProxy.Listen,
		Handler: handler,
		BaseContext: func(_ net.Listener) context.Context {
			return ctx
		},
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second, // Slowloris protection
		WriteTimeout:      writeTimeout,
		IdleTimeout:       120 * time.Second,
	}

	// Agent listeners are managed by the CLI layer (run.go) which
	// pre-binds ports for fail-fast error reporting. proxy.Start()
	// only manages the main server lifecycle.

	// Graceful shutdown on context cancellation.
	// The done channel ensures this goroutine exits if ListenAndServe
	// fails immediately (e.g., address already in use).
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			for _, srv := range p.agentServers {
				if shutErr := srv.Shutdown(shutdownCtx); shutErr != nil {
					p.logger.LogError(audit.LogContext{Method: "SHUTDOWN", URL: srv.Addr}, shutErr)
				}
			}
			if err := p.server.Shutdown(shutdownCtx); err != nil {
				p.logger.LogError(audit.LogContext{Method: "SHUTDOWN", URL: cfg.FetchProxy.Listen}, err)
			}
			p.Close()
		case <-done:
		}
	}()

	// Warn if listen address exposes metrics/stats to the network.
	// Skip when metrics_listen is set — metrics are on a separate port.
	if cfg.MetricsListen == "" {
		if host, _, splitErr := net.SplitHostPort(cfg.FetchProxy.Listen); splitErr == nil {
			ip := net.ParseIP(host)
			if host == "" || host == "0.0.0.0" || host == "::" || (ip != nil && !ip.IsLoopback()) {
				p.logger.LogAnomaly(audit.LogContext{Method: "STARTUP", URL: cfg.FetchProxy.Listen}, "",
					"listen address is not loopback — /metrics and /stats endpoints are exposed to the network",
					0.5)
			}
		}
	}

	p.logger.LogStartup(cfg.FetchProxy.Listen, cfg.Mode, Version, cfg.Hash())

	err := p.server.ListenAndServe()
	close(done) // unblock shutdown goroutine if server failed immediately
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// handleFetch processes URL fetch requests.
func (p *Proxy) handleFetch(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	clientIP, requestID := requestMeta(r)

	// Resolve per-agent config and scanner from a single registry snapshot.
	// This prevents TOCTOU races during hot-reload where knownProfiles()
	// and resolveAgent() could read different registries.
	resolved, id := p.resolveAgentFromRequest(r)
	cfg := resolved.Config
	sc := resolved.Scanner
	agent := id.Name
	if agent == "" {
		agent = agentAnonymous
	}
	agentLabel := id.Profile // bounded cardinality for Prometheus labels

	// Create a per-request sub-logger tagged with the agent name
	log := p.logger.With("agent", agent)

	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, FetchResponse{
			Error:   "only GET allowed",
			Blocked: false,
		})
		return
	}

	targetURL := extractTargetURL(r)
	if targetURL == "" {
		writeJSON(w, http.StatusBadRequest, FetchResponse{
			Error:   "missing 'url' query parameter",
			Blocked: false,
		})
		return
	}

	// Strip control characters before URL parsing. Go's url.Parse rejects
	// URLs with control chars (returns "invalid control character" error),
	// which means a null byte in "sk-ant-%00key..." would be rejected as a
	// parse error instead of being detected by the DLP scanner. Stripping
	// first ensures the cleaned URL flows through the full scanner pipeline.
	targetURL = stripFetchControlChars(targetURL)

	// Parse and validate URL scheme
	parsed, err := url.Parse(targetURL)
	if err != nil || (parsed.Scheme != schemeHTTP && parsed.Scheme != schemeHTTPS) {
		writeJSON(w, http.StatusBadRequest, FetchResponse{
			URL:     targetURL,
			Error:   "invalid URL: must be http or https",
			Blocked: false,
		})
		return
	}

	// Fully decode the URL for display in responses and logs. The scanner
	// internally decodes for matching, but targetURL retains partial decoding
	// from Go's query parsing. Operators should see the final resolved URL.
	displayURL := scanner.IterativeDecode(targetURL)
	actx := audit.LogContext{
		Method:    http.MethodGet,
		URL:       displayURL,
		ClientIP:  clientIP,
		RequestID: requestID,
		Agent:     agent,
	}

	// Scan URL through all scanners
	result := sc.Scan(r.Context(), targetURL)

	// Capture observer: record URL verdict for policy replay.
	urlFindings := urlResultToFindings(result)
	urlOutcome := captureOutcome(config.ActionBlock, result.Allowed)
	urlAction := ""
	if !result.Allowed {
		urlAction = config.ActionBlock
	}
	p.captureObs.ObserveURLVerdict(r.Context(), &capture.URLVerdictRecord{
		Subsurface:        "fetch_url",
		Transport:         "fetch",
		RequestID:         requestID,
		Agent:             agent,
		Request:           capture.CaptureRequest{Method: r.Method, URL: displayURL},
		RawFindings:       urlFindings,
		EffectiveFindings: urlFindings,
		EffectiveAction:   urlAction,
		Outcome:           urlOutcome,
	})

	// Session profiling: record BEFORE the enforce-mode early return so adaptive
	// signals (SignalBlock) fire even for blocked requests. Pass deferClean=true
	// so RecordClean is NOT applied inside recordSessionActivity: header DLP,
	// CEE, and response scanning may still find something after this point, and
	// a clean decay before those stages would incorrectly counteract a later signal.
	sr := p.recordSessionActivity(clientIP, agent, parsed.Hostname(), requestID, result, cfg, log, true)

	// Look up the live session recorder for Fix 4+5: use EscalationLevel() at
	// each enforcement point (not the snapshot in sr.Level) so mid-request CEE
	// or response-scan escalations are reflected immediately. Also used to call
	// RecordClean at the end when no finding was detected.
	var fetchRec session.Recorder
	if sm := p.sessionMgrPtr.Load(); sm != nil {
		fetchSessionKey := clientIP
		if agent != "" && agent != agentAnonymous {
			fetchSessionKey = agent + "|" + clientIP
		}
		fetchRec = sm.GetOrCreate(fetchSessionKey)
	}

	// Airlock check: drain tier blocks all traffic including fetch.
	if fetchSess, ok := fetchRec.(*SessionState); ok && fetchSess != nil {
		tier := fetchSess.Airlock().Tier()
		if tier == config.AirlockTierDrain {
			p.logger.LogAirlockDeny(fetchSess.key, tier, TransportFetch, r.Method, clientIP, requestID)
			p.metrics.RecordAirlockDenial(tier, TransportFetch, "read")
			writeJSON(w, http.StatusForbidden, FetchResponse{
				URL: displayURL, Agent: agent, Blocked: true,
				BlockReason: "session in airlock drain",
			})
			return
		}
	}

	// hasFinding tracks whether any scanning stage (header DLP, CEE, response)
	// detected something for this request. RecordClean is only applied at the
	// end when no finding was detected. A near-miss (scored but allowed) counts
	// as a finding to prevent inadvertent score decay.
	hasFinding := (!result.Allowed && !result.IsProtective()) || (result.Score > 0 && result.Allowed)

	if !result.Allowed {
		if cfg.EnforceEnabled() {
			log.LogBlocked(actx, result.Scanner, result.Reason)
			p.recordDecision(config.ActionBlock, result.Scanner, result.Reason, "fetch", requestID)
			p.emitReceipt(receipt.EmitOpts{
				ActionID:  receipt.NewActionID(),
				Verdict:   config.ActionBlock,
				Layer:     result.Scanner,
				Pattern:   result.Reason,
				Transport: "fetch",
				Method:    http.MethodGet,
				Target:    displayURL,
				RequestID: requestID,
				Agent:     agent,
			})
			p.metrics.RecordBlocked(parsed.Hostname(), result.Scanner, time.Since(start), agentLabel)
			status := http.StatusForbidden
			if result.Scanner == scanner.ScannerRateLimit {
				status = http.StatusTooManyRequests
			}
			resp := FetchResponse{
				URL:         displayURL,
				Agent:       agent,
				Blocked:     true,
				BlockReason: result.Reason,
			}
			if cfg.ExplainBlocksEnabled() {
				resp.Hint = result.Hint
			}
			writeJSON(w, status, resp)
			return
		}
		// Audit mode: base action is "warn". Adaptive escalation may upgrade to block.
		baseAction := config.ActionWarn
		effectiveAction := decide.UpgradeAction(baseAction, sr.Level, &cfg.AdaptiveEnforcement)
		if effectiveAction == config.ActionBlock {
			sessionKey := clientIP
			if agent != "" && agent != agentAnonymous {
				sessionKey = agent + "|" + clientIP
			}
			log.LogAdaptiveUpgrade(sessionKey, session.EscalationLabel(sr.Level), baseAction, effectiveAction, result.Scanner, clientIP, requestID)
			p.metrics.RecordAdaptiveUpgrade(baseAction, effectiveAction, session.EscalationLabel(sr.Level))
			log.LogBlocked(actx, result.Scanner, result.Reason+" (escalated)")
			p.metrics.RecordBlocked(parsed.Hostname(), result.Scanner, time.Since(start), agentLabel)
			escalatedStatus := http.StatusForbidden
			if result.Scanner == scanner.ScannerRateLimit {
				escalatedStatus = http.StatusTooManyRequests
			}
			writeJSON(w, escalatedStatus, FetchResponse{
				URL:         displayURL,
				Agent:       agent,
				Blocked:     true,
				BlockReason: result.Reason + " (escalated)",
			})
			return
		}
		log.LogAnomaly(actx, result.Scanner, result.Reason, result.Score)
	}

	if sr.Blocked {
		writeJSON(w, http.StatusForbidden, FetchResponse{
			URL:         displayURL,
			Agent:       agent,
			Blocked:     true,
			BlockReason: sr.Detail,
		})
		return
	}

	// block_all enforcement: deny ALL traffic (including clean) when the
	// session is at an escalation level with block_all=true. UpgradeAction
	// with an empty base action returns "block" only when block_all is set.
	if sr.Level > 0 && decide.UpgradeAction("", sr.Level, &cfg.AdaptiveEnforcement) == config.ActionBlock {
		sessionKey := clientIP
		if agent != "" && agent != agentAnonymous {
			sessionKey = agent + "|" + clientIP
		}
		log.LogAdaptiveUpgrade(sessionKey, session.EscalationLabel(sr.Level), "", config.ActionBlock, "session_deny", clientIP, requestID)
		p.metrics.RecordAdaptiveUpgrade("", config.ActionBlock, session.EscalationLabel(sr.Level))
		writeJSON(w, http.StatusForbidden, FetchResponse{
			URL:         displayURL,
			Agent:       agent,
			Blocked:     true,
			BlockReason: "session escalation level " + session.EscalationLabel(sr.Level),
		})
		return
	}

	// Request header DLP scanning (fetch is GET-only, no body to scan).
	// hadFinding is true even in audit/warn mode so RecordClean is not applied
	// when a header DLP match was detected.
	headerBlocked, headerHadFinding := p.evalHeaderDLP(r.Context(), r.Header, cfg, sc, log, actx, parsed.Hostname(), start)

	// Capture observer: record header DLP verdict for policy replay.
	{
		hdrAction := ""
		if headerBlocked {
			hdrAction = config.ActionBlock
		} else if headerHadFinding {
			hdrAction = config.ActionWarn
		}
		p.captureObs.ObserveDLPVerdict(r.Context(), &capture.DLPVerdictRecord{
			Subsurface:      "dlp_fetch_header",
			Transport:       "fetch",
			RequestID:       requestID,
			Agent:           agent,
			Request:         capture.CaptureRequest{Method: r.Method, URL: displayURL},
			TransformKind:   capture.TransformHeaderValue,
			EffectiveAction: hdrAction,
			Outcome:         captureOutcome(hdrAction, !headerHadFinding),
		})
	}

	if headerHadFinding {
		hasFinding = true
		if fetchRec != nil && cfg.AdaptiveEnforcement.Enabled {
			// Blocked header DLP → SignalBlock (high confidence); warn-mode → SignalNearMiss.
			headerSignal := session.SignalNearMiss
			if headerBlocked {
				headerSignal = session.SignalBlock
			}
			decide.RecordSignal(fetchRec, headerSignal, decide.EscalationParams{
				Threshold: cfg.AdaptiveEnforcement.EscalationThreshold,
				Logger:    log,
				Metrics:   p.metrics,
				Session:   CeeSessionKey(agent, clientIP),
				ClientIP:  clientIP,
				RequestID: requestID,
			})
		}
	}
	if headerBlocked {
		writeJSON(w, http.StatusForbidden, FetchResponse{
			URL:         displayURL,
			Agent:       agent,
			Blocked:     true,
			BlockReason: "request header contains secret",
		})
		return
	}
	// Re-check block_all after header DLP near-miss may have escalated the session.
	if fetchRec != nil && cfg.AdaptiveEnforcement.Enabled &&
		decide.UpgradeAction("", fetchRec.EscalationLevel(), &cfg.AdaptiveEnforcement) == config.ActionBlock {
		headerSessionKey := CeeSessionKey(agent, clientIP)
		log.LogAdaptiveUpgrade(headerSessionKey, session.EscalationLabel(fetchRec.EscalationLevel()), "", config.ActionBlock, "session_deny", clientIP, requestID)
		p.metrics.RecordAdaptiveUpgrade("", config.ActionBlock, session.EscalationLabel(fetchRec.EscalationLevel()))
		writeJSON(w, http.StatusForbidden, FetchResponse{
			URL:         displayURL,
			Agent:       agent,
			Blocked:     true,
			BlockReason: "session escalation level " + session.EscalationLabel(fetchRec.EscalationLevel()),
		})
		return
	}

	// Budget admission check: enforce request count and domain limits before
	// making the outbound request. Byte budget is checked after the response.
	if err := resolved.Budget.CheckAdmission(strings.ToLower(parsed.Hostname())); err != nil {
		reason := err.Error()
		log.LogBlocked(actx, "budget", reason)
		p.metrics.RecordBlocked(parsed.Hostname(), "budget", time.Since(start), agentLabel)
		writeJSON(w, http.StatusTooManyRequests, FetchResponse{
			URL:         displayURL,
			Agent:       agent,
			Blocked:     true,
			BlockReason: reason,
		})
		return
	}

	// CEE pre-forward admission: check cross-request entropy and fragment
	// reassembly before the outbound request leaves the proxy. Fetch is
	// GET-only so the outbound data is the target URL path and query values.
	ceeCfg := ceeEffectiveConfig(cfg.CrossRequestDetection, cfg.EnforceEnabled())
	if ceeCfg.Enabled {
		sessionKey := CeeSessionKey(agent, clientIP)
		outbound := urlPayload(parsed)
		keys := queryParamKeys(parsed)

		ceeRes := ceeAdmit(r.Context(), sessionKey, outbound, keys, displayURL, agent, clientIP, requestID,
			ceeCfg, p.entropyTrackerPtr.Load(), p.fragmentBufferPtr.Load(), sc, log, p.metrics)

		// Capture observer: record CEE verdict for policy replay.
		ceeFindings := ceeResultToFindings(ceeRes)
		ceeAction := ""
		if ceeRes.Blocked {
			ceeAction = config.ActionBlock
		} else if ceeRes.EntropyHit || ceeRes.FragmentHit {
			ceeAction = config.ActionWarn
		}
		p.captureObs.ObserveCEEVerdict(r.Context(), &capture.CEERecord{
			Subsurface:        "cee_fetch",
			Transport:         "fetch",
			RequestID:         requestID,
			Agent:             agent,
			Request:           capture.CaptureRequest{Method: r.Method, URL: displayURL},
			TransformKind:     capture.TransformCEEWindow,
			RawFindings:       ceeFindings,
			EffectiveFindings: ceeFindings,
			EffectiveAction:   ceeAction,
			Outcome:           captureOutcome(ceeAction, !ceeRes.Blocked && !ceeRes.EntropyHit && !ceeRes.FragmentHit),
		})

		if sm := p.sessionMgrPtr.Load(); sm != nil && cfg.AdaptiveEnforcement.Enabled {
			ceeRecordSignals(ceeRes, sm, sessionKey, cfg.AdaptiveEnforcement.EscalationThreshold, log, p.metrics, clientIP, requestID)
		}

		if ceeRes.EntropyHit || ceeRes.FragmentHit || ceeRes.Blocked {
			hasFinding = true
		}

		if ceeRes.Blocked {
			p.metrics.RecordBlocked(parsed.Hostname(), "cross_request", time.Since(start), agentLabel)
			writeJSON(w, http.StatusForbidden, FetchResponse{
				URL:         displayURL,
				Agent:       agent,
				Blocked:     true,
				BlockReason: ceeRes.Reason,
			})
			return
		}

		// Re-check block_all after CEE may have escalated the session. Use the
		// live recorder so mid-request escalations are reflected immediately.
		if fetchRec != nil && decide.UpgradeAction("", fetchRec.EscalationLevel(), &cfg.AdaptiveEnforcement) == config.ActionBlock {
			log.LogAdaptiveUpgrade(sessionKey, session.EscalationLabel(fetchRec.EscalationLevel()), "", config.ActionBlock, "session_deny", clientIP, requestID)
			p.metrics.RecordAdaptiveUpgrade("", config.ActionBlock, session.EscalationLabel(fetchRec.EscalationLevel()))
			writeJSON(w, http.StatusForbidden, FetchResponse{
				URL:         displayURL,
				Agent:       agent,
				Blocked:     true,
				BlockReason: "session escalation level " + session.EscalationLabel(fetchRec.EscalationLevel()),
			})
			return
		}
	}

	// Fetch the URL — attach clientIP/requestID/agent and resolved agent
	// config/scanner to context for redirect logging and per-agent redirect enforcement.
	ctx := context.WithValue(r.Context(), ctxKeyClientIP, clientIP)
	ctx = context.WithValue(ctx, ctxKeyRequestID, requestID)
	ctx = context.WithValue(ctx, ctxKeyAgent, agent)
	ctx = context.WithValue(ctx, ctxKeyAgentConfig, cfg)
	ctx = context.WithValue(ctx, ctxKeyAgentScanner, sc)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		log.LogError(actx, err)
		writeJSON(w, http.StatusInternalServerError, FetchResponse{
			URL:   displayURL,
			Agent: agent,
			Error: fmt.Sprintf("creating request: %v", err),
		})
		return
	}

	req.Header.Set("User-Agent", cfg.FetchProxy.UserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,text/plain,*/*;q=0.8")

	resp, err := p.client.Do(req) //nolint:gosec // G704: URL validated by scanner pipeline before reaching here
	if err != nil {
		// Detect redirect blocks (from CheckRedirect) and report as blocked, not error.
		if strings.Contains(err.Error(), "redirect blocked:") {
			reason := err.Error()
			log.LogBlocked(actx, "redirect", reason)
			p.metrics.RecordBlocked(parsed.Hostname(), "redirect", time.Since(start), agentLabel)
			resp := FetchResponse{
				URL:         displayURL,
				Agent:       agent,
				Blocked:     true,
				BlockReason: reason,
			}
			if cfg.ExplainBlocksEnabled() {
				resp.Hint = "Request was redirected to a different origin. Cross-origin redirects are blocked to prevent open redirect attacks."
			}
			writeJSON(w, http.StatusForbidden, resp)
			return
		}
		log.LogError(actx, err)
		writeJSON(w, http.StatusBadGateway, FetchResponse{
			URL:   displayURL,
			Agent: agent,
			Error: fmt.Sprintf("fetch failed: %v", err),
		})
		return
	}
	defer safeClose(resp.Body, "resp.Body", p.logger)

	// Limit response body size: use the tighter of max_response_mb and the
	// remaining per-agent byte budget, so oversized responses are blocked
	// at read time rather than after the full body has been consumed.
	configMaxBytes := int64(cfg.FetchProxy.MaxResponseMB) * 1024 * 1024
	maxBytes := configMaxBytes
	remaining := resolved.Budget.RemainingBytes()
	if remaining >= 0 && remaining < maxBytes {
		maxBytes = remaining
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1)) // +1 to detect truncation
	if err != nil {
		log.LogError(actx, err)
		writeJSON(w, http.StatusBadGateway, FetchResponse{
			URL:   displayURL,
			Agent: agent,
			Error: fmt.Sprintf("reading response: %v", err),
		})
		return
	}
	if int64(len(body)) > maxBytes {
		// Determine which limit was the actual constraint.
		if remaining < 0 || configMaxBytes <= remaining {
			// Config max_response_mb was the limiter, not budget.
			// Return 502 (response too large) without recording against budget.
			reason := fmt.Sprintf("response size %d exceeds max_response_mb %d", len(body), configMaxBytes)
			log.LogBlocked(actx, "response_size", reason)
			p.metrics.RecordBlocked(parsed.Hostname(), "response_size", time.Since(start), agentLabel)
			writeJSON(w, http.StatusBadGateway, FetchResponse{
				URL:         displayURL,
				Agent:       agent,
				Blocked:     true,
				BlockReason: reason,
			})
			return
		}
		// Budget was the limiter: return 429.
		reason := fmt.Sprintf("response size %d exceeds byte budget %d", len(body), maxBytes)
		log.LogBlocked(actx, "budget", reason)
		p.metrics.RecordBlocked(parsed.Hostname(), "budget", time.Since(start), agentLabel)
		_ = resolved.Budget.RecordBytes(int64(len(body)))
		writeJSON(w, http.StatusTooManyRequests, FetchResponse{
			URL:         displayURL,
			Agent:       agent,
			Blocked:     true,
			BlockReason: reason,
		})
		return
	}

	contentType := resp.Header.Get("Content-Type")
	title := ""

	isHTML := strings.Contains(contentType, "text/html") || strings.Contains(contentType, "application/xhtml")

	// Browser Shield: strip fingerprinting, extension probing, and agent traps
	// before the content reaches readability extraction and response scanning.
	// Use the final response origin (after redirects), not the original request
	// URL. An exempt origin that 302s to a non-exempt host must still be shielded.
	shieldHost := resp.Request.URL.Hostname()
	body, shieldBlocked := p.applyShield(body, contentType, shieldHost, resp.Header, cfg, actx, clientIP, requestID, TransportFetch)
	if shieldBlocked {
		p.metrics.RecordBlocked(parsed.Hostname(), "shield_oversize", time.Since(start), agentLabel)
		writeJSON(w, http.StatusForbidden, FetchResponse{
			URL: displayURL, Agent: agent, Blocked: true,
			BlockReason: "response body exceeds browser shield size limit",
		})
		return
	}
	content := string(body)

	// Extract text from HTML hiding spots (comments, script/style bodies)
	// that readability strips. Scan only those fragments for injection,
	// not the full HTML markup, to avoid false positives on legitimate tags.
	// Use the final response origin after redirects, not the original request
	// URL. An exempt origin that 302s to a non-exempt host must still be scanned.
	finalHost := resp.Request.URL.Hostname()
	responseScanExempt := isResponseScanExempt(finalHost, cfg.ResponseScanning.ExemptDomains)
	if sc.ResponseScanningEnabled() && responseScanExempt {
		log.LogResponseScanExempt(actx, finalHost)
	}
	var hiddenInjectionFound bool
	if sc.ResponseScanningEnabled() && isHTML {
		hidden := extractHiddenContent(content)
		if hidden != "" {
			rawResult := sc.ScanResponse(r.Context(), hidden)
			// Use live escalation level so mid-request CEE escalations are reflected.
			// Exempt domains: scan for visibility but pin to warn, no adaptive scoring.
			blocked, _, found := p.filterAndActOnResponseScan(w, rawResult, content, displayURL, agent, clientIP, requestID, sc, cfg, log, recEscalationLevel(fetchRec), responseScanExempt)
			if blocked {
				return
			}
			if found {
				hasFinding = true
			}
			hiddenInjectionFound = found
		}
	}

	// Use go-readability for HTML content extraction.
	readabilityOK := false
	if isHTML {
		article, err := readability.FromReader(strings.NewReader(content), parsed)
		if err != nil {
			log.LogAnomaly(actx, "", fmt.Sprintf("readability extraction failed: %v", err), 0.3)
		} else if article.TextContent != "" {
			title = article.Title
			content = article.TextContent
			readabilityOK = true
		}
	}

	// Fail-closed: if hidden injection was detected in HTML comments/script/
	// style/hidden elements but readability failed to strip them, block rather
	// than delivering raw HTML with embedded injection. The pre-scan's
	// TransformedContent cannot map back to the full HTML (it operates on
	// concatenated fragments), so strip cannot function here.
	if hiddenInjectionFound && !readabilityOK {
		reason := "hidden injection detected and readability extraction failed (fail-closed)"
		log.LogBlocked(actx, "response_scan", reason)
		p.metrics.RecordBlocked(parsed.Hostname(), "response_scan", time.Since(start), agentLabel)
		writeJSON(w, http.StatusForbidden, FetchResponse{URL: displayURL, Agent: agent, Blocked: true, BlockReason: reason})
		return
	}

	// Response scanning: check extracted content for prompt injection.
	// Exempt domains are still scanned for visibility (findings logged as warn)
	// but adaptive scoring is skipped and actions are not upgraded.
	if sc.ResponseScanningEnabled() {
		scanResult := sc.ScanResponse(r.Context(), content)

		// Capture observer: record response scan verdict for policy replay.
		respAction := sc.ResponseAction()
		if responseScanExempt {
			respAction = config.ActionWarn
		}
		if scanResult.Clean {
			respAction = ""
		}
		p.captureObs.ObserveResponseVerdict(r.Context(), &capture.ResponseVerdictRecord{
			Subsurface:        "response_fetch",
			Transport:         "fetch",
			RequestID:         requestID,
			Agent:             agent,
			Request:           capture.CaptureRequest{Method: r.Method, URL: displayURL},
			TransformKind:     capture.TransformReadability,
			RawFindings:       responseMatchesToFindings(scanResult.Matches, respAction),
			EffectiveFindings: responseMatchesToFindings(scanResult.Matches, respAction),
			EffectiveAction:   respAction,
			Outcome:           captureOutcome(respAction, scanResult.Clean),
		})

		// Use live escalation level so mid-request CEE escalations are reflected.
		// Exempt domains: scan for visibility but pin to warn, no adaptive scoring.
		blocked, newContent, found := p.filterAndActOnResponseScan(w, scanResult, content, displayURL, agent, clientIP, requestID, sc, cfg, log, recEscalationLevel(fetchRec), responseScanExempt)
		if found {
			hasFinding = true
		}
		if blocked {
			p.metrics.RecordBlocked(parsed.Hostname(), "response_scan", time.Since(start), agentLabel)
			return
		}
		content = newContent
	}

	// Deferred RecordClean: apply score decay only when no finding was detected
	// during the entire fetch lifecycle (URL, header DLP, CEE, response scan).
	// This ensures warn/near-miss findings do not inadvertently decay score.
	if fetchRec != nil && cfg.AdaptiveEnforcement.Enabled && !hasFinding {
		fetchRec.RecordClean(cfg.AdaptiveEnforcement.DecayPerCleanRequest)
	}

	// Record response size for per-domain data budget tracking
	sc.RecordRequest(strings.ToLower(parsed.Hostname()), len(body))

	// Record response bytes against the per-agent byte budget. Oversize
	// responses are already blocked during the read phase above, so this
	// records the actual bytes consumed for successful responses.
	_ = resolved.Budget.RecordBytes(int64(len(body)))

	duration := time.Since(start)
	p.metrics.RecordAllowed(duration, agentLabel)
	p.emitReceipt(receipt.EmitOpts{
		ActionID:  receipt.NewActionID(),
		Verdict:   config.ActionAllow,
		Transport: "fetch",
		Method:    http.MethodGet,
		Target:    displayURL,
		RequestID: requestID,
		Agent:     agent,
	})
	log.LogAllowed(actx, resp.StatusCode, len(body), duration)

	writeJSON(w, http.StatusOK, FetchResponse{
		URL:         displayURL,
		Agent:       agent,
		StatusCode:  resp.StatusCode,
		ContentType: contentType,
		Title:       title,
		Content:     content,
		Blocked:     false,
	})
}

// filterAndActOnResponseScan applies suppression filtering and the configured
// response scanning action to a scan result. Returns blocked=true if the
// request was blocked (HTTP response already written), the output content
// (possibly stripped), and found=true if unsuppressed findings remain.
// sessionLevel is the current adaptive escalation level from recordSessionActivity.
// exempt indicates the domain was in exempt_domains: findings are logged as
// warn but adaptive scoring is skipped and UpgradeAction is not applied.
// This preserves operator visibility without triggering escalation death spirals.
func (p *Proxy) filterAndActOnResponseScan(
	w http.ResponseWriter,
	result scanner.ResponseScanResult,
	content, displayURL, agent, clientIP, requestID string,
	sc *scanner.Scanner,
	cfg *config.Config,
	log *audit.Logger,
	sessionLevel int,
	exempt bool,
) (blocked bool, out string, found bool) {
	out = content

	// Filter out suppressed findings.
	if !result.Clean && len(cfg.Suppress) > 0 {
		var kept []scanner.ResponseMatch
		for _, m := range result.Matches {
			if !config.IsSuppressed(m.PatternName, displayURL, cfg.Suppress) {
				kept = append(kept, m)
			}
		}
		result.Matches = kept
		result.Clean = len(kept) == 0
	}
	if result.Clean {
		return false, out, false
	}

	patternNames := make([]string, len(result.Matches))
	for i, m := range result.Matches {
		patternNames[i] = m.PatternName
	}
	bundleRules := responseBundleRules(result.Matches)

	// Adaptive enforcement: upgrade the response action before the switch.
	// Exempt domains are pinned to warn — the operator's trust decision
	// overrides adaptive escalation. This prevents death spirals where LLM
	// responses naturally contain instruction-like text.
	action := sc.ResponseAction()
	if exempt {
		action = config.ActionWarn
	}
	originalAction := action
	if !exempt {
		action = decide.UpgradeAction(action, sessionLevel, &cfg.AdaptiveEnforcement)
	}
	if action != originalAction {
		sessionKey := clientIP
		if agent != "" && agent != agentAnonymous {
			sessionKey = agent + "|" + clientIP
		}
		log.LogAdaptiveUpgrade(sessionKey, session.EscalationLabel(sessionLevel), originalAction, action, "response_scan", clientIP, requestID)
		p.metrics.RecordAdaptiveUpgrade(originalAction, action, session.EscalationLabel(sessionLevel))
	}

	// recordResponseSignal records an adaptive enforcement signal for the
	// response scan result. Exempt domains skip scoring — their findings
	// are logged but don't contribute to session escalation.
	recordResponseSignal := func(sig session.SignalType) {
		if exempt {
			return
		}
		if sm := p.sessionMgrPtr.Load(); sm != nil && cfg.AdaptiveEnforcement.Enabled {
			sessionKey := clientIP
			if agent != "" && agent != agentAnonymous {
				sessionKey = agent + "|" + clientIP
			}
			sess := sm.GetOrCreate(sessionKey)
			decide.RecordSignal(sess, sig, decide.EscalationParams{
				Threshold: cfg.AdaptiveEnforcement.EscalationThreshold,
				Logger:    log,
				Metrics:   p.metrics,
				Session:   sessionKey,
				ClientIP:  clientIP,
				RequestID: requestID,
			})
		}
	}

	switch action {
	case config.ActionBlock:
		recordResponseSignal(session.SignalBlock)
		reason := fmt.Sprintf("response contains prompt injection: %s", strings.Join(patternNames, ", "))
		log.LogBlocked(audit.LogContext{Method: "GET", URL: displayURL, ClientIP: clientIP, RequestID: requestID, Agent: agent}, "response_scan", reason)
		writeJSON(w, http.StatusForbidden, FetchResponse{URL: displayURL, Agent: agent, Blocked: true, BlockReason: reason})
		return true, "", true
	case config.ActionAsk:
		if p.approver == nil {
			recordResponseSignal(session.SignalBlock)
			reason := fmt.Sprintf("response contains prompt injection: %s (no HITL approver)", strings.Join(patternNames, ", "))
			log.LogBlocked(audit.LogContext{Method: "GET", URL: displayURL, ClientIP: clientIP, RequestID: requestID, Agent: agent}, "response_scan", reason)
			writeJSON(w, http.StatusForbidden, FetchResponse{URL: displayURL, Agent: agent, Blocked: true, BlockReason: reason})
			return true, "", true
		}
		preview := content
		if len(preview) > 200 {
			preview = preview[:200]
		}
		d := p.approver.Ask(&hitl.Request{
			Agent:    agent,
			URL:      displayURL,
			Reason:   fmt.Sprintf("prompt injection detected: %s", strings.Join(patternNames, ", ")),
			Patterns: patternNames,
			Preview:  preview,
		})
		switch d {
		case hitl.DecisionAllow:
			log.LogResponseScan(audit.LogContext{URL: displayURL, ClientIP: clientIP, RequestID: requestID, Agent: agent}, "ask:allow", len(result.Matches), patternNames, bundleRules)
		case hitl.DecisionStrip:
			out = result.TransformedContent
			log.LogResponseScan(audit.LogContext{URL: displayURL, ClientIP: clientIP, RequestID: requestID, Agent: agent}, "ask:strip", len(result.Matches), patternNames, bundleRules)
		default:
			recordResponseSignal(session.SignalBlock)
			reason := fmt.Sprintf("response blocked by operator: %s", strings.Join(patternNames, ", "))
			log.LogBlocked(audit.LogContext{Method: "GET", URL: displayURL, ClientIP: clientIP, RequestID: requestID, Agent: agent}, "response_scan", reason)
			writeJSON(w, http.StatusForbidden, FetchResponse{URL: displayURL, Agent: agent, Blocked: true, BlockReason: reason})
			return true, "", true
		}
	case config.ActionStrip:
		recordResponseSignal(session.SignalStrip)
		out = result.TransformedContent
		log.LogResponseScan(audit.LogContext{URL: displayURL, ClientIP: clientIP, RequestID: requestID, Agent: agent}, config.ActionStrip, len(result.Matches), patternNames, bundleRules)
	case config.ActionWarn:
		recordResponseSignal(session.SignalNearMiss)
		log.LogResponseScan(audit.LogContext{URL: displayURL, ClientIP: clientIP, RequestID: requestID, Agent: agent}, config.ActionWarn, len(result.Matches), patternNames, bundleRules)
	default:
		recordResponseSignal(session.SignalNearMiss)
		log.LogResponseScan(audit.LogContext{URL: displayURL, ClientIP: clientIP, RequestID: requestID, Agent: agent}, action, len(result.Matches), patternNames, bundleRules)
	}
	return false, out, true
}

// stripFetchControlChars removes C0 control characters (0x00-0x1F) and DEL
// (0x7F) from a URL string. These characters break url.Parse (Go rejects them
// as "invalid control character") and can be used to evade DLP scanning by
// splitting regex matches (e.g., "sk-ant-%00key..." parsed as invalid instead
// of being caught as a DLP match). Preserves all printable characters.
func stripFetchControlChars(s string) string {
	return strings.Map(func(r rune) rune {
		if r <= 0x1F || r == 0x7F {
			return -1
		}
		return r
	}, s)
}

// extractTargetURL extracts the full target URL from the request query string.
// Standard url.Values parsing splits on '&', which silently truncates unencoded
// target URLs: /fetch?url=https://example.com/?a=b&secret=key is parsed as two
// separate params (url=…a=b, secret=key) — the secret escapes all scanners.
//
// This function detects truncation by checking for unrecognized query params
// (the /fetch endpoint only uses "url" and "agent") and falls back to raw
// query string extraction when truncation is detected.
func extractTargetURL(r *http.Request) string {
	query := r.URL.Query()
	targetURL := query.Get("url")
	if targetURL == "" {
		return ""
	}

	// If only recognized params exist, standard parsing was correct.
	for key := range query {
		if key != "url" && key != "agent" {
			// Unknown param — target URL contains unencoded '&' and was truncated.
			return extractRawURLParam(r.URL.RawQuery)
		}
	}
	return targetURL
}

// extractRawURLParam extracts the url= value from a raw query string without
// splitting on '&'. This preserves the full target URL including any unencoded
// ampersands. The value is URL-decoded to handle percent-encoded characters.
func extractRawURLParam(rawQuery string) string {
	const prefix = "url="
	var start int
	if strings.HasPrefix(rawQuery, prefix) {
		start = len(prefix)
	} else if i := strings.Index(rawQuery, "&"+prefix); i >= 0 {
		start = i + 1 + len(prefix)
	} else {
		return ""
	}

	value := rawQuery[start:]

	if decoded, err := url.QueryUnescape(value); err == nil {
		return decoded
	}
	return value
}

// healthResponse is the JSON response returned by the /health endpoint.
type healthResponse struct {
	Status                 string  `json:"status"`
	Version                string  `json:"version"`
	Mode                   string  `json:"mode"`
	UptimeSeconds          float64 `json:"uptime_seconds"`
	DLPPatterns            int     `json:"dlp_patterns"`
	ResponseScanEnabled    bool    `json:"response_scan_enabled"`
	GitProtectionEnabled   bool    `json:"git_protection_enabled"`
	RateLimitEnabled       bool    `json:"rate_limit_enabled"`
	ForwardProxyEnabled    bool    `json:"forward_proxy_enabled"`
	WebSocketProxyEnabled  bool    `json:"websocket_proxy_enabled"`
	RequestBodyScanEnabled bool    `json:"request_body_scan_enabled"`
	TLSInterceptionEnabled bool    `json:"tls_interception_enabled"`
	KillSwitchActive       bool    `json:"kill_switch_active"`
}

// handleHealth returns proxy health status including uptime and feature flags.
func (p *Proxy) handleHealth(w http.ResponseWriter, _ *http.Request) {
	cfg := p.cfgPtr.Load()
	resp := healthResponse{
		Status:                 "healthy",
		Version:                Version,
		Mode:                   cfg.Mode,
		UptimeSeconds:          time.Since(p.startTime).Seconds(),
		DLPPatterns:            len(cfg.DLP.Patterns),
		ResponseScanEnabled:    cfg.ResponseScanning.Enabled,
		GitProtectionEnabled:   cfg.GitProtection.Enabled,
		RateLimitEnabled:       cfg.FetchProxy.Monitoring.MaxReqPerMinute > 0,
		ForwardProxyEnabled:    cfg.ForwardProxy.Enabled,
		WebSocketProxyEnabled:  cfg.WebSocketProxy.Enabled,
		RequestBodyScanEnabled: cfg.RequestBodyScanning.Enabled,
		TLSInterceptionEnabled: cfg.TLSInterception.Enabled,
	}
	if p.ks != nil {
		// Read-only kill switch status — no auth needed. Lets operators
		// see kill switch state from the main port even when the API
		// is on a separate port.
		for _, active := range p.ks.Sources() {
			if active {
				resp.KillSwitchActive = true
				break
			}
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		// Best effort: header already sent, log to stderr
		fmt.Fprintf(os.Stderr, "pipelock: writeJSON encode error: %v\n", err)
	}
}
