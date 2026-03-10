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
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	readability "github.com/go-shiori/go-readability"
	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/certgen"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/edition"
	"github.com/luckyPipewrench/pipelock/internal/hitl"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
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
	dialer            *net.Dialer
	client            *http.Client
	tlsTransport      *http.Transport // shared Transport for TLS interception upstream connections
	server            *http.Server
	agentServers      []*http.Server // per-agent listeners (managed by CLI)
	startTime         time.Time
	reloadMu          sync.Mutex // serializes Reload calls
	approver          *hitl.Approver
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
		logger:    logger,
		metrics:   m,
		startTime: time.Now(),
	}
	for _, opt := range opts {
		opt(p)
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
		p.sessionMgrPtr.Store(NewSessionManager(&cfg.SessionProfiling, m))
	}

	if cfg.CrossRequestDetection.Enabled {
		if cfg.CrossRequestDetection.EntropyBudget.Enabled {
			et := scanner.NewEntropyTracker(
				cfg.CrossRequestDetection.EntropyBudget.BitsPerWindow,
				cfg.CrossRequestDetection.EntropyBudget.WindowMinutes*60, // minutes to seconds
			)
			p.entropyTrackerPtr.Store(et)
		}
		if cfg.CrossRequestDetection.FragmentReassembly.Enabled {
			fb := scanner.NewFragmentBuffer(
				cfg.CrossRequestDetection.FragmentReassembly.MaxBufferBytes,
				10000, // max concurrent sessions for fragment tracking
				cfg.CrossRequestDetection.EntropyBudget.WindowMinutes*60, // minutes to seconds
				cfg.CrossRequestDetection.FragmentReassembly.RescanDebounceMs,
			)
			p.fragmentBufferPtr.Store(fb)
		}
	}

	p.updateCEEStats()

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
			result := currentScanner.Scan(redirectURL)
			if !result.Allowed {
				if currentCfg.EnforceEnabled() {
					logger.LogBlocked("GET", redirectURL, "redirect", fmt.Sprintf("redirect from %s blocked: %s", originalURL, result.Reason), clientIP, requestID, agentName)
					return fmt.Errorf("redirect blocked: %s", result.Reason)
				}
				logger.LogAnomaly("GET", redirectURL, result.Scanner, fmt.Sprintf("redirect from %s: %s", originalURL, result.Reason), clientIP, requestID, agentName, result.Score)
			}
			return nil
		},
	}

	p.tlsTransport = newTLSInterceptTransport(p.ssrfSafeDialContext, m.RecordTLSHandshake, nil)

	return p, nil
}

// CurrentConfig returns the currently active config. Used for reload comparison.
func (p *Proxy) CurrentConfig() *config.Config {
	return p.cfgPtr.Load()
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
		p.logger.LogError("RELOAD", "", "", "", "", fmt.Errorf("edition rebuild failed, keeping old config: %w", edErr))
		sc.Close() // caller-allocated scanner must be closed since we're not using it
		return
	}

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
	wasEnabled := oldCfg.SessionProfiling.Enabled
	isEnabled := cfg.SessionProfiling.Enabled
	if !wasEnabled && isEnabled {
		p.sessionMgrPtr.Store(NewSessionManager(&cfg.SessionProfiling, p.metrics))
	} else if wasEnabled && !isEnabled {
		if old := p.sessionMgrPtr.Swap(nil); old != nil {
			old.Close()
		}
	} else if wasEnabled && isEnabled {
		// Config values changed while profiling stays enabled — update in place
		// so TTL/capacity thresholds take effect without losing session state.
		if sm := p.sessionMgrPtr.Load(); sm != nil {
			sm.UpdateConfig(&cfg.SessionProfiling)
		}
	}

	// Toggle CEE components on config change. Entropy/fragment data is lost
	// on reload, which is acceptable for short sliding windows (typically 5 min).
	if oldET := p.entropyTrackerPtr.Swap(nil); oldET != nil {
		oldET.Close()
	}
	if oldFB := p.fragmentBufferPtr.Swap(nil); oldFB != nil {
		oldFB.Close()
	}
	if cfg.CrossRequestDetection.Enabled {
		if cfg.CrossRequestDetection.EntropyBudget.Enabled {
			et := scanner.NewEntropyTracker(
				cfg.CrossRequestDetection.EntropyBudget.BitsPerWindow,
				cfg.CrossRequestDetection.EntropyBudget.WindowMinutes*60, // minutes to seconds
			)
			p.entropyTrackerPtr.Store(et)
		}
		if cfg.CrossRequestDetection.FragmentReassembly.Enabled {
			fb := scanner.NewFragmentBuffer(
				cfg.CrossRequestDetection.FragmentReassembly.MaxBufferBytes,
				10000, // max concurrent sessions for fragment tracking
				cfg.CrossRequestDetection.EntropyBudget.WindowMinutes*60, // minutes to seconds
				cfg.CrossRequestDetection.FragmentReassembly.RescanDebounceMs,
			)
			p.fragmentBufferPtr.Store(fb)
		}
	}

	p.updateCEEStats()
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

// updateCEEStats registers a callback that returns live CEE state for the
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
// Returns (blocked, blockDetail) when the request should be rejected due to a
// session anomaly in block mode.
func (p *Proxy) recordSessionActivity(clientIP, agent, hostname, requestID string, resultAllowed bool, resultScore float64, cfg *config.Config, log *audit.Logger) (bool, string) {
	sm := p.sessionMgrPtr.Load()
	if sm == nil || !cfg.SessionProfiling.Enabled {
		return false, ""
	}

	// Build session key: agent|clientIP when agent is known, else just clientIP.
	key := clientIP
	if agent != "" && agent != agentAnonymous {
		key = agent + "|" + clientIP
	}

	sess := sm.GetOrCreate(key)
	anomalies := sess.RecordRequest(hostname, &cfg.SessionProfiling)

	// IP-level domain tracking: catches header rotation attacks where the
	// agent identity changes per request but the source IP stays the same.
	ipAnomalies := sm.RecordIPDomain(clientIP, hostname, &cfg.SessionProfiling)
	anomalies = append(anomalies, ipAnomalies...)

	// Record adaptive signals (only when adaptive enforcement is enabled).
	// NOTE: v1 is scoring-only — signals accumulate and escalation events are
	// logged/metriced for observability, but enforcement behavior is not yet
	// changed by escalation level. Escalation-aware blocking is planned for v2.
	if cfg.AdaptiveEnforcement.Enabled {
		adaptiveCfg := cfg.AdaptiveEnforcement
		if !resultAllowed {
			if escalated, from, to := sess.RecordSignal(SignalBlock, adaptiveCfg.EscalationThreshold); escalated {
				log.LogAdaptiveEscalation(key, from, to, clientIP, requestID, sess.ThreatScore())
				p.metrics.RecordSessionEscalation(from, to)
			}
		} else if resultScore > 0 {
			if escalated, from, to := sess.RecordSignal(SignalDLPNearMiss, adaptiveCfg.EscalationThreshold); escalated {
				log.LogAdaptiveEscalation(key, from, to, clientIP, requestID, sess.ThreatScore())
				p.metrics.RecordSessionEscalation(from, to)
			}
		} else {
			sess.RecordClean(adaptiveCfg.DecayPerCleanRequest)
		}
	}

	for _, a := range anomalies {
		log.LogSessionAnomaly(key, a.Type, a.Detail, clientIP, requestID, a.Score)
		p.metrics.RecordSessionAnomaly(a.Type)

		if cfg.SessionProfiling.AnomalyAction == config.ActionBlock && cfg.EnforceEnabled() {
			return true, fmt.Sprintf("session anomaly: %s", a.Detail)
		}
	}

	return false, ""
}

// ssrfSafeDialContext resolves DNS and validates all IPs against internal
// CIDRs before connecting. Prevents DNS rebinding SSRF where an attacker
// returns a safe IP during scanning but a private IP at connection time.
// Used by both the HTTP client transport and CONNECT tunnel dialing.
func (p *Proxy) ssrfSafeDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("ssrfSafeDialContext: split addr %q: %w", addr, err)
	}

	// If the host is already an IP, check it and dial directly.
	if ip := net.ParseIP(host); ip != nil {
		// Normalize IPv4-mapped IPv6 (::ffff:x.x.x.x) to 4-byte form,
		// consistent with the DNS resolution path below.
		if v4 := ip.To4(); v4 != nil {
			ip = v4
		}
		if currentSc := p.scannerPtr.Load(); currentSc.IsInternalIP(ip) {
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
					p.logger.LogError("SHUTDOWN", srv.Addr, "", "", "", shutErr)
				}
			}
			if err := p.server.Shutdown(shutdownCtx); err != nil {
				p.logger.LogError("SHUTDOWN", cfg.FetchProxy.Listen, "", "", "", err)
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
				p.logger.LogAnomaly("STARTUP", cfg.FetchProxy.Listen, "",
					"listen address is not loopback — /metrics and /stats endpoints are exposed to the network",
					"", "", "", 0.5)
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

	// Scan URL through all scanners
	result := sc.Scan(targetURL)

	// Session profiling: record BEFORE the enforce-mode early return so adaptive
	// signals (SignalBlock) fire even for blocked requests.
	sessionBlocked, sessionDetail := p.recordSessionActivity(clientIP, agent, parsed.Hostname(), requestID, result.Allowed, result.Score, cfg, log)

	if !result.Allowed {
		if cfg.EnforceEnabled() {
			log.LogBlocked("GET", displayURL, result.Scanner, result.Reason, clientIP, requestID, agent)
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
		// Audit mode: log anomaly but allow through
		log.LogAnomaly("GET", displayURL, result.Scanner, result.Reason, clientIP, requestID, agent, result.Score)
	}

	if sessionBlocked {
		writeJSON(w, http.StatusForbidden, FetchResponse{
			URL:         displayURL,
			Agent:       agent,
			Blocked:     true,
			BlockReason: sessionDetail,
		})
		return
	}

	// Request header DLP scanning (fetch is GET-only, no body to scan).
	if p.evalHeaderDLP(r.Header, cfg, sc, log, "GET", displayURL, parsed.Hostname(), clientIP, requestID, agent, start) {
		writeJSON(w, http.StatusForbidden, FetchResponse{
			URL:         displayURL,
			Agent:       agent,
			Blocked:     true,
			BlockReason: "request header contains secret",
		})
		return
	}

	// Budget admission check: enforce request count and domain limits before
	// making the outbound request. Byte budget is checked after the response.
	if err := resolved.Budget.CheckAdmission(strings.ToLower(parsed.Hostname())); err != nil {
		reason := err.Error()
		log.LogBlocked("GET", displayURL, "budget", reason, clientIP, requestID, agent)
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
	// GET-only so the outbound data is the query parameters from the target URL.
	ceeCfg := cfg.CrossRequestDetection
	if ceeCfg.Enabled {
		sessionKey := ceeSessionKey(agent, clientIP)
		var outbound []byte
		if qv := parsed.Query(); len(qv) > 0 {
			var parts []string
			for _, values := range qv {
				parts = append(parts, values...)
			}
			outbound = []byte(strings.Join(parts, ""))
		}

		ceeRes := ceeAdmit(sessionKey, outbound, displayURL, agent, clientIP, requestID,
			ceeCfg, p.entropyTrackerPtr.Load(), p.fragmentBufferPtr.Load(), sc, log, p.metrics)

		if sm := p.sessionMgrPtr.Load(); sm != nil && cfg.AdaptiveEnforcement.Enabled {
			ceeRecordSignals(ceeRes, sm, sessionKey, cfg.AdaptiveEnforcement.EscalationThreshold, log, p.metrics, clientIP, requestID)
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
		log.LogError("GET", displayURL, clientIP, requestID, agent, err)
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
			log.LogBlocked("GET", displayURL, "redirect", reason, clientIP, requestID, agent)
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
		log.LogError("GET", displayURL, clientIP, requestID, agent, err)
		writeJSON(w, http.StatusBadGateway, FetchResponse{
			URL:   displayURL,
			Agent: agent,
			Error: fmt.Sprintf("fetch failed: %v", err),
		})
		return
	}
	defer resp.Body.Close() //nolint:errcheck // response body

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
		log.LogError("GET", displayURL, clientIP, requestID, agent, err)
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
			log.LogBlocked("GET", displayURL, "response_size", reason, clientIP, requestID, agent)
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
		log.LogBlocked("GET", displayURL, "budget", reason, clientIP, requestID, agent)
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
	content := string(body)
	title := ""

	isHTML := strings.Contains(contentType, "text/html") || strings.Contains(contentType, "application/xhtml")

	// Extract text from HTML hiding spots (comments, script/style bodies)
	// that readability strips. Scan only those fragments for injection,
	// not the full HTML markup, to avoid false positives on legitimate tags.
	var hiddenInjectionFound bool
	if sc.ResponseScanningEnabled() && isHTML {
		hidden := extractHiddenContent(content)
		if hidden != "" {
			rawResult := sc.ScanResponse(hidden)
			blocked, _, found := p.filterAndActOnResponseScan(w, rawResult, content, displayURL, agent, clientIP, requestID, sc, cfg, log)
			if blocked {
				return
			}
			hiddenInjectionFound = found
		}
	}

	// Use go-readability for HTML content extraction.
	readabilityOK := false
	if isHTML {
		article, err := readability.FromReader(strings.NewReader(content), parsed)
		if err != nil {
			log.LogAnomaly("GET", displayURL, "", fmt.Sprintf("readability extraction failed: %v", err), clientIP, requestID, agent, 0.3)
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
		log.LogBlocked("GET", displayURL, "response_scan", reason, clientIP, requestID, agent)
		p.metrics.RecordBlocked(parsed.Hostname(), "response_scan", time.Since(start), agentLabel)
		writeJSON(w, http.StatusForbidden, FetchResponse{URL: displayURL, Agent: agent, Blocked: true, BlockReason: reason})
		return
	}

	// Response scanning: check extracted content for prompt injection.
	if sc.ResponseScanningEnabled() {
		scanResult := sc.ScanResponse(content)
		blocked, newContent, _ := p.filterAndActOnResponseScan(w, scanResult, content, displayURL, agent, clientIP, requestID, sc, cfg, log)
		if blocked {
			p.metrics.RecordBlocked(parsed.Hostname(), "response_scan", time.Since(start), agentLabel)
			return
		}
		content = newContent
	}

	// Record response size for per-domain data budget tracking
	sc.RecordRequest(strings.ToLower(parsed.Hostname()), len(body))

	// Record response bytes against the per-agent byte budget. Oversize
	// responses are already blocked during the read phase above, so this
	// records the actual bytes consumed for successful responses.
	_ = resolved.Budget.RecordBytes(int64(len(body)))

	duration := time.Since(start)
	p.metrics.RecordAllowed(duration, agentLabel)
	log.LogAllowed("GET", displayURL, clientIP, requestID, resp.StatusCode, len(body), duration, agent)

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
func (p *Proxy) filterAndActOnResponseScan(
	w http.ResponseWriter,
	result scanner.ResponseScanResult,
	content, displayURL, agent, clientIP, requestID string,
	sc *scanner.Scanner,
	cfg *config.Config,
	log *audit.Logger,
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

	switch sc.ResponseAction() {
	case config.ActionBlock:
		reason := fmt.Sprintf("response contains prompt injection: %s", strings.Join(patternNames, ", "))
		log.LogBlocked("GET", displayURL, "response_scan", reason, clientIP, requestID, agent)
		writeJSON(w, http.StatusForbidden, FetchResponse{URL: displayURL, Agent: agent, Blocked: true, BlockReason: reason})
		return true, "", true
	case config.ActionAsk:
		if p.approver == nil {
			reason := fmt.Sprintf("response contains prompt injection: %s (no HITL approver)", strings.Join(patternNames, ", "))
			log.LogBlocked("GET", displayURL, "response_scan", reason, clientIP, requestID, agent)
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
			log.LogResponseScan(displayURL, clientIP, requestID, agent, "ask:allow", len(result.Matches), patternNames)
		case hitl.DecisionStrip:
			out = result.TransformedContent
			log.LogResponseScan(displayURL, clientIP, requestID, agent, "ask:strip", len(result.Matches), patternNames)
		default:
			reason := fmt.Sprintf("response blocked by operator: %s", strings.Join(patternNames, ", "))
			log.LogBlocked("GET", displayURL, "response_scan", reason, clientIP, requestID, agent)
			writeJSON(w, http.StatusForbidden, FetchResponse{URL: displayURL, Agent: agent, Blocked: true, BlockReason: reason})
			return true, "", true
		}
	case config.ActionStrip:
		out = result.TransformedContent
		log.LogResponseScan(displayURL, clientIP, requestID, agent, config.ActionStrip, len(result.Matches), patternNames)
	case config.ActionWarn:
		log.LogResponseScan(displayURL, clientIP, requestID, agent, config.ActionWarn, len(result.Matches), patternNames)
	default:
		log.LogResponseScan(displayURL, clientIP, requestID, agent, sc.ResponseAction(), len(result.Matches), patternNames)
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
