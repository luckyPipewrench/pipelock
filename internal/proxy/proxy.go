// Package proxy implements the Pipelock fetch proxy HTTP server.
// The fetch proxy runs in an unprivileged zone with NO access to secrets.
// It receives URL requests from the agent, scans them, fetches content,
// and returns extracted text.
package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	readability "github.com/go-shiori/go-readability"
	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
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
)

// requestCounter provides monotonic request IDs.
var requestCounter atomic.Uint64

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

// Proxy is the Pipelock fetch proxy server.
type Proxy struct {
	cfgPtr        atomic.Pointer[config.Config]
	scannerPtr    atomic.Pointer[scanner.Scanner]
	sessionMgrPtr atomic.Pointer[SessionManager] // nil when profiling disabled
	logger        *audit.Logger
	metrics       *metrics.Metrics
	ks            *killswitch.Controller
	ksAPI         *killswitch.APIHandler
	dialer        *net.Dialer
	client        *http.Client
	server        *http.Server
	startTime     time.Time
	reloadMu      sync.Mutex // serializes Reload calls
	approver      *hitl.Approver
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
}

// New creates a new fetch proxy from config.
func New(cfg *config.Config, logger *audit.Logger, sc *scanner.Scanner, m *metrics.Metrics, opts ...Option) *Proxy {
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

	if cfg.SessionProfiling.Enabled {
		p.sessionMgrPtr.Store(NewSessionManager(&cfg.SessionProfiling, m))
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
			rlog := logger
			if agentName != "" {
				rlog = logger.With("agent", agentName)
			}
			rlog.LogRedirect(originalURL, redirectURL, clientIP, requestID, len(via))
			// Scan each redirect URL through the current scanner
			currentCfg := p.cfgPtr.Load()
			currentScanner := p.scannerPtr.Load()
			result := currentScanner.Scan(redirectURL)
			if !result.Allowed {
				if currentCfg.EnforceEnabled() {
					rlog.LogBlocked("GET", redirectURL, "redirect", fmt.Sprintf("redirect from %s blocked: %s", originalURL, result.Reason), clientIP, requestID)
					return fmt.Errorf("redirect blocked: %s", result.Reason)
				}
				rlog.LogAnomaly("GET", redirectURL, fmt.Sprintf("[audit] redirect from %s: %s", originalURL, result.Reason), clientIP, requestID, result.Score)
			}
			return nil
		},
	}
	return p
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

	oldCfg := p.cfgPtr.Load()
	p.cfgPtr.Store(cfg)
	old := p.scannerPtr.Swap(sc)

	if old != nil {
		old.Close()
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
}

// Close releases resources owned by the proxy (session manager goroutine).
// Safe to call multiple times. Does not stop the HTTP server — use context
// cancellation in Start() for that.
func (p *Proxy) Close() {
	if sm := p.sessionMgrPtr.Load(); sm != nil {
		sm.Close()
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
	if agent != "" && agent != "anonymous" { //nolint:goconst // clarity over deduplication
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
				p.logger.LogKillSwitchDeny("http", r.URL.Path, d.Source, d.Message, clientIP)
				p.metrics.RecordKillSwitchDenial("http", r.URL.Path)
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

// Start starts the fetch proxy HTTP server. It blocks until the context
// is cancelled or the server encounters a fatal error.
func (p *Proxy) Start(ctx context.Context) error {
	cfg := p.cfgPtr.Load()

	mux := http.NewServeMux()
	mux.HandleFunc("/fetch", p.handleFetch)
	mux.HandleFunc("/ws", p.handleWebSocket)
	mux.HandleFunc("/health", p.handleHealth)
	mux.Handle("/metrics", p.metrics.PrometheusHandler())
	mux.HandleFunc("/stats", p.metrics.StatsHandler())
	// Register kill switch API routes only when the API is NOT running on a
	// separate port. When api_listen is configured, these routes are served
	// by the dedicated API server — the main port returns 404, preventing
	// the agent from reaching the API to self-deactivate.
	if p.ksAPI != nil && cfg.KillSwitch.APIListen == "" {
		mux.HandleFunc("/api/v1/killswitch", p.ksAPI.HandleToggle)
		mux.HandleFunc("/api/v1/killswitch/status", p.ksAPI.HandleStatus)
	}

	handler := p.buildHandler(mux)

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

	// Graceful shutdown on context cancellation.
	// The done channel ensures this goroutine exits if ListenAndServe
	// fails immediately (e.g., address already in use).
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := p.server.Shutdown(shutdownCtx); err != nil {
				p.logger.LogError("SHUTDOWN", cfg.FetchProxy.Listen, "", "", err)
			}
			p.Close()
		case <-done:
		}
	}()

	// Warn if listen address exposes metrics/stats to the network
	if host, _, splitErr := net.SplitHostPort(cfg.FetchProxy.Listen); splitErr == nil {
		ip := net.ParseIP(host)
		if host == "" || host == "0.0.0.0" || host == "::" || (ip != nil && !ip.IsLoopback()) {
			p.logger.LogAnomaly("STARTUP", cfg.FetchProxy.Listen,
				"listen address is not loopback — /metrics and /stats endpoints are exposed to the network",
				"", "", 0.5)
		}
	}

	p.logger.LogStartup(cfg.FetchProxy.Listen, cfg.Mode)

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
	cfg := p.cfgPtr.Load()
	sc := p.scannerPtr.Load()

	clientIP, requestID := requestMeta(r)
	agent := ExtractAgent(r)

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
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") { //nolint:goconst // scheme literal
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
			log.LogBlocked("GET", displayURL, result.Scanner, result.Reason, clientIP, requestID)
			p.metrics.RecordBlocked(parsed.Hostname(), result.Scanner, time.Since(start))
			status := http.StatusForbidden
			if result.Scanner == "ratelimit" {
				status = http.StatusTooManyRequests
			}
			writeJSON(w, status, FetchResponse{
				URL:         displayURL,
				Agent:       agent,
				Blocked:     true,
				BlockReason: result.Reason,
			})
			return
		}
		// Audit mode: log anomaly but allow through
		log.LogAnomaly("GET", displayURL, fmt.Sprintf("[audit] %s: %s", result.Scanner, result.Reason), clientIP, requestID, result.Score)
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

	// Fetch the URL — attach clientIP/requestID/agent to context for redirect logging
	ctx := context.WithValue(r.Context(), ctxKeyClientIP, clientIP)
	ctx = context.WithValue(ctx, ctxKeyRequestID, requestID)
	ctx = context.WithValue(ctx, ctxKeyAgent, agent)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		log.LogError("GET", displayURL, clientIP, requestID, err)
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
			log.LogBlocked("GET", displayURL, "redirect", reason, clientIP, requestID)
			p.metrics.RecordBlocked(parsed.Hostname(), "redirect", time.Since(start))
			writeJSON(w, http.StatusForbidden, FetchResponse{
				URL:         displayURL,
				Agent:       agent,
				Blocked:     true,
				BlockReason: reason,
			})
			return
		}
		log.LogError("GET", displayURL, clientIP, requestID, err)
		writeJSON(w, http.StatusBadGateway, FetchResponse{
			URL:   displayURL,
			Agent: agent,
			Error: fmt.Sprintf("fetch failed: %v", err),
		})
		return
	}
	defer resp.Body.Close() //nolint:errcheck // response body

	// Limit response body size
	maxBytes := int64(cfg.FetchProxy.MaxResponseMB) * 1024 * 1024
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes))
	if err != nil {
		log.LogError("GET", displayURL, clientIP, requestID, err)
		writeJSON(w, http.StatusBadGateway, FetchResponse{
			URL:   displayURL,
			Agent: agent,
			Error: fmt.Sprintf("reading response: %v", err),
		})
		return
	}

	contentType := resp.Header.Get("Content-Type")
	content := string(body)
	title := ""

	// Use go-readability for HTML content extraction
	if strings.Contains(contentType, "text/html") || strings.Contains(contentType, "application/xhtml") {
		article, err := readability.FromReader(strings.NewReader(content), parsed)
		if err != nil {
			log.LogAnomaly("GET", displayURL, fmt.Sprintf("readability extraction failed: %v", err), clientIP, requestID, 0.3)
		} else if article.TextContent != "" {
			title = article.Title
			content = article.TextContent
		}
	}

	// Response scanning: check fetched content for prompt injection
	if sc.ResponseScanningEnabled() {
		scanResult := sc.ScanResponse(content)
		// Filter out suppressed findings before acting.
		if !scanResult.Clean && len(cfg.Suppress) > 0 {
			var kept []scanner.ResponseMatch
			for _, m := range scanResult.Matches {
				if !config.IsSuppressed(m.PatternName, displayURL, cfg.Suppress) {
					kept = append(kept, m)
				}
			}
			scanResult.Matches = kept
			scanResult.Clean = len(kept) == 0
		}
		if !scanResult.Clean {
			patternNames := make([]string, len(scanResult.Matches))
			for i, m := range scanResult.Matches {
				patternNames[i] = m.PatternName
			}
			switch sc.ResponseAction() {
			case config.ActionBlock:
				reason := fmt.Sprintf("response contains prompt injection: %s", strings.Join(patternNames, ", "))
				log.LogBlocked("GET", displayURL, "response_scan", reason, clientIP, requestID)
				writeJSON(w, http.StatusForbidden, FetchResponse{URL: displayURL, Agent: agent, Blocked: true, BlockReason: reason})
				return
			case config.ActionAsk:
				if p.approver == nil {
					reason := fmt.Sprintf("response contains prompt injection: %s (no HITL approver)", strings.Join(patternNames, ", "))
					log.LogBlocked("GET", displayURL, "response_scan", reason, clientIP, requestID)
					writeJSON(w, http.StatusForbidden, FetchResponse{URL: displayURL, Agent: agent, Blocked: true, BlockReason: reason})
					return
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
					log.LogResponseScan(displayURL, clientIP, requestID, "ask:allow", len(scanResult.Matches), patternNames)
				case hitl.DecisionStrip:
					content = scanResult.TransformedContent
					log.LogResponseScan(displayURL, clientIP, requestID, "ask:strip", len(scanResult.Matches), patternNames)
				default:
					reason := fmt.Sprintf("response blocked by operator: %s", strings.Join(patternNames, ", "))
					log.LogBlocked("GET", displayURL, "response_scan", reason, clientIP, requestID)
					writeJSON(w, http.StatusForbidden, FetchResponse{URL: displayURL, Agent: agent, Blocked: true, BlockReason: reason})
					return
				}
			case config.ActionStrip:
				content = scanResult.TransformedContent
				log.LogResponseScan(displayURL, clientIP, requestID, config.ActionStrip, len(scanResult.Matches), patternNames)
			case config.ActionWarn:
				log.LogResponseScan(displayURL, clientIP, requestID, config.ActionWarn, len(scanResult.Matches), patternNames)
			default:
				log.LogResponseScan(displayURL, clientIP, requestID, sc.ResponseAction(), len(scanResult.Matches), patternNames)
			}
		}
	}

	// Record response size for per-domain data budget tracking
	sc.RecordRequest(strings.ToLower(parsed.Hostname()), len(body))

	duration := time.Since(start)
	p.metrics.RecordAllowed(duration)
	log.LogAllowed("GET", displayURL, clientIP, requestID, resp.StatusCode, len(body), duration)

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
	Status                string  `json:"status"`
	Version               string  `json:"version"`
	Mode                  string  `json:"mode"`
	UptimeSeconds         float64 `json:"uptime_seconds"`
	DLPPatterns           int     `json:"dlp_patterns"`
	ResponseScanEnabled   bool    `json:"response_scan_enabled"`
	GitProtectionEnabled  bool    `json:"git_protection_enabled"`
	RateLimitEnabled      bool    `json:"rate_limit_enabled"`
	ForwardProxyEnabled   bool    `json:"forward_proxy_enabled"`
	WebSocketProxyEnabled bool    `json:"websocket_proxy_enabled"`
	KillSwitchActive      bool    `json:"kill_switch_active"`
}

// handleHealth returns proxy health status including uptime and feature flags.
func (p *Proxy) handleHealth(w http.ResponseWriter, _ *http.Request) {
	cfg := p.cfgPtr.Load()
	resp := healthResponse{
		Status:                "healthy",
		Version:               Version,
		Mode:                  cfg.Mode,
		UptimeSeconds:         time.Since(p.startTime).Seconds(),
		DLPPatterns:           len(cfg.DLP.Patterns),
		ResponseScanEnabled:   cfg.ResponseScanning.Enabled,
		GitProtectionEnabled:  cfg.GitProtection.Enabled,
		RateLimitEnabled:      cfg.FetchProxy.Monitoring.MaxReqPerMinute > 0,
		ForwardProxyEnabled:   cfg.ForwardProxy.Enabled,
		WebSocketProxyEnabled: cfg.WebSocketProxy.Enabled,
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
