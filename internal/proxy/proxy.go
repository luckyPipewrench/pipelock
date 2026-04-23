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
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/hitl"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
	"github.com/luckyPipewrench/pipelock/internal/mcp"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/redact"
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

	// ctxKeyReverseEnvelopeOpts stores the envelope.BuildOpts that the
	// reverse proxy pre-computes in ServeHTTP so the signing
	// RoundTripper (wrapping proxy.Transport) can attach a signature
	// AFTER httputil.ReverseProxy's Director has rewritten the URL to
	// the upstream target. Without this flow, signing at ServeHTTP
	// time would sign the inbound-relative @target-uri instead of the
	// upstream-absolute one, and any verifier checking @target-uri
	// would reject the signature.
	ctxKeyReverseEnvelopeOpts
	// ctxKeyReverseEnvelopeBody carries the scanner-buffered request
	// body (or nil when body scanning was disabled) across the same
	// boundary so the signer can compute content-digest without a
	// second drain pass.
	ctxKeyReverseEnvelopeBody
	// ctxKeyReverseEnvelopeCfg carries the per-request *Config used
	// by the reverse proxy dispatch so the RoundTripper sees the same
	// config snapshot ServeHTTP loaded rather than re-loading the
	// atomic pointer (which could race with a reload in flight).
	ctxKeyReverseEnvelopeCfg
	// ctxKeyReverseEnvelopeEmitter snapshots the *envelope.Emitter at
	// admission time so RoundTrip uses the same signing state that
	// ServeHTTP used to decide "signing is on." Without this, a
	// reload between ServeHTTP and RoundTrip could flip signing on/off
	// mid-request — a TOCTOU race flagged by CodeRabbit on PR #403.
	ctxKeyReverseEnvelopeEmitter

	// ctxKeyEnvelopeEmitter snapshots the *envelope.Emitter at the
	// point the fetch/forward handler first signs the outbound request.
	// refreshEnvelopeForRedirect reads this instead of the global
	// atomic so a reload mid-redirect-chain cannot flip signing
	// state for an in-flight request. Same TOCTOU fix as
	// ctxKeyReverseEnvelopeEmitter but for the client-side path.
	ctxKeyEnvelopeEmitter

	// ctxKeyRedirectTransport is the transport label ("fetch" or
	// "forward") attached by the fetch and forward handlers before
	// handing the request to p.client. The shared CheckRedirect
	// closure reads it so redirect audit events are labelled with
	// the transport that originated the request rather than the
	// hardcoded default. See Info 2 on the envelope-signing review.
	ctxKeyRedirectTransport
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

const (
	blockLayerMediationEnvelope  = "mediation_envelope"
	mediationEnvelopeBlockReason = "mediation envelope signing failed"
)

// blockedRequestError signals a fail-closed block in a request path that still
// travels through net/http error plumbing (redirect checks, reverse proxy
// transports, and similar). reason is safe to return to the client; detail is
// the fuller operator-facing log message.
type blockedRequestError struct {
	layer  string
	reason string
	detail string
}

func (e *blockedRequestError) Error() string {
	if e == nil {
		return ""
	}
	return e.reason
}

func newBlockedRequestError(layer, reason, detail string) *blockedRequestError {
	if detail == "" {
		detail = reason
	}
	return &blockedRequestError{
		layer:  layer,
		reason: reason,
		detail: detail,
	}
}

func blockedRequestErrorFrom(err error) (*blockedRequestError, bool) {
	var blockedErr *blockedRequestError
	if !errors.As(err, &blockedErr) {
		return nil, false
	}
	return blockedErr, true
}

// newRedirectBlockedRequest builds a typed block error for a redirect
// that was denied by a scanner pass. originLayer is the scanner label
// from the block source (SSRF, DLP, blocklist, …) so downstream metrics
// and receipts can attribute the decision to the scanner that actually
// made it, rather than collapsing every redirect denial into a generic
// "redirect" bucket. An empty originLayer falls back to "redirect" so
// call sites that genuinely do not know the scanner keep working.
func newRedirectBlockedRequest(originLayer, reason string) *blockedRequestError {
	fullReason := "redirect blocked: " + reason
	layer := originLayer
	if layer == "" {
		layer = "redirect"
	}
	return newBlockedRequestError(layer, fullReason, fullReason)
}

func newEnvelopeBlockedRequest(err error) *blockedRequestError {
	return newBlockedRequestError(
		blockLayerMediationEnvelope,
		mediationEnvelopeBlockReason,
		mediationEnvelopeBlockReason+": "+err.Error(),
	)
}

func newRedirectEnvelopeBlockedRequest(err error) *blockedRequestError {
	reason := "redirect blocked: " + mediationEnvelopeBlockReason
	return newBlockedRequestError(
		blockLayerMediationEnvelope,
		reason,
		reason+": "+err.Error(),
	)
}

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

func newHTTPAuditContext(logger *audit.Logger, method, targetURL, clientIP, requestID, agent string) audit.LogContext {
	ctx, err := audit.NewHTTPLogContext(method, targetURL, clientIP, requestID, agent)
	if err != nil {
		if logger != nil {
			logger.LogError(audit.NewMethodLogContext(method), err)
		}
		return audit.NewMethodLogContext(method)
	}
	return ctx
}

func newConnectAuditContext(logger *audit.Logger, target, clientIP, requestID, agent string) audit.LogContext {
	ctx, err := audit.NewConnectLogContext(target, clientIP, requestID, agent)
	if err != nil {
		if logger != nil {
			logger.LogError(audit.NewMethodLogContext(http.MethodConnect), err)
		}
		return audit.NewMethodLogContext(http.MethodConnect)
	}
	return ctx
}

// Version is set at build time via ldflags.
var Version = "0.1.0-dev"

// editionSnapshot wraps an Edition for atomic pointer storage.
type editionSnapshot struct{ edition.Edition }

// Proxy is the Pipelock fetch proxy server.
type Proxy struct {
	cfgPtr              atomic.Pointer[config.Config]
	scannerPtr          atomic.Pointer[scanner.Scanner]
	editionPtr          atomic.Pointer[editionSnapshot]
	sessionMgrPtr       atomic.Pointer[SessionManager]         // nil when profiling disabled
	certCachePtr        atomic.Pointer[certgen.CertCache]      // nil when TLS interception disabled
	entropyTrackerPtr   atomic.Pointer[scanner.EntropyTracker] // nil when entropy budget disabled
	fragmentBufferPtr   atomic.Pointer[scanner.FragmentBuffer] // nil when fragment reassembly disabled
	redactionRuntimePtr atomic.Pointer[redactionRuntime]       // nil when redaction disabled
	redactMatcherPtr    atomic.Pointer[redact.Matcher]         // nil when redaction disabled
	logger              *audit.Logger
	metrics             *metrics.Metrics
	ks                  *killswitch.Controller
	ksAPI               *killswitch.APIHandler
	sessionAPI          *SessionAPIHandler
	dialer              *net.Dialer
	client              *http.Client
	tlsTransport        *http.Transport // shared Transport for TLS interception upstream connections
	server              *http.Server
	agentServers        []*http.Server // per-agent listeners (managed by CLI)
	startTime           time.Time
	reloadMu            sync.RWMutex // serializes Reload and coherent request-time runtime snapshots
	approver            *hitl.Approver
	a2aCardBaseline     *mcp.CardBaseline // Agent Card drift detection across requests
	captureObs          capture.CaptureObserver
	recorder            *recorder.Recorder               // flight recorder for tamper-evident evidence (nil = disabled)
	receiptEmitterPtr   atomic.Pointer[receipt.Emitter]  // action receipt emitter (nil = disabled)
	receiptKeyPath      string                           // active signing key path, for reload comparison
	envelopeEmitterPtr  atomic.Pointer[envelope.Emitter] // mediation envelope emitter (nil = disabled)
	shieldEngine        *shield.Engine                   // browser shield HTML/JS rewriter (nil = not initialized)
	frozenTools         *FrozenToolRegistry              // frozen tool inventories for airlock hard tier
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

// WithEnvelopeEmitter sets the mediation envelope emitter. When non-nil, the
// proxy injects signed mediation envelopes into proxied requests. Pass nil to
// disable (default).
func WithEnvelopeEmitter(e *envelope.Emitter) Option {
	return func(p *Proxy) { p.envelopeEmitterPtr.Store(e) }
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

	// Startup envelope wiring mirrors the reload lane: ensure an
	// enabled envelope always has the canonical policy hash installed,
	// and when sign:true is configured, replace any header-only
	// startup emitter with a signer-backed instance before the first
	// request is served. This closes the cold-start gap where the
	// runtime passed WithEnvelopeEmitter(header-only) and the signer
	// would not appear until the first reload.
	if cfg.MediationEnvelope.Enabled {
		if em := p.envelopeEmitterPtr.Load(); em == nil || (cfg.MediationEnvelope.Sign && !em.HasSigner()) {
			stage, err := p.buildEnvelopeEmitter(cfg)
			if err != nil {
				return nil, fmt.Errorf("envelope emitter init: %w", err)
			}
			if stage.enabled {
				p.envelopeEmitterPtr.Store(stage.emitter)
			}
		} else {
			em.UpdateConfigHash(cfg.CanonicalPolicyHash())
		}
	}

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

	if err := p.setupRedaction(cfg); err != nil {
		return nil, err
	}

	// Create session admin API handler when an API token is configured.
	// Mirrors the kill switch env-var override: PIPELOCK_KILLSWITCH_API_TOKEN
	// takes precedence over the YAML value.
	apiToken := cfg.KillSwitch.APIToken
	if envToken := os.Getenv(killswitch.EnvAPIToken); envToken != "" {
		apiToken = envToken
	}
	if apiToken != "" {
		p.sessionAPI = NewSessionAPIHandler(SessionAPIOptions{
			SessionMgrPtr: &p.sessionMgrPtr,
			EntropyPtr:    &p.entropyTrackerPtr,
			FragmentPtr:   &p.fragmentBufferPtr,
			Metrics:       m,
			Logger:        logger,
			APIToken:      apiToken,
		})
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
			redirectWarnCtx := scanner.DLPWarnContextFromCtx(req.Context())
			redirectWarnCtx.Method = req.Method
			redirectWarnCtx.URL = redirectURL
			redirectWarnCtx.ClientIP = clientIP
			redirectWarnCtx.RequestID = requestID
			redirectWarnCtx.Agent = agentName
			// Derive transport from the original request context so
			// forward-proxy redirects log and audit as "forward" and
			// fetch-proxy redirects log as "fetch". Hard-coding
			// TransportFetch here mislabels every forward-proxy
			// redirect — both paths share p.client and therefore
			// share this CheckRedirect closure.
			if t, ok := req.Context().Value(ctxKeyRedirectTransport).(string); ok && t != "" {
				redirectWarnCtx.Transport = t
			} else {
				redirectWarnCtx.Transport = TransportFetch
			}
			result := currentScanner.Scan(scanner.WithDLPWarnContext(req.Context(), redirectWarnCtx), redirectURL)
			if !result.Allowed {
				actx := newHTTPAuditContext(logger, req.Method, redirectURL, clientIP, requestID, agentName)
				if currentCfg.EnforceEnabled() {
					// Preserve the originating scanner label (SSRF,
					// DLP, blocklist, …) in the typed block error so
					// receipts, metrics, and /fetch hints can tell
					// operators *which* scanner made the decision
					// instead of reporting every denial as a generic
					// "redirect" block.
					logger.LogBlocked(actx, result.Scanner, fmt.Sprintf("redirect from %s blocked: %s", originalURL, result.Reason))
					return newRedirectBlockedRequest(result.Scanner, result.Reason)
				}
				logger.LogAnomaly(actx, result.Scanner, fmt.Sprintf("redirect from %s: %s", originalURL, result.Reason), result.Score)
			}
			// Mediation envelope refresh: on every allowed redirect,
			// rebuild the envelope on req so ph, hop, and @target-uri
			// reflect the redirected leg rather than the original.
			// The stdlib has already copied headers from via[0] to
			// req; we replace the Pipelock-Mediation slot and re-sign
			// (if signing is active). Any refresh/signing error aborts
			// the redirect so a sign:true deployment never silently
			// degrades to an unsigned or stale-signature hop.
			if err := p.refreshEnvelopeForRedirect(req, via, currentCfg); err != nil {
				return err
			}
			return nil
		},
	}

	p.tlsTransport = newTLSInterceptTransport(p.ssrfSafeDialContext, m.RecordTLSHandshake, nil)

	return p, nil
}

// refreshEnvelopeForRedirect rebuilds the Pipelock-Mediation header
// on a redirected request so ph, hop, and (if signing is active)
// @target-uri reflect the redirected leg rather than the original.
//
// stdlib's redirect machinery copies headers from via[0] to the new
// req before calling CheckRedirect. That copy includes the original
// Pipelock-Mediation header verbatim — its @target-uri / action /
// timestamp are now stale, and any pipelock1 signature on the
// headers signs a base string for the pre-redirect URL. Without
// this refresh a downstream verifier would reject the redirected
// leg on @target-uri mismatch.
//
// Steps:
//  1. Parse the inbound Pipelock-Mediation header to recover the
//     original envelope fields we want to preserve (Actor, ActorAuth,
//     ReceiptID, AuthorityKind, SessionTaint, TaskID, Action).
//  2. Increment Hop.
//  3. Derive fresh body bytes via req.GetBody when the redirect
//     preserves method + body (307/308). On method-switching
//     redirects (303 POST→GET) the stdlib nil's out req.Body and
//     GetBody, so body bytes are nil and content-digest drops.
//  4. Strip any stale Content-Digest the copy propagated from via[0]
//     — the signer will set a fresh one if body bytes are present.
//  5. Call emitter.InjectAndSign on req with the rebuilt BuildOpts.
//
// Any failure to refresh or re-sign the redirected request aborts the
// redirect. sign:true is a hard integrity contract: a redirected hop
// must not continue with a stale or missing pipelock signature.
func (p *Proxy) refreshEnvelopeForRedirect(req *http.Request, via []*http.Request, cfg *config.Config) error {
	// Prefer the request-scoped snapshot so a reload mid-chain
	// cannot flip signing state for this request. Fall back to the
	// global atomic for backwards-compat with callers that don't
	// set the context key (e.g. tests calling this helper directly).
	em, _ := req.Context().Value(ctxKeyEnvelopeEmitter).(*envelope.Emitter)
	if em == nil {
		em = p.currentEnvelopeEmitter()
	}
	if em == nil {
		return nil
	}

	clientIP, _ := req.Context().Value(ctxKeyClientIP).(string)
	requestID, _ := req.Context().Value(ctxKeyRequestID).(string)
	agentName, _ := req.Context().Value(ctxKeyAgent).(string)
	actx := newHTTPAuditContext(p.logger, req.Method, req.URL.String(), clientIP, requestID, agentName)

	// 1. Parse the ORIGINAL envelope. Identity fields (Actor,
	//    ActorAuth, ReceiptID, Authority, Taint, TaskID, RequiresReauth)
	//    are immutable across a redirect chain, so we always read
	//    them from the first request in the chain. In the live
	//    CheckRedirect path via[] is always non-empty and via[0] is
	//    the original request; we intentionally do NOT read from
	//    req.Header in that case because Go's net/http redirect
	//    machinery copies headers from via[0] onto each new req,
	//    overwriting any mutations a previous CheckRedirect hop made.
	//    Reading from req.Header would therefore always observe
	//    hop=0 and cap the counter at 1 regardless of chain depth.
	//    Tests that call this helper directly pass via=nil to
	//    exercise the refresh logic on a single request; fall back
	//    to req.Header in that case so the test path still works.
	var (
		prev    envelope.Envelope
		rawPrev string
	)
	if len(via) > 0 {
		rawPrev = via[0].Header.Get(envelope.HeaderName)
	} else {
		rawPrev = req.Header.Get(envelope.HeaderName)
	}
	if rawPrev != "" {
		parsed, parseErr := envelope.Parse(rawPrev)
		if parseErr != nil {
			p.logger.LogAnomaly(actx, "",
				fmt.Sprintf("envelope refresh: parsing prior envelope failed: %v", parseErr), 0.1)
			// Fall through with zero-value prev — the refresh will
			// still install a new envelope.
		} else {
			prev = parsed
		}
	}

	// 2. Authoritative hop counter. Use len(via) when available
	//    (live CheckRedirect path): it is the number of requests
	//    already dispatched in this redirect chain, and stdlib
	//    calls CheckRedirect once per hop, so len(via) equals the
	//    number of hops the refreshed request has traversed. Falls
	//    back to prev.Hop+1 for direct test invocations where via
	//    is nil, which mirrors "one refresh from the previous
	//    observed value."
	if len(via) > 0 {
		prev.Hop = len(via)
	} else {
		prev.Hop++
	}

	// 3. Fresh body bytes via GetBody when available. Cap the read to
	//    max_body_bytes so a redirect to a large-body endpoint cannot
	//    spike memory past the signer's intended ceiling. Over-cap
	//    bodies are signed without content-digest, matching the
	//    first-hop InjectAndSign behavior.
	var body []byte
	if req.GetBody != nil {
		if rc, err := req.GetBody(); err == nil && rc != nil {
			maxBody := int64(cfg.MediationEnvelope.MaxBodyBytes)
			var (
				buffered []byte
				readErr  error
			)
			if maxBody > 0 {
				buffered, readErr = io.ReadAll(io.LimitReader(rc, maxBody+1))
			} else {
				buffered, readErr = io.ReadAll(rc)
			}
			_ = rc.Close()
			if readErr != nil {
				return newRedirectEnvelopeBlockedRequest(
					fmt.Errorf("draining redirect GetBody: %w", readErr),
				)
			}
			if maxBody > 0 && int64(len(buffered)) > maxBody {
				body = nil
			} else {
				body = buffered
			}
		} else if err != nil {
			return newRedirectEnvelopeBlockedRequest(
				fmt.Errorf("opening redirect GetBody: %w", err),
			)
		}
	}

	// 4. Strip stale Content-Digest. The signer will repopulate it
	//    if body is non-nil AND content-digest is in the signer's
	//    declared component list; otherwise its absence is correct.
	req.Header.Del("Content-Digest")

	// 5. Rebuild BuildOpts from prev + redirect context. Preserve
	//    Actor / ActorAuth / ReceiptID / AuthorityKind / SessionTaint
	//    / TaskID from the original envelope so the redirect chain
	//    threads through as one logical action. Recompute Action
	//    from the new method because the redirect could have
	//    downgraded a POST to a GET (303).
	actionID := prev.ReceiptID
	if actionID == "" {
		// No prior envelope to preserve ReceiptID from — mint a
		// fresh one. This is unusual but survives a nil-prev hop.
		actionID = receipt.NewActionID()
	}
	opts := envelope.BuildOpts{
		ActionID:       actionID,
		Action:         string(receipt.ClassifyHTTP(req.Method)),
		Verdict:        prev.Verdict,
		SideEffect:     string(receipt.SideEffectFromMethod(req.Method)),
		Actor:          prev.Actor,
		ActorAuth:      prev.ActorAuth,
		SessionTaint:   prev.SessionTaint,
		TaskID:         prev.TaskID,
		AuthorityKind:  prev.AuthorityKind,
		AuthorityRef:   prev.AuthorityRef,
		RequiresReauth: prev.RequiresReauth,
		PolicyHash:     envelope.PolicyHashFromHex(cfg.CanonicalPolicyHash()),
	}
	if opts.Verdict == "" {
		opts.Verdict = config.ActionAllow
	}

	// The envelope emitter cannot accept a Hop override via
	// BuildOpts (the Hop field lives on the output envelope, not the
	// build opts), so we build the envelope first and then
	// overwrite its Hop before serializing. We do this by calling
	// Emitter.Build directly and serializing by hand rather than
	// going through InjectAndSign, which would reset Hop to zero.
	env := em.Build(opts)
	env.Hop = prev.Hop
	if err := envelope.InjectHTTP(req.Header, env); err != nil {
		return newRedirectEnvelopeBlockedRequest(
			fmt.Errorf("injecting refreshed envelope: %w", err),
		)
	}

	// Sign the refreshed envelope over the redirected request if
	// a signer is installed. Content-Digest was cleared above, so
	// the signer computes it fresh from the new body (if any) and
	// the Signature-Input declared list reflects the per-request
	// effective components.
	if signer := em.Signer(); signer != nil {
		if err := signer.SignRequest(req, body); err != nil {
			return newRedirectEnvelopeBlockedRequest(
				fmt.Errorf("re-signing redirect request: %w", err),
			)
		}
	}

	// Preserve the hop/ph/sig across any future redirects in the
	// same chain by leaving req as-is. stdlib will copy this header
	// to the next req when CheckRedirect fires again.
	_ = via // reserved for future per-hop logging
	return nil
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
	p.reloadMu.RLock()
	e := p.receiptEmitterPtr.Load()
	p.reloadMu.RUnlock()
	if e == nil {
		return
	}
	if err := e.Emit(opts); err != nil {
		p.logger.LogError(audit.NewRequestLogContext(opts.RequestID), err)
	}
}

// receiptEmitterStage is the staged result of a receipt-emitter reload.
// Reload stages both the envelope and receipt emitters before publishing
// either, so a failure in the second stage cannot leave the first already
// stored under p.envelopeEmitterPtr while the config is still the old one.
type receiptEmitterStage struct {
	// emitter is the new *receipt.Emitter to install. A nil value means
	// "receipts are intentionally disabled for this cfg" — either no
	// signing key path is set or the recorder is nil. The caller should
	// Store(nil) on publish in that case and also reset receiptKeyPath
	// to "" via the keyPath field.
	emitter *receipt.Emitter
	// keyPath is the signing key path that was actually loaded, or ""
	// when receipts are disabled. The caller assigns this to
	// p.receiptKeyPath at publish time.
	keyPath string
}

// buildReceiptEmitter stages the receipt emitter lifecycle transition for
// cfg WITHOUT publishing anything to p.receiptEmitterPtr or
// p.receiptKeyPath. Must be called under reloadMu from Reload, which
// publishes the returned stage atomically after all other reload
// preconditions succeed.
//
// Return value semantics:
//
//   - (stage, nil) — staging succeeded. Publish via Store/assignment.
//   - (_, non-nil) — staging failed. Caller MUST abort the config swap.
//     Signed receipts are part of the evidence contract; swapping cfg
//     while keeping an old receipt emitter would attest the wrong policy
//     hash for future actions.
func (p *Proxy) buildReceiptEmitter(cfg *config.Config) (receiptEmitterStage, error) {
	keyPath := cfg.FlightRecorder.SigningKeyPath

	if keyPath == "" {
		// No signing key configured — receipts are disabled for this
		// cfg. Stage a nil emitter; Reload will clear both pointers.
		return receiptEmitterStage{}, nil
	}

	if p.recorder == nil {
		// No recorder means receipts have nowhere to land regardless
		// of config. Treat this as "receipts disabled" from a staging
		// perspective — the caller won't touch receipt state.
		return receiptEmitterStage{keyPath: p.receiptKeyPath}, nil
	}

	// Always reload the key file to detect both path changes and
	// in-place content changes (key rotation at the same path).
	privKey, err := signing.LoadPrivateKeyFile(filepath.Clean(keyPath))
	if err != nil {
		return receiptEmitterStage{}, fmt.Errorf("loading receipt signing key %q: %w", keyPath, err)
	}

	return receiptEmitterStage{
		emitter: receipt.NewEmitter(receipt.EmitterConfig{
			Recorder:   p.recorder,
			PrivKey:    privKey,
			ConfigHash: cfg.Hash(),
			Principal:  "local",
			Actor:      "pipelock",
		}),
		keyPath: keyPath,
	}, nil
}

// envelopeEmitterStage is the staged result of an envelope-emitter reload.
// Like receiptEmitterStage, it lets Reload build the new emitter without
// publishing it so both emitters can be swapped atomically after every
// staging step has succeeded.
type envelopeEmitterStage struct {
	// enabled reports whether the cfg wants envelope emission at all.
	// When false, the publish step should Store(nil) regardless of
	// what emitter holds — the field mirrors the disable-path that
	// used to live in reloadEnvelopeEmitter.
	enabled bool
	// emitter is the freshly constructed *envelope.Emitter to install
	// when enabled is true. nil when enabled is false.
	emitter *envelope.Emitter
}

// buildEnvelopeEmitter stages the envelope emitter lifecycle transition
// for cfg WITHOUT publishing anything to p.envelopeEmitterPtr. Must be
// called under reloadMu from Reload, which publishes the returned stage
// atomically after all other reload preconditions succeed. New() also
// calls this helper at startup to install the first signer-backed
// emitter before serving the first request.
//
// Return value semantics:
//
//   - (stage, nil) — staging succeeded. Publish via Store on publish.
//   - (_, non-nil) — staging failed. Caller MUST abort the config swap.
//     The previous emitter is left in place so in-flight traffic keeps
//     its signing invariant until operator intervention. This is the
//     fail-closed resolution for the "reload with unreadable signing
//     key" case: never silent-downgrade to unsigned.
//
// The fallback hash is the GLOBAL config's CanonicalPolicyHash — what
// a request without a resolved per-agent config sees. Transports that
// have a per-agent effective *Config MUST pass envelope.PolicyHashFromHex
// of that resolved config's canonical hash via BuildOpts.PolicyHash so
// the envelope ph field reflects the agent's actual policy rather than
// the global default. See the BuildOpts.PolicyHash doc comment.
func (p *Proxy) buildEnvelopeEmitter(cfg *config.Config) (envelopeEmitterStage, error) {
	if !cfg.MediationEnvelope.Enabled {
		return envelopeEmitterStage{enabled: false}, nil
	}

	emCfg := envelope.EmitterConfig{
		ConfigHash: cfg.CanonicalPolicyHash(),
	}

	// Load the signing key fresh on every reload so the file rotation
	// story works without a process restart. If sign is disabled the
	// resulting emitter has no signer attached and acts as a header-
	// only envelope producer.
	if cfg.MediationEnvelope.Sign {
		privKey, err := signing.LoadPrivateKeyFile(filepath.Clean(cfg.MediationEnvelope.SigningKeyPath))
		if err != nil {
			return envelopeEmitterStage{}, fmt.Errorf("loading envelope signing key %q: %w",
				cfg.MediationEnvelope.SigningKeyPath, err)
		}
		signer, err := envelope.NewSigner(envelope.SignerConfig{
			PrivKey:          privKey,
			KeyID:            cfg.MediationEnvelope.KeyID,
			SignedComponents: cfg.MediationEnvelope.SignedComponents,
			MaxBodyBytes:     cfg.MediationEnvelope.MaxBodyBytes,
		})
		if err != nil {
			return envelopeEmitterStage{}, fmt.Errorf("constructing envelope signer: %w", err)
		}
		emCfg.Signer = signer
	}

	return envelopeEmitterStage{
		enabled: true,
		emitter: envelope.NewEmitter(emCfg),
	}, nil
}

// CurrentConfig returns the currently active config. Used for reload comparison.
func (p *Proxy) CurrentConfig() *config.Config {
	return p.cfgPtr.Load()
}

// ReloadLock exposes the proxy reload lock for long-lived handlers that need
// coherent config/scanner/emitter snapshots with Reload publication.
func (p *Proxy) ReloadLock() *sync.RWMutex {
	return &p.reloadMu
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

// SessionAPI returns the proxy's admin session API handler, or nil when
// no api_token is configured. run.go mounts this on the dedicated
// kill-switch API port (when kill_switch.api_listen is set) instead of
// building a second handler, so Reload's hot-reload token rotation
// covers both the main and dedicated mounts with one SetAPIToken call.
func (p *Proxy) SessionAPI() *SessionAPIHandler {
	return p.sessionAPI
}

// EnvelopeEmitterPtr returns the atomic pointer to the envelope emitter.
// Used by the reverse proxy handler to share the emitter and receive
// hot-reload updates.
func (p *Proxy) EnvelopeEmitterPtr() *atomic.Pointer[envelope.Emitter] {
	return &p.envelopeEmitterPtr
}

// ReceiptEmitterPtr returns the atomic pointer to the receipt emitter.
// Long-lived runtimes use this to pick up hot-reload receipt config changes.
func (p *Proxy) ReceiptEmitterPtr() *atomic.Pointer[receipt.Emitter] {
	return &p.receiptEmitterPtr
}

// RedactMatcherPtr returns the atomic pointer to the compiled redaction
// matcher. Long-lived helpers outside package proxy (notably MCP startup
// wiring) use this when they only need the matcher itself. Request paths use
// RedactionRuntimePtr/currentRedactionRuntime instead so matcher, limits, and
// allowlist publish as one coherent snapshot.
func (p *Proxy) RedactMatcherPtr() *atomic.Pointer[redact.Matcher] {
	return &p.redactMatcherPtr
}

// Reload atomically swaps the config and scanner for hot-reload support.
// The old scanner is closed to release its rate limiter goroutine.
// Session manager lifecycle is toggled when session_profiling.enabled changes.
// The returned bool reports whether the staged runtime was fully published;
// false means the previous runtime stayed live.
//
// Note: HTTP client timeouts, transport settings, and server listen address
// are set at construction in New()/Start() and are NOT updated by Reload.
// Only config values read per-request (mode, enforce, user-agent, blocklists,
// DLP patterns, response scanning, etc.) take effect immediately.
func (p *Proxy) Reload(cfg *config.Config, sc *scanner.Scanner) bool {
	p.reloadMu.Lock()
	defer p.reloadMu.Unlock()

	// Build new edition BEFORE swapping config/scanner.
	// If this fails, keep all existing state unchanged (fail-safe).
	oldSnap := p.editionPtr.Load()
	newEd, edErr := oldSnap.Reload(cfg, sc)
	if edErr != nil {
		p.logger.LogError(audit.NewMethodLogContext("RELOAD"), fmt.Errorf("edition rebuild failed, keeping old config: %w", edErr))
		sc.Close() // caller-allocated scanner must be closed since we're not using it
		return false
	}

	// Envelope and receipt emitters are staged BEFORE either is
	// published, so a failure in the second stage cannot leave the
	// first already stored under p.envelopeEmitterPtr while the rest
	// of the config is still the old one. Both stages are fail-closed:
	// any error aborts the whole reload and leaves in-flight traffic
	// signing / attesting under the last good config.
	//
	// Without this staging, a narrow race window exists on the receipt
	// reload failure path: reloadEnvelopeEmitter used to Store() into
	// p.envelopeEmitterPtr directly, so a subsequent receipt-emitter
	// failure would leave the new envelope signer already published
	// while cfg stayed at the old value. Evidence chains produced in
	// that window would attest the wrong policy hash.
	envelopeStage, envErr := p.buildEnvelopeEmitter(cfg)
	if envErr != nil {
		p.logger.LogError(audit.NewMethodLogContext("RELOAD"),
			fmt.Errorf("envelope emitter reload failed, keeping old config: %w", envErr))
		sc.Close()
		if newEd != nil {
			newEd.Close()
		}
		return false
	}
	receiptStage, rcptErr := p.buildReceiptEmitter(cfg)
	if rcptErr != nil {
		p.logger.LogError(audit.NewMethodLogContext("RELOAD"),
			fmt.Errorf("receipt emitter reload failed, keeping old config: %w", rcptErr))
		sc.Close()
		if newEd != nil {
			newEd.Close()
		}
		return false
	}
	// Stage the full redaction runtime BEFORE publication so a failed
	// matcher build aborts the whole reload instead of mixing matcher,
	// limits, and allowlist from different policy revisions.
	newRedactionRuntime, redactErr := p.buildRedactionRuntime(cfg)
	if redactErr != nil {
		p.logger.LogError(audit.NewMethodLogContext("RELOAD"),
			fmt.Errorf("redaction runtime reload failed, keeping old config: %w", redactErr))
		sc.Close()
		if newEd != nil {
			newEd.Close()
		}
		return false
	}

	// Publish both emitters now that staging has fully succeeded. The
	// atomic.Pointer swaps are individually atomic; between them, a
	// request can observe "new envelope + old receipt" for a few
	// nanoseconds, but that is the same race class the envelope and
	// receipt emitters had before Reload was fail-closed, and neither
	// emitter attests the other's policy hash.
	if envelopeStage.enabled {
		p.envelopeEmitterPtr.Store(envelopeStage.emitter)
	} else {
		p.envelopeEmitterPtr.Store(nil)
	}
	// Receipt publish: Store the staged emitter (may be nil) and
	// mirror the receiptKeyPath field. When the recorder is missing
	// we leave p.receiptKeyPath untouched so the startup-time invariant
	// (receipts silently off when no recorder) is preserved.
	if cfg.FlightRecorder.SigningKeyPath == "" {
		p.receiptEmitterPtr.Store(nil)
		p.receiptKeyPath = ""
	} else if p.recorder != nil {
		p.receiptEmitterPtr.Store(receiptStage.emitter)
		p.receiptKeyPath = receiptStage.keyPath
	}

	// Publish the staged redaction runtime as one snapshot so body-scan
	// request paths cannot observe a new matcher with old limits/allowlist
	// or vice versa. Keep redactMatcherPtr mirrored for non-request users
	// that only need the compiled matcher.
	p.redactionRuntimePtr.Store(newRedactionRuntime)
	if newRedactionRuntime != nil {
		p.redactMatcherPtr.Store(newRedactionRuntime.matcher)
	} else {
		p.redactMatcherPtr.Store(nil)
	}

	oldCfg := p.cfgPtr.Load()
	p.cfgPtr.Store(cfg)

	// Hot-reload the admin API bearer token so operators can rotate
	// kill_switch.api_token (or the env override) without restarting.
	// Env var continues to take precedence over the YAML value, mirroring
	// the bootstrap resolution in New().
	if p.sessionAPI != nil {
		newToken := cfg.KillSwitch.APIToken
		if envToken := os.Getenv(killswitch.EnvAPIToken); envToken != "" {
			newToken = envToken
		}
		p.sessionAPI.SetAPIToken(newToken)
	}

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
	return true
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

// buildRedactMatcher compiles the active redaction profile into a Matcher.
// setupRedaction/buildRedactionRuntime wrap this in the per-request snapshot
// that body-scan callers consume. Returns nil (no matcher) when redaction is
// disabled or unresolved. A compile error is returned so callers can surface
// it at startup/reload time rather than silently degrading.
func (p *Proxy) buildRedactMatcher(cfg *config.Config) (*redact.Matcher, error) {
	if !cfg.Redaction.Enabled {
		return nil, nil
	}
	return cfg.Redaction.BuildMatcher(cfg.Redaction.DefaultProfile)
}

// setupRedaction stores the compiled redaction runtime at startup. When
// redaction is disabled, the pointers are cleared so request handlers fall
// through without running the redaction step.
func (p *Proxy) setupRedaction(cfg *config.Config) error {
	rt, err := p.buildRedactionRuntime(cfg)
	if err != nil {
		return fmt.Errorf("redaction runtime build: %w", err)
	}
	p.redactionRuntimePtr.Store(rt)
	if rt != nil {
		p.redactMatcherPtr.Store(rt.matcher)
	} else {
		p.redactMatcherPtr.Store(nil)
	}
	return nil
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

// resolveAgentRuntimeFromRequest snapshots the request's resolved agent state
// and envelope emitter under the reload lock. The request then keeps that
// emitter for its forwarding and redirect path so a reload cannot pair the
// old config with a newly disabled or rotated emitter.
func (p *Proxy) resolveAgentRuntimeFromRequest(r *http.Request) (*edition.ResolvedAgent, edition.AgentIdentity, *envelope.Emitter) {
	p.reloadMu.RLock()
	defer p.reloadMu.RUnlock()
	resolved, id := p.resolveAgentFromRequest(r)
	return resolved, id, p.envelopeEmitterPtr.Load()
}

func (p *Proxy) currentEnvelopeEmitter() *envelope.Emitter {
	p.reloadMu.RLock()
	defer p.reloadMu.RUnlock()
	return p.envelopeEmitterPtr.Load()
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
	// escalated tracks whether the current request actually crossed an
	// adaptive escalation threshold. Downstream airlock triggering is
	// edge-bound on this flag so a session that merely sits at a trigger
	// level (plateau) does not repeatedly re-arm airlock on every request.
	// Plateau triggering produced a drain -> hard -> drain deadlock under
	// retrying clients: timer-based de-escalation would recover to hard,
	// the next allowed request would observe the still-elevated level,
	// slam SetTier(drain) again, and the loop never broke. See
	// TestAirlockEdgeTrigger_NoPlateauReentry.
	escalated := false
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
				escalated = true
				sess.SetBlockAll(decide.UpgradeAction("", sess.EscalationLevel(), &adaptiveCfg) == config.ActionBlock)
			}
		} else if !result.Allowed {
			if decide.RecordSignal(sess, session.SignalBlock, ep) {
				escalated = true
				// Update block_all flag so RecordRequest stops refreshing lastActivity.
				sess.SetBlockAll(decide.UpgradeAction("", sess.EscalationLevel(), &adaptiveCfg) == config.ActionBlock)
			}
		} else if result.Score > 0 {
			if decide.RecordSignal(sess, session.SignalNearMiss, ep) {
				escalated = true
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

	// Airlock auto-triggers fire on adaptive escalation EDGES only, not on
	// every request that happens to observe a session at a trigger level.
	// See the long comment at the `escalated` declaration above.
	if cfg.Airlock.Enabled && escalated {
		targetTier := ""
		trigger := ""
		switch session.EscalationLabel(level) {
		case "elevated":
			targetTier = cfg.Airlock.Triggers.OnElevated
			trigger = airlockTriggerOnElevated
		case "high":
			targetTier = cfg.Airlock.Triggers.OnHigh
			trigger = airlockTriggerOnHigh
		case "critical":
			targetTier = cfg.Airlock.Triggers.OnCritical
			trigger = airlockTriggerOnCritical
		}
		if targetTier != "" && targetTier != config.AirlockTierNone {
			if changed, from, to := sess.Airlock().SetTierWithProvenance(targetTier, trigger, airlockSourceTriggers); changed {
				sess.RecordEvent(SessionEvent{
					Kind:     "airlock_enter",
					Target:   to,
					Detail:   from + "->" + to,
					Severity: "warn",
					Score:    sess.ThreatScore(),
				})
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

		sess.RecordEvent(SessionEvent{
			Kind:     "anomaly",
			Target:   hostname,
			Detail:   a.Detail,
			Severity: "warn",
			Score:    a.Score,
		})

		if cfg.SessionProfiling.AnomalyAction == config.ActionBlock && cfg.EnforceEnabled() {
			return SessionResult{Blocked: true, Detail: fmt.Sprintf("session anomaly: %s", a.Detail), Level: level}
		}
	}

	// Record a block event on any non-allowed scanner result so inspect/
	// explain operators can see the specific evidence that drove escalation.
	// Score-neutral cases (protective, config-mismatch) still record so the
	// operator trail reflects the full picture; empty Reason is preserved.
	if !result.Allowed {
		sess.RecordEvent(SessionEvent{
			Kind:     "block",
			Target:   hostname,
			Detail:   result.Reason,
			Severity: "critical",
			Score:    result.Score,
		})
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

	// Content-type gate: skip shield entirely for non-shieldable media
	// (image/*, audio/*, video/*, application/pdf, arbitrary octet-stream
	// that does not sniff as HTML/JS/SVG, etc.). This MUST run before the
	// max_shield_bytes ceiling so a large binary payload from a legitimate
	// media API is not blocked as "oversize" when the shield would return
	// PipelineNone anyway. runShieldPipeline performs the same detection
	// on the rewrite path; we short-circuit here for binary bodies so the
	// oversize ceiling only applies to content the shield would actually
	// rewrite (HTML, JS, SVG).
	prefixLen := len(body)
	if prefixLen > 512 {
		prefixLen = 512
	}
	if shield.DetectPipeline(contentType, body[:prefixLen]) == shield.PipelineNone {
		p.metrics.RecordShieldSkipped("non_shieldable_content")
		return body, false
	}

	// Max shield bytes: enforce oversize action. Only runs for content the
	// shield would rewrite (HTML/JS/SVG) per the gate above.
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
			p.logger.LogShieldRewrite("extension", shieldResult.ExtensionHits, transport, actx.URL(), clientIP, requestID)
		}
		if shieldResult.TrackingHits > 0 {
			p.metrics.RecordShieldRewrite("tracking", transport)
			p.logger.LogShieldRewrite("tracking", shieldResult.TrackingHits, transport, actx.URL(), clientIP, requestID)
		}
		if shieldResult.TrapHits > 0 {
			p.metrics.RecordShieldRewrite("trap", transport)
			p.logger.LogShieldRewrite("trap", shieldResult.TrapHits, transport, actx.URL(), clientIP, requestID)
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
// The four-segment fallback (/api/v1/sessions/{key}) routes to HandleInspect.
func (p *Proxy) sessionAPIRouter(w http.ResponseWriter, r *http.Request) {
	path := r.URL.EscapedPath()
	switch {
	case killswitch.IsSessionActionPath(path, "airlock"):
		p.sessionAPI.HandleAirlock(w, r)
	case killswitch.IsSessionActionPath(path, "task"):
		p.sessionAPI.HandleTask(w, r)
	case killswitch.IsSessionActionPath(path, "trust"):
		p.sessionAPI.HandleTrust(w, r)
	case killswitch.IsSessionActionPath(path, "reset"):
		p.sessionAPI.HandleReset(w, r)
	case killswitch.IsSessionActionPath(path, "explain"):
		p.sessionAPI.HandleExplain(w, r)
	case killswitch.IsSessionActionPath(path, "terminate"):
		p.sessionAPI.HandleTerminate(w, r)
	case killswitch.IsSessionKeyPath(path):
		p.sessionAPI.HandleInspect(w, r)
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
					p.logger.LogError(audit.NewResourceLogContext("SHUTDOWN", srv.Addr), shutErr)
				}
			}
			if err := p.server.Shutdown(shutdownCtx); err != nil {
				p.logger.LogError(audit.NewResourceLogContext("SHUTDOWN", cfg.FetchProxy.Listen), err)
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
				p.logger.LogAnomaly(audit.NewResourceLogContext("STARTUP", cfg.FetchProxy.Listen), "",
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

	// Strip inbound mediation envelope headers to prevent forgery.
	envelope.StripInbound(r.Header)

	// Pre-generate a single ActionID for correlation between envelope and receipt.
	actionID := receipt.NewActionID()

	// Resolve per-agent config and scanner from a single registry snapshot.
	// This prevents TOCTOU races during hot-reload where knownProfiles()
	// and resolveAgent() could read different registries.
	resolved, id, envEmitter := p.resolveAgentRuntimeFromRequest(r)
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
	actx := newHTTPAuditContext(p.logger, http.MethodGet, displayURL, clientIP, requestID, agent)

	// Scan URL through all scanners
	scanCtx := scanner.WithDLPWarnContext(r.Context(), scanner.DLPWarnContext{
		Method: http.MethodGet, URL: targetURL, ClientIP: clientIP,
		RequestID: requestID, Agent: agent, Transport: "fetch",
	})
	r = r.WithContext(scanCtx)
	result := sc.Scan(scanCtx, targetURL)

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
	fetchTaint := evaluateHTTPTaint(cfg, fetchRec, http.MethodGet, parsed)

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
				ActionID:            actionID,
				Verdict:             config.ActionBlock,
				Layer:               result.Scanner,
				Pattern:             result.Reason,
				Transport:           "fetch",
				Method:              http.MethodGet,
				Target:              displayURL,
				RequestID:           requestID,
				Agent:               agent,
				SessionTaintLevel:   fetchTaint.Risk.Level.String(),
				SessionContaminated: fetchTaint.Risk.Contaminated,
				RecentTaintSources:  fetchTaint.Risk.Sources,
				SessionTaskID:       fetchTaint.Task.CurrentTaskID,
				SessionTaskLabel:    fetchTaint.Task.CurrentTaskLabel,
				AuthorityKind:       fetchTaint.Authority.String(),
				TaintDecision:       fetchTaint.Result.Decision.String(),
				TaintDecisionReason: fetchTaint.Result.Reason,
				TaskOverrideApplied: fetchTaint.TaskOverrideApplied,
			})
			p.metrics.RecordBlocked(parsed.Hostname(), result.Scanner, time.Since(start), agentLabel)
			status := http.StatusForbidden
			if result.Scanner == scanner.ScannerRateLimit {
				status = http.StatusTooManyRequests
			}
			// Redact the echoed URL when the block came from a
			// content-matching scanner (DLP, seed-phrase, address
			// protection, etc.) — the URL itself likely carries the
			// secret-shaped bytes that fired the match. Without this,
			// the 403 response body leaks the credential back to the
			// caller (round-5 of the pre-tag gate finding: structured log redaction
			// was in place but client response still echoed).
			echoURL := displayURL
			if audit.IsContentScanner(result.Scanner) {
				echoURL = audit.RedactContentBearingURL(displayURL)
			}
			resp := FetchResponse{
				URL:         echoURL,
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
			p.emitReceipt(receipt.EmitOpts{
				ActionID:            receipt.NewActionID(),
				Verdict:             config.ActionBlock,
				Layer:               result.Scanner,
				Pattern:             result.Reason + " (escalated)",
				Transport:           "fetch",
				Method:              http.MethodGet,
				Target:              displayURL,
				RequestID:           requestID,
				Agent:               agent,
				SessionTaintLevel:   fetchTaint.Risk.Level.String(),
				SessionContaminated: fetchTaint.Risk.Contaminated,
				RecentTaintSources:  fetchTaint.Risk.Sources,
				SessionTaskID:       fetchTaint.Task.CurrentTaskID,
				SessionTaskLabel:    fetchTaint.Task.CurrentTaskLabel,
				AuthorityKind:       fetchTaint.Authority.String(),
				TaintDecision:       fetchTaint.Result.Decision.String(),
				TaintDecisionReason: fetchTaint.Result.Reason,
				TaskOverrideApplied: fetchTaint.TaskOverrideApplied,
			})
			escalatedStatus := http.StatusForbidden
			if result.Scanner == scanner.ScannerRateLimit {
				escalatedStatus = http.StatusTooManyRequests
			}
			escalatedEchoURL := displayURL
			if audit.IsContentScanner(result.Scanner) {
				escalatedEchoURL = audit.RedactContentBearingURL(displayURL)
			}
			writeJSON(w, escalatedStatus, FetchResponse{
				URL:         escalatedEchoURL,
				Agent:       agent,
				Blocked:     true,
				BlockReason: result.Reason + " (escalated)",
			})
			return
		}
		log.LogAnomaly(actx, result.Scanner, result.Reason, result.Score)
	}

	if sr.Blocked {
		p.emitReceipt(receipt.EmitOpts{
			ActionID:            receipt.NewActionID(),
			Verdict:             config.ActionBlock,
			Layer:               "session_profiling",
			Pattern:             sr.Detail,
			Transport:           "fetch",
			Method:              http.MethodGet,
			Target:              displayURL,
			RequestID:           requestID,
			Agent:               agent,
			SessionTaintLevel:   fetchTaint.Risk.Level.String(),
			SessionContaminated: fetchTaint.Risk.Contaminated,
			RecentTaintSources:  fetchTaint.Risk.Sources,
			SessionTaskID:       fetchTaint.Task.CurrentTaskID,
			SessionTaskLabel:    fetchTaint.Task.CurrentTaskLabel,
			AuthorityKind:       fetchTaint.Authority.String(),
			TaintDecision:       fetchTaint.Result.Decision.String(),
			TaintDecisionReason: fetchTaint.Result.Reason,
			TaskOverrideApplied: fetchTaint.TaskOverrideApplied,
		})
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
		p.emitReceipt(receipt.EmitOpts{
			ActionID:            receipt.NewActionID(),
			Verdict:             config.ActionBlock,
			Layer:               "session_deny",
			Pattern:             "session escalation level " + session.EscalationLabel(sr.Level),
			Transport:           "fetch",
			Method:              http.MethodGet,
			Target:              displayURL,
			RequestID:           requestID,
			Agent:               agent,
			SessionTaintLevel:   fetchTaint.Risk.Level.String(),
			SessionContaminated: fetchTaint.Risk.Contaminated,
			RecentTaintSources:  fetchTaint.Risk.Sources,
			SessionTaskID:       fetchTaint.Task.CurrentTaskID,
			SessionTaskLabel:    fetchTaint.Task.CurrentTaskLabel,
			AuthorityKind:       fetchTaint.Authority.String(),
			TaintDecision:       fetchTaint.Result.Decision.String(),
			TaintDecisionReason: fetchTaint.Result.Reason,
			TaskOverrideApplied: fetchTaint.TaskOverrideApplied,
		})
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
		p.emitReceipt(receipt.EmitOpts{
			ActionID:            receipt.NewActionID(),
			Verdict:             config.ActionBlock,
			Layer:               "dlp_header",
			Pattern:             "request header contains secret",
			Transport:           "fetch",
			Method:              http.MethodGet,
			Target:              displayURL,
			RequestID:           requestID,
			Agent:               agent,
			SessionTaintLevel:   fetchTaint.Risk.Level.String(),
			SessionContaminated: fetchTaint.Risk.Contaminated,
			RecentTaintSources:  fetchTaint.Risk.Sources,
			SessionTaskID:       fetchTaint.Task.CurrentTaskID,
			SessionTaskLabel:    fetchTaint.Task.CurrentTaskLabel,
			AuthorityKind:       fetchTaint.Authority.String(),
			TaintDecision:       fetchTaint.Result.Decision.String(),
			TaintDecisionReason: fetchTaint.Result.Reason,
			TaskOverrideApplied: fetchTaint.TaskOverrideApplied,
		})
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
		p.emitReceipt(receipt.EmitOpts{
			ActionID:            receipt.NewActionID(),
			Verdict:             config.ActionBlock,
			Layer:               "session_deny",
			Pattern:             "session escalation level " + session.EscalationLabel(fetchRec.EscalationLevel()),
			Transport:           "fetch",
			Method:              http.MethodGet,
			Target:              displayURL,
			RequestID:           requestID,
			Agent:               agent,
			SessionTaintLevel:   fetchTaint.Risk.Level.String(),
			SessionContaminated: fetchTaint.Risk.Contaminated,
			RecentTaintSources:  fetchTaint.Risk.Sources,
			SessionTaskID:       fetchTaint.Task.CurrentTaskID,
			SessionTaskLabel:    fetchTaint.Task.CurrentTaskLabel,
			AuthorityKind:       fetchTaint.Authority.String(),
			TaintDecision:       fetchTaint.Result.Decision.String(),
			TaintDecisionReason: fetchTaint.Result.Reason,
			TaskOverrideApplied: fetchTaint.TaskOverrideApplied,
		})
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
		p.emitReceipt(receipt.EmitOpts{
			ActionID:            receipt.NewActionID(),
			Verdict:             config.ActionBlock,
			Layer:               "budget",
			Pattern:             reason,
			Transport:           "fetch",
			Method:              http.MethodGet,
			Target:              displayURL,
			RequestID:           requestID,
			Agent:               agent,
			SessionTaintLevel:   fetchTaint.Risk.Level.String(),
			SessionContaminated: fetchTaint.Risk.Contaminated,
			RecentTaintSources:  fetchTaint.Risk.Sources,
			SessionTaskID:       fetchTaint.Task.CurrentTaskID,
			SessionTaskLabel:    fetchTaint.Task.CurrentTaskLabel,
			AuthorityKind:       fetchTaint.Authority.String(),
			TaintDecision:       fetchTaint.Result.Decision.String(),
			TaintDecisionReason: fetchTaint.Result.Reason,
			TaskOverrideApplied: fetchTaint.TaskOverrideApplied,
		})
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
			p.emitReceipt(receipt.EmitOpts{
				ActionID:            receipt.NewActionID(),
				Verdict:             config.ActionBlock,
				Layer:               "cross_request",
				Pattern:             ceeRes.Reason,
				Transport:           "fetch",
				Method:              http.MethodGet,
				Target:              displayURL,
				RequestID:           requestID,
				Agent:               agent,
				SessionTaintLevel:   fetchTaint.Risk.Level.String(),
				SessionContaminated: fetchTaint.Risk.Contaminated,
				RecentTaintSources:  fetchTaint.Risk.Sources,
				SessionTaskID:       fetchTaint.Task.CurrentTaskID,
				SessionTaskLabel:    fetchTaint.Task.CurrentTaskLabel,
				AuthorityKind:       fetchTaint.Authority.String(),
				TaintDecision:       fetchTaint.Result.Decision.String(),
				TaintDecisionReason: fetchTaint.Result.Reason,
				TaskOverrideApplied: fetchTaint.TaskOverrideApplied,
			})
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
			p.emitReceipt(receipt.EmitOpts{
				ActionID:            receipt.NewActionID(),
				Verdict:             config.ActionBlock,
				Layer:               "session_deny",
				Pattern:             "session escalation level " + session.EscalationLabel(fetchRec.EscalationLevel()),
				Transport:           "fetch",
				Method:              http.MethodGet,
				Target:              displayURL,
				RequestID:           requestID,
				Agent:               agent,
				SessionTaintLevel:   fetchTaint.Risk.Level.String(),
				SessionContaminated: fetchTaint.Risk.Contaminated,
				RecentTaintSources:  fetchTaint.Risk.Sources,
				SessionTaskID:       fetchTaint.Task.CurrentTaskID,
				SessionTaskLabel:    fetchTaint.Task.CurrentTaskLabel,
				AuthorityKind:       fetchTaint.Authority.String(),
				TaintDecision:       fetchTaint.Result.Decision.String(),
				TaintDecisionReason: fetchTaint.Result.Reason,
				TaskOverrideApplied: fetchTaint.TaskOverrideApplied,
			})
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
	ctx = context.WithValue(ctx, ctxKeyRedirectTransport, TransportFetch)
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

	// Inject mediation envelope (and attach RFC 9421 signature when
	// the envelope emitter has a signer) before forwarding on the
	// allow path. The fetch handler only builds GET requests
	// internally — there is no request body to sign over, so
	// InjectAndSign is called with body=nil and the signer drops
	// content-digest from the declared component list.
	if envEmitter != nil {
		// Snapshot the emitter on the request context so
		// refreshEnvelopeForRedirect uses the same signing state
		// for the entire redirect chain, even if a reload fires.
		req = req.WithContext(context.WithValue(req.Context(), ctxKeyEnvelopeEmitter, envEmitter))
		policyHash := envelope.PolicyHashFromHex(cfg.CanonicalPolicyHash())
		if envErr := envEmitter.InjectAndSign(req, nil, envelope.BuildOpts{
			ActionID:      actionID,
			Action:        string(receipt.ActionRead),
			Verdict:       config.ActionAllow,
			SideEffect:    string(receipt.SideEffectExternalRead),
			Actor:         agent,
			ActorAuth:     id.Auth,
			SessionTaint:  fetchTaint.Risk.Level.String(),
			TaskID:        fetchTaint.Task.CurrentTaskID,
			AuthorityKind: fetchTaint.Authority.String(),
			PolicyHash:    policyHash,
		}); envErr != nil {
			blockedErr := newEnvelopeBlockedRequest(envErr)
			log.LogBlocked(actx, blockedErr.layer, blockedErr.detail)
			p.recordDecision(config.ActionBlock, blockedErr.layer, blockedErr.reason, "fetch", requestID)
			p.emitReceipt(receipt.EmitOpts{
				ActionID:            actionID,
				Verdict:             config.ActionBlock,
				Layer:               blockedErr.layer,
				Pattern:             blockedErr.reason,
				Transport:           "fetch",
				Method:              http.MethodGet,
				Target:              displayURL,
				RequestID:           requestID,
				Agent:               agent,
				SessionTaintLevel:   fetchTaint.Risk.Level.String(),
				SessionContaminated: fetchTaint.Risk.Contaminated,
				RecentTaintSources:  fetchTaint.Risk.Sources,
				SessionTaskID:       fetchTaint.Task.CurrentTaskID,
				SessionTaskLabel:    fetchTaint.Task.CurrentTaskLabel,
				AuthorityKind:       fetchTaint.Authority.String(),
				TaintDecision:       fetchTaint.Result.Decision.String(),
				TaintDecisionReason: fetchTaint.Result.Reason,
				TaskOverrideApplied: fetchTaint.TaskOverrideApplied,
			})
			p.metrics.RecordBlocked(parsed.Hostname(), blockedErr.layer, time.Since(start), agentLabel)
			writeJSON(w, http.StatusForbidden, FetchResponse{
				URL:         displayURL,
				Agent:       agent,
				Blocked:     true,
				BlockReason: blockedErr.reason,
			})
			return
		}
	}

	resp, err := p.client.Do(req) //nolint:gosec // G704: URL validated by scanner pipeline before reaching here
	if err != nil {
		// Detect fail-closed blocks from CheckRedirect and report them as blocked.
		if blockedErr, ok := blockedRequestErrorFrom(err); ok {
			log.LogBlocked(actx, blockedErr.layer, blockedErr.detail)
			p.metrics.RecordBlocked(parsed.Hostname(), blockedErr.layer, time.Since(start), agentLabel)
			resp := FetchResponse{
				URL:         displayURL,
				Agent:       agent,
				Blocked:     true,
				BlockReason: blockedErr.reason,
			}
			// Open-redirect hint: fires on any fail-closed redirect
			// block regardless of which scanner layer owned the
			// decision. Detect via the reason-string prefix rather
			// than the layer label, because the layer now carries
			// the scanner provenance (ssrf / dlp / blocklist / …)
			// rather than a generic "redirect" bucket.
			if strings.HasPrefix(blockedErr.reason, "redirect blocked:") && cfg.ExplainBlocksEnabled() {
				resp.Hint = "Request was redirected to a different origin. Cross-origin redirects are blocked to prevent open redirect attacks."
			}
			p.emitReceipt(receipt.EmitOpts{
				ActionID:  actionID,
				Verdict:   config.ActionBlock,
				Layer:     blockedErr.layer,
				Pattern:   blockedErr.reason,
				Transport: "fetch",
				Method:    http.MethodGet,
				Target:    displayURL,
				RequestID: requestID,
				Agent:     agent,
			})
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

	responsePromptHit := false
	defer func() {
		observeHTTPResponseTaint(fetchRec, cfg, resp.Request.URL.String(), resp.Header.Get("Content-Type"), "fetch_response", responsePromptHit)
	}()

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
			p.emitReceipt(receipt.EmitOpts{
				ActionID:  receipt.NewActionID(),
				Verdict:   config.ActionBlock,
				Layer:     "response_size",
				Pattern:   reason,
				Transport: "fetch",
				Method:    http.MethodGet,
				Target:    displayURL,
				RequestID: requestID,
				Agent:     agent,
			})
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
		p.emitReceipt(receipt.EmitOpts{
			ActionID:  receipt.NewActionID(),
			Verdict:   config.ActionBlock,
			Layer:     "budget",
			Pattern:   reason,
			Transport: "fetch",
			Method:    http.MethodGet,
			Target:    displayURL,
			RequestID: requestID,
			Agent:     agent,
		})
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
		p.emitReceipt(receipt.EmitOpts{
			ActionID:  receipt.NewActionID(),
			Verdict:   config.ActionBlock,
			Layer:     "shield_oversize",
			Pattern:   "response body exceeds browser shield size limit",
			Transport: "fetch",
			Method:    http.MethodGet,
			Target:    displayURL,
			RequestID: requestID,
			Agent:     agent,
		})
		writeJSON(w, http.StatusForbidden, FetchResponse{
			URL: displayURL, Agent: agent, Blocked: true,
			BlockReason: "response body exceeds browser shield size limit",
		})
		return
	}

	// Media policy on fetched responses. Runs after shield so HTML passes
	// through unchanged and image/audio/video responses get transport-
	// agnostic enforcement. Blocks yield a structured FetchResponse so the
	// client sees the policy reason, not a generic 403.
	mediaVerdict := applyMediaPolicy(cfg, contentType, body)
	logMediaExposureIfPresent(log, actx, mediaVerdict, "fetch")
	if mediaVerdict.Blocked {
		log.LogBlocked(actx, "media_policy", mediaVerdict.BlockReason)
		p.metrics.RecordBlocked(parsed.Hostname(), "media_policy", time.Since(start), agentLabel)
		// Terminal block receipt. Reuse the request's actionID so this
		// receipt correlates with the allow envelope that was injected
		// on the outbound request. Without this emit, a response-side
		// media deny would leave the envelope/receipt pair half-closed
		// and break downstream causality reconstruction.
		p.emitReceipt(receipt.EmitOpts{
			ActionID:  actionID,
			Verdict:   config.ActionBlock,
			Layer:     "media_policy",
			Pattern:   mediaVerdict.BlockReason,
			Transport: "fetch",
			Method:    http.MethodGet,
			Target:    displayURL,
			RequestID: requestID,
			Agent:     agent,
		})
		writeJSON(w, http.StatusForbidden, FetchResponse{
			URL: displayURL, Agent: agent, Blocked: true,
			BlockReason: mediaVerdict.BlockReason,
		})
		return
	}
	if mediaVerdict.StripResult != nil && mediaVerdict.StripResult.Changed() {
		body = mediaVerdict.Body
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
		p.metrics.RecordResponseScanExempt(ExemptReasonDomain, TransportFetch)
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
			responsePromptHit = responsePromptHit || found
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
		responsePromptHit = true
		reason := "hidden injection detected and readability extraction failed (fail-closed)"
		log.LogBlocked(actx, "response_scan", reason)
		p.metrics.RecordBlocked(parsed.Hostname(), "response_scan", time.Since(start), agentLabel)
		p.emitReceipt(receipt.EmitOpts{
			ActionID:  receipt.NewActionID(),
			Verdict:   config.ActionBlock,
			Layer:     "response_scan",
			Pattern:   reason,
			Transport: "fetch",
			Method:    http.MethodGet,
			Target:    displayURL,
			RequestID: requestID,
			Agent:     agent,
		})
		writeJSON(w, http.StatusForbidden, FetchResponse{URL: displayURL, Agent: agent, Blocked: true, BlockReason: reason})
		return
	}

	// Response scanning: check extracted content for prompt injection.
	// Exempt domains are still scanned for visibility (findings logged as warn)
	// but adaptive scoring is skipped and actions are not upgraded.
	if sc.ResponseScanningEnabled() {
		scanResult := sc.ScanResponse(r.Context(), content)

		// Filter out suppressed findings before deriving taint or capture action.
		if !scanResult.Clean && len(cfg.Suppress) > 0 {
			var kept []scanner.ResponseMatch
			for _, m := range scanResult.Matches {
				if !config.IsSuppressed(m.PatternName, displayURL, cfg.Suppress) {
					kept = append(kept, m)
				} else {
					p.metrics.RecordResponseScanExempt(ExemptReasonSuppress, TransportFetch)
				}
			}
			scanResult.Matches = kept
			scanResult.Clean = len(kept) == 0
		}
		if !scanResult.Clean {
			responsePromptHit = true
		}

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
		ActionID:            actionID,
		Verdict:             config.ActionAllow,
		Transport:           "fetch",
		Method:              http.MethodGet,
		Target:              displayURL,
		RequestID:           requestID,
		Agent:               agent,
		SessionTaintLevel:   fetchTaint.Risk.Level.String(),
		SessionContaminated: fetchTaint.Risk.Contaminated,
		RecentTaintSources:  fetchTaint.Risk.Sources,
		SessionTaskID:       fetchTaint.Task.CurrentTaskID,
		SessionTaskLabel:    fetchTaint.Task.CurrentTaskLabel,
		AuthorityKind:       fetchTaint.Authority.String(),
		TaintDecision:       fetchTaint.Result.Decision.String(),
		TaintDecisionReason: fetchTaint.Result.Reason,
		TaskOverrideApplied: fetchTaint.TaskOverrideApplied,
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

	// Suppress filter: serves both the main response scan path (where the caller's
	// inline loop already stripped suppressed matches before the capture observer) and
	// the hidden content scan path (where this is the only suppress point). For the
	// main path, no suppressed matches remain so this loop is a no-op. For the hidden
	// content path, this loop filters and emits the metric correctly.
	if !result.Clean && len(cfg.Suppress) > 0 {
		var kept []scanner.ResponseMatch
		for _, m := range result.Matches {
			if !config.IsSuppressed(m.PatternName, displayURL, cfg.Suppress) {
				kept = append(kept, m)
			} else {
				p.metrics.RecordResponseScanExempt(ExemptReasonSuppress, TransportFetch)
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
		log.LogBlocked(newHTTPAuditContext(p.logger, http.MethodGet, displayURL, clientIP, requestID, agent), "response_scan", reason)
		p.emitReceipt(receipt.EmitOpts{
			ActionID:  receipt.NewActionID(),
			Verdict:   config.ActionBlock,
			Layer:     "response_scan",
			Pattern:   reason,
			Transport: "fetch",
			Method:    http.MethodGet,
			Target:    displayURL,
			RequestID: requestID,
			Agent:     agent,
		})
		writeJSON(w, http.StatusForbidden, FetchResponse{URL: displayURL, Agent: agent, Blocked: true, BlockReason: reason})
		return true, "", true
	case config.ActionAsk:
		if p.approver == nil {
			recordResponseSignal(session.SignalBlock)
			reason := fmt.Sprintf("response contains prompt injection: %s (no HITL approver)", strings.Join(patternNames, ", "))
			log.LogBlocked(newHTTPAuditContext(p.logger, http.MethodGet, displayURL, clientIP, requestID, agent), "response_scan", reason)
			p.emitReceipt(receipt.EmitOpts{
				ActionID:  receipt.NewActionID(),
				Verdict:   config.ActionBlock,
				Layer:     "response_scan",
				Pattern:   reason,
				Transport: "fetch",
				Method:    http.MethodGet,
				Target:    displayURL,
				RequestID: requestID,
				Agent:     agent,
			})
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
			log.LogResponseScan(newHTTPAuditContext(log, http.MethodGet, displayURL, clientIP, requestID, agent), "ask:allow", len(result.Matches), patternNames, bundleRules)
		case hitl.DecisionStrip:
			out = result.TransformedContent
			log.LogResponseScan(newHTTPAuditContext(log, http.MethodGet, displayURL, clientIP, requestID, agent), "ask:strip", len(result.Matches), patternNames, bundleRules)
		default:
			recordResponseSignal(session.SignalBlock)
			reason := fmt.Sprintf("response blocked by operator: %s", strings.Join(patternNames, ", "))
			log.LogBlocked(newHTTPAuditContext(p.logger, http.MethodGet, displayURL, clientIP, requestID, agent), "response_scan", reason)
			p.emitReceipt(receipt.EmitOpts{
				ActionID:  receipt.NewActionID(),
				Verdict:   config.ActionBlock,
				Layer:     "response_scan",
				Pattern:   reason,
				Transport: "fetch",
				Method:    http.MethodGet,
				Target:    displayURL,
				RequestID: requestID,
				Agent:     agent,
			})
			writeJSON(w, http.StatusForbidden, FetchResponse{URL: displayURL, Agent: agent, Blocked: true, BlockReason: reason})
			return true, "", true
		}
	case config.ActionStrip:
		recordResponseSignal(session.SignalStrip)
		out = result.TransformedContent
		log.LogResponseScan(newHTTPAuditContext(log, http.MethodGet, displayURL, clientIP, requestID, agent), config.ActionStrip, len(result.Matches), patternNames, bundleRules)
	case config.ActionWarn:
		recordResponseSignal(session.SignalNearMiss)
		log.LogResponseScan(newHTTPAuditContext(log, http.MethodGet, displayURL, clientIP, requestID, agent), config.ActionWarn, len(result.Matches), patternNames, bundleRules)
	default:
		recordResponseSignal(session.SignalNearMiss)
		log.LogResponseScan(newHTTPAuditContext(log, http.MethodGet, displayURL, clientIP, requestID, agent), action, len(result.Matches), patternNames, bundleRules)
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
