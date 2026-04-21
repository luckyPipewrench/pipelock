// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"

	"github.com/luckyPipewrench/pipelock/internal/addressprotect"
	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/capture"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/decide"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/redact"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/session"
	plwsutil "github.com/luckyPipewrench/pipelock/internal/wsutil"
)

// wsSemaphore limits concurrent WebSocket proxy connections.
// Capacity is fixed on first use (sync.Once). Config reload changes to
// max_concurrent_connections require a restart to take effect.
var (
	wsSem     *tunnelSemaphore
	wsSemOnce sync.Once
)

func getWSSemaphore(capacity int) *tunnelSemaphore {
	wsSemOnce.Do(func() {
		wsSem = newTunnelSemaphore(capacity)
	})
	return wsSem
}

// wsRelay holds per-connection state for a proxied WebSocket connection.
type wsRelay struct {
	clientConn   net.Conn
	upstreamConn net.Conn
	scanner      *scanner.Scanner
	proxy        *Proxy
	cfg          *config.Config
	redaction    *redactionRuntime
	agent        string
	clientIP     string
	requestID    string
	targetURL    string
	hostname     string
	maxMsg       int
	scanText     bool
	allowBinary  bool
	redactionLog *redact.Report
	rec          session.Recorder // live escalation level for UpgradeAction; nil when profiling disabled
	terminalOnce sync.Once        // ensures only one terminal receipt (kill_switch/session_deny) is emitted across concurrent relay goroutines
}

// escalationLevel returns the live escalation level from the session recorder.
// Returns 0 (normal) when the recorder is nil (profiling disabled).
func (r *wsRelay) escalationLevel() int {
	if r.rec != nil {
		return r.rec.EscalationLevel()
	}
	return 0
}

// recordSignal records an adaptive enforcement signal on the relay's session
// recorder. No-op when the recorder is nil or adaptive enforcement is disabled.
func (r *wsRelay) recordSignal(sig session.SignalType, log *audit.Logger) {
	if r.rec == nil || !r.cfg.AdaptiveEnforcement.Enabled {
		return
	}
	sessionKey := r.clientIP
	if r.agent != "" && r.agent != agentAnonymous {
		sessionKey = r.agent + "|" + r.clientIP
	}
	decide.RecordSignal(r.rec, sig, decide.EscalationParams{
		Threshold: r.cfg.AdaptiveEnforcement.EscalationThreshold,
		Logger:    log,
		Metrics:   r.proxy.metrics,
		Session:   sessionKey,
		ClientIP:  r.clientIP,
		RequestID: r.requestID,
	})
}

// wsRelayStats collects per-connection counters for audit logging.
type wsRelayStats struct {
	clientToServer int64
	serverToClient int64
	textFrames     int64
	binaryFrames   int64
	blocked        bool // true if relay terminated due to a policy/DLP/injection block
}

// handleWebSocket handles /ws WebSocket proxy requests.
func (p *Proxy) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	clientIP, requestID := requestMeta(r)

	// Strip inbound mediation envelope headers to prevent forgery.
	envelope.StripInbound(r.Header)

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

	if !cfg.WebSocketProxy.Enabled {
		http.Error(w, "WebSocket proxy not enabled", http.StatusNotFound)
		return
	}

	log := p.logger.With("agent", agent)

	// Extract and validate target URL. Uses the same extraction logic as /fetch
	// to handle unencoded '&' in target URLs without silent truncation.
	targetURL := extractTargetURL(r)
	if targetURL == "" {
		http.Error(w, "missing 'url' query parameter", http.StatusBadRequest)
		return
	}

	targetURL = stripFetchControlChars(targetURL)

	parsed, err := url.Parse(targetURL)
	if err != nil || (parsed.Scheme != "ws" && parsed.Scheme != "wss") {
		http.Error(w, "invalid URL: must be ws or wss", http.StatusBadRequest)
		return
	}

	// Map ws->http, wss->https for the scanner pipeline (scanner expects HTTP schemes).
	scanScheme := schemeHTTP
	if parsed.Scheme == "wss" {
		scanScheme = schemeHTTPS
	}
	scanURL := scanScheme + "://" + parsed.Host + parsed.RequestURI()

	actx := newHTTPAuditContext(log, "WS", targetURL, clientIP, requestID, agent)

	// Run through all 9 scanner layers.
	wsScanCtx := scanner.WithDLPWarnContext(r.Context(), scanner.DLPWarnContext{
		Method: "WS", URL: scanURL, ClientIP: clientIP,
		RequestID: requestID, Agent: agent, Transport: "websocket",
	})
	r = r.WithContext(wsScanCtx)
	result := sc.Scan(wsScanCtx, scanURL)

	// Capture observer: record WebSocket URL verdict for policy replay.
	{
		findings := urlResultToFindings(result)
		action := ""
		if !result.Allowed {
			action = config.ActionBlock
		}
		p.captureObs.ObserveURLVerdict(r.Context(), &capture.URLVerdictRecord{
			Subsurface:        "ws_url",
			Transport:         "websocket",
			RequestID:         requestID,
			Agent:             agent,
			Request:           capture.CaptureRequest{Method: r.Method, URL: targetURL},
			RawFindings:       findings,
			EffectiveFindings: findings,
			EffectiveAction:   action,
			Outcome:           captureOutcome(action, result.Allowed),
		})
	}

	// Session profiling: record BEFORE the enforce-mode early return so adaptive
	// signals (SignalBlock) fire even for blocked requests. Pass deferClean=true
	// so header DLP findings on the same handshake don't get offset by early decay.
	sr := p.recordSessionActivity(clientIP, agent, parsed.Hostname(), requestID, result, cfg, log, true)
	wsHasFinding := !result.Allowed && !result.IsProtective()

	if !result.Allowed {
		status := http.StatusForbidden
		if result.Scanner == scanner.ScannerRateLimit {
			status = http.StatusTooManyRequests
		}
		if cfg.EnforceEnabled() {
			log.LogBlocked(actx, result.Scanner, result.Reason)
			p.metrics.RecordWSBlocked()
			p.emitReceipt(receipt.EmitOpts{
				ActionID:  receipt.NewActionID(),
				Verdict:   config.ActionBlock,
				Layer:     result.Scanner,
				Pattern:   result.Reason,
				Transport: "websocket",
				Method:    "WS",
				Target:    targetURL,
				RequestID: requestID,
				Agent:     agent,
			})
			if cfg.ExplainBlocksEnabled() && result.Hint != "" {
				w.Header().Set("X-Pipelock-Hint", result.Hint)
			}
			http.Error(w, "WebSocket blocked: "+result.Reason, status)
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
			p.metrics.RecordWSBlocked()
			p.emitReceipt(receipt.EmitOpts{
				ActionID:  receipt.NewActionID(),
				Verdict:   config.ActionBlock,
				Layer:     result.Scanner,
				Pattern:   result.Reason + " (escalated)",
				Transport: "websocket",
				Method:    "WS",
				Target:    targetURL,
				RequestID: requestID,
				Agent:     agent,
			})
			http.Error(w, "WebSocket blocked: "+result.Reason+" (escalated)", status)
			return
		}
		log.LogAnomaly(actx, result.Scanner,
			result.Reason, result.Score)
	}

	if sr.Blocked {
		p.emitReceipt(receipt.EmitOpts{
			ActionID:  receipt.NewActionID(),
			Verdict:   config.ActionBlock,
			Layer:     "session_profiling",
			Pattern:   sr.Detail,
			Transport: "websocket",
			Method:    "WS",
			Target:    targetURL,
			RequestID: requestID,
			Agent:     agent,
		})
		http.Error(w, sr.Detail, http.StatusForbidden)
		return
	}

	// block_all enforcement: deny ALL traffic (including clean) when the
	// session is at an escalation level with block_all=true.
	if sr.Level > 0 && decide.UpgradeAction("", sr.Level, &cfg.AdaptiveEnforcement) == config.ActionBlock {
		sessionKey := clientIP
		if agent != "" && agent != agentAnonymous {
			sessionKey = agent + "|" + clientIP
		}
		log.LogAdaptiveUpgrade(sessionKey, session.EscalationLabel(sr.Level), "", config.ActionBlock, "session_deny", clientIP, requestID)
		p.metrics.RecordAdaptiveUpgrade("", config.ActionBlock, session.EscalationLabel(sr.Level))
		p.metrics.RecordWSBlocked()
		p.emitReceipt(receipt.EmitOpts{
			ActionID:  receipt.NewActionID(),
			Verdict:   config.ActionBlock,
			Layer:     "session_deny",
			Pattern:   "session escalation level " + session.EscalationLabel(sr.Level),
			Transport: "websocket",
			Method:    "WS",
			Target:    targetURL,
			RequestID: requestID,
			Agent:     agent,
		})
		http.Error(w, "WebSocket blocked: session escalation level "+session.EscalationLabel(sr.Level), http.StatusForbidden)
		return
	}

	// Budget admission check: enforce request count and domain limits.
	if err := resolved.Budget.CheckAdmission(strings.ToLower(parsed.Hostname())); err != nil {
		reason := err.Error()
		log.LogBlocked(actx, "budget", reason)
		p.metrics.RecordWSBlocked()
		p.emitReceipt(receipt.EmitOpts{
			ActionID:  receipt.NewActionID(),
			Verdict:   config.ActionBlock,
			Layer:     "budget",
			Pattern:   reason,
			Transport: "websocket",
			Method:    "WS",
			Target:    targetURL,
			RequestID: requestID,
			Agent:     agent,
		})
		http.Error(w, "WebSocket blocked: "+reason, http.StatusTooManyRequests)
		return
	}

	// Check connection semaphore.
	sem := getWSSemaphore(cfg.WebSocketProxy.MaxConcurrentConnections)
	if !sem.TryAcquire() {
		http.Error(w, "too many active WebSocket connections", http.StatusServiceUnavailable)
		return
	}
	defer sem.Release()

	// Build headers for upstream handshake.
	fwdHeaders := p.buildWSForwardHeaders(r, parsed, cfg, sc)

	// DLP-scan forwarded header values regardless of destination or enforce mode.
	// In audit mode, findings are logged as anomalies but traffic is allowed.
	if blocked, reason := p.dlpScanWSHeaders(r.Context(), fwdHeaders, sc); blocked {
		// Capture observer: record WS header DLP verdict for policy replay.
		p.captureObs.ObserveDLPVerdict(r.Context(), &capture.DLPVerdictRecord{
			Subsurface:      "dlp_ws_header",
			Transport:       "websocket",
			RequestID:       requestID,
			Agent:           agent,
			Request:         capture.CaptureRequest{Method: r.Method, URL: targetURL},
			TransformKind:   capture.TransformHeaderValue,
			EffectiveAction: config.ActionBlock,
			Outcome:         capture.OutcomeBlocked,
			SkipReason:      reason,
		})
		wsHasFinding = true
		// Record session activity so adaptive enforcement sees header-DLP hits.
		headerSR := p.recordSessionActivity(clientIP, agent, parsed.Hostname(), requestID, scanner.Result{Allowed: false, Score: 0.9}, cfg, log, false)
		if cfg.EnforceEnabled() {
			log.LogWSBlocked(targetURL, audit.DirectionClientToServer, audit.ScannerDLP, reason, clientIP, requestID)
			p.metrics.RecordWSBlocked()
			p.emitReceipt(receipt.EmitOpts{
				ActionID:  receipt.NewActionID(),
				Verdict:   config.ActionBlock,
				Layer:     "dlp_header",
				Pattern:   reason,
				Transport: "websocket",
				Method:    "WS",
				Target:    targetURL,
				RequestID: requestID,
				Agent:     agent,
			})
			http.Error(w, "WebSocket blocked: "+reason, http.StatusForbidden)
			return
		}
		log.LogAnomaly(actx, audit.ScannerDLP, reason, 0)
		// Re-check block_all after header DLP may have escalated the session.
		if cfg.AdaptiveEnforcement.Enabled && headerSR.Level > 0 &&
			decide.UpgradeAction("", headerSR.Level, &cfg.AdaptiveEnforcement) == config.ActionBlock {
			sessionKey := clientIP
			if agent != "" && agent != agentAnonymous {
				sessionKey = agent + "|" + clientIP
			}
			log.LogAdaptiveUpgrade(sessionKey, session.EscalationLabel(headerSR.Level), "", config.ActionBlock, "session_deny", clientIP, requestID)
			p.metrics.RecordAdaptiveUpgrade("", config.ActionBlock, session.EscalationLabel(headerSR.Level))
			p.metrics.RecordWSBlocked()
			p.emitReceipt(receipt.EmitOpts{
				ActionID:  receipt.NewActionID(),
				Verdict:   config.ActionBlock,
				Layer:     "session_deny",
				Pattern:   "session escalation level " + session.EscalationLabel(headerSR.Level),
				Transport: "websocket",
				Method:    "WS",
				Target:    targetURL,
				RequestID: requestID,
				Agent:     agent,
			})
			http.Error(w, "WebSocket blocked: session escalation level "+session.EscalationLabel(headerSR.Level), http.StatusForbidden)
			return
		}
	}

	// Upgrade the client connection.
	upgrader := ws.HTTPUpgrader{
		Timeout: 10 * time.Second,
	}
	clientConn, _, _, upgradeErr := upgrader.Upgrade(r, w)
	if upgradeErr != nil {
		log.LogError(actx, fmt.Errorf("client upgrade: %w", upgradeErr))
		// If Upgrade fails, it already wrote the HTTP error response.
		return
	}
	defer safeClose(clientConn, "ws.clientConn", log)

	// Obtain a live session recorder for the relay. This provides live
	// escalation level lookups instead of a stale snapshot, so that
	// escalation changes during long-lived WS connections take effect.
	var wsRec session.Recorder
	if sm := p.sessionMgrPtr.Load(); sm != nil {
		sessionKey := clientIP
		if agent != "" && agent != agentAnonymous {
			sessionKey = agent + "|" + clientIP
		}
		wsRec = sm.GetOrCreate(sessionKey)
	}

	// Airlock admission check: deny new WebSocket connections to sessions
	// already in hard/drain tier. Existing connections are torn down via
	// RegisterCancel; this blocks new ones from being established.
	if wsSess, ok := wsRec.(*SessionState); ok && wsSess != nil {
		tier := wsSess.Airlock().Tier()
		if tier == config.AirlockTierHard || tier == config.AirlockTierDrain {
			log.LogAirlockDeny(wsSess.key, tier, TransportWS, http.MethodGet, clientIP, requestID)
			p.metrics.RecordAirlockDenial(tier, TransportWS, http.MethodGet)
			p.metrics.RecordWSBlocked()
			p.emitReceipt(receipt.EmitOpts{
				ActionID:  receipt.NewActionID(),
				Verdict:   config.ActionBlock,
				Layer:     "airlock",
				Pattern:   "airlock: WebSocket blocked during quarantine",
				Transport: "websocket",
				Method:    "WS",
				Target:    targetURL,
				RequestID: requestID,
				Agent:     agent,
			})
			plwsutil.WriteCloseFrame(clientConn, ws.StatusPolicyViolation, "airlock: WebSocket blocked during quarantine")
			return
		}
	}

	// Inject mediation envelope after all admission checks but before the
	// upstream handshake so the forwarded headers on the accepted connection
	// carry the final verdict. WebSocket handshakes are body-less GETs, so
	// content-digest is always dropped from the declared component list;
	// signing covers @method, @target-uri, and pipelock-mediation.
	//
	// gobwas/ws does not expose the *http.Request it synthesizes before
	// dialing, so we build a request value here that mirrors what the
	// dialer will send: method=GET, URL=parsed(targetURL), Header=fwdHeaders,
	// Host=parsed.Host. The signer mutates req.Header (i.e. fwdHeaders)
	// in place, so Signature / Signature-Input land on the handshake
	// headers the dialer hands to the upstream server. @target-uri in
	// the signature base therefore matches the URL being dialed, even
	// though the actual dial happens a few lines later in wsDialUpstream.
	//
	// Defense-in-depth note: targetURL was already parsed successfully
	// at the top of this handler (the first url.Parse call), so the
	// second Parse below cannot fail today. The check is intentional
	// future-proofing — a later refactor that threads a different
	// targetURL through this path must still fail closed on malformed
	// input. A deliberately unreachable branch is cheaper than a
	// silent unsigned envelope on a future regression.
	actionID := receipt.NewActionID()
	if envEmitter := p.envelopeEmitterPtr.Load(); envEmitter != nil {
		parsedTarget, parseErr := url.Parse(targetURL)
		if parseErr != nil {
			blockedErr := newEnvelopeBlockedRequest(parseErr)
			log.LogBlocked(actx, blockedErr.layer, blockedErr.detail)
			p.metrics.RecordWSBlocked()
			// Emit a block receipt so handshake-time envelope denials
			// land in the audit chain. The CONNECT path already does
			// this; WebSocket parity matters because operators lose
			// visibility into sign failures otherwise.
			p.emitReceipt(receipt.EmitOpts{
				ActionID:  actionID,
				Verdict:   config.ActionBlock,
				Layer:     blockedErr.layer,
				Pattern:   blockedErr.reason,
				Transport: "websocket",
				Method:    "WS",
				Target:    targetURL,
				RequestID: requestID,
				Agent:     agent,
			})
			plwsutil.WriteCloseFrame(clientConn, ws.StatusPolicyViolation, blockedErr.reason)
			return
		}
		synthReq := &http.Request{
			Method: http.MethodGet,
			URL:    parsedTarget,
			Header: fwdHeaders,
			Host:   parsedTarget.Host,
		}
		if envErr := envEmitter.InjectAndSign(synthReq, nil, envelope.BuildOpts{
			ActionID:   actionID,
			Action:     string(receipt.ActionDelegate),
			Verdict:    config.ActionAllow,
			SideEffect: string(receipt.SideEffectExternalWrite),
			Actor:      agent,
			ActorAuth:  id.Auth,
			PolicyHash: envelope.PolicyHashFromHex(cfg.CanonicalPolicyHash()),
		}); envErr != nil {
			blockedErr := newEnvelopeBlockedRequest(envErr)
			log.LogBlocked(actx, blockedErr.layer, blockedErr.detail)
			p.metrics.RecordWSBlocked()
			p.emitReceipt(receipt.EmitOpts{
				ActionID:  actionID,
				Verdict:   config.ActionBlock,
				Layer:     blockedErr.layer,
				Pattern:   blockedErr.reason,
				Transport: "websocket",
				Method:    "WS",
				Target:    targetURL,
				RequestID: requestID,
				Agent:     agent,
			})
			plwsutil.WriteCloseFrame(clientConn, ws.StatusPolicyViolation, blockedErr.reason)
			return
		}
	}

	// Dial upstream via SSRF-safe dialer.
	upstreamConn, dialErr := p.wsDialUpstream(r.Context(), targetURL, fwdHeaders, cfg)
	if dialErr != nil {
		log.LogError(actx, fmt.Errorf("upstream dial: %w", dialErr))
		plwsutil.WriteCloseFrame(clientConn, ws.StatusInternalServerError, "upstream dial failed")
		return
	}
	defer safeClose(upstreamConn, "ws.upstreamConn", log)

	if wsSess, ok := wsRec.(*SessionState); ok && wsSess != nil {
		// Register airlock cancel for WebSocket connections. When the session
		// escalates to hard/drain, closing both ends terminates the relay.
		wsSess.Airlock().RegisterCancel(func() {
			safeClose(clientConn, "airlock.ws.clientConn", log)
			safeClose(upstreamConn, "airlock.ws.upstreamConn", log)
		})
	}

	p.metrics.IncrActiveWS()
	log.LogWSOpen(targetURL, clientIP, requestID, agent)

	scanTextFrames := cfg.WebSocketProxy.ScanTextFrames == nil || *cfg.WebSocketProxy.ScanTextFrames

	// Deferred clean decay: only apply if the entire handshake was clean
	// (no URL scan hit, no header DLP hit). This prevents same-handshake
	// raise+decay when a header carries a secret but the URL is clean.
	if wsRec != nil && cfg.AdaptiveEnforcement.Enabled && !wsHasFinding {
		wsRec.RecordClean(cfg.AdaptiveEnforcement.DecayPerCleanRequest)
	}

	relay := &wsRelay{
		clientConn:   clientConn,
		upstreamConn: upstreamConn,
		scanner:      sc,
		proxy:        p,
		cfg:          cfg,
		redaction:    p.currentRedactionRuntimeFor(cfg),
		agent:        agent,
		clientIP:     clientIP,
		requestID:    requestID,
		targetURL:    targetURL,
		hostname:     strings.ToLower(parsed.Hostname()),
		maxMsg:       cfg.WebSocketProxy.MaxMessageBytes,
		scanText:     scanTextFrames,
		allowBinary:  cfg.WebSocketProxy.AllowBinaryFrames,
		rec:          wsRec,
	}

	if scanTextFrames && sc.ResponseScanningEnabled() && isResponseScanExempt(relay.hostname, cfg.ResponseScanning.ExemptDomains) {
		log.LogResponseScanExempt(actx, relay.hostname)
	}

	stats := relay.run(r.Context())

	p.metrics.DecrActiveWS()
	duration := time.Since(start)
	if stats.blocked {
		p.metrics.RecordWSBlocked()
	} else {
		p.metrics.RecordWSCompleted()
	}
	p.metrics.RecordWSStats(duration, stats.clientToServer, stats.serverToClient)
	log.LogWSClose(targetURL, clientIP, requestID, agent,
		stats.clientToServer, stats.serverToClient,
		stats.textFrames, stats.binaryFrames, duration)

	closeVerdict := config.ActionAllow
	if stats.blocked {
		closeVerdict = config.ActionBlock
	}
	p.emitReceipt(receipt.EmitOpts{
		ActionID:         actionID,
		Verdict:          closeVerdict,
		Layer:            "session_close",
		Transport:        "websocket",
		Method:           "WS",
		Target:           targetURL,
		RequestID:        requestID,
		Agent:            agent,
		RedactionProfile: cfg.Redaction.DefaultProfile,
		RedactionReport:  relay.redactionLog,
	})

	sc.RecordRequest(relay.hostname, int(stats.clientToServer+stats.serverToClient))

	// Record WebSocket bytes for per-agent budget tracking. WebSocket
	// connections are streaming: bytes are tracked after close and enforced
	// on the next admission check, not mid-stream.
	_ = resolved.Budget.RecordBytes(stats.clientToServer + stats.serverToClient)
}

// buildWSForwardHeaders builds the HTTP headers to forward during upstream WS handshake.
// Follows the allowlist approach: forward known-safe headers, strip everything else.
func (p *Proxy) buildWSForwardHeaders(r *http.Request, parsed *url.URL, cfg *config.Config, _ *scanner.Scanner) http.Header {
	fwd := make(http.Header)

	// Authorization (required by most authenticated WS APIs).
	if v := r.Header.Get("Authorization"); v != "" {
		fwd.Set("Authorization", v)
	}

	// Provider-specific auth headers.
	for _, key := range []string{"X-Api-Key", "X-Goog-Api-Key"} {
		if v := r.Header.Get(key); v != "" {
			fwd.Set(key, v)
		}
	}

	// Subprotocol negotiation.
	if v := r.Header.Get("Sec-WebSocket-Protocol"); v != "" {
		fwd.Set("Sec-WebSocket-Protocol", v)
	}

	// Origin policy.
	switch cfg.WebSocketProxy.OriginPolicy {
	case config.OriginPolicyForward:
		if v := r.Header.Get("Origin"); v != "" {
			fwd.Set("Origin", v)
		}
	case "strip":
		// Do not forward Origin.
	default: // "rewrite"
		scheme := schemeHTTPS
		if parsed.Scheme == "ws" {
			scheme = schemeHTTP
		}
		fwd.Set("Origin", scheme+"://"+parsed.Host)
	}

	// Cookies (opt-in only).
	if cfg.WebSocketProxy.ForwardCookies {
		if v := r.Header.Get("Cookie"); v != "" {
			fwd.Set("Cookie", v)
		}
	}

	// User-Agent with pipelock suffix.
	ua := r.Header.Get("User-Agent")
	if ua == "" {
		ua = cfg.FetchProxy.UserAgent
	}
	fwd.Set("User-Agent", ua+" pipelock/"+Version)

	return fwd
}

// dlpScanWSHeaders runs DLP scanning on all forwarded header values before the
// upstream handshake. Headers are scanned regardless of destination (no
// allowlist skip) because agents can exfiltrate secrets in any header value.
func (p *Proxy) dlpScanWSHeaders(ctx context.Context, headers http.Header, sc *scanner.Scanner) (blocked bool, reason string) {
	// Scan all headers that buildWSForwardHeaders may forward. This covers
	// auth headers, cookies, origin, subprotocol, and user-agent. An agent
	// can exfiltrate data in any of these values.
	for _, key := range []string{
		"Authorization", "X-Api-Key", "X-Goog-Api-Key", "Cookie",
		"Origin", "Sec-WebSocket-Protocol", "User-Agent",
	} {
		val := headers.Get(key)
		if val == "" {
			continue
		}
		result := sc.ScanTextForDLP(ctx, val)
		if !result.Clean {
			names := make([]string, len(result.Matches))
			for i, m := range result.Matches {
				names[i] = m.PatternName
			}
			return true, fmt.Sprintf("DLP match in %s header: %s", key, strings.Join(names, ", "))
		}
	}
	return false, ""
}

// isHostAllowlisted checks if a hostname matches any pattern in the allowlist.
// Supports leading wildcard patterns (e.g., "*.openai.com").
func isHostAllowlisted(hostname string, allowlist []string) bool {
	hostname = strings.ToLower(hostname)
	for _, pattern := range allowlist {
		pattern = strings.ToLower(pattern)
		if pattern == hostname {
			return true
		}
		if strings.HasPrefix(pattern, "*.") {
			suffix := pattern[1:] // ".openai.com"
			if strings.HasSuffix(hostname, suffix) {
				return true
			}
		}
	}
	return false
}

// wsDialUpstream dials the upstream WebSocket server using the SSRF-safe dialer.
func (p *Proxy) wsDialUpstream(ctx context.Context, targetURL string, fwdHeaders http.Header, cfg *config.Config) (net.Conn, error) {
	timeout := time.Duration(cfg.WebSocketProxy.MaxConnectionSeconds) * time.Second
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	dialer := ws.Dialer{
		NetDial:    p.ssrfSafeDialContext,
		Header:     ws.HandshakeHeaderHTTP(fwdHeaders),
		Timeout:    30 * time.Second,
		Extensions: nil, // disable permessage-deflate; relay does not handle compressed frames
	}

	conn, _, _, err := dialer.Dial(dialCtx, targetURL)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// run starts bidirectional frame relay. Returns stats when both directions complete.
func (r *wsRelay) run(ctx context.Context) wsRelayStats {
	maxDuration := time.Duration(r.cfg.WebSocketProxy.MaxConnectionSeconds) * time.Second
	idleTimeout := time.Duration(r.cfg.WebSocketProxy.IdleTimeoutSeconds) * time.Second

	ctx, cancel := context.WithTimeout(ctx, maxDuration)
	defer cancel()

	// Use separate per-direction counters to avoid data races. The goroutine
	// writes c2s*, the main goroutine writes s2c*, and we sum after wg.Wait().
	var c2sBytes, c2sText, c2sBinary int64
	var c2sBlocked bool
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		c2sBytes, c2sText, c2sBinary, c2sBlocked = r.clientToUpstream(ctx, cancel, idleTimeout)
	}()

	s2cBytes, s2cText, s2cBinary, s2cBlocked := r.upstreamToClient(ctx, cancel, idleTimeout)

	wg.Wait()
	return wsRelayStats{
		clientToServer: c2sBytes,
		serverToClient: s2cBytes,
		textFrames:     c2sText + s2cText,
		binaryFrames:   c2sBinary + s2cBinary,
		blocked:        c2sBlocked || s2cBlocked,
	}
}

func (r *wsRelay) scanClientMessageBody(ctx context.Context, msg []byte) ([]byte, BodyScanResult) {
	maxBytes := r.maxMsg
	if cfgMax := r.cfg.RequestBodyScanning.MaxBodyBytes; cfgMax > 0 && cfgMax < maxBytes {
		maxBytes = cfgMax
	}

	contentType := ""
	if json.Valid(msg) {
		contentType = contentTypeJSON
	}

	bodyReq := BodyScanRequest{
		Body:        bytes.NewReader(msg),
		ContentType: contentType,
		MaxBytes:    maxBytes,
		Scanner:     r.scanner,
		AgentID:     r.agent,
		Host:        r.hostname,
	}
	applyBodyScanRedaction(&bodyReq, r.redaction)
	return scanRequestBody(ctx, bodyReq)
}

func updateWSCrossMessageTail(tail []byte, msg []byte) []byte {
	if len(msg) >= crossMsgOverlap {
		next := make([]byte, crossMsgOverlap)
		copy(next, msg[len(msg)-crossMsgOverlap:])
		return next
	}

	next := append(tail, msg...)
	if len(next) > crossMsgOverlap {
		next = next[len(next)-crossMsgOverlap:]
	}
	return next
}

func (r *wsRelay) scanClientText(ctx context.Context, log *audit.Logger, scanInput []byte) (blocked bool) {
	dlpResult := r.scanner.ScanTextForDLP(ctx, string(scanInput))
	var addrFindings []addressprotect.Finding
	if checker := r.scanner.AddressChecker(); checker != nil {
		addrFindings = checker.CheckText(string(scanInput), r.agent).Findings
	}

	return r.handleClientTextFindings(log, dlpResult.Matches, addrFindings)
}

func (r *wsRelay) scanClientCrossMessageText(ctx context.Context, log *audit.Logger, tail []byte, msg []byte) (blocked bool) {
	if len(tail) == 0 {
		return false
	}

	combined := make([]byte, 0, len(tail)+len(msg))
	combined = append(combined, tail...)
	combined = append(combined, msg...)

	combinedDLP := r.scanner.ScanTextForDLPQuiet(ctx, string(combined))
	prevDLP := r.scanner.ScanTextForDLPQuiet(ctx, string(tail))
	currDLP := r.scanner.ScanTextForDLPQuiet(ctx, string(msg))

	crossDLP, crossWarns := wsCrossMessageDLPMatches(combinedDLP, prevDLP, currDLP)
	if len(crossWarns) > 0 {
		r.scanner.EmitTextDLPWarnMatches(ctx, crossWarns)
	}

	var crossAddr []addressprotect.Finding
	if checker := r.scanner.AddressChecker(); checker != nil {
		combinedAddr := checker.CheckText(string(combined), r.agent)
		if len(combinedAddr.Findings) > 0 {
			prevAddr := checker.CheckText(string(tail), r.agent)
			currAddr := checker.CheckText(string(msg), r.agent)
			crossAddr = wsCrossMessageAddressFindings(combinedAddr.Findings, prevAddr.Findings, currAddr.Findings)
		}
	}

	return r.handleClientTextFindings(log, crossDLP, crossAddr)
}

func (r *wsRelay) handleClientTextFindings(log *audit.Logger, dlpMatches []scanner.TextDLPMatch, addrFindings []addressprotect.Finding) (blocked bool) {
	if len(dlpMatches) > 0 {
		names := make([]string, len(dlpMatches))
		for i, m := range dlpMatches {
			names[i] = m.PatternName
		}
		wsBundleRules := dlpBundleRules(dlpMatches)
		if r.cfg.EnforceEnabled() {
			r.recordSignal(session.SignalBlock, log)
			reason := fmt.Sprintf("DLP match: %s", strings.Join(names, ", "))
			log.LogWSBlocked(r.targetURL, audit.DirectionClientToServer, audit.ScannerDLP, reason, r.clientIP, r.requestID)
			r.proxy.metrics.RecordWSScanHit(audit.ScannerDLP)
			r.proxy.emitReceipt(receipt.EmitOpts{
				ActionID:  receipt.NewActionID(),
				Verdict:   config.ActionBlock,
				Layer:     audit.ScannerDLP,
				Pattern:   reason,
				Transport: "websocket",
				Method:    "WS",
				Target:    r.targetURL,
				RequestID: r.requestID,
				Agent:     r.agent,
			})
			plwsutil.WriteCloseFrame(r.clientConn, ws.StatusPolicyViolation, "DLP violation")
			plwsutil.WriteClientCloseFrame(r.upstreamConn, ws.StatusPolicyViolation, "DLP violation")
			return true
		}

		baseAction := config.ActionWarn
		effectiveAction := decide.UpgradeAction(baseAction, r.escalationLevel(), &r.cfg.AdaptiveEnforcement)
		if effectiveAction == config.ActionBlock {
			r.recordSignal(session.SignalBlock, log)
			sessionKey := r.clientIP
			if r.agent != "" && r.agent != agentAnonymous {
				sessionKey = r.agent + "|" + r.clientIP
			}
			log.LogAdaptiveUpgrade(sessionKey, session.EscalationLabel(r.escalationLevel()), baseAction, effectiveAction, audit.ScannerDLP, r.clientIP, r.requestID)
			r.proxy.metrics.RecordAdaptiveUpgrade(baseAction, effectiveAction, session.EscalationLabel(r.escalationLevel()))
			reason := fmt.Sprintf("DLP match: %s (escalated)", strings.Join(names, ", "))
			log.LogWSBlocked(r.targetURL, audit.DirectionClientToServer, audit.ScannerDLP, reason, r.clientIP, r.requestID)
			r.proxy.metrics.RecordWSScanHit(audit.ScannerDLP)
			r.proxy.emitReceipt(receipt.EmitOpts{
				ActionID:  receipt.NewActionID(),
				Verdict:   config.ActionBlock,
				Layer:     audit.ScannerDLP,
				Pattern:   reason,
				Transport: "websocket",
				Method:    "WS",
				Target:    r.targetURL,
				RequestID: r.requestID,
				Agent:     r.agent,
			})
			plwsutil.WriteCloseFrame(r.clientConn, ws.StatusPolicyViolation, "DLP violation")
			plwsutil.WriteClientCloseFrame(r.upstreamConn, ws.StatusPolicyViolation, "DLP violation")
			return true
		}

		r.recordSignal(session.SignalNearMiss, log)
		log.LogWSScan(r.targetURL, audit.DirectionClientToServer, r.clientIP, r.requestID, "audit", len(dlpMatches), names, wsBundleRules)
	}

	if len(addrFindings) > 0 {
		addrAction := addressprotect.StrictestAction(addrFindings)
		names := make([]string, len(addrFindings))
		for i, f := range addrFindings {
			names[i] = f.Explanation
		}
		for _, f := range addrFindings {
			verdictLabel := "unknown"
			if f.Verdict == addressprotect.VerdictLookalike {
				verdictLabel = "lookalike"
			}
			r.proxy.metrics.RecordAddressFinding(f.Chain, verdictLabel)
		}

		originalAddrAction := addrAction
		addrAction = decide.UpgradeAction(addrAction, r.escalationLevel(), &r.cfg.AdaptiveEnforcement)
		if addrAction != originalAddrAction {
			sessionKey := r.clientIP
			if r.agent != "" && r.agent != agentAnonymous {
				sessionKey = r.agent + "|" + r.clientIP
			}
			log.LogAdaptiveUpgrade(sessionKey, session.EscalationLabel(r.escalationLevel()), originalAddrAction, addrAction, scannerLabelAddressProtection, r.clientIP, r.requestID)
			r.proxy.metrics.RecordAdaptiveUpgrade(originalAddrAction, addrAction, session.EscalationLabel(r.escalationLevel()))
		}
		if r.cfg.EnforceEnabled() && addrAction == config.ActionBlock {
			r.recordSignal(session.SignalBlock, log)
			var blockExplanation string
			for _, f := range addrFindings {
				if f.Action == config.ActionBlock {
					blockExplanation = f.Explanation
					break
				}
			}
			reason := fmt.Sprintf("address poisoning: %s", blockExplanation)
			log.LogWSBlocked(r.targetURL, audit.DirectionClientToServer, scannerLabelAddressProtection, reason, r.clientIP, r.requestID)
			r.proxy.emitReceipt(receipt.EmitOpts{
				ActionID:  receipt.NewActionID(),
				Verdict:   config.ActionBlock,
				Layer:     "address_protection",
				Pattern:   reason,
				Transport: "websocket",
				Method:    "WS",
				Target:    r.targetURL,
				RequestID: r.requestID,
				Agent:     r.agent,
			})
			plwsutil.WriteCloseFrame(r.clientConn, ws.StatusPolicyViolation, "address poisoning detected")
			plwsutil.WriteClientCloseFrame(r.upstreamConn, ws.StatusPolicyViolation, "address poisoning detected")
			return true
		}
		if !r.cfg.EnforceEnabled() && addrAction == config.ActionBlock && addrAction != originalAddrAction {
			r.recordSignal(session.SignalBlock, log)
			reason := fmt.Sprintf("address poisoning: %s (escalated)", names[0])
			log.LogWSBlocked(r.targetURL, audit.DirectionClientToServer, scannerLabelAddressProtection, reason, r.clientIP, r.requestID)
			r.proxy.emitReceipt(receipt.EmitOpts{
				ActionID:  receipt.NewActionID(),
				Verdict:   config.ActionBlock,
				Layer:     "address_protection",
				Pattern:   reason,
				Transport: "websocket",
				Method:    "WS",
				Target:    r.targetURL,
				RequestID: r.requestID,
				Agent:     r.agent,
			})
			plwsutil.WriteCloseFrame(r.clientConn, ws.StatusPolicyViolation, "address poisoning detected")
			plwsutil.WriteClientCloseFrame(r.upstreamConn, ws.StatusPolicyViolation, "address poisoning detected")
			return true
		}

		r.recordSignal(session.SignalNearMiss, log)
		log.LogWSScan(r.targetURL, audit.DirectionClientToServer, r.clientIP, r.requestID, scannerLabelAddressProtection, len(addrFindings), names, nil)
	}

	return false
}

func wsCrossMessageDLPMatches(
	combined scanner.TextDLPResult,
	prev scanner.TextDLPResult,
	current scanner.TextDLPResult,
) ([]scanner.TextDLPMatch, []scanner.TextDLPMatch) {
	singleMessageMatches := make(map[string]struct{},
		len(prev.Matches)+len(current.Matches)+len(prev.InformationalMatches)+len(current.InformationalMatches))
	wsAddDLPMatchKeys(singleMessageMatches, prev.Matches)
	wsAddDLPMatchKeys(singleMessageMatches, current.Matches)
	wsAddDLPMatchKeys(singleMessageMatches, prev.InformationalMatches)
	wsAddDLPMatchKeys(singleMessageMatches, current.InformationalMatches)

	return wsFilterUniqueDLPMatches(combined.Matches, singleMessageMatches),
		wsFilterUniqueDLPMatches(combined.InformationalMatches, singleMessageMatches)
}

func wsCrossMessageAddressFindings(
	combined []addressprotect.Finding,
	prev []addressprotect.Finding,
	current []addressprotect.Finding,
) []addressprotect.Finding {
	singleMessageFindings := make(map[string]struct{}, len(prev)+len(current))
	wsAddAddressFindingKeys(singleMessageFindings, prev)
	wsAddAddressFindingKeys(singleMessageFindings, current)

	filtered := make([]addressprotect.Finding, 0, len(combined))
	seen := make(map[string]struct{}, len(combined))
	for _, finding := range combined {
		key := wsAddressFindingKey(finding)
		if _, ok := singleMessageFindings[key]; ok {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		filtered = append(filtered, finding)
	}
	return filtered
}

func wsAddDLPMatchKeys(seen map[string]struct{}, matches []scanner.TextDLPMatch) {
	for _, match := range matches {
		seen[wsDLPMatchKey(match)] = struct{}{}
	}
}

func wsFilterUniqueDLPMatches(matches []scanner.TextDLPMatch, excluded map[string]struct{}) []scanner.TextDLPMatch {
	filtered := make([]scanner.TextDLPMatch, 0, len(matches))
	seen := make(map[string]struct{}, len(matches))
	for _, match := range matches {
		key := wsDLPMatchKey(match)
		if _, ok := excluded[key]; ok {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		filtered = append(filtered, match)
	}
	return filtered
}

func wsDLPMatchKey(match scanner.TextDLPMatch) string {
	return match.PatternName + "\x00" + match.Encoded
}

func wsAddAddressFindingKeys(seen map[string]struct{}, findings []addressprotect.Finding) {
	for _, finding := range findings {
		seen[wsAddressFindingKey(finding)] = struct{}{}
	}
}

func wsAddressFindingKey(finding addressprotect.Finding) string {
	return fmt.Sprintf("%s\x00%s\x00%d\x00%s\x00%s", finding.Chain, finding.Normalized, finding.Verdict, finding.Action, finding.MatchedAddr)
}

func wsMergeRedactionReport(dst **redact.Report, src *redact.Report) {
	if src == nil || !src.Applied || src.TotalRedactions == 0 {
		return
	}
	if *dst == nil {
		byClass := make(map[redact.Class]int, len(src.ByClass))
		for class, count := range src.ByClass {
			byClass[class] = count
		}
		*dst = &redact.Report{
			Applied:         true,
			TotalRedactions: src.TotalRedactions,
			ByClass:         byClass,
		}
		return
	}
	(*dst).Applied = true
	(*dst).TotalRedactions += src.TotalRedactions
	if len(src.ByClass) == 0 {
		return
	}
	if (*dst).ByClass == nil {
		(*dst).ByClass = make(map[redact.Class]int, len(src.ByClass))
	}
	for class, count := range src.ByClass {
		(*dst).ByClass[class] += count
	}
}

func (r *wsRelay) handleClientMessageBodyResult(log *audit.Logger, bodyBytes []byte, result BodyScanResult) (blocked bool) {
	if result.Clean {
		return false
	}

	scannerLabel := scannerLabelBodyDLP
	receiptLayer := audit.ScannerDLP
	closeReason := "DLP violation"
	if len(result.AddressFindings) > 0 && len(result.DLPMatches) == 0 {
		scannerLabel = scannerLabelAddressProtection
		receiptLayer = scannerLabelAddressProtection
		closeReason = "address poisoning detected"
	}
	if result.RedactionBlockReason != "" {
		scannerLabel = scannerLabelRedaction
		receiptLayer = scannerLabelRedaction
		closeReason = string(result.RedactionBlockReason)
	}

	reason := result.Reason
	if reason == "" {
		patternNames := dlpMatchNames(result.DLPMatches)
		if len(patternNames) > 0 {
			reason = fmt.Sprintf("request body contains secret: %s", strings.Join(patternNames, ", "))
		}
	}
	if reason == "" && len(result.AddressFindings) > 0 {
		reason = fmt.Sprintf("address poisoning: %s", result.AddressFindings[0].Explanation)
	}
	if reason == "" && result.RedactionBlockReason != "" {
		reason = "redaction blocked request: " + string(result.RedactionBlockReason)
	}
	if reason == "" {
		reason = "request body contains secret patterns"
	}

	if isFailClosedBodyResult(result, bodyBytes) {
		r.recordSignal(session.SignalBlock, log)
		log.LogWSBlocked(r.targetURL, audit.DirectionClientToServer, scannerLabel, reason, r.clientIP, r.requestID)
		r.proxy.metrics.RecordWSScanHit(scannerLabel)
		r.proxy.emitReceipt(receipt.EmitOpts{
			ActionID:         receipt.NewActionID(),
			Verdict:          config.ActionBlock,
			Layer:            receiptLayer,
			Pattern:          reason,
			Transport:        "websocket",
			Method:           "WS",
			Target:           r.targetURL,
			RequestID:        r.requestID,
			Agent:            r.agent,
			RedactionProfile: r.cfg.Redaction.DefaultProfile,
			RedactionReport:  result.RedactionReport,
		})
		plwsutil.WriteCloseFrame(r.clientConn, ws.StatusPolicyViolation, closeReason)
		plwsutil.WriteClientCloseFrame(r.upstreamConn, ws.StatusPolicyViolation, closeReason)
		return true
	}

	action := result.Action
	if action == "" {
		if r.cfg.EnforceEnabled() {
			action = config.ActionBlock
		} else {
			action = config.ActionWarn
		}
	}

	originalAction := action
	action = decide.UpgradeAction(action, r.escalationLevel(), &r.cfg.AdaptiveEnforcement)
	if action != originalAction {
		sessionKey := r.clientIP
		if r.agent != "" && r.agent != agentAnonymous {
			sessionKey = r.agent + "|" + r.clientIP
		}
		log.LogAdaptiveUpgrade(sessionKey, session.EscalationLabel(r.escalationLevel()), originalAction, action, scannerLabel, r.clientIP, r.requestID)
		r.proxy.metrics.RecordAdaptiveUpgrade(originalAction, action, session.EscalationLabel(r.escalationLevel()))
	}

	switch action {
	case config.ActionBlock:
		if !r.cfg.EnforceEnabled() && action == originalAction && len(result.AddressFindings) > 0 {
			r.recordSignal(session.SignalNearMiss, log)
			names := make([]string, len(result.AddressFindings))
			for i, f := range result.AddressFindings {
				names[i] = f.Explanation
			}
			log.LogWSScan(r.targetURL, audit.DirectionClientToServer, r.clientIP, r.requestID, scannerLabelAddressProtection, len(result.AddressFindings), names, nil)
			return false
		}
		r.recordSignal(session.SignalBlock, log)
		blockReason := reason
		if !r.cfg.EnforceEnabled() && action != originalAction {
			blockReason += " (escalated)"
		}
		log.LogWSBlocked(r.targetURL, audit.DirectionClientToServer, scannerLabel, blockReason, r.clientIP, r.requestID)
		r.proxy.metrics.RecordWSScanHit(scannerLabel)
		r.proxy.emitReceipt(receipt.EmitOpts{
			ActionID:         receipt.NewActionID(),
			Verdict:          config.ActionBlock,
			Layer:            receiptLayer,
			Pattern:          blockReason,
			Transport:        "websocket",
			Method:           "WS",
			Target:           r.targetURL,
			RequestID:        r.requestID,
			Agent:            r.agent,
			RedactionProfile: r.cfg.Redaction.DefaultProfile,
			RedactionReport:  result.RedactionReport,
		})
		plwsutil.WriteCloseFrame(r.clientConn, ws.StatusPolicyViolation, closeReason)
		plwsutil.WriteClientCloseFrame(r.upstreamConn, ws.StatusPolicyViolation, closeReason)
		return true
	case config.ActionWarn:
		r.recordSignal(session.SignalNearMiss, log)
		if len(result.DLPMatches) > 0 {
			log.LogWSScan(r.targetURL, audit.DirectionClientToServer, r.clientIP, r.requestID, "audit", len(result.DLPMatches), dlpMatchNames(result.DLPMatches), dlpBundleRules(result.DLPMatches))
		}
		if len(result.AddressFindings) > 0 {
			names := make([]string, len(result.AddressFindings))
			for i, f := range result.AddressFindings {
				names[i] = f.Explanation
			}
			log.LogWSScan(r.targetURL, audit.DirectionClientToServer, r.clientIP, r.requestID, scannerLabelAddressProtection, len(result.AddressFindings), names, nil)
		}
	}

	return false
}

// clientToUpstream reads frames from client, DLP-scans text, writes to upstream.
func (r *wsRelay) clientToUpstream(ctx context.Context, cancel context.CancelFunc, idleTimeout time.Duration) (bytesTransferred, textFrames, binaryFrames int64, blocked bool) {
	defer cancel()
	frag := &plwsutil.FragmentState{MaxBytes: r.maxMsg}
	var crossMsgTail []byte // rolling tail for cross-message DLP scanning
	log := r.proxy.logger.With("agent", r.agent)
	redactionEnabled := r.redaction != nil && r.redaction.required

	for {
		select {
		case <-ctx.Done():
			// ctx is canceled for two reasons: the max-connection deadline
			// expired (real timeout — block) or the sibling relay goroutine
			// returned and its defer cancel() fired (clean close — exit).
			// Only the first should mark blocked and write a close frame;
			// otherwise clean closes race into the blocked metric and turn
			// session_close receipts into bogus "block" verdicts.
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				plwsutil.WriteCloseFrame(r.clientConn, ws.StatusGoingAway, "connection timeout")
				blocked = true
			}
			return
		default:
		}

		// Kill switch: terminate WebSocket relay when activated mid-stream.
		if r.proxy.ks != nil && r.proxy.ks.IsActive() {
			r.terminalOnce.Do(func() {
				r.proxy.emitReceipt(receipt.EmitOpts{
					ActionID:  receipt.NewActionID(),
					Verdict:   config.ActionBlock,
					Layer:     "kill_switch",
					Pattern:   "kill switch active",
					Transport: "websocket",
					Method:    "WS",
					Target:    r.targetURL,
					RequestID: r.requestID,
					Agent:     r.agent,
				})
			})
			plwsutil.WriteCloseFrame(r.clientConn, ws.StatusPolicyViolation, "kill switch active")
			plwsutil.WriteClientCloseFrame(r.upstreamConn, ws.StatusPolicyViolation, "kill switch active")
			blocked = true
			return
		}

		// On-entry de-escalation for long-lived WebSocket connections.
		if changed, fromLabel, toLabel := trySessionRecovery(r.rec, &r.cfg.AdaptiveEnforcement, r.proxy.metrics); changed {
			sessionKey := r.clientIP
			if r.agent != "" && r.agent != agentAnonymous {
				sessionKey = r.agent + "|" + r.clientIP
			}
			log.LogAdaptiveEscalation(sessionKey, fromLabel, toLabel, r.clientIP, r.requestID, r.rec.ThreatScore())
		}

		// block_all check: if the session has escalated to a level with
		// block_all=true, close the WebSocket immediately. This prevents
		// clean frames from flowing after escalation during long-lived connections.
		if decide.UpgradeAction("", r.escalationLevel(), &r.cfg.AdaptiveEnforcement) == config.ActionBlock {
			sessionKey := r.clientIP
			if r.agent != "" && r.agent != agentAnonymous {
				sessionKey = r.agent + "|" + r.clientIP
			}
			log.LogAdaptiveUpgrade(sessionKey, session.EscalationLabel(r.escalationLevel()), "", config.ActionBlock, "session_deny", r.clientIP, r.requestID)
			r.proxy.metrics.RecordAdaptiveUpgrade("", config.ActionBlock, session.EscalationLabel(r.escalationLevel()))
			r.terminalOnce.Do(func() {
				r.proxy.emitReceipt(receipt.EmitOpts{
					ActionID:  receipt.NewActionID(),
					Verdict:   config.ActionBlock,
					Layer:     "session_deny",
					Pattern:   "session escalation",
					Transport: "websocket",
					Method:    "WS",
					Target:    r.targetURL,
					RequestID: r.requestID,
					Agent:     r.agent,
				})
			})
			plwsutil.WriteCloseFrame(r.clientConn, ws.StatusPolicyViolation, "session escalation")
			plwsutil.WriteClientCloseFrame(r.upstreamConn, ws.StatusPolicyViolation, "session escalation")
			blocked = true
			return
		}

		_ = r.clientConn.SetReadDeadline(time.Now().Add(idleTimeout))

		hdr, err := ws.ReadHeader(r.clientConn)
		if err != nil {
			if !plwsutil.IsExpectedCloseErr(err) {
				plwsutil.WriteClientCloseFrame(r.upstreamConn, ws.StatusGoingAway, "client disconnected")
			}
			return
		}

		// Guard against OOM: reject frames exceeding limits before allocating.
		if hdr.OpCode.IsControl() && hdr.Length > plwsutil.MaxControlPayload {
			plwsutil.WriteCloseFrame(r.clientConn, ws.StatusProtocolError, "control frame too large")
			blocked = true
			return
		}
		if !hdr.OpCode.IsControl() && hdr.Length > int64(r.maxMsg) {
			plwsutil.WriteCloseFrame(r.clientConn, ws.StatusMessageTooBig, plwsutil.ReasonMessageTooLarge)
			plwsutil.WriteClientCloseFrame(r.upstreamConn, ws.StatusMessageTooBig, plwsutil.ReasonMessageTooLarge)
			blocked = true
			return
		}

		// Reject compressed frames (RSV1 = permessage-deflate indicator).
		// Compressed bytes bypass DLP pattern matching entirely.
		if hdr.Rsv1() {
			plwsutil.WriteCloseFrame(r.clientConn, ws.StatusProtocolError, "compressed frames not supported")
			plwsutil.WriteClientCloseFrame(r.upstreamConn, ws.StatusProtocolError, "compressed frames not supported")
			blocked = true
			return
		}

		// Read payload. Hard guard mirrors the size checks above; if this fires
		// it means a code change broke the earlier validation.
		if hdr.Length < 0 || hdr.Length > int64(r.maxMsg) {
			return
		}
		payload := make([]byte, hdr.Length)
		if hdr.Length > 0 {
			if _, err := io.ReadFull(r.clientConn, payload); err != nil {
				return
			}
		}

		// Unmask client frames (clients must mask per RFC 6455).
		if hdr.Masked {
			ws.Cipher(payload, hdr.Mask, 0)
		}

		r.proxy.metrics.RecordWSFrame(opCodeLabel(hdr.OpCode))

		// Control frames: forward as-is.
		if hdr.OpCode.IsControl() {
			if hdr.OpCode == ws.OpClose {
				// Forward close frame to upstream, then exit.
				plwsutil.WriteClientCloseFrame(r.upstreamConn, ws.StatusNormalClosure, "client closed")
				return
			}
			// Ping/Pong: forward to upstream (proxy is CLIENT to upstream).
			err = wsutil.WriteClientMessage(r.upstreamConn, hdr.OpCode, payload)
			if err != nil {
				return
			}
			continue
		}

		// Binary frames.
		if hdr.OpCode == ws.OpBinary || (hdr.OpCode == ws.OpContinuation && frag.Active && frag.Opcode == ws.OpBinary) {
			binaryFrames++
			if !r.allowBinary {
				log.LogWSBlocked(r.targetURL, audit.DirectionClientToServer, "ws_protocol", "binary frames not allowed", r.clientIP, r.requestID)
				r.proxy.metrics.RecordWSScanHit("ws_protocol")
				r.proxy.emitReceipt(receipt.EmitOpts{
					ActionID:  receipt.NewActionID(),
					Verdict:   config.ActionBlock,
					Layer:     "ws_protocol",
					Pattern:   "binary frames not allowed",
					Transport: "websocket",
					Method:    "WS",
					Target:    r.targetURL,
					RequestID: r.requestID,
					Agent:     r.agent,
				})
				plwsutil.WriteCloseFrame(r.clientConn, ws.StatusPolicyViolation, "binary frames not allowed")
				plwsutil.WriteClientCloseFrame(r.upstreamConn, ws.StatusPolicyViolation, "binary frames not allowed")
				blocked = true
				return
			}
		}

		if redactionEnabled && !hdr.OpCode.IsControl() && (!hdr.Fin || hdr.OpCode == ws.OpContinuation) {
			reason := string(redact.ReasonWebSocketFragmented)
			log.LogWSBlocked(r.targetURL, audit.DirectionClientToServer, scannerLabelRedaction, reason, r.clientIP, r.requestID)
			r.proxy.metrics.RecordWSScanHit(scannerLabelRedaction)
			r.proxy.emitReceipt(receipt.EmitOpts{
				ActionID:  receipt.NewActionID(),
				Verdict:   config.ActionBlock,
				Layer:     scannerLabelRedaction,
				Pattern:   reason,
				Transport: "websocket",
				Method:    "WS",
				Target:    r.targetURL,
				RequestID: r.requestID,
				Agent:     r.agent,
			})
			plwsutil.WriteCloseFrame(r.clientConn, ws.StatusPolicyViolation, reason)
			plwsutil.WriteClientCloseFrame(r.upstreamConn, ws.StatusPolicyViolation, reason)
			blocked = true
			return
		}

		// Fragment reassembly for text frames.
		complete, msg, closeCode, closeReason := frag.Process(hdr, payload)
		if closeCode != 0 {
			log.LogWSBlocked(r.targetURL, audit.DirectionClientToServer, "ws_protocol", closeReason, r.clientIP, r.requestID)
			r.proxy.emitReceipt(receipt.EmitOpts{
				ActionID:  receipt.NewActionID(),
				Verdict:   config.ActionBlock,
				Layer:     "ws_protocol",
				Pattern:   closeReason,
				Transport: "websocket",
				Method:    "WS",
				Target:    r.targetURL,
				RequestID: r.requestID,
				Agent:     r.agent,
			})
			plwsutil.WriteCloseFrame(r.clientConn, closeCode, closeReason)
			plwsutil.WriteClientCloseFrame(r.upstreamConn, closeCode, closeReason)
			blocked = true
			return
		}

		if !complete {
			// Fragment accumulated, not yet complete. Buffer until the full
			// message is available for scanning before forwarding.
			continue
		}

		// Complete message available. Count and scan.
		isTextMessage := frag.Opcode == ws.OpText || hdr.OpCode == ws.OpText
		if isTextMessage {
			textFrames++

			// UTF-8 validation per RFC 6455.
			if !utf8.Valid(msg) {
				plwsutil.WriteCloseFrame(r.clientConn, ws.StatusInvalidFramePayloadData, "invalid UTF-8")
				plwsutil.WriteClientCloseFrame(r.upstreamConn, ws.StatusInvalidFramePayloadData, "invalid UTF-8")
				blocked = true
				return
			}
		}

		if redactionEnabled {
			buf, bodyResult := r.scanClientMessageBody(ctx, msg)
			wsMergeRedactionReport(&r.redactionLog, bodyResult.RedactionReport)
			if r.handleClientMessageBodyResult(log, buf, bodyResult) {
				blocked = true
				return
			}
			msg = buf
		}

		if isTextMessage && r.scanText {
			prevTail := crossMsgTail
			var scanInput []byte
			if !redactionEnabled {
				if len(prevTail) > 0 {
					scanInput = append(prevTail, msg...)
				} else {
					scanInput = msg
				}
			}
			crossMsgTail = updateWSCrossMessageTail(prevTail, msg)
			if !redactionEnabled {
				if len(scanInput) > 0 && r.scanClientText(ctx, log, scanInput) {
					blocked = true
					return
				}
			} else if len(prevTail) > 0 && r.scanClientCrossMessageText(ctx, log, prevTail, msg) {
				blocked = true
				return
			}
		}

		// CEE: record outbound frame for cross-request exfiltration detection.
		// Entropy tracking applies to all frame types (text + binary) since
		// binary frames can carry high-entropy exfiltrated data. Fragment
		// buffering only applies to text frames (DLP patterns match text).
		if ceeCfg := ceeEffectiveConfig(r.cfg.CrossRequestDetection, r.cfg.EnforceEnabled()); ceeCfg.Enabled {
			isText := frag.Opcode == ws.OpText || hdr.OpCode == ws.OpText
			sessionKey := CeeSessionKey(r.agent, r.clientIP)

			// Pass fragment buffer only for text frames; binary content
			// doesn't match DLP text patterns.
			var fb *scanner.FragmentBuffer
			if isText {
				fb = r.proxy.fragmentBufferPtr.Load()
			}

			ceeRes := ceeAdmit(ctx, sessionKey, msg, nil, r.targetURL, r.agent, r.clientIP, r.requestID,
				ceeCfg, r.proxy.entropyTrackerPtr.Load(), fb, r.scanner, r.proxy.logger, r.proxy.metrics)

			if sm := r.proxy.sessionMgrPtr.Load(); sm != nil && r.cfg.AdaptiveEnforcement.Enabled {
				ceeRecordSignals(ceeRes, sm, sessionKey, r.cfg.AdaptiveEnforcement.EscalationThreshold, r.proxy.logger, r.proxy.metrics, r.clientIP, r.requestID)
			}

			if ceeRes.Blocked {
				log.LogWSBlocked(r.targetURL, audit.DirectionClientToServer, "cross_request", ceeRes.Reason, r.clientIP, r.requestID)
				r.proxy.metrics.RecordWSScanHit("cross_request")
				r.proxy.emitReceipt(receipt.EmitOpts{
					ActionID:  receipt.NewActionID(),
					Verdict:   config.ActionBlock,
					Layer:     "cross_request",
					Pattern:   ceeRes.Reason,
					Transport: "websocket",
					Method:    "WS",
					Target:    r.targetURL,
					RequestID: r.requestID,
					Agent:     r.agent,
				})
				plwsutil.WriteCloseFrame(r.clientConn, ws.StatusPolicyViolation, "cross-request exfiltration detected")
				plwsutil.WriteClientCloseFrame(r.upstreamConn, ws.StatusPolicyViolation, "cross-request exfiltration detected")
				blocked = true
				return
			}
		}

		// Forward complete message to upstream (proxy is CLIENT, so masked).
		opCode := hdr.OpCode
		if frag.Opcode != 0 {
			opCode = frag.Opcode
		}
		err = wsutil.WriteClientMessage(r.upstreamConn, opCode, msg)
		if err != nil {
			return
		}
		bytesTransferred += int64(len(msg))
		frag.Reset()
	}
}

// upstreamToClient reads frames from upstream, injection-scans text, writes to client.
func (r *wsRelay) upstreamToClient(ctx context.Context, cancel context.CancelFunc, idleTimeout time.Duration) (bytesTransferred, textFrames, binaryFrames int64, blocked bool) {
	defer cancel()
	frag := &plwsutil.FragmentState{MaxBytes: r.maxMsg}
	log := r.proxy.logger.With("agent", r.agent)

	for {
		select {
		case <-ctx.Done():
			// See clientToUpstream: distinguish real deadline expiry from
			// sibling-triggered cancel so clean closes do not inflate the
			// blocked metric.
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				plwsutil.WriteClientCloseFrame(r.upstreamConn, ws.StatusGoingAway, "connection timeout")
				blocked = true
			}
			return
		default:
		}

		// Kill switch: terminate WebSocket relay when activated mid-stream.
		if r.proxy.ks != nil && r.proxy.ks.IsActive() {
			r.terminalOnce.Do(func() {
				r.proxy.emitReceipt(receipt.EmitOpts{
					ActionID:  receipt.NewActionID(),
					Verdict:   config.ActionBlock,
					Layer:     "kill_switch",
					Pattern:   "kill switch active",
					Transport: "websocket",
					Method:    "WS",
					Target:    r.targetURL,
					RequestID: r.requestID,
					Agent:     r.agent,
				})
			})
			plwsutil.WriteCloseFrame(r.clientConn, ws.StatusPolicyViolation, "kill switch active")
			plwsutil.WriteClientCloseFrame(r.upstreamConn, ws.StatusPolicyViolation, "kill switch active")
			blocked = true
			return
		}

		// On-entry de-escalation for long-lived WebSocket connections.
		if changed, fromLabel, toLabel := trySessionRecovery(r.rec, &r.cfg.AdaptiveEnforcement, r.proxy.metrics); changed {
			sessionKey := r.clientIP
			if r.agent != "" && r.agent != agentAnonymous {
				sessionKey = r.agent + "|" + r.clientIP
			}
			log.LogAdaptiveEscalation(sessionKey, fromLabel, toLabel, r.clientIP, r.requestID, r.rec.ThreatScore())
		}

		// block_all check: if the session has escalated to a level with
		// block_all=true, close the WebSocket immediately.
		if decide.UpgradeAction("", r.escalationLevel(), &r.cfg.AdaptiveEnforcement) == config.ActionBlock {
			sessionKey := r.clientIP
			if r.agent != "" && r.agent != agentAnonymous {
				sessionKey = r.agent + "|" + r.clientIP
			}
			log.LogAdaptiveUpgrade(sessionKey, session.EscalationLabel(r.escalationLevel()), "", config.ActionBlock, "session_deny", r.clientIP, r.requestID)
			r.proxy.metrics.RecordAdaptiveUpgrade("", config.ActionBlock, session.EscalationLabel(r.escalationLevel()))
			r.terminalOnce.Do(func() {
				r.proxy.emitReceipt(receipt.EmitOpts{
					ActionID:  receipt.NewActionID(),
					Verdict:   config.ActionBlock,
					Layer:     "session_deny",
					Pattern:   "session escalation",
					Transport: "websocket",
					Method:    "WS",
					Target:    r.targetURL,
					RequestID: r.requestID,
					Agent:     r.agent,
				})
			})
			plwsutil.WriteCloseFrame(r.clientConn, ws.StatusPolicyViolation, "session escalation")
			plwsutil.WriteClientCloseFrame(r.upstreamConn, ws.StatusPolicyViolation, "session escalation")
			blocked = true
			return
		}

		_ = r.upstreamConn.SetReadDeadline(time.Now().Add(idleTimeout))

		hdr, err := ws.ReadHeader(r.upstreamConn)
		if err != nil {
			if !plwsutil.IsExpectedCloseErr(err) {
				plwsutil.WriteCloseFrame(r.clientConn, ws.StatusGoingAway, "upstream disconnected")
			}
			return
		}

		// Guard against OOM: reject frames exceeding limits before allocating.
		if hdr.OpCode.IsControl() && hdr.Length > plwsutil.MaxControlPayload {
			plwsutil.WriteClientCloseFrame(r.upstreamConn, ws.StatusProtocolError, "control frame too large")
			blocked = true
			return
		}
		if !hdr.OpCode.IsControl() && hdr.Length > int64(r.maxMsg) {
			plwsutil.WriteCloseFrame(r.clientConn, ws.StatusMessageTooBig, plwsutil.ReasonMessageTooLarge)
			plwsutil.WriteClientCloseFrame(r.upstreamConn, ws.StatusMessageTooBig, plwsutil.ReasonMessageTooLarge)
			blocked = true
			return
		}

		// Reject compressed frames (RSV1 = permessage-deflate indicator).
		// Compressed bytes bypass DLP pattern matching entirely.
		if hdr.Rsv1() {
			plwsutil.WriteCloseFrame(r.clientConn, ws.StatusProtocolError, "compressed frames not supported")
			plwsutil.WriteClientCloseFrame(r.upstreamConn, ws.StatusProtocolError, "compressed frames not supported")
			blocked = true
			return
		}

		// Read payload. Hard guard mirrors the size checks above; if this fires
		// it means a code change broke the earlier validation.
		if hdr.Length < 0 || hdr.Length > int64(r.maxMsg) {
			return
		}
		payload := make([]byte, hdr.Length)
		if hdr.Length > 0 {
			if _, err := io.ReadFull(r.upstreamConn, payload); err != nil {
				return
			}
		}

		// Server frames should not be masked, but unmask if they are.
		if hdr.Masked {
			ws.Cipher(payload, hdr.Mask, 0)
		}

		r.proxy.metrics.RecordWSFrame(opCodeLabel(hdr.OpCode))

		// Control frames.
		if hdr.OpCode.IsControl() {
			if hdr.OpCode == ws.OpClose {
				plwsutil.WriteCloseFrame(r.clientConn, ws.StatusNormalClosure, "upstream closed")
				return
			}
			// Forward Ping/Pong to client (proxy is SERVER to client, no masking).
			err = wsutil.WriteServerMessage(r.clientConn, hdr.OpCode, payload)
			if err != nil {
				return
			}
			continue
		}

		// Binary frames.
		if hdr.OpCode == ws.OpBinary || (hdr.OpCode == ws.OpContinuation && frag.Active && frag.Opcode == ws.OpBinary) {
			binaryFrames++
			if !r.allowBinary {
				log.LogWSBlocked(r.targetURL, audit.DirectionServerToClient, "ws_protocol", "binary frames not allowed", r.clientIP, r.requestID)
				r.proxy.metrics.RecordWSScanHit("ws_protocol")
				r.proxy.emitReceipt(receipt.EmitOpts{
					ActionID:  receipt.NewActionID(),
					Verdict:   config.ActionBlock,
					Layer:     "ws_protocol",
					Pattern:   "binary frames not allowed",
					Transport: "websocket",
					Method:    "WS",
					Target:    r.targetURL,
					RequestID: r.requestID,
					Agent:     r.agent,
				})
				plwsutil.WriteCloseFrame(r.clientConn, ws.StatusPolicyViolation, "binary frames not allowed")
				plwsutil.WriteClientCloseFrame(r.upstreamConn, ws.StatusPolicyViolation, "binary frames not allowed")
				blocked = true
				return
			}
		}

		// Fragment reassembly.
		complete, msg, closeCode, closeReason := frag.Process(hdr, payload)
		if closeCode != 0 {
			log.LogWSBlocked(r.targetURL, audit.DirectionServerToClient, "ws_protocol", closeReason, r.clientIP, r.requestID)
			r.proxy.emitReceipt(receipt.EmitOpts{
				ActionID:  receipt.NewActionID(),
				Verdict:   config.ActionBlock,
				Layer:     "ws_protocol",
				Pattern:   closeReason,
				Transport: "websocket",
				Method:    "WS",
				Target:    r.targetURL,
				RequestID: r.requestID,
				Agent:     r.agent,
			})
			plwsutil.WriteCloseFrame(r.clientConn, closeCode, closeReason)
			plwsutil.WriteClientCloseFrame(r.upstreamConn, closeCode, closeReason)
			blocked = true
			return
		}

		if !complete {
			// Fragment accumulated, not yet complete. Buffer until the full
			// message is available for scanning before forwarding.
			continue
		}

		opCode := hdr.OpCode
		if frag.Opcode != 0 {
			opCode = frag.Opcode
		}

		// Complete message. Count and scan.
		if opCode == ws.OpBinary {
			actx := newHTTPAuditContext(log, "WS", r.targetURL, r.clientIP, r.requestID, r.agent)
			mediaVerdict := applyMediaPolicy(r.cfg, "", msg)
			logMediaExposureIfPresent(log, actx, mediaVerdict, "websocket")
			if mediaVerdict.Blocked {
				log.LogWSBlocked(r.targetURL, audit.DirectionServerToClient, "media_policy", mediaVerdict.BlockReason, r.clientIP, r.requestID)
				r.proxy.metrics.RecordWSScanHit("media_policy")
				r.proxy.emitReceipt(receipt.EmitOpts{
					ActionID:  receipt.NewActionID(),
					Verdict:   config.ActionBlock,
					Layer:     "media_policy",
					Pattern:   mediaVerdict.BlockReason,
					Transport: "websocket",
					Method:    "WS",
					Target:    r.targetURL,
					RequestID: r.requestID,
					Agent:     r.agent,
				})
				plwsutil.WriteCloseFrame(r.clientConn, ws.StatusPolicyViolation, "media blocked")
				plwsutil.WriteClientCloseFrame(r.upstreamConn, ws.StatusPolicyViolation, "media blocked")
				blocked = true
				return
			}
			if mediaVerdict.StripResult != nil && mediaVerdict.StripResult.Changed() {
				msg = mediaVerdict.Body
			}
		}

		if opCode == ws.OpText {
			textFrames++

			// UTF-8 validation.
			if !utf8.Valid(msg) {
				plwsutil.WriteCloseFrame(r.clientConn, ws.StatusInvalidFramePayloadData, "invalid UTF-8")
				plwsutil.WriteClientCloseFrame(r.upstreamConn, ws.StatusInvalidFramePayloadData, "invalid UTF-8")
				blocked = true
				return
			}

			// Response injection scanning.
			// Exempt domains are still scanned for visibility but findings are
			// pinned to warn with no adaptive scoring or action upgrade.
			wsRespExempt := isResponseScanExempt(r.hostname, r.cfg.ResponseScanning.ExemptDomains)
			if r.scanText && r.scanner.ResponseScanningEnabled() {
				scanResult := r.scanner.ScanResponse(ctx, string(msg))
				if !scanResult.Clean {
					if wsRespExempt {
						r.proxy.metrics.RecordResponseScanExempt(ExemptReasonDomain, TransportWS)
					}
					patternNames := make([]string, len(scanResult.Matches))
					for i, m := range scanResult.Matches {
						patternNames[i] = m.PatternName
					}
					respBundleRules := responseBundleRules(scanResult.Matches)
					r.proxy.metrics.RecordWSScanHit("injection")

					// Adaptive enforcement: upgrade the response action before the switch.
					// Exempt domains: pin to warn, skip upgrade.
					wsAction := r.scanner.ResponseAction()
					if wsRespExempt {
						wsAction = config.ActionWarn
					}
					originalWSAction := wsAction
					if !wsRespExempt {
						wsAction = decide.UpgradeAction(wsAction, r.escalationLevel(), &r.cfg.AdaptiveEnforcement)
					}
					if wsAction != originalWSAction {
						sessionKey := r.clientIP
						if r.agent != "" && r.agent != agentAnonymous {
							sessionKey = r.agent + "|" + r.clientIP
						}
						log.LogAdaptiveUpgrade(sessionKey, session.EscalationLabel(r.escalationLevel()), originalWSAction, wsAction, "response_scan", r.clientIP, r.requestID)
						r.proxy.metrics.RecordAdaptiveUpgrade(originalWSAction, wsAction, session.EscalationLabel(r.escalationLevel()))
					}

					switch wsAction {
					case config.ActionBlock:
						reason := fmt.Sprintf("injection detected: %s", strings.Join(patternNames, ", "))
						log.LogWSBlocked(r.targetURL, audit.DirectionServerToClient, "response_scan", reason, r.clientIP, r.requestID)
						r.proxy.emitReceipt(receipt.EmitOpts{
							ActionID:  receipt.NewActionID(),
							Verdict:   config.ActionBlock,
							Layer:     "response_scan",
							Pattern:   reason,
							Transport: "websocket",
							Method:    "WS",
							Target:    r.targetURL,
							RequestID: r.requestID,
							Agent:     r.agent,
						})
						plwsutil.WriteCloseFrame(r.clientConn, ws.StatusPolicyViolation, "injection detected")
						plwsutil.WriteClientCloseFrame(r.upstreamConn, ws.StatusPolicyViolation, "injection detected")
						blocked = true
						return
					case config.ActionStrip:
						// Record SignalStrip for adaptive enforcement scoring.
						// Exempt domains skip scoring — findings are logged but don't escalate.
						if !wsRespExempt {
							if sm := r.proxy.sessionMgrPtr.Load(); sm != nil && r.cfg.AdaptiveEnforcement.Enabled {
								sessionKey := r.clientIP
								if r.agent != "" && r.agent != agentAnonymous {
									sessionKey = r.agent + "|" + r.clientIP
								}
								sess := sm.GetOrCreate(sessionKey)
								decide.RecordSignal(sess, session.SignalStrip, decide.EscalationParams{
									Threshold: r.cfg.AdaptiveEnforcement.EscalationThreshold,
									Logger:    log,
									Metrics:   r.proxy.metrics,
									Session:   sessionKey,
									ClientIP:  r.clientIP,
									RequestID: r.requestID,
								})
							}
						}
						if scanResult.TransformedContent != "" {
							msg = []byte(scanResult.TransformedContent)
						} else {
							// Cannot strip, fall back to block.
							reason := fmt.Sprintf("injection detected (strip failed): %s", strings.Join(patternNames, ", "))
							log.LogWSBlocked(r.targetURL, audit.DirectionServerToClient, "response_scan", reason, r.clientIP, r.requestID)
							plwsutil.WriteCloseFrame(r.clientConn, ws.StatusPolicyViolation, "injection detected")
							plwsutil.WriteClientCloseFrame(r.upstreamConn, ws.StatusPolicyViolation, "injection detected")
							blocked = true
							return
						}
						log.LogWSScan(r.targetURL, audit.DirectionServerToClient, r.clientIP, r.requestID, config.ActionStrip, len(scanResult.Matches), patternNames, respBundleRules)
					case config.ActionWarn:
						log.LogWSScan(r.targetURL, audit.DirectionServerToClient, r.clientIP, r.requestID, config.ActionWarn, len(scanResult.Matches), patternNames, respBundleRules)
					case config.ActionAsk:
						// HITL not supported for WebSocket (no request/response cycle).
						// Fail closed: block.
						reason := fmt.Sprintf("injection detected (ask not supported for WS): %s", strings.Join(patternNames, ", "))
						log.LogWSBlocked(r.targetURL, audit.DirectionServerToClient, "response_scan", reason, r.clientIP, r.requestID)
						plwsutil.WriteCloseFrame(r.clientConn, ws.StatusPolicyViolation, "injection detected")
						plwsutil.WriteClientCloseFrame(r.upstreamConn, ws.StatusPolicyViolation, "injection detected")
						blocked = true
						return
					default:
						log.LogWSScan(r.targetURL, audit.DirectionServerToClient, r.clientIP, r.requestID, wsAction, len(scanResult.Matches), patternNames, respBundleRules)
					}
				}
			}
		}

		// Forward complete message to client (proxy is SERVER, no masking).
		err = wsutil.WriteServerMessage(r.clientConn, opCode, msg)
		if err != nil {
			return
		}
		bytesTransferred += int64(len(msg))
		frag.Reset()
	}
}

const (
	// crossMsgOverlap is how many bytes of the previous text message to retain
	// for cross-message DLP scanning. Secrets split across separate WebSocket
	// messages (each FIN=1) would evade per-message scanning without this overlap.
	// 4096 bytes prevents attackers from padding >512 bytes after the first half
	// of a secret to push it out of the overlap window.
	crossMsgOverlap = 4096
)

// opCodeLabel returns a human-readable label for metrics.
func opCodeLabel(op ws.OpCode) string {
	switch op {
	case ws.OpText:
		return "text"
	case ws.OpBinary:
		return "binary"
	default:
		return "control"
	}
}
