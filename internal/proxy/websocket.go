// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
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

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
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
	agent        string
	clientIP     string
	requestID    string
	targetURL    string
	hostname     string
	maxMsg       int
	scanText     bool
	allowBinary  bool
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

	// Run through all 9 scanner layers.
	result := sc.Scan(r.Context(), scanURL)

	// Session profiling: record BEFORE the enforce-mode early return so adaptive
	// signals (SignalBlock) fire even for blocked requests.
	sessionBlocked, sessionDetail := p.recordSessionActivity(clientIP, agent, parsed.Hostname(), requestID, result.Allowed, result.Score, cfg, log)

	if !result.Allowed {
		if cfg.EnforceEnabled() {
			log.LogBlocked("WS", targetURL, result.Scanner, result.Reason, clientIP, requestID, agent)
			p.metrics.RecordWSBlocked()
			if cfg.ExplainBlocksEnabled() && result.Hint != "" {
				w.Header().Set("X-Pipelock-Hint", result.Hint)
			}
			http.Error(w, "WebSocket blocked: "+result.Reason, http.StatusForbidden)
			return
		}
		log.LogAnomaly("WS", targetURL, result.Scanner,
			result.Reason, clientIP, requestID, agent, result.Score)
	}

	if sessionBlocked {
		http.Error(w, sessionDetail, http.StatusForbidden)
		return
	}

	// Budget admission check: enforce request count and domain limits.
	if err := resolved.Budget.CheckAdmission(strings.ToLower(parsed.Hostname())); err != nil {
		reason := err.Error()
		log.LogBlocked("WS", targetURL, "budget", reason, clientIP, requestID, agent)
		p.metrics.RecordWSBlocked()
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

	// DLP-scan forwarded auth header values regardless of destination.
	if cfg.EnforceEnabled() {
		if blocked, reason := p.dlpScanWSHeaders(r.Context(), fwdHeaders, sc); blocked {
			log.LogWSBlocked(targetURL, audit.DirectionClientToServer, audit.ScannerDLP, reason, clientIP, requestID)
			p.metrics.RecordWSBlocked()
			http.Error(w, "WebSocket blocked: "+reason, http.StatusForbidden)
			return
		}
	}

	// Upgrade the client connection.
	upgrader := ws.HTTPUpgrader{
		Timeout: 10 * time.Second,
	}
	clientConn, _, _, upgradeErr := upgrader.Upgrade(r, w)
	if upgradeErr != nil {
		log.LogError("WS", targetURL, clientIP, requestID, agent, fmt.Errorf("client upgrade: %w", upgradeErr))
		// If Upgrade fails, it already wrote the HTTP error response.
		return
	}
	defer clientConn.Close() //nolint:errcheck // best effort

	// Dial upstream via SSRF-safe dialer.
	upstreamConn, dialErr := p.wsDialUpstream(r.Context(), targetURL, fwdHeaders, cfg)
	if dialErr != nil {
		log.LogError("WS", targetURL, clientIP, requestID, agent, fmt.Errorf("upstream dial: %w", dialErr))
		plwsutil.WriteCloseFrame(clientConn, ws.StatusInternalServerError, "upstream dial failed")
		return
	}
	defer upstreamConn.Close() //nolint:errcheck // best effort

	p.metrics.IncrActiveWS()
	log.LogWSOpen(targetURL, clientIP, requestID, agent)

	scanTextFrames := cfg.WebSocketProxy.ScanTextFrames == nil || *cfg.WebSocketProxy.ScanTextFrames

	relay := &wsRelay{
		clientConn:   clientConn,
		upstreamConn: upstreamConn,
		scanner:      sc,
		proxy:        p,
		cfg:          cfg,
		agent:        agent,
		clientIP:     clientIP,
		requestID:    requestID,
		targetURL:    targetURL,
		hostname:     strings.ToLower(parsed.Hostname()),
		maxMsg:       cfg.WebSocketProxy.MaxMessageBytes,
		scanText:     scanTextFrames,
		allowBinary:  cfg.WebSocketProxy.AllowBinaryFrames,
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
	case "forward":
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

// dlpScanWSHeaders runs DLP scanning on auth header values before the upstream
// handshake. Headers are scanned regardless of destination (no allowlist skip)
// because agents can exfiltrate secrets in auth headers to any host.
func (p *Proxy) dlpScanWSHeaders(ctx context.Context, headers http.Header, sc *scanner.Scanner) (blocked bool, reason string) {
	// Scan auth-bearing header values. Cookie is included because
	// buildWSForwardHeaders copies it when ForwardCookies is enabled.
	for _, key := range []string{"Authorization", "X-Api-Key", "X-Goog-Api-Key", "Cookie"} {
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
		NetDial: p.ssrfSafeDialContext,
		Header:  ws.HandshakeHeaderHTTP(fwdHeaders),
		Timeout: 30 * time.Second,
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

// clientToUpstream reads frames from client, DLP-scans text, writes to upstream.
func (r *wsRelay) clientToUpstream(ctx context.Context, cancel context.CancelFunc, idleTimeout time.Duration) (bytesTransferred, textFrames, binaryFrames int64, blocked bool) {
	defer cancel()
	frag := &plwsutil.FragmentState{MaxBytes: r.maxMsg}
	var crossMsgTail []byte // rolling tail for cross-message DLP scanning
	log := r.proxy.logger.With("agent", r.agent)

	for {
		select {
		case <-ctx.Done():
			plwsutil.WriteCloseFrame(r.clientConn, ws.StatusGoingAway, "connection timeout")
			return
		default:
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
			return
		}
		if !hdr.OpCode.IsControl() && hdr.Length > int64(r.maxMsg) {
			plwsutil.WriteCloseFrame(r.clientConn, ws.StatusMessageTooBig, plwsutil.ReasonMessageTooLarge)
			plwsutil.WriteClientCloseFrame(r.upstreamConn, ws.StatusMessageTooBig, plwsutil.ReasonMessageTooLarge)
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
				plwsutil.WriteCloseFrame(r.clientConn, ws.StatusPolicyViolation, "binary frames not allowed")
				plwsutil.WriteClientCloseFrame(r.upstreamConn, ws.StatusPolicyViolation, "binary frames not allowed")
				blocked = true
				return
			}
		}

		// Fragment reassembly for text frames.
		complete, msg, closeCode, closeReason := frag.Process(hdr, payload)
		if closeCode != 0 {
			log.LogWSBlocked(r.targetURL, audit.DirectionClientToServer, "ws_protocol", closeReason, r.clientIP, r.requestID)
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
		if frag.Opcode == ws.OpText || hdr.OpCode == ws.OpText {
			textFrames++

			// UTF-8 validation per RFC 6455.
			if !utf8.Valid(msg) {
				plwsutil.WriteCloseFrame(r.clientConn, ws.StatusInvalidFramePayloadData, "invalid UTF-8")
				plwsutil.WriteClientCloseFrame(r.upstreamConn, ws.StatusInvalidFramePayloadData, "invalid UTF-8")
				return
			}

			// DLP scanning on reassembled text.
			// Cross-message DLP: prepend tail of previous message to catch
			// secrets split across separate WebSocket message boundaries.
			if r.scanText {
				var scanInput []byte
				if len(crossMsgTail) > 0 {
					scanInput = append(crossMsgTail, msg...)
				} else {
					scanInput = msg
				}
				dlpResult := r.scanner.ScanTextForDLP(context.Background(), string(scanInput))

				// Update rolling tail for next message (always, regardless of result).
				if len(msg) >= crossMsgOverlap {
					crossMsgTail = make([]byte, crossMsgOverlap)
					copy(crossMsgTail, msg[len(msg)-crossMsgOverlap:])
				} else {
					crossMsgTail = append(crossMsgTail, msg...)
					if len(crossMsgTail) > crossMsgOverlap {
						crossMsgTail = crossMsgTail[len(crossMsgTail)-crossMsgOverlap:]
					}
				}

				if !dlpResult.Clean {
					names := make([]string, len(dlpResult.Matches))
					for i, m := range dlpResult.Matches {
						names[i] = m.PatternName
					}
					if r.cfg.EnforceEnabled() {
						reason := fmt.Sprintf("DLP match: %s", strings.Join(names, ", "))
						log.LogWSBlocked(r.targetURL, audit.DirectionClientToServer, audit.ScannerDLP, reason, r.clientIP, r.requestID)
						r.proxy.metrics.RecordWSScanHit(audit.ScannerDLP)
						plwsutil.WriteCloseFrame(r.clientConn, ws.StatusPolicyViolation, "DLP violation")
						plwsutil.WriteClientCloseFrame(r.upstreamConn, ws.StatusPolicyViolation, "DLP violation")
						blocked = true
						return
					}
					log.LogWSScan(r.targetURL, audit.DirectionClientToServer, r.clientIP, r.requestID, "audit", len(dlpResult.Matches), names)
				}
			}
		}

		// CEE: record outbound frame for cross-request exfiltration detection.
		// Entropy tracking applies to all frame types (text + binary) since
		// binary frames can carry high-entropy exfiltrated data. Fragment
		// buffering only applies to text frames (DLP patterns match text).
		if ceeCfg := ceeEffectiveConfig(r.cfg.CrossRequestDetection, r.cfg.EnforceEnabled()); ceeCfg.Enabled {
			isText := frag.Opcode == ws.OpText || hdr.OpCode == ws.OpText
			sessionKey := ceeSessionKey(r.agent, r.clientIP)

			// Pass fragment buffer only for text frames; binary content
			// doesn't match DLP text patterns.
			var fb *scanner.FragmentBuffer
			if isText {
				fb = r.proxy.fragmentBufferPtr.Load()
			}

			ceeRes := ceeAdmit(context.Background(), sessionKey, msg, nil, r.targetURL, r.agent, r.clientIP, r.requestID,
				ceeCfg, r.proxy.entropyTrackerPtr.Load(), fb, r.scanner, r.proxy.logger, r.proxy.metrics)

			if sm := r.proxy.sessionMgrPtr.Load(); sm != nil && r.cfg.AdaptiveEnforcement.Enabled {
				ceeRecordSignals(ceeRes, sm, sessionKey, r.cfg.AdaptiveEnforcement.EscalationThreshold, r.proxy.logger, r.proxy.metrics, r.clientIP, r.requestID)
			}

			if ceeRes.Blocked {
				log.LogWSBlocked(r.targetURL, audit.DirectionClientToServer, "cross_request", ceeRes.Reason, r.clientIP, r.requestID)
				r.proxy.metrics.RecordWSScanHit("cross_request")
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
			plwsutil.WriteClientCloseFrame(r.upstreamConn, ws.StatusGoingAway, "connection timeout")
			return
		default:
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
			return
		}
		if !hdr.OpCode.IsControl() && hdr.Length > int64(r.maxMsg) {
			plwsutil.WriteCloseFrame(r.clientConn, ws.StatusMessageTooBig, plwsutil.ReasonMessageTooLarge)
			plwsutil.WriteClientCloseFrame(r.upstreamConn, ws.StatusMessageTooBig, plwsutil.ReasonMessageTooLarge)
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

		// Complete message. Count and scan.
		if frag.Opcode == ws.OpText || hdr.OpCode == ws.OpText {
			textFrames++

			// UTF-8 validation.
			if !utf8.Valid(msg) {
				plwsutil.WriteCloseFrame(r.clientConn, ws.StatusInvalidFramePayloadData, "invalid UTF-8")
				plwsutil.WriteClientCloseFrame(r.upstreamConn, ws.StatusInvalidFramePayloadData, "invalid UTF-8")
				return
			}

			// Response injection scanning.
			if r.scanText && r.scanner.ResponseScanningEnabled() {
				scanResult := r.scanner.ScanResponse(context.Background(), string(msg))
				if !scanResult.Clean {
					patternNames := make([]string, len(scanResult.Matches))
					for i, m := range scanResult.Matches {
						patternNames[i] = m.PatternName
					}
					r.proxy.metrics.RecordWSScanHit("injection")

					switch r.scanner.ResponseAction() {
					case config.ActionBlock:
						reason := fmt.Sprintf("injection detected: %s", strings.Join(patternNames, ", "))
						log.LogWSBlocked(r.targetURL, audit.DirectionServerToClient, "response_scan", reason, r.clientIP, r.requestID)
						plwsutil.WriteCloseFrame(r.clientConn, ws.StatusPolicyViolation, "injection detected")
						plwsutil.WriteClientCloseFrame(r.upstreamConn, ws.StatusPolicyViolation, "injection detected")
						blocked = true
						return
					case config.ActionStrip:
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
						log.LogWSScan(r.targetURL, audit.DirectionServerToClient, r.clientIP, r.requestID, config.ActionStrip, len(scanResult.Matches), patternNames)
					case config.ActionWarn:
						log.LogWSScan(r.targetURL, audit.DirectionServerToClient, r.clientIP, r.requestID, config.ActionWarn, len(scanResult.Matches), patternNames)
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
						log.LogWSScan(r.targetURL, audit.DirectionServerToClient, r.clientIP, r.requestID, r.scanner.ResponseAction(), len(scanResult.Matches), patternNames)
					}
				}
			}
		}

		// Forward complete message to client (proxy is SERVER, no masking).
		opCode := hdr.OpCode
		if frag.Opcode != 0 {
			opCode = frag.Opcode
		}
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
	// 512 bytes covers any single-line DLP pattern with headroom.
	crossMsgOverlap = 512
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
