// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package livechat

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/playground"
)

// Route paths for the live-chat API.
const (
	// RouteAPIPrefix is the common prefix for every live-chat API route. It is
	// the mount point used when serving a static UI at / on the same origin, so
	// the API and the UI share one host (and one CF Access gate).
	RouteAPIPrefix = "/api/live/"

	RouteSession = "/api/live/session"
	RouteStream  = "/api/live/stream"
	RouteMessage = "/api/live/message"
	RouteBundle  = "/api/live/bundle"
	RouteHealth  = "/api/live/health"
)

// maxRequestBody bounds request bodies on the JSON endpoints so a client cannot
// stream an unbounded body. The message size cap (Limits.MaxInputBytes) is
// enforced separately on the decoded field.
const maxRequestBody = 64 * 1024

// ServerConfig configures the live-chat HTTP server.
type ServerConfig struct {
	// Gate validates invite codes and session tokens. Required.
	Gate *Gate
	// Limits caps message size and session wall-clock. Clamped on construction.
	Limits Limits
	// IPRate / CodeRate configure the per-IP and per-code rate limiters.
	IPRate   RateConfig
	CodeRate RateConfig
	// MaxConcurrent caps simultaneous live sessions (global). Never unlimited.
	MaxConcurrent int
	// DailyTurnBudget is the hard global ceiling on total model ROUND TRIPS per
	// UTC day -- the spend kill switch. Each visitor message reserves its
	// worst-case round trips (the model loop's max steps) up front, so the cap
	// bounds real model spend, not visitor-message count. 0 = unlimited (dev/local
	// only; public exposure MUST set a positive value). When the day's budget is
	// spent, further messages are refused until the next UTC day.
	DailyTurnBudget int
	// PerIPDailyBudget and PerCodeDailyBudget cap model round trips per client IP
	// and per invite code per UTC day, so one identity cannot drain the global
	// DailyTurnBudget alone (the global cap and the per-key rate limiters do not
	// stop a single identity spending the whole day's budget below the rate). 0 =
	// no per-identity cap. Like the global budget they are denominated in model
	// round trips and reserve each message's worst case.
	PerIPDailyBudget   int
	PerCodeDailyBudget int
	// MaxMessagesPerSession caps how many messages one session may send (each is a
	// real model call). 0 = the conservative default applied in NewServer.
	MaxMessagesPerSession int
	// RequireContainment is passed to each session. Public exposure MUST be true.
	RequireContainment bool
	// Containment proves kernel containment per session. Required (non-nil) when
	// RequireContainment is true.
	Containment playground.ContainmentVerifier
	// OrchestratorKeyPath / ToyAgentBin / WebToolBin are forwarded to sessions.
	OrchestratorKeyPath string
	ToyAgentBin         string
	WebToolBin          string
	// ProxyPort is the fixed loopback port each session's in-process proxy binds.
	// It must match the single port the kernel owner-match rule allows the
	// contained agent uid to reach (`pipelock contain install --proxy-port`). 0 =
	// ephemeral (dev/test); the command layer defaults contained serves to the
	// stock port before constructing ServerConfig.
	// With MaxConcurrent > 1 a single fixed port collides, so public contained
	// exposure pins MaxConcurrent: 1 (or a future reserved port range).
	ProxyPort int
	// LLMAgent, when non-nil, drives every session with the model-backed agent
	// subprocess instead of the deterministic IntentAgent. The same config is
	// reused for each session (static model/binary/secret settings).
	LLMAgent *playground.LLMAgentConfig
	// TrustForwardedFor reads the client IP from X-Forwarded-For (set true only
	// behind a trusted reverse proxy / CDN).
	TrustForwardedFor bool
	// AllowOrigin sets Access-Control-Allow-Origin for the browser. Empty = none.
	AllowOrigin string
	// VerifierBinaries supplies the real shipped pipelock-verifier binaries used
	// to build per-session OS-specific live verification kits.
	VerifierBinaries playground.VerifyKitBinaries
}

type liveEntry struct {
	sess    *playground.LiveSession
	release func()
	cancel  context.CancelFunc
	codeID  string
	runDir  string
	expires time.Time
	timer   *time.Timer

	// seal (assemble + offline-verify + build the downloadable archive) runs at
	// most once, whether triggered by a bundle download or by teardown. bundle
	// holds the assembled .tar.gz bytes in memory so serving never races
	// teardown's run-dir removal. teardown (close + delete) is separately once-d.
	sealOnce     sync.Once
	sealErr      error
	bundle       []byte
	teardownOnce sync.Once

	streamMu sync.Mutex
	streamOn bool

	msgMu    sync.Mutex
	msgCount int
}

// tryMessage atomically admits one message against the per-session cap. cap <= 0
// means unlimited. It returns false (without counting) once the session has used
// its budget, so the check has no TOCTOU under concurrent messages.
func (e *liveEntry) tryMessage(limit int) bool {
	if limit <= 0 {
		return true
	}
	e.msgMu.Lock()
	defer e.msgMu.Unlock()
	if e.msgCount >= limit {
		return false
	}
	e.msgCount++
	return true
}

// refundMessage returns one reserved message slot. It is intentionally narrow:
// only call it when no turn could have started.
func (e *liveEntry) refundMessage(limit int) {
	if limit <= 0 {
		return
	}
	e.msgMu.Lock()
	defer e.msgMu.Unlock()
	if e.msgCount > 0 {
		e.msgCount--
	}
}

// Server is the live-chat HTTP/SSE front door.
type Server struct {
	cfg              ServerConfig
	limits           Limits
	ipRate           *RateLimiter
	codeRate         *RateLimiter
	conc             *ConcurrencyLimiter
	budget           *DailyBudget
	perIP            *KeyedDailyBudget
	perCode          *KeyedDailyBudget
	maxMsgPerSession int
	// roundTripsPerMsg is the worst-case model round trips one visitor message can
	// drive (the model loop's max steps). The daily budget is denominated in model
	// round trips, so each message reserves this many units up front -- the safe
	// over-count for a spend kill switch. 1 for the deterministic agent.
	roundTripsPerMsg int

	// killed is the operator emergency stop. Unlike the daily budget (which caps
	// spend by refusing new charges), tripping this terminates every ACTIVE
	// session immediately and refuses all new sessions and messages until Resume.
	killed atomic.Bool

	mu       sync.Mutex
	sessions map[string]*liveEntry
}

// defaultMaxMessagesPerSession bounds one session's model calls when the operator
// does not set MaxMessagesPerSession. Matches the playground cost plan's 40-message
// session cap.
const defaultMaxMessagesPerSession = 40

// NewServer builds the server. It returns an error (fail-closed at startup) when
// the gate is missing, or containment is required but no verifier is supplied.
func NewServer(cfg ServerConfig) (*Server, error) {
	if cfg.Gate == nil {
		return nil, errors.New("livechat: server requires a gate")
	}
	if cfg.RequireContainment && cfg.Containment == nil {
		return nil, errors.New("livechat: RequireContainment set but no ContainmentVerifier supplied")
	}
	if cfg.MaxMessagesPerSession < 0 {
		return nil, errors.New("livechat: MaxMessagesPerSession must be >= 0")
	}
	maxMsg := cfg.MaxMessagesPerSession
	if maxMsg == 0 {
		maxMsg = defaultMaxMessagesPerSession
	}
	// The daily budget counts model ROUND TRIPS, not visitor messages: a
	// model-backed message can drive up to MaxSteps model calls, so reserve that
	// many per message. The deterministic agent makes no model calls; charge 1.
	roundTripsPerMsg := 1
	if cfg.LLMAgent != nil {
		roundTripsPerMsg = cfg.LLMAgent.EffectiveMaxSteps()
	}
	for _, c := range []struct {
		name string
		v    int
	}{
		{"DailyTurnBudget", cfg.DailyTurnBudget},
		{"PerIPDailyBudget", cfg.PerIPDailyBudget},
		{"PerCodeDailyBudget", cfg.PerCodeDailyBudget},
	} {
		if c.v < 0 {
			return nil, fmt.Errorf("livechat: %s must be >= 0", c.name)
		}
		if c.v > 0 && c.v < roundTripsPerMsg {
			return nil, fmt.Errorf("livechat: %s (%d) is below one message's worst-case model round trips (%d); raise the budget or lower --model-max-steps", c.name, c.v, roundTripsPerMsg)
		}
	}
	return &Server{
		cfg:              cfg,
		limits:           cfg.Limits.Clamp(),
		ipRate:           NewRateLimiter(cfg.IPRate),
		codeRate:         NewRateLimiter(cfg.CodeRate),
		conc:             NewConcurrencyLimiter(cfg.MaxConcurrent),
		budget:           NewDailyBudget(cfg.DailyTurnBudget),
		perIP:            NewKeyedDailyBudget(cfg.PerIPDailyBudget, 0),
		perCode:          NewKeyedDailyBudget(cfg.PerCodeDailyBudget, 0),
		maxMsgPerSession: maxMsg,
		roundTripsPerMsg: roundTripsPerMsg,
		sessions:         make(map[string]*liveEntry),
	}, nil
}

// Handler returns the HTTP routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(RouteSession, s.handleSession)
	mux.HandleFunc(RouteStream, s.handleStream)
	mux.HandleFunc(RouteMessage, s.handleMessage)
	mux.HandleFunc(RouteBundle, s.handleBundle)
	mux.HandleFunc(RouteHealth, s.handleHealth)
	return mux
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	s.setCORS(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":               s.cfg.Gate.Open() && s.budget.Open() && !s.killed.Load(),
		"in_use":           s.conc.InUse(),
		"capacity":         s.conc.Cap(),
		"contained":        s.cfg.RequireContainment,
		"budget_remaining": s.budget.Remaining(),
		"killed":           s.killed.Load(),
	})
}

type createReq struct {
	Code string `json:"code"`
}

type createResp struct {
	Token     string `json:"token"`
	SessionID string `json:"session_id"`
	ExpiresAt string `json:"expires_at"`
	State     string `json:"state"`
}

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	s.setCORS(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	ip := s.clientIP(r)
	if !s.ipRate.Allow("ip:" + ip) {
		writeErr(w, http.StatusTooManyRequests, "rate limited")
		return
	}
	if s.killed.Load() {
		writeErr(w, http.StatusServiceUnavailable, "the demo is paused")
		return
	}

	var body createReq
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "bad request")
		return
	}
	if body.Code == "" {
		writeErr(w, http.StatusUnauthorized, "invite code required")
		return
	}
	if !s.budget.Open() {
		writeErr(w, http.StatusServiceUnavailable, "daily limit reached, the demo is paused until tomorrow")
		return
	}

	// Reserve a global slot BEFORE consuming the code budget, so a busy server
	// does not burn an attendee's invite.
	release, ok := s.conc.Acquire()
	if !ok {
		writeErr(w, http.StatusServiceUnavailable, "at capacity, try again shortly")
		return
	}

	sid, err := newSessionID()
	if err != nil {
		release()
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	token, claims, err := s.cfg.Gate.Redeem(body.Code, sid)
	if err != nil {
		release()
		writeErr(w, gateErrStatus(err), "invite code rejected")
		return
	}
	if !s.codeRate.Allow("code:" + claims.CodeID) {
		s.cfg.Gate.Refund(claims)
		release()
		writeErr(w, http.StatusTooManyRequests, "rate limited")
		return
	}

	// The session outlives the request, so give it its own context. Bound it by
	// the token's actual expiry (claims.ExpiresAt), the SAME instant used for the
	// response, the TTL timer below, and token validation — one effective expiry,
	// no drift between when the token dies and when the session is torn down.
	// Never r.Context(), which cancels when this handler returns.
	sessCtx, cancel := context.WithDeadline(context.Background(), claims.ExpiresAt)
	runDir, err := os.MkdirTemp("", "livechat-run-*")
	if err != nil {
		s.cfg.Gate.Refund(claims)
		cancel()
		release()
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}

	sess, err := playground.StartLiveSession(sessCtx, playground.LiveSessionConfig{
		RunNonce:            sid,
		RequireContainment:  s.cfg.RequireContainment,
		Containment:         s.cfg.Containment,
		OrchestratorKeyPath: s.cfg.OrchestratorKeyPath,
		ToyAgentBin:         s.cfg.ToyAgentBin,
		WebToolBin:          s.cfg.WebToolBin,
		ProxyPort:           s.cfg.ProxyPort,
		LLMAgent:            s.cfg.LLMAgent,
	})
	if err != nil {
		_ = os.RemoveAll(runDir)
		s.cfg.Gate.Refund(claims)
		cancel()
		release()
		// Containment refusal is the most likely cause and is fail-closed.
		writeErr(w, http.StatusServiceUnavailable, "session could not be started")
		return
	}

	entry := &liveEntry{
		sess:    sess,
		release: release,
		cancel:  cancel,
		codeID:  claims.CodeID,
		runDir:  runDir,
		expires: claims.ExpiresAt,
	}
	cleanupStartedSession := func() {
		sess.Close()
		_ = os.RemoveAll(runDir)
		s.cfg.Gate.Refund(claims)
		cancel()
		release()
	}
	ttl := time.Until(claims.ExpiresAt)
	if ttl <= 0 {
		cleanupStartedSession()
		writeErr(w, http.StatusServiceUnavailable, "session expired before start")
		return
	}

	s.mu.Lock()
	if s.killed.Load() {
		s.mu.Unlock()
		cleanupStartedSession()
		writeErr(w, http.StatusServiceUnavailable, "the demo is paused")
		return
	}
	s.sessions[sid] = entry
	entry.timer = time.AfterFunc(ttl, func() { s.finalize(sid) })
	s.mu.Unlock()
	s.cfg.Gate.Commit(claims)

	state := playground.LiveStateDev
	if s.cfg.RequireContainment {
		state = playground.LiveStateContained
	}
	writeJSON(w, http.StatusOK, createResp{
		Token:     token,
		SessionID: sid,
		ExpiresAt: claims.ExpiresAt.UTC().Format(time.RFC3339),
		State:     state,
	})
}

func (s *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	s.setCORS(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	ip := s.clientIP(r)
	if !s.ipRate.Allow("ip:" + ip) {
		writeErr(w, http.StatusTooManyRequests, "rate limited")
		return
	}
	claims, err := s.cfg.Gate.Validate(r.URL.Query().Get("token"))
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "invalid or expired token")
		return
	}
	entry := s.lookup(claims.SessionID)
	if entry == nil {
		writeErr(w, http.StatusNotFound, "session not found")
		return
	}
	if !entry.acquireStream() {
		writeErr(w, http.StatusConflict, "stream already connected")
		return
	}
	defer entry.releaseStream()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	events := entry.sess.Events()
	for {
		select {
		case <-r.Context().Done():
			return
		case ev, open := <-events:
			if !open {
				_, _ = fmt.Fprint(w, "event: done\ndata: {}\n\n")
				flusher.Flush()
				return
			}
			b, mErr := json.Marshal(ev)
			if mErr != nil {
				continue
			}
			_, _ = fmt.Fprintf(w, "data: %s\n\n", b)
			flusher.Flush()
		}
	}
}

type messageReq struct {
	Token   string `json:"token"`
	Message string `json:"message"`
}

func (s *Server) handleMessage(w http.ResponseWriter, r *http.Request) {
	s.setCORS(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	ip := s.clientIP(r)
	if !s.ipRate.Allow("ip:" + ip) {
		writeErr(w, http.StatusTooManyRequests, "rate limited")
		return
	}
	if s.killed.Load() {
		writeErr(w, http.StatusServiceUnavailable, "the demo is paused")
		return
	}
	var body messageReq
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "bad request")
		return
	}
	claims, err := s.cfg.Gate.Validate(body.Token)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "invalid or expired token")
		return
	}
	if !s.codeRate.Allow("code:" + claims.CodeID) {
		writeErr(w, http.StatusTooManyRequests, "rate limited")
		return
	}
	if err := s.limits.CheckInput(body.Message); err != nil {
		if errors.Is(err, ErrInputTooLarge) {
			writeErr(w, http.StatusRequestEntityTooLarge, "message too large")
		} else {
			writeErr(w, http.StatusBadRequest, "empty message")
		}
		return
	}
	entry := s.lookup(claims.SessionID)
	if entry == nil {
		writeErr(w, http.StatusNotFound, "session not found")
		return
	}
	// Spend caps, charged in order through a rollback stack so any downstream
	// refusal returns every upstream reservation exactly once (no leak, no mint).
	// Each layer reserves this message's worst-case model round trips: per-session
	// (each message is a real model call), then per-IP and per-code daily caps so
	// one client or one invite code cannot drain the global budget alone, then the
	// global daily kill switch.
	units := s.roundTripsPerMsg
	var rollback []func()
	undo := func() {
		for i := len(rollback) - 1; i >= 0; i-- {
			rollback[i]()
		}
	}

	if !entry.tryMessage(s.maxMsgPerSession) {
		writeErr(w, http.StatusTooManyRequests, "session message limit reached")
		return
	}
	rollback = append(rollback, func() { entry.refundMessage(s.maxMsgPerSession) })

	if !s.perIP.Charge("ip:"+ip, units) {
		undo()
		writeErr(w, http.StatusTooManyRequests, "daily limit reached for your address")
		return
	}
	rollback = append(rollback, func() { s.perIP.Refund("ip:"+ip, units) })

	if !s.perCode.Charge("code:"+claims.CodeID, units) {
		undo()
		writeErr(w, http.StatusTooManyRequests, "daily limit reached for this code")
		return
	}
	rollback = append(rollback, func() { s.perCode.Refund("code:"+claims.CodeID, units) })

	if !s.budget.Charge(units) {
		undo()
		writeErr(w, http.StatusServiceUnavailable, "daily limit reached, the demo is paused until tomorrow")
		return
	}
	rollback = append(rollback, func() { s.budget.Refund(units) })

	if err := entry.sess.Send(r.Context(), body.Message); err != nil {
		undo()
		if errors.Is(err, playground.ErrSessionClosed) {
			writeErr(w, http.StatusConflict, "session is closed")
			return
		}
		if errors.Is(err, playground.ErrModelProviderPaused) {
			writeErr(w, http.StatusServiceUnavailable, playground.ModelProviderPausedMessage)
			return
		}
		writeErr(w, http.StatusInternalServerError, "send failed")
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "accepted"})
}

// handleBundle serves the downloadable, offline-verifiable session proof. It
// seals the run on demand (the visitor signalling "I'm done, prove it"). By
// default it preserves the raw .tar.gz bundle for manual/CLI fallback; with
// ?os=linux|macos|windows it returns a one-click zip kit containing that
// session's real audit packet plus the shipped verifier binary. Archives are
// served from in-memory bytes captured at seal time, so there is no
// path-traversal surface and no race with the run dir's eventual removal.
// Token-gated and rate-limited like every other route; an expired token (or a
// session already torn down) cannot download.
func (s *Server) handleBundle(w http.ResponseWriter, r *http.Request) {
	s.setCORS(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	ip := s.clientIP(r)
	if !s.ipRate.Allow("ip:" + ip) {
		writeErr(w, http.StatusTooManyRequests, "rate limited")
		return
	}
	claims, err := s.cfg.Gate.Validate(r.URL.Query().Get("token"))
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "invalid or expired token")
		return
	}
	entry := s.lookup(claims.SessionID)
	if entry == nil {
		writeErr(w, http.StatusNotFound, "session not found")
		return
	}
	rawOS := r.URL.Query().Get("os")
	var osName playground.VerifyKitOS
	if rawOS != "" {
		var pErr error
		osName, pErr = playground.ParseVerifyKitOS(rawOS)
		if pErr != nil {
			writeErr(w, http.StatusBadRequest, "unsupported verify kit")
			return
		}
	}
	// Seal on demand: assemble + offline-verify + build the archive. Sealing
	// marks the session terminal (no further messages), which is the intended
	// "finish and prove it" semantic. Fail closed if the run did not verify.
	if err := s.seal(entry); err != nil {
		s.releaseSessionResources(entry)
		writeErr(w, http.StatusServiceUnavailable, "session bundle is not available")
		return
	}
	s.releaseSessionResources(entry)
	if rawOS != "" {
		kit, filename, kErr := playground.BuildLiveVerifyKit(osName, s.cfg.VerifierBinaries.Path(osName), entry.bundle)
		if kErr != nil {
			_, _ = fmt.Fprintf(os.Stderr, "livechat: verify kit build failed: %v\n", kErr)
			writeErr(w, http.StatusServiceUnavailable, "verify kit is not available")
			return
		}
		w.Header().Set("Content-Type", "application/zip")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(kit)
		return
	}
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", "pipelock-session-"+claims.SessionID+".tar.gz"))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(entry.bundle)
}

// seal assembles, offline-verifies, and archives the run exactly once. It does
// NOT tear the session down: the entry stays in the live set and the archive
// bytes are retained so the visitor can download the verified bundle until the
// session expires. The verified event reaches any connected stream as a side
// effect of Finalize. Idempotent; the stored sealErr is returned on every call.
func (s *Server) seal(entry *liveEntry) error {
	entry.sealOnce.Do(func() {
		if _, err := entry.sess.Finalize(entry.runDir); err != nil {
			entry.sealErr = err
			// Server-side observability: a seal failure surfaces to the client only
			// as a generic 503, so log the real cause for the operator.
			_, _ = fmt.Fprintf(os.Stderr, "livechat: session seal failed at finalize: %v\n", err)
			return
		}
		arc, err := playground.ArchiveRunForDownload(entry.runDir, entry.sess.OrchestratorPubHex())
		if err != nil {
			entry.sealErr = fmt.Errorf("archive session bundle: %w", err)
			_, _ = fmt.Fprintf(os.Stderr, "livechat: session seal failed at archive: %v\n", err)
			return
		}
		entry.bundle = arc
	})
	return entry.sealErr
}

// releaseSessionResources closes the session, releases its concurrency slot,
// and deletes its run dir exactly once. It intentionally does not remove the
// entry from the live map: after a visitor downloads a sealed bundle, the slot
// should be freed immediately while the in-memory archive remains downloadable
// until the token/session TTL removes the map entry.
func (s *Server) releaseSessionResources(entry *liveEntry) {
	entry.teardownOnce.Do(func() {
		entry.sess.Close()
		entry.cancel()
		entry.release()
		_ = os.RemoveAll(entry.runDir)
	})
}

// teardown stops the timer, closes the session, releases the global slot, and
// deletes the run dir exactly once, removing the entry from the live set. The
// archive bytes captured by seal live on the entry, so a download already in
// flight is unaffected by run-dir removal.
func (s *Server) teardown(sid string) {
	entry := s.take(sid)
	if entry == nil {
		return
	}
	if entry.timer != nil {
		entry.timer.Stop()
	}
	s.releaseSessionResources(entry)
}

// finalize seals (best-effort) then tears a session down. Used by the TTL timer
// and server shutdown. seal runs while the entry is still in the live set so the
// archive bytes are captured before teardown removes the entry and run dir.
func (s *Server) finalize(sid string) {
	entry := s.lookup(sid)
	if entry == nil {
		return
	}
	_ = s.seal(entry)
	s.teardown(sid)
}

// finalizeAll seals and tears down every currently-active session. The snapshot
// of ids is taken under the lock; finalize re-checks membership, so a session
// that ends concurrently is simply skipped.
func (s *Server) finalizeAll() {
	s.mu.Lock()
	ids := make([]string, 0, len(s.sessions))
	for id := range s.sessions {
		ids = append(ids, id)
	}
	s.mu.Unlock()
	for _, id := range ids {
		s.finalize(id)
	}
}

// Close finalizes all live sessions. Call on server shutdown.
func (s *Server) Close() {
	s.finalizeAll()
}

// Kill trips the operator emergency stop: it refuses all new sessions and
// messages and immediately seals + terminates every active session. It is the
// runtime kill switch a demo operator reaches for to stop everything now --
// distinct from the daily budget, which only caps new spend and lets active
// sessions run to their TTL. Idempotent.
func (s *Server) Kill() {
	s.killed.Store(true)
	s.finalizeAll()
}

// Resume clears the kill switch so the server accepts new sessions again. Active
// sessions are not restored (they were terminated by Kill); this only reopens
// the door.
func (s *Server) Resume() {
	s.killed.Store(false)
}

// Killed reports whether the emergency stop is currently engaged.
func (s *Server) Killed() bool {
	return s.killed.Load()
}

func (s *Server) lookup(sid string) *liveEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sessions[sid]
}

func (s *Server) take(sid string) *liveEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry := s.sessions[sid]
	if entry != nil {
		delete(s.sessions, sid)
	}
	return entry
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
	return ClientIP(r, s.cfg.TrustForwardedFor)
}

func gateErrStatus(err error) int {
	switch {
	case errors.Is(err, ErrGateClosed):
		return http.StatusServiceUnavailable
	default:
		// Unknown / exhausted codes are an auth failure from the client's view.
		return http.StatusUnauthorized
	}
}

func decodeJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, maxRequestBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	var extra struct{}
	if err := dec.Decode(&extra); err != io.EOF {
		return errors.New("livechat: request body must contain exactly one JSON object")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func newSessionID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("livechat: generate session id: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

func (e *liveEntry) acquireStream() bool {
	e.streamMu.Lock()
	defer e.streamMu.Unlock()
	if e.streamOn {
		return false
	}
	e.streamOn = true
	return true
}

func (e *liveEntry) releaseStream() {
	e.streamMu.Lock()
	e.streamOn = false
	e.streamMu.Unlock()
}
