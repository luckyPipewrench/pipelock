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
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/playground"
)

// Route paths for the live-chat API.
const (
	RouteSession = "/api/live/session"
	RouteStream  = "/api/live/stream"
	RouteMessage = "/api/live/message"
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
	// RequireContainment is passed to each session. Public exposure MUST be true.
	RequireContainment bool
	// Containment proves kernel containment per session. Required (non-nil) when
	// RequireContainment is true.
	Containment playground.ContainmentVerifier
	// OrchestratorKeyPath / ToyAgentBin / WebToolBin are forwarded to sessions.
	OrchestratorKeyPath string
	ToyAgentBin         string
	WebToolBin          string
	// TrustForwardedFor reads the client IP from X-Forwarded-For (set true only
	// behind a trusted reverse proxy / CDN).
	TrustForwardedFor bool
	// AllowOrigin sets Access-Control-Allow-Origin for the browser. Empty = none.
	AllowOrigin string
}

type liveEntry struct {
	sess    *playground.LiveSession
	release func()
	cancel  context.CancelFunc
	codeID  string
	runDir  string
	expires time.Time
	timer   *time.Timer
	finOnce sync.Once

	streamMu sync.Mutex
	streamOn bool
}

// Server is the live-chat HTTP/SSE front door.
type Server struct {
	cfg      ServerConfig
	limits   Limits
	ipRate   *RateLimiter
	codeRate *RateLimiter
	conc     *ConcurrencyLimiter

	mu       sync.Mutex
	sessions map[string]*liveEntry
}

// NewServer builds the server. It returns an error (fail-closed at startup) when
// the gate is missing, or containment is required but no verifier is supplied.
func NewServer(cfg ServerConfig) (*Server, error) {
	if cfg.Gate == nil {
		return nil, errors.New("livechat: server requires a gate")
	}
	if cfg.RequireContainment && cfg.Containment == nil {
		return nil, errors.New("livechat: RequireContainment set but no ContainmentVerifier supplied")
	}
	return &Server{
		cfg:      cfg,
		limits:   cfg.Limits.Clamp(),
		ipRate:   NewRateLimiter(cfg.IPRate),
		codeRate: NewRateLimiter(cfg.CodeRate),
		conc:     NewConcurrencyLimiter(cfg.MaxConcurrent),
		sessions: make(map[string]*liveEntry),
	}, nil
}

// Handler returns the HTTP routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(RouteSession, s.handleSession)
	mux.HandleFunc(RouteStream, s.handleStream)
	mux.HandleFunc(RouteMessage, s.handleMessage)
	mux.HandleFunc(RouteHealth, s.handleHealth)
	return mux
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":        s.cfg.Gate.Open(),
		"in_use":    s.conc.InUse(),
		"capacity":  s.conc.Cap(),
		"contained": s.cfg.RequireContainment,
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

	var body createReq
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "bad request")
		return
	}
	if body.Code == "" {
		writeErr(w, http.StatusUnauthorized, "invite code required")
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
	entry.timer = time.AfterFunc(time.Until(claims.ExpiresAt), func() { s.finalize(sid) })

	s.mu.Lock()
	s.sessions[sid] = entry
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
	if err := entry.sess.Send(r.Context(), body.Message); err != nil {
		writeErr(w, http.StatusInternalServerError, "send failed")
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "accepted"})
}

// finalize seals, verifies, and tears down a session exactly once.
func (s *Server) finalize(sid string) {
	entry := s.take(sid)
	if entry == nil {
		return
	}
	entry.finOnce.Do(func() {
		if entry.timer != nil {
			entry.timer.Stop()
		}
		// Best-effort seal + offline verify; the verified event reaches any
		// connected stream before Close shuts the channel.
		_, _ = entry.sess.Finalize(entry.runDir)
		entry.sess.Close()
		entry.cancel()
		entry.release()
		_ = os.RemoveAll(entry.runDir)
	})
}

// Close finalizes all live sessions. Call on server shutdown.
func (s *Server) Close() {
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
	if s.cfg.TrustForwardedFor {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			if i := strings.IndexByte(xff, ','); i >= 0 {
				return strings.TrimSpace(xff[:i])
			}
			return strings.TrimSpace(xff)
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
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
