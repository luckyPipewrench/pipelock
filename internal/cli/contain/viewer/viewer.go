// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package viewer

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
)

// Lifetimes are server-side: a ticket lasts 30 seconds, a session expires
// after 12 hours without client activity or 24 hours from creation, and a
// control lease lasts 30 seconds unless renewed.
const (
	ticketLifetime   = 30 * time.Second
	idleLifetime     = 12 * time.Hour
	absoluteLifetime = 24 * time.Hour
	leaseLifetime    = 30 * time.Second
	maxTickets       = 256
	maxSessions      = 256
	defaultViewers   = 4
	maxFrame         = 1 << 20
	maxCutText       = 256 << 10
)

// Config supplies the fixed public origin and private RFB socket. PathPrefix is a
// URL path (default /); no request Host or forwarded header is used for authority.
type Config struct {
	Origin      string
	Display     string
	PathPrefix  string
	SocketPath  string
	Clipboard   bool
	MaxViewers  int
	Dial        func() (net.Conn, error)
	ExpectedUID uint32
	PeerUID     func(net.Conn) (uint32, error)
	Now         func() time.Time
	Logger      *slog.Logger
}
type ticket struct {
	display, mode string
	expires       time.Time
}

// Session contains an opaque server-side identifier and its display binding.
type Session struct {
	ID, Display, Mode string
	created, last     time.Time
}
type lease struct {
	id      string
	expires time.Time
}
type Viewer struct {
	cfg      Config
	mu       sync.Mutex
	tickets  map[string]ticket
	sessions map[string]*Session
	leases   map[string]lease
	conns    map[string]map[net.Conn]struct{}
	viewers  int
}

func New(cfg Config) (*Viewer, error) {
	if cfg.Display == "" {
		return nil, errors.New("viewer: missing display")
	}
	u, err := url.Parse(cfg.Origin)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("viewer: invalid origin")
	}
	if cfg.PathPrefix == "" {
		cfg.PathPrefix = "/"
	}
	if !strings.HasPrefix(cfg.PathPrefix, "/") || strings.Contains(cfg.PathPrefix, "..") {
		return nil, errors.New("viewer: invalid path prefix")
	}
	cfg.PathPrefix = strings.TrimSuffix(cfg.PathPrefix, "/")
	if cfg.PathPrefix == "" {
		cfg.PathPrefix = "/"
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.MaxViewers <= 0 {
		cfg.MaxViewers = defaultViewers
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Dial == nil {
		if cfg.SocketPath == "" {
			return nil, errors.New("viewer: missing socket")
		}
		cfg.Dial = func() (net.Conn, error) {
			return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(context.Background(), "unix", cfg.SocketPath)
		}
	}
	if cfg.PeerUID == nil {
		cfg.PeerUID = peerUID
	}
	return &Viewer{cfg: cfg, tickets: make(map[string]ticket), sessions: make(map[string]*Session), leases: make(map[string]lease), conns: make(map[string]map[net.Conn]struct{})}, nil
}

func token() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

func (v *Viewer) MintTicket(display, mode string) (string, error) {
	if display != v.cfg.Display || (mode != "view" && mode != "control") {
		return "", errors.New("viewer: invalid display or mode")
	}
	id, err := token()
	if err != nil {
		return "", err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	now := v.cfg.Now()
	for k, t := range v.tickets {
		if !now.Before(t.expires) {
			delete(v.tickets, k)
		}
	}
	if len(v.tickets) >= maxTickets {
		return "", errors.New("viewer: ticket cap")
	}
	v.tickets[id] = ticket{display, mode, now.Add(ticketLifetime)}
	return id, nil
}

func (v *Viewer) Exchange(id string) (Session, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	t, ok := v.tickets[id]
	delete(v.tickets, id)
	now := v.cfg.Now()
	if !ok || !now.Before(t.expires) {
		return Session{}, errors.New("viewer: invalid ticket")
	}
	for k, s := range v.sessions {
		if !v.validLocked(s, now) {
			delete(v.sessions, k)
		}
	}
	if len(v.sessions) >= maxSessions {
		return Session{}, errors.New("viewer: session cap")
	}
	sid, err := token()
	if err != nil {
		return Session{}, err
	}
	s := Session{ID: sid, Display: t.display, Mode: t.mode, created: now, last: now}
	v.sessions[sid] = &s
	return s, nil
}

func (v *Viewer) validLocked(s *Session, now time.Time) bool {
	return now.Sub(s.last) < idleLifetime && now.Sub(s.created) < absoluteLifetime
}

func (v *Viewer) session(id string) (Session, bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	s := v.sessions[id]
	if s == nil {
		return Session{}, false
	}
	now := v.cfg.Now()
	if !v.validLocked(s, now) {
		delete(v.sessions, id)
		return Session{}, false
	}
	s.last = now
	return *s, true
}

func (v *Viewer) sessionValid(id string) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	s := v.sessions[id]
	if s == nil {
		return false
	}
	if !v.validLocked(s, v.cfg.Now()) {
		delete(v.sessions, id)
		return false
	}
	return true
}

func (v *Viewer) Revoke(id string) {
	v.mu.Lock()
	delete(v.sessions, id)
	v.releaseLocked(id, "release")
	conns := v.conns[id]
	delete(v.conns, id)
	v.mu.Unlock()
	for c := range conns {
		_ = c.Close()
	}
}

func (v *Viewer) RevokeAll() {
	v.mu.Lock()
	ids := make([]string, 0, len(v.sessions))
	for id := range v.sessions {
		ids = append(ids, id)
	}
	v.mu.Unlock()
	for _, id := range ids {
		v.Revoke(id)
	}
}

func (v *Viewer) Acquire(s Session) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	now := v.cfg.Now()
	current := v.sessions[s.ID]
	if current == nil || !v.validLocked(current, now) || current.Mode != "control" || current.Display != s.Display {
		v.cfg.Logger.Info("viewer lease denied", "event", "renew-denied")
		return false
	}
	l := v.leases[s.Display]
	if l.id != "" && now.Before(l.expires) && l.id != s.ID {
		v.cfg.Logger.Info("viewer lease denied", "event", "renew-denied", "display", s.Display)
		return false
	}
	v.leases[s.Display] = lease{s.ID, now.Add(leaseLifetime)}
	v.cfg.Logger.Info("viewer lease acquired", "event", "acquire", "display", s.Display)
	return true
}

func (v *Viewer) Renew(s Session) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	l := v.leases[s.Display]
	now := v.cfg.Now()
	current := v.sessions[s.ID]
	if l.id != s.ID || !now.Before(l.expires) || current == nil || current.Display != s.Display || !v.validLocked(current, now) {
		v.cfg.Logger.Info("viewer lease denied", "event", "renew-denied", "display", s.Display)
		return false
	}
	v.leases[s.Display] = lease{s.ID, now.Add(leaseLifetime)}
	return true
}

func (v *Viewer) releaseLocked(id, event string) {
	for d, l := range v.leases {
		if l.id == id {
			delete(v.leases, d)
			v.cfg.Logger.Info("viewer lease changed", "event", event, "display", d)
		}
	}
}
func (v *Viewer) Release(s Session) { v.mu.Lock(); v.releaseLocked(s.ID, "release"); v.mu.Unlock() }
func (v *Viewer) controls(s Session) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	l := v.leases[s.Display]
	if l.id != s.ID {
		return false
	}
	if !v.cfg.Now().Before(l.expires) {
		delete(v.leases, s.Display)
		v.cfg.Logger.Info("viewer lease expired", "event", "expire", "display", s.Display)
		return false
	}
	return true
}

func (v *Viewer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	if v.cfg.PathPrefix != "/" {
		if !strings.HasPrefix(path, v.cfg.PathPrefix+"/") && path != v.cfg.PathPrefix {
			http.NotFound(w, r)
			return
		}
		path = strings.TrimPrefix(path, v.cfg.PathPrefix)
		if path == "" {
			path = "/"
		}
	}
	switch path {
	case "/":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, "<!doctype html><title>Display viewer</title><p>Browser client is not bundled yet.</p>")
	case "/session":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		// Same origin rule as every other state-changing endpoint: a foreign
		// page must not be able to log this browser into a session it chose.
		if r.Header.Get("Origin") != v.cfg.Origin {
			v.reject(w, "origin")
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		s, err := v.Exchange(r.PostForm.Get("ticket"))
		if err != nil {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "viewer_session", Value: s.ID, Path: v.cfg.PathPrefix, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
		w.WriteHeader(http.StatusNoContent)
	case "/control/acquire", "/control/release":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.Header.Get("Origin") != v.cfg.Origin {
			v.reject(w, "origin")
			return
		}
		s, ok := v.requestSession(r)
		if !ok {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if path == "/control/acquire" {
			if !v.Acquire(s) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
		} else {
			v.Release(s)
		}
		w.WriteHeader(http.StatusNoContent)
	case "/ws":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		v.serveWS(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (v *Viewer) requestSession(r *http.Request) (Session, bool) {
	c, err := r.Cookie("viewer_session")
	if err != nil {
		return Session{}, false
	}
	return v.session(c.Value)
}

func (v *Viewer) reject(w http.ResponseWriter, reason string) {
	v.cfg.Logger.Info("viewer websocket refused", "reason", reason)
	http.Error(w, "forbidden", http.StatusForbidden)
}

func (v *Viewer) serveWS(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	u, err := url.Parse(origin)
	if err != nil || origin != v.cfg.Origin || u.String() != v.cfg.Origin {
		v.reject(w, "origin")
		return
	}
	s, ok := v.requestSession(r)
	if !ok {
		v.reject(w, "session")
		return
	}
	v.mu.Lock()
	if v.viewers >= v.cfg.MaxViewers {
		v.mu.Unlock()
		v.reject(w, "viewer cap")
		return
	}
	v.viewers++
	v.mu.Unlock()
	defer func() { v.mu.Lock(); v.viewers--; v.mu.Unlock() }()
	upstream, err := v.cfg.Dial()
	if err != nil {
		v.cfg.Logger.Info("viewer RFB dial failed", "error", err)
		http.Error(w, "display unavailable", http.StatusServiceUnavailable)
		return
	}
	defer func() { _ = upstream.Close() }()
	if v.cfg.ExpectedUID != 0 {
		uid, credErr := v.cfg.PeerUID(upstream)
		if credErr != nil || uid != v.cfg.ExpectedUID {
			v.cfg.Logger.Info("viewer RFB peer refused")
			http.Error(w, "display unavailable", http.StatusServiceUnavailable)
			return
		}
	}
	upgrader := ws.HTTPUpgrader{Timeout: 10 * time.Second}
	client, buf, _, err := upgrader.Upgrade(r, w)
	if err != nil {
		return
	}
	defer func() { _ = client.Close() }()
	v.mu.Lock()
	if v.conns[s.ID] == nil {
		v.conns[s.ID] = make(map[net.Conn]struct{})
	}
	v.conns[s.ID][client] = struct{}{}
	v.mu.Unlock()
	defer func() {
		v.mu.Lock()
		delete(v.conns[s.ID], client)
		v.releaseLocked(s.ID, "release")
		if len(v.conns[s.ID]) == 0 {
			delete(v.conns, s.ID)
		}
		v.mu.Unlock()
	}()
	done := make(chan struct{})
	stop := make(chan struct{})
	heartbeatDone := make(chan struct{})
	var writeMu sync.Mutex
	go func() { defer close(done); v.serverToClient(client, upstream, &writeMu) }()
	go func() {
		defer close(heartbeatDone)
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				if !v.sessionValid(s.ID) {
					_ = client.Close()
					return
				}
				writeMu.Lock()
				_ = client.SetWriteDeadline(time.Now().Add(10 * time.Second))
				err := wsutil.WriteServerMessage(client, ws.OpPing, nil)
				writeMu.Unlock()
				if err != nil {
					_ = client.Close()
					return
				}
			}
		}
	}()
	v.clientToServer(client, buf, upstream, s, &writeMu)
	close(stop)
	_ = client.Close()
	_ = upstream.Close()
	<-done
	<-heartbeatDone
}

func (v *Viewer) serverToClient(client, upstream net.Conn, writeMu *sync.Mutex) {
	buf := make([]byte, 32<<10)
	for {
		n, err := upstream.Read(buf)
		if n > 0 {
			writeMu.Lock()
			_ = client.SetWriteDeadline(time.Now().Add(10 * time.Second))
			e := wsutil.WriteServerBinary(client, buf[:n])
			writeMu.Unlock()
			if e != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func (v *Viewer) clientToServer(client net.Conn, source io.Reader, upstream net.Conn, s Session, writeMu *sync.Mutex) {
	reader := wsutil.NewServerSideReader(source)
	reader.MaxFrameSize = maxFrame
	reader.OnIntermediate = func(h ws.Header, r io.Reader) error {
		if h.OpCode == ws.OpClose {
			return io.EOF
		}
		if h.OpCode == ws.OpPing {
			payload, err := io.ReadAll(io.LimitReader(r, 126))
			if err != nil || len(payload) > 125 {
				return errors.New("invalid websocket ping")
			}
			writeMu.Lock()
			defer writeMu.Unlock()
			_ = client.SetWriteDeadline(time.Now().Add(10 * time.Second))
			return wsutil.WriteServerMessage(client, ws.OpPong, payload)
		}
		_, err := io.Copy(io.Discard, r)
		return err
	}
	filter := newFilter(func() bool { return v.controls(s) }, v.cfg.Clipboard)
	handshakeDeadline := time.Now().Add(10 * time.Second)
	for {
		deadline := time.Now().Add(5 * time.Minute)
		if filter.stage < 3 {
			deadline = handshakeDeadline
		}
		_ = client.SetReadDeadline(deadline)
		h, err := reader.NextFrame()
		if err != nil {
			return
		}
		if h.OpCode != ws.OpBinary {
			return
		}
		if _, ok := v.session(s.ID); !ok {
			return
		}
		payload, err := io.ReadAll(io.LimitReader(reader, maxFrame+1))
		if err != nil || len(payload) > maxFrame {
			return
		}
		out, err := filter.feed(payload)
		if err != nil {
			v.cfg.Logger.Info("viewer RFB input closed", "error", err)
			return
		}
		if len(out) > 0 {
			_ = upstream.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if _, err = upstream.Write(out); err != nil {
				return
			}
		}
	}
}

var _ http.Handler = (*Viewer)(nil)
