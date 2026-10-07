// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/edition"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/identitykey"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

const (
	// defaultBucketName is the operator's default_agent_identity in these tests.
	defaultBucketName = "team-bot"
	// defaultBucketHeaderName is a name a caller supplies in X-Pipelock-Agent.
	defaultBucketHeaderName = "sidecar-x"
	// defaultBucketPeer is the client address httptest requests present.
	defaultBucketPeer = "192.0.2.1"
	defaultBucketKey  = defaultBucketName + "|" + defaultBucketPeer
)

func resolveDefaultBucketIdentity(t *testing.T, cfg *config.Config, header string, knownProfiles map[string]bool) edition.AgentIdentity {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://api.vendor.example/", nil)
	if header != "" {
		req.Header.Set(edition.AgentHeader, header)
	}
	return edition.ResolveAgentIdentity(req, knownProfiles, cfg.DefaultAgentIdentity, cfg.BindDefaultAgentIdentity)
}

func TestStateIdentityProjection(t *testing.T) {
	unbound := func() *config.Config {
		cfg := config.Defaults()
		cfg.DefaultAgentIdentity = defaultBucketName
		return cfg
	}
	bound := func() *config.Config {
		cfg := unbound()
		cfg.BindDefaultAgentIdentity = true
		return cfg
	}
	noDefault := config.Defaults
	sanitized := func() *config.Config {
		cfg := config.Defaults()
		cfg.DefaultAgentIdentity = "deployment/my agent"
		return cfg
	}

	tests := []struct {
		name      string
		cfg       *config.Config
		agent     string
		auth      envelope.ActorAuth
		wantAgent string
		wantAuth  envelope.ActorAuth
	}{
		{"nil config is unchanged", nil, defaultBucketHeaderName, envelope.ActorAuthSelfDeclared, defaultBucketHeaderName, envelope.ActorAuthSelfDeclared},
		{"no default is unchanged", noDefault(), defaultBucketHeaderName, envelope.ActorAuthSelfDeclared, defaultBucketHeaderName, envelope.ActorAuthSelfDeclared},
		{"bound default is unchanged", bound(), defaultBucketHeaderName, envelope.ActorAuthSelfDeclared, defaultBucketHeaderName, envelope.ActorAuthSelfDeclared},
		{"bound listener keeps its own identity", unbound(), "agent-one", envelope.ActorAuthBound, "agent-one", envelope.ActorAuthBound},
		{"config default keeps its own identity", unbound(), defaultBucketName, envelope.ActorAuthConfigDefault, defaultBucketName, envelope.ActorAuthConfigDefault},
		{"self-declared header projects to the default", unbound(), defaultBucketHeaderName, envelope.ActorAuthSelfDeclared, defaultBucketName, envelope.ActorAuthConfigDefault},
		{"matched header projects to the default", unbound(), "known-profile", envelope.ActorAuthMatched, defaultBucketName, envelope.ActorAuthConfigDefault},
		{"unknown grade projects to the default", unbound(), "", envelope.ActorAuthUnknown, defaultBucketName, envelope.ActorAuthConfigDefault},
		{"default name is sanitized like the resolver", sanitized(), defaultBucketHeaderName, envelope.ActorAuthSelfDeclared, "deployment_my_agent", envelope.ActorAuthConfigDefault},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			agent, auth := stateIdentity(tt.cfg, tt.agent, tt.auth)
			if agent != tt.wantAgent || auth != tt.wantAuth {
				t.Fatalf("stateIdentity() = (%q, %q), want (%q, %q)", agent, auth, tt.wantAgent, tt.wantAuth)
			}
		})
	}
}

// TestDefaultIdentityHeaderDoesNotSplitStateKeys is the premise and the fix in
// one: the raw key primitive splits one peer into two buckets depending on
// whether it sends X-Pipelock-Agent, and every state key built through the
// projection lands both requests in one.
func TestDefaultIdentityHeaderDoesNotSplitStateKeys(t *testing.T) {
	cfg := config.Defaults()
	cfg.DefaultAgentIdentity = defaultBucketName
	known := map[string]bool{defaultBucketHeaderName: true}

	noHeader := resolveDefaultBucketIdentity(t, cfg, "", known)
	selfDeclared := resolveDefaultBucketIdentity(t, cfg, "other-name", known)
	matched := resolveDefaultBucketIdentity(t, cfg, defaultBucketHeaderName, known)
	if noHeader.Auth != envelope.ActorAuthConfigDefault || selfDeclared.Auth != envelope.ActorAuthSelfDeclared || matched.Auth != envelope.ActorAuthMatched {
		t.Fatalf("grades = %q/%q/%q, want config-default/self-declared/matched", noHeader.Auth, selfDeclared.Auth, matched.Auth)
	}

	// Premise: the unprojected primitive keys the two requests differently.
	rawNone := identitykey.CEESafeKey(noHeader.Name, defaultBucketPeer, noHeader.Auth)
	rawHeader := identitykey.CEESafeKey(selfDeclared.Name, defaultBucketPeer, selfDeclared.Auth)
	if rawNone != defaultBucketKey || rawHeader != defaultBucketPeer {
		t.Fatalf("raw keys = %q / %q, want %q / %q", rawNone, rawHeader, defaultBucketKey, defaultBucketPeer)
	}

	keyers := map[string]func(id edition.AgentIdentity) string{
		"sessionKeyFor": func(id edition.AgentIdentity) string {
			return sessionKeyFor(cfg, id.Name, defaultBucketPeer, id.Auth)
		},
		"ceeSessionKey": func(id edition.AgentIdentity) string {
			return ceeSessionKey(cfg, id.Name, defaultBucketPeer, id.Auth)
		},
		"responseTaintSessionKey": func(id edition.AgentIdentity) string {
			return responseTaintSessionKey(cfg, id.Name, defaultBucketPeer, id.Auth)
		},
		"newCEEIdentity": func(id edition.AgentIdentity) string {
			return newCEEIdentity(cfg, id.Name, defaultBucketPeer, id.Auth).Key()
		},
	}
	for name, key := range keyers {
		for label, id := range map[string]edition.AgentIdentity{"no header": noHeader, "self-declared header": selfDeclared, "matched header": matched} {
			if got := key(id); got != defaultBucketKey {
				t.Errorf("%s with %s = %q, want the default bucket %q", name, label, got, defaultBucketKey)
			}
		}
	}
	if got := identitykey.BaselineKeyForSessionKey(defaultBucketKey); got != defaultBucketName {
		t.Fatalf("baseline key = %q, want %q", got, defaultBucketName)
	}
}

func TestDefaultIdentityProjectionControls(t *testing.T) {
	t.Run("bind default keeps one bucket without the projection", func(t *testing.T) {
		cfg := config.Defaults()
		cfg.DefaultAgentIdentity = defaultBucketName
		cfg.BindDefaultAgentIdentity = true
		for _, header := range []string{"", defaultBucketHeaderName} {
			id := resolveDefaultBucketIdentity(t, cfg, header, nil)
			if got := sessionKeyFor(cfg, id.Name, defaultBucketPeer, id.Auth); got != defaultBucketKey {
				t.Fatalf("header %q: key = %q, want %q", header, got, defaultBucketKey)
			}
			if got := identitykey.CEESafeKey(id.Name, defaultBucketPeer, id.Auth); got != defaultBucketKey {
				t.Fatalf("header %q: raw key = %q, want %q (bind must not depend on the projection)", header, got, defaultBucketKey)
			}
		}
	})

	t.Run("no default keeps header requests on their own grade", func(t *testing.T) {
		cfg := config.Defaults()
		id := resolveDefaultBucketIdentity(t, cfg, defaultBucketHeaderName, nil)
		if got := sessionKeyFor(cfg, id.Name, defaultBucketPeer, id.Auth); got != defaultBucketPeer {
			t.Fatalf("key = %q, want the folded client bucket %q", got, defaultBucketPeer)
		}
	})

	t.Run("bound listener ignores the header and keeps its bucket", func(t *testing.T) {
		cfg := config.Defaults()
		cfg.DefaultAgentIdentity = defaultBucketName
		for _, header := range []string{"", defaultBucketHeaderName} {
			req := httptest.NewRequestWithContext(edition.WithAgentOverride(t.Context(), "listener-agent"), http.MethodGet, "http://api.vendor.example/", nil)
			if header != "" {
				req.Header.Set(edition.AgentHeader, header)
			}
			id := edition.ResolveAgentIdentity(req, nil, cfg.DefaultAgentIdentity, cfg.BindDefaultAgentIdentity)
			if id.Auth != envelope.ActorAuthBound {
				t.Fatalf("grade = %q, want bound", id.Auth)
			}
			want := "listener-agent|" + defaultBucketPeer
			if got := sessionKeyFor(cfg, id.Name, defaultBucketPeer, id.Auth); got != want {
				t.Fatalf("header %q: key = %q, want %q", header, got, want)
			}
		}
	})
}

// defaultBucketProxyConfig is an unbound default identity with the stateful
// detectors that key by identity switched on.
func defaultBucketProxyConfig() *config.Config {
	cfg := adaptiveConfig()
	cfg.DefaultAgentIdentity = defaultBucketName
	cfg.BindDefaultAgentIdentity = false
	cfg.CrossRequestDetection.Enabled = true
	cfg.CrossRequestDetection.EntropyBudget.Enabled = true
	cfg.CrossRequestDetection.EntropyBudget.BitsPerWindow = 100000
	cfg.CrossRequestDetection.EntropyBudget.WindowMinutes = 5
	cfg.CrossRequestDetection.EntropyBudget.Action = config.ActionWarn
	return cfg
}

func sessionKeys(p *Proxy) []string {
	var keys []string
	for _, snap := range p.sessionMgrPtr.Load().Snapshot() {
		keys = append(keys, snap.Key)
	}
	sort.Strings(keys)
	return keys
}

// TestDefaultIdentityHeaderAndNoHeaderShareOneBucketOnHTTPTransports sends the
// same peer's requests with and without X-Pipelock-Agent through the real
// handlers and requires one adaptive session and one entropy owner.
func TestDefaultIdentityHeaderAndNoHeaderShareOneBucketOnHTTPTransports(t *testing.T) {
	upstream := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(upstream.Close)
	opaque := opaqueHighEntropyBodyValue()

	transports := map[string]func(p *Proxy, header string) *httptest.ResponseRecorder{
		"forward": func(p *Proxy, header string) *httptest.ResponseRecorder {
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, upstream.URL+"/data?cursor="+opaque, nil)
			if header != "" {
				req.Header.Set(edition.AgentHeader, header)
			}
			w := httptest.NewRecorder()
			p.buildHandler(http.NewServeMux()).ServeHTTP(w, req)
			return w
		},
		"fetch": func(p *Proxy, header string) *httptest.ResponseRecorder {
			mux := http.NewServeMux()
			mux.HandleFunc("/fetch", p.handleFetch)
			target := upstream.URL + "/data?cursor=" + opaque
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/fetch?url="+url.QueryEscape(target), nil)
			if header != "" {
				req.Header.Set(edition.AgentHeader, header)
			}
			w := httptest.NewRecorder()
			p.buildHandler(mux).ServeHTTP(w, req)
			return w
		},
	}

	for name, send := range transports {
		t.Run(name, func(t *testing.T) {
			p := newTestProxyWithConfig(t, defaultBucketProxyConfig())
			for _, header := range []string{"", defaultBucketHeaderName, "", "another-name"} {
				if w := send(p, header); w.Code != http.StatusOK {
					t.Fatalf("header %q: status = %d, want 200: %s", header, w.Code, w.Body.String())
				}
			}
			if got := sessionKeys(p); len(got) != 1 || got[0] != defaultBucketKey {
				t.Fatalf("session keys = %v, want exactly [%s]", got, defaultBucketKey)
			}
			et := p.entropyTrackerPtr.Load()
			if et == nil {
				t.Fatal("entropy tracker not initialized")
			}
			owner := identitykey.NewCEEIdentity(defaultBucketName, defaultBucketPeer, envelope.ActorAuthConfigDefault)
			folded := identitykey.NewCEEIdentity("", defaultBucketPeer, envelope.ActorAuthSelfDeclared)
			if et.CurrentUsage(owner) <= 0 {
				t.Fatal("no entropy recorded under the default bucket")
			}
			if usage := et.CurrentUsage(folded); usage != 0 {
				t.Fatalf("entropy usage under the folded client bucket = %.2f, want 0 (the header request split off)", usage)
			}
		})
	}
}

// TestDefaultIdentityConnectEntropyUsesTheDefaultBucket proves CONNECT reads
// the same entropy owner for a header request: a budget the peer already spent
// under the default bucket denies the tunnel whether or not it sent the header.
func TestDefaultIdentityConnectEntropyUsesTheDefaultBucket(t *testing.T) {
	target := newIPv4Server(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(target.Close)
	proxyAddr, p, cleanup := setupForwardProxyWithInstance(t, func(cfg *config.Config) {
		cfg.DefaultAgentIdentity = defaultBucketName
		cfg.CrossRequestDetection.Enabled = true
		cfg.CrossRequestDetection.Action = config.ActionBlock
		cfg.CrossRequestDetection.EntropyBudget.Enabled = true
		cfg.CrossRequestDetection.EntropyBudget.BitsPerWindow = 20
		cfg.CrossRequestDetection.EntropyBudget.WindowMinutes = 5
		cfg.CrossRequestDetection.EntropyBudget.Action = config.ActionBlock
	})
	t.Cleanup(cleanup)

	// The loopback test client connects from 127.0.0.1; spend the budget under
	// the bucket a header-less request from that peer resolves to.
	et := p.entropyTrackerPtr.Load()
	if et == nil {
		t.Fatal("entropy tracker not initialized")
	}
	owner := identitykey.NewCEEIdentity(defaultBucketName, adaptiveSessionKeyLoopback, envelope.ActorAuthConfigDefault)
	et.Record(owner, []byte(opaqueHighEntropyBodyValue()+opaqueHighEntropyBodyValue()))
	if !et.BudgetExceeded(owner) {
		t.Fatal("test setup did not exhaust the default bucket's entropy budget")
	}

	host := target.Listener.Addr().String()
	for _, header := range []string{"", defaultBucketHeaderName} {
		conn := dialProxy(t, proxyAddr)
		extra := ""
		if header != "" {
			extra = edition.AgentHeader + ": " + header + "\r\n"
		}
		_, _ = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n%s\r\n", host, host, extra)
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			_ = conn.Close()
			t.Fatalf("header %q: read response: %v", header, err)
		}
		status := resp.StatusCode
		_ = resp.Body.Close()
		_ = conn.Close()
		if status != http.StatusForbidden {
			t.Fatalf("header %q: CONNECT status = %d, want 403 from the spent default-bucket budget", header, status)
		}
	}
}

// issuerBucketIdentity is how a request's identity reaches the intercept
// handler: its display name and its declared grade.
type issuerBucketIdentity struct {
	agent string
	auth  envelope.ActorAuth
}

var (
	issuerBucketDefault = issuerBucketIdentity{defaultBucketName, envelope.ActorAuthConfigDefault}
	issuerBucketHeader  = issuerBucketIdentity{defaultBucketHeaderName, envelope.ActorAuthSelfDeclared}
	issuerBucketOther   = issuerBucketIdentity{"another-name", envelope.ActorAuthSelfDeclared}
	issuerBucketBound   = issuerBucketIdentity{"listener-agent", envelope.ActorAuthBound}
)

// TestDefaultIdentityIssuerCookieEvidenceIsOneBucket issues a JWT session
// cookie to one request identity and returns it as another. The same peer must
// be recognized whether or not it sends X-Pipelock-Agent, and a different
// bucket must still not inherit the evidence. Every return runs under a
// configured block action, so a recognized cookie is the issuer-bound omission
// and an unrecognized one is denied.
func TestDefaultIdentityIssuerCookieEvidenceIsOneBucket(t *testing.T) {
	jwt := issuerJWTShapedValue()
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			w.Header().Add("Set-Cookie", "session="+jwt+"; Path=/; Secure; HttpOnly")
		}
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(upstream.Close)

	tests := []struct {
		name        string
		defaultName string
		bind        bool
		issueTo     issuerBucketIdentity
		returnAs    issuerBucketIdentity
		want        int
	}{
		{"cookie issued on a header request is recognized without the header", defaultBucketName, false, issuerBucketHeader, issuerBucketDefault, http.StatusOK},
		{"cookie issued without the header is recognized on a header request", defaultBucketName, false, issuerBucketDefault, issuerBucketHeader, http.StatusOK},
		{"cookie issued under one header name is recognized under another", defaultBucketName, false, issuerBucketHeader, issuerBucketOther, http.StatusOK},
		{"a bound listener bucket does not share evidence with the default", defaultBucketName, false, issuerBucketBound, issuerBucketHeader, http.StatusForbidden},
		{"evidence issued to the default is not shared with a bound listener", defaultBucketName, false, issuerBucketHeader, issuerBucketBound, http.StatusForbidden},
		{"no default configured: a self-declared identity never gets the allowance", "", false, issuerBucketHeader, issuerBucketHeader, http.StatusForbidden},
		{"bound default: the configured identity is recognized as before", defaultBucketName, true, issuerBucketDefault, issuerBucketDefault, http.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Issuer evidence persists under XDG_STATE_HOME, which the package
			// shares; isolate it so one case cannot issue for the next.
			t.Setenv("XDG_STATE_HOME", t.TempDir())
			cache, pool, cfg, _, _, m := testInterceptSetup(t)
			issuerCookieTestConfig(t, cfg)
			cfg.DefaultAgentIdentity = tt.defaultName
			cfg.BindDefaultAgentIdentity = tt.bind
			logger := audit.NewNop()
			sc := scanner.MustNew(cfg)
			t.Cleanup(sc.Close)
			p, err := New(cfg, logger, sc, m)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(p.Close)

			do := func(id issuerBucketIdentity, path, cookie string) int {
				t.Helper()
				req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, upstream.URL+path, nil)
				if err != nil {
					t.Fatal(err)
				}
				if cookie != "" {
					req.Header.Set("Cookie", cookie)
				}
				resp := interceptAndRequestWithRecorder(t, interceptRequestOptions{
					Upstream: upstream, Cache: cache, Pool: pool, Config: cfg, Scanner: sc,
					Logger: logger, Metrics: m, Request: req, Proxy: p,
					Agent: id.agent, ActorAuth: id.auth,
				})
				defer func() { _ = resp.Body.Close() }()
				_, _ = io.Copy(io.Discard, resp.Body)
				return resp.StatusCode
			}

			returned := "session=" + jwt
			if got := do(tt.returnAs, "/account", returned); got != http.StatusForbidden {
				t.Fatalf("before issuance status = %d, want 403: the allowance must come from evidence", got)
			}
			if got := do(tt.issueTo, "/login", ""); got != http.StatusOK {
				t.Fatalf("issuing response status = %d, want 200", got)
			}
			if got := do(tt.returnAs, "/account", returned); got != tt.want {
				t.Fatalf("returned cookie status = %d, want %d", got, tt.want)
			}
		})
	}
}

// TestDefaultIdentityIssuerQueryStoreTrustGate pins that the query-evidence
// store is reachable for a header-carrying request exactly when the default
// identity makes its bucket the default's, and is not for a self-declared
// identity with nothing configured.
func TestDefaultIdentityIssuerQueryStoreTrustGate(t *testing.T) {
	build := func(t *testing.T, defaultName string, agent string, auth envelope.ActorAuth) *InterceptContext {
		t.Helper()
		t.Setenv("XDG_STATE_HOME", t.TempDir())
		_, _, cfg, _, _, m := testInterceptSetup(t)
		issuerCookieTestConfig(t, cfg)
		cfg.DefaultAgentIdentity = defaultName
		sc := scanner.MustNew(cfg)
		t.Cleanup(sc.Close)
		p, err := New(cfg, audit.NewNop(), sc, m)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(p.Close)
		return &InterceptContext{Proxy: p, Config: cfg, Agent: agent, ActorAuth: auth}
	}

	ic := build(t, defaultBucketName, defaultBucketHeaderName, envelope.ActorAuthSelfDeclared)
	if ic.issuerQueryStore() == nil || ic.issuerCookieStore() == nil {
		t.Fatal("a header request under an unbound default must reach issuer evidence")
	}
	if ic.ActorAuth != envelope.ActorAuthSelfDeclared {
		t.Fatalf("declared grade = %q; the projection must not rewrite it", ic.ActorAuth)
	}

	ic = build(t, "", defaultBucketHeaderName, envelope.ActorAuthSelfDeclared)
	if ic.issuerQueryStore() != nil || ic.issuerCookieStore() != nil {
		t.Fatal("a self-declared identity with no default must not reach issuer evidence")
	}
}

// TestDefaultIdentityWhoamiReportsTheSharedBucket pins the operator surface:
// whoami names the key real traffic lands in, so a reset hint built from it
// targets the bucket that holds the state, while the declared identity and
// grade stay as the request presented them.
func TestDefaultIdentityWhoamiReportsTheSharedBucket(t *testing.T) {
	cfg := config.Defaults()
	cfg.DefaultAgentIdentity = defaultBucketName

	sm := newAdaptiveOperatorTestManager(t)
	var smPtr atomic.Pointer[SessionManager]
	smPtr.Store(sm)
	var etPtr atomic.Pointer[scanner.EntropyTracker]
	var fbPtr atomic.Pointer[scanner.FragmentBuffer]
	handler := NewSessionAPIHandler(SessionAPIOptions{
		SessionMgrPtr: &smPtr,
		EntropyPtr:    &etPtr,
		FragmentPtr:   &fbPtr,
		Metrics:       metrics.New(),
		Logger:        audit.NewNop(),
		APIToken:      testSessionAPIToken,
		ResolveAgentIdentity: func(r *http.Request) edition.AgentIdentity {
			return edition.ResolveAgentIdentity(r, nil, cfg.DefaultAgentIdentity, cfg.BindDefaultAgentIdentity)
		},
		Config: func() *config.Config { return cfg },
	})
	sm.GetOrCreate(defaultBucketKey)

	for _, header := range []string{"", defaultBucketHeaderName} {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/adaptive/whoami", nil)
		req.RemoteAddr = defaultBucketPeer + ":4567"
		req.Header.Set("Authorization", "Bearer "+testSessionAPIToken)
		if header != "" {
			req.Header.Set(edition.AgentHeader, header)
		}
		w := httptest.NewRecorder()
		handler.HandleAdaptiveWhoami(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("header %q: status = %d: %s", header, w.Code, w.Body.String())
		}
		var resp AdaptiveWhoami
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		if resp.SessionKey != defaultBucketKey || !resp.Exists {
			t.Fatalf("header %q: session_key = %q exists=%v, want the shared bucket %q", header, resp.SessionKey, resp.Exists, defaultBucketKey)
		}
		wantProvenance, wantAgent := string(envelope.ActorAuthConfigDefault), defaultBucketName
		if header != "" {
			wantProvenance, wantAgent = string(envelope.ActorAuthSelfDeclared), header
		}
		if resp.Provenance != wantProvenance || resp.Agent != wantAgent {
			t.Fatalf("header %q: agent/provenance = %q/%q, want the declared %q/%q", header, resp.Agent, resp.Provenance, wantAgent, wantProvenance)
		}
	}
}

// TestDefaultIdentityIPDomainTrackerKeepsDeclaredGrade pins the one place that
// must NOT follow the projection: the per-IP domain tracker exists to catch
// header rotation and still treats a header-supplied name as untrusted.
func TestDefaultIdentityIPDomainTrackerKeepsDeclaredGrade(t *testing.T) {
	cfg := defaultBucketProxyConfig()
	cfg.SessionProfiling.DomainBurst = 2
	p := newTestProxyWithConfig(t, cfg)
	sm := p.sessionMgrPtr.Load()
	for _, host := range []string{"a.vendor.example", "b.vendor.example", "c.vendor.example", "d.vendor.example"} {
		p.recordSessionActivityWithUserAgent(sessionActivityOptions{
			ClientIP: defaultBucketPeer, Agent: defaultBucketHeaderName, ActorAuth: envelope.ActorAuthSelfDeclared,
			Hostname: host, RequestID: "req", Result: scanner.Result{Allowed: true}, Config: cfg, Logger: audit.NewNop(), DeferClean: true,
		})
	}
	if got := sm.RecordIPDomain(defaultBucketPeer, "e.vendor.example", &cfg.SessionProfiling); len(got) == 0 {
		t.Fatal("per-IP domain tracker saw no burst from a header-carrying identity; it must keep the declared grade")
	}
	if got := sessionKeys(p); len(got) != 1 || !strings.HasPrefix(got[0], defaultBucketName+"|") {
		t.Fatalf("session keys = %v, want the single default bucket", got)
	}
}
