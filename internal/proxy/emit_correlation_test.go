// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/certgen"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/emit"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

const (
	corrTestHeader   = "X-Correlation-Id"
	corrTestTag      = "case-0042"
	corrTestConnTag  = "connect-0007"
	corrTestInnerTag = "inner-0013"
	corrWaitTimeout  = 5 * time.Second
)

// corrTestAWSKey is assembled at runtime so the source holds no credential
// literal.
func corrTestAWSKey() string { return "AKIA" + "IOSFODNN7EXAMPLE" }

// newCorrelationAuditLogger returns a logger that emits allowed events too, so
// a test can assert on both allow and block decisions.
func newCorrelationAuditLogger(t *testing.T) (*audit.Logger, *reverseEmitSink) {
	t.Helper()
	logger, err := audit.NewWithStream("json", "stdout", "", true, true, io.Discard)
	if err != nil {
		t.Fatalf("audit logger: %v", err)
	}
	sink := &reverseEmitSink{}
	emitter := emit.NewEmitter("correlation-test", sink)
	logger.SetEmitter(emitter)
	t.Cleanup(func() { _ = emitter.Close() })
	return logger, sink
}

func withCorrelationHeader(cfg *config.Config) {
	cfg.Emit.CorrelationHeader = corrTestHeader
}

// findEvent returns the first emitted event of the given type.
func findEvent(events []emit.Event, eventType string) (emit.Event, bool) {
	for _, ev := range events {
		if ev.Type == eventType {
			return ev, true
		}
	}
	return emit.Event{}, false
}

func waitForEvent(t *testing.T, sink *reverseEmitSink, eventType string) emit.Event {
	t.Helper()
	var found emit.Event
	testwait.For(t, corrWaitTimeout, func() bool {
		ev, ok := findEvent(sink.eventsSnapshot(), eventType)
		found = ev
		return ok
	}, "emitted %s event", eventType)
	return found
}

func requireCorrelation(t *testing.T, ev emit.Event, want string) {
	t.Helper()
	got, ok := ev.Fields[audit.FieldCorrelationID]
	if want == "" {
		if ok {
			t.Fatalf("%s event carries correlation_id %v, want absent; fields=%v", ev.Type, got, ev.Fields)
		}
		return
	}
	if got != want {
		t.Fatalf("%s event correlation_id = %v, want %q; fields=%v", ev.Type, got, want, ev.Fields)
	}
	if rid, _ := ev.Fields["request_id"].(string); rid == "" {
		t.Fatalf("%s event has correlation_id but no request_id: %v", ev.Type, ev.Fields)
	}
}

func okUpstream(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "hello")
	}))
	t.Cleanup(srv.Close)
	return srv
}

// doCorrelationGET sends one GET and returns the status code after draining
// and closing the body.
func doCorrelationGET(t *testing.T, client *http.Client, target, tag string) int {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	if tag != "" {
		req.Header.Set(corrTestHeader, tag)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", target, err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode
}

func TestEmitCorrelation_Fetch(t *testing.T) {
	t.Parallel()
	upstream := okUpstream(t)

	t.Run("allowed", func(t *testing.T) {
		t.Parallel()
		logger, sink := newCorrelationAuditLogger(t)
		addr, _, cleanup := setupForwardProxyWithLogger(t, logger, withCorrelationHeader)
		defer cleanup()
		status := doCorrelationGET(t, http.DefaultClient, "http://"+addr+"/fetch?url="+url.QueryEscape(upstream.URL+"/ok"), corrTestTag)
		if status != http.StatusOK {
			t.Fatalf("status = %d, want 200", status)
		}
		requireCorrelation(t, waitForEvent(t, sink, emit.EventAllowed), corrTestTag)
	})

	t.Run("blocked", func(t *testing.T) {
		t.Parallel()
		logger, sink := newCorrelationAuditLogger(t)
		addr, _, cleanup := setupForwardProxyWithLogger(t, logger, withCorrelationHeader)
		defer cleanup()
		target := upstream.URL + "/?k=" + corrTestAWSKey()
		status := doCorrelationGET(t, http.DefaultClient, "http://"+addr+"/fetch?url="+url.QueryEscape(target), corrTestTag)
		if status == http.StatusOK {
			t.Fatal("DLP URL was not blocked")
		}
		requireCorrelation(t, waitForEvent(t, sink, emit.EventBlocked), corrTestTag)
	})

	// A secret placed in the correlation header is never copied into the
	// event, and the request itself is unaffected by the hygiene failure.
	t.Run("secret-shaped tag omitted without blocking", func(t *testing.T) {
		t.Parallel()
		logger, sink := newCorrelationAuditLogger(t)
		addr, _, cleanup := setupForwardProxyWithLogger(t, logger, func(cfg *config.Config) {
			withCorrelationHeader(cfg)
			// Header DLP would block this request outright; this case is
			// about the emit hygiene, not header scanning.
			cfg.RequestBodyScanning.ScanHeaders = false
		})
		defer cleanup()
		status := doCorrelationGET(t, http.DefaultClient, "http://"+addr+"/fetch?url="+url.QueryEscape(upstream.URL+"/ok"), corrTestAWSKey())
		if status != http.StatusOK {
			t.Fatalf("status = %d, want 200 (hygiene failure must not block)", status)
		}
		ev := waitForEvent(t, sink, emit.EventAllowed)
		requireCorrelation(t, ev, "")
		for _, e := range sink.eventsSnapshot() {
			for k, v := range e.Fields {
				if s, ok := v.(string); ok && strings.Contains(s, corrTestAWSKey()) {
					t.Fatalf("%s.%s leaked the secret-shaped header value", e.Type, k)
				}
			}
		}
	})

	t.Run("oversized and control-char tags omitted", func(t *testing.T) {
		t.Parallel()
		logger, sink := newCorrelationAuditLogger(t)
		addr, _, cleanup := setupForwardProxyWithLogger(t, logger, withCorrelationHeader)
		defer cleanup()
		doCorrelationGET(t, http.DefaultClient, "http://"+addr+"/fetch?url="+url.QueryEscape(upstream.URL+"/ok"), strings.Repeat("a", audit.CorrelationIDMaxBytes+1))
		requireCorrelation(t, waitForEvent(t, sink, emit.EventAllowed), "")
	})

	t.Run("feature off", func(t *testing.T) {
		t.Parallel()
		logger, sink := newCorrelationAuditLogger(t)
		addr, _, cleanup := setupForwardProxyWithLogger(t, logger, nil)
		defer cleanup()
		doCorrelationGET(t, http.DefaultClient, "http://"+addr+"/fetch?url="+url.QueryEscape(upstream.URL+"/ok"), corrTestTag)
		requireCorrelation(t, waitForEvent(t, sink, emit.EventAllowed), "")
	})
}

func forwardProxyClient(t *testing.T, proxyAddr string, tr *http.Transport) *http.Client {
	t.Helper()
	proxyURL, err := url.Parse("http://" + proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	if tr == nil {
		tr = &http.Transport{}
	}
	tr.Proxy = http.ProxyURL(proxyURL)
	t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr, Timeout: corrWaitTimeout}
}

func TestEmitCorrelation_ForwardHTTP(t *testing.T) {
	t.Parallel()
	upstream := okUpstream(t)

	t.Run("allowed", func(t *testing.T) {
		t.Parallel()
		logger, sink := newCorrelationAuditLogger(t)
		addr, _, cleanup := setupForwardProxyWithLogger(t, logger, withCorrelationHeader)
		defer cleanup()
		status := doCorrelationGET(t, forwardProxyClient(t, addr, nil), upstream.URL+"/ok", corrTestTag)
		if status != http.StatusOK {
			t.Fatalf("status = %d, want 200", status)
		}
		requireCorrelation(t, waitForEvent(t, sink, emit.EventForwardHTTP), corrTestTag)
	})

	t.Run("blocked", func(t *testing.T) {
		t.Parallel()
		logger, sink := newCorrelationAuditLogger(t)
		addr, _, cleanup := setupForwardProxyWithLogger(t, logger, withCorrelationHeader)
		defer cleanup()
		status := doCorrelationGET(t, forwardProxyClient(t, addr, nil), upstream.URL+"/?k="+corrTestAWSKey(), corrTestTag)
		if status == http.StatusOK {
			t.Fatal("DLP URL was not blocked")
		}
		requireCorrelation(t, waitForEvent(t, sink, emit.EventBlocked), corrTestTag)
	})
}

// CONNECT passthrough: only headers on the CONNECT request itself are
// visible. Headers inside the encrypted tunnel never reach the event.
func TestEmitCorrelation_ConnectPassthrough(t *testing.T) {
	t.Parallel()
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(backend.Close)
	pool := x509.NewCertPool()
	pool.AddCert(backend.Certificate())

	t.Run("connect header carried", func(t *testing.T) {
		t.Parallel()
		logger, sink := newCorrelationAuditLogger(t)
		addr, _, cleanup := setupForwardProxyWithLogger(t, logger, withCorrelationHeader)
		defer cleanup()
		tr := &http.Transport{
			TLSClientConfig:    &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
			ProxyConnectHeader: http.Header{corrTestHeader: []string{corrTestConnTag}},
		}
		doCorrelationGET(t, forwardProxyClient(t, addr, tr), backend.URL+"/", corrTestInnerTag)
		requireCorrelation(t, waitForEvent(t, sink, emit.EventTunnelOpen), corrTestConnTag)
	})

	t.Run("inner header invisible", func(t *testing.T) {
		t.Parallel()
		logger, sink := newCorrelationAuditLogger(t)
		addr, _, cleanup := setupForwardProxyWithLogger(t, logger, withCorrelationHeader)
		defer cleanup()
		tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}
		doCorrelationGET(t, forwardProxyClient(t, addr, tr), backend.URL+"/", corrTestInnerTag)
		requireCorrelation(t, waitForEvent(t, sink, emit.EventTunnelOpen), "")
	})
}

// setupCorrelationTLSProxy is setupForwardProxyWithTLS with a caller-supplied
// audit logger and the correlation header configured.
func setupCorrelationTLSProxy(t *testing.T, logger *audit.Logger, upstreamRootCAs *x509.CertPool) (string, *x509.CertPool) {
	t.Helper()
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "ca.pem")
	keyPath := filepath.Join(tmpDir, "ca-key.pem")
	ca, caKey, _, err := certgen.GenerateCA("Test", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := certgen.SaveCAForce(certPath, keyPath, ca, caKey); err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)

	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	cfg.APIAllowlist = nil
	cfg.ForwardProxy.Enabled = true
	cfg.ForwardProxy.MaxTunnelSeconds = 10
	cfg.ForwardProxy.IdleTimeoutSeconds = 2
	cfg.FetchProxy.TimeoutSeconds = 5
	cfg.TLSInterception.Enabled = true
	cfg.TLSInterception.CACertPath = certPath
	cfg.TLSInterception.CAKeyPath = keyPath
	withCorrelationHeader(cfg)
	cfg.ApplyDefaults()
	cfg.Internal = nil

	sc := scanner.MustNew(cfg)
	m := metrics.New()
	p, err := New(cfg, logger, sc, m)
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	if err := p.LoadCertCache(cfg); err != nil {
		t.Fatalf("LoadCertCache: %v", err)
	}
	p.tlsTransport = newTLSInterceptTransport(p.ssrfSafeDialContext, m.RecordTLSHandshake, upstreamRootCAs)

	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{Handler: p.buildHandler(http.NewServeMux()), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		p.Close()
	})
	return ln.Addr().String(), pool
}

// TLS interception: inner request headers are visible, so each inner request
// uses its own tag, falling back to the CONNECT request's tag when it has none.
func TestEmitCorrelation_TLSIntercept(t *testing.T) {
	t.Parallel()
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(backend.Close)
	backendPool := x509.NewCertPool()
	backendPool.AddCert(backend.Certificate())

	tests := []struct {
		name       string
		connectTag string
		innerTag   string
		want       string
	}{
		{name: "inner tag wins", connectTag: corrTestConnTag, innerTag: corrTestInnerTag, want: corrTestInnerTag},
		{name: "falls back to connect tag", connectTag: corrTestConnTag, innerTag: "", want: corrTestConnTag},
		{name: "inner tag only", connectTag: "", innerTag: corrTestInnerTag, want: corrTestInnerTag},
		{name: "no tag", connectTag: "", innerTag: "", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			logger, sink := newCorrelationAuditLogger(t)
			addr, caPool := setupCorrelationTLSProxy(t, logger, backendPool)
			tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: caPool, MinVersion: tls.VersionTLS12}}
			if tt.connectTag != "" {
				tr.ProxyConnectHeader = http.Header{corrTestHeader: []string{tt.connectTag}}
			}
			status := doCorrelationGET(t, forwardProxyClient(t, addr, tr), backend.URL+"/?k="+corrTestAWSKey(), tt.innerTag)
			if status == http.StatusOK {
				t.Fatal("DLP URL inside the intercepted tunnel was not blocked")
			}
			requireCorrelation(t, waitForEvent(t, sink, emit.EventBlocked), tt.want)
		})
	}
}

func TestEmitCorrelation_WebSocket(t *testing.T) {
	t.Parallel()
	backendAddr, backendCleanup := wsEchoServer(t)
	t.Cleanup(backendCleanup)

	logger, sink := newCorrelationAuditLogger(t)
	proxyAddr, _, cleanup := setupWSProxyWithLogger(t, logger, withCorrelationHeader, nil, nil)
	t.Cleanup(cleanup)

	conn, err := dialWSConnWithHeader(proxyAddr, backendAddr, http.Header{corrTestHeader: []string{corrTestTag}})
	if err != nil {
		t.Fatalf("ws dial: %v", err)
	}
	requireCorrelation(t, waitForEvent(t, sink, emit.EventWSOpen), corrTestTag)
	_ = conn.Close()
	// The relay outlives the upgrade request; its close event must still
	// carry the tag captured at upgrade time.
	requireCorrelation(t, waitForEvent(t, sink, emit.EventWSClose), corrTestTag)
}

func TestEmitCorrelation_WebSocketWithoutTag(t *testing.T) {
	t.Parallel()
	backendAddr, backendCleanup := wsEchoServer(t)
	t.Cleanup(backendCleanup)

	logger, sink := newCorrelationAuditLogger(t)
	proxyAddr, _, cleanup := setupWSProxyWithLogger(t, logger, withCorrelationHeader, nil, nil)
	t.Cleanup(cleanup)

	conn, err := dialWSConnWithHeader(proxyAddr, backendAddr, nil)
	if err != nil {
		t.Fatalf("ws dial: %v", err)
	}
	requireCorrelation(t, waitForEvent(t, sink, emit.EventWSOpen), "")
	_ = conn.Close()
}

// The CEE adaptive-escalation logger in enforceClientCEE is built from the
// relay's captured tag, separately from the frame logger. Text-frame DLP is off
// so only CEE fragment reassembly sees the key split across two frames, and the
// action is warn so the escalation event is the only emission from that path.
func TestEmitCorrelation_WebSocketCEEAdaptiveEscalation(t *testing.T) {
	t.Parallel()
	backendAddr, backendCleanup := wsEchoServer(t)
	t.Cleanup(backendCleanup)

	logger, sink := newCorrelationAuditLogger(t)
	proxyAddr, _, cleanup := setupWSProxyWithLogger(t, logger, func(cfg *config.Config) {
		withCorrelationHeader(cfg)
		scanText := false
		cfg.WebSocketProxy.ScanTextFrames = &scanText
		cfg.CrossRequestDetection.Enabled = true
		cfg.CrossRequestDetection.Action = config.ActionWarn
		cfg.CrossRequestDetection.EntropyBudget.Enabled = false
		cfg.CrossRequestDetection.FragmentReassembly.Enabled = true
		cfg.CrossRequestDetection.FragmentReassembly.MaxBufferBytes = 65536
		cfg.CrossRequestDetection.FragmentReassembly.WindowMinutes = 5
		cfg.SessionProfiling.Enabled = true
		cfg.SessionProfiling.MaxSessions = 100
		cfg.AdaptiveEnforcement.Enabled = true
		cfg.AdaptiveEnforcement.EscalationThreshold = 3
	}, nil, nil)
	t.Cleanup(cleanup)

	conn, err := dialWSConnWithHeader(proxyAddr, backendAddr, http.Header{corrTestHeader: []string{corrTestTag}})
	if err != nil {
		t.Fatalf("ws dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	half1, half2 := pathSecretHalves()
	for _, part := range []string{half1, half2} {
		if err := wsutil.WriteClientMessage(conn, ws.OpText, []byte(part)); err != nil {
			t.Fatalf("write frame: %v", err)
		}
		if _, _, err := wsutil.ReadServerData(conn); err != nil {
			t.Fatalf("read echo: %v", err)
		}
	}
	requireCorrelation(t, waitForEvent(t, sink, emit.EventAdaptiveEscalation), corrTestTag)
}

func TestEmitCorrelation_ReverseProxy(t *testing.T) {
	t.Parallel()
	cfg := captureMetadataConfig()
	withCorrelationHeader(cfg)
	logger, sink := newCorrelationAuditLogger(t)
	rp := newCaptureMetadataReverseProxy(t, cfg, logger, nil, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/submit", strings.NewReader("token="+corrTestAWSKey()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set(corrTestHeader, corrTestTag)
	rec := httptest.NewRecorder()
	rp.ServeHTTP(rec, req)
	if rec.Code == http.StatusOK {
		t.Fatal("reverse proxy body DLP did not block")
	}
	var found bool
	for _, ev := range sink.eventsSnapshot() {
		if ev.Fields["request_id"] == nil {
			continue
		}
		found = true
		requireCorrelation(t, ev, corrTestTag)
	}
	if !found {
		t.Fatalf("no request-scoped event emitted; events=%v", sink.eventsSnapshot())
	}
}
