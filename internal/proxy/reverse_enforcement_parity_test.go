// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/edition"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

// TestReverseURLDLPBlockRecordsAdaptiveSignal proves an enforce-mode URL DLP
// block still contributes an adaptive SignalBlock to the shared session, the way
// the forward proxy records session activity before its enforce-mode block
// return. Without it a run of blocked reverse requests leaves the session's
// scoped adaptive score at zero, so a caller probing URL-embedded secrets never
// escalates.
func TestReverseURLDLPBlockRecordsAdaptiveSignal(t *testing.T) {
	cfg := reverseParityBaseConfig(t)
	cfg.CrossRequestDetection.Enabled = false
	cfg.Taint.Enabled = false
	cfg.SessionProfiling.Enabled = true
	cfg.SessionProfiling.MaxSessions = 1000
	cfg.SessionProfiling.DomainBurst = 100
	cfg.SessionProfiling.WindowMinutes = 5
	cfg.SessionProfiling.SessionTTLMinutes = 30
	cfg.SessionProfiling.CleanupIntervalSeconds = 600
	cfg.AdaptiveEnforcement.Enabled = true
	cfg.AdaptiveEnforcement.EscalationThreshold = adaptiveTestThreshold
	cfg.RequestBodyScanning.Enabled = true
	cfg.RequestBodyScanning.Action = config.ActionBlock

	var upstreamCalls atomic.Int32
	rp, p, upstreamURL := newReverseParityHarness(t, cfg, func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls.Add(1)
		_, _ = w.Write([]byte("ok"))
	})

	const clientHost = "10.0.0.31"
	// Build the AWS key at runtime so this test's own source does not trip DLP.
	apiKey := "AKIA" + "IOSFODNN7EXAMPLE"
	const blocks = 2
	for i := 0; i < blocks; i++ {
		rec := reverseParityRequest(t, rp, http.MethodGet, "http://reverse.example/x?token="+apiKey, clientHost+":9000", nil)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("request %d: URL DLP must block, got %d: %s", i, rec.Code, rec.Body.String())
		}
		if got := rec.Header().Get(blockreason.HeaderLayer); got != scanner.ScannerDLP {
			t.Fatalf("request %d: block layer = %q, want %q", i, got, scanner.ScannerDLP)
		}
	}
	if got := upstreamCalls.Load(); got != 0 {
		t.Fatalf("URL-DLP-blocked requests reached upstream %d times, want 0", got)
	}

	sm := p.SessionMgrPtr().Load()
	if sm == nil {
		t.Fatal("session manager not initialized")
	}
	sess := sm.GetOrCreate(sessionKeyFor("", clientHost))
	scope := adaptiveScopeForHost(upstreamURL.Hostname())
	if score := sess.ScopedThreatScore(scope); score != blocks*session.SignalPoints[session.SignalBlock] {
		t.Fatalf("blocked URL DLP requests recorded scoped threat score=%.4f, want %.4f for %d block signals", score, blocks*session.SignalPoints[session.SignalBlock], blocks)
	}
}

func TestReverseURLDLPAuditModeRecordsOneNearMiss(t *testing.T) {
	cfg := reverseParityBaseConfig(t)
	cfg.CrossRequestDetection.Enabled = false
	cfg.Taint.Enabled = false
	cfg.SessionProfiling.Enabled = true
	cfg.SessionProfiling.DomainBurst = 100
	cfg.SessionProfiling.WindowMinutes = 5
	cfg.AdaptiveEnforcement.Enabled = true
	cfg.AdaptiveEnforcement.EscalationThreshold = adaptiveTestThreshold
	cfg.RequestBodyScanning.Enabled = true
	cfg.RequestBodyScanning.Action = config.ActionBlock
	enforce := false
	cfg.Enforce = &enforce

	rp, p, upstreamURL := newReverseParityHarness(t, cfg, nil)
	const clientHost = "10.0.0.33"
	apiKey := "AKIA" + "IOSFODNN7EXAMPLE"
	rec := reverseParityRequest(t, rp, http.MethodGet, "http://reverse.example/x?token="+apiKey, clientHost+":9000", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("audit-mode URL DLP status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != "ok" {
		t.Fatalf("audit-mode URL DLP body = %q, want upstream body %q", rec.Body.String(), "ok")
	}

	sess := p.SessionMgrPtr().Load().GetOrCreate(sessionKeyFor("", clientHost))
	scope := adaptiveScopeForHost(upstreamURL.Hostname())
	if score := sess.ScopedThreatScore(scope); score != session.SignalPoints[session.SignalNearMiss] {
		t.Fatalf("audit-mode URL DLP score = %.4f, want one near-miss score %.4f", score, session.SignalPoints[session.SignalNearMiss])
	}
}

// TestReverseHeaderDLPBlockRecordsAdaptiveSignal is the header-DLP sibling of the
// URL-DLP case: an enforce-mode header DLP block must also feed a SignalBlock,
// matching the forward proxy which records the block signal before returning.
func TestReverseHeaderDLPBlockRecordsAdaptiveSignal(t *testing.T) {
	cfg := reverseParityBaseConfig(t)
	cfg.CrossRequestDetection.Enabled = false
	cfg.Taint.Enabled = false
	cfg.SessionProfiling.Enabled = true
	cfg.SessionProfiling.MaxSessions = 1000
	cfg.SessionProfiling.DomainBurst = 100
	cfg.SessionProfiling.WindowMinutes = 5
	cfg.SessionProfiling.SessionTTLMinutes = 30
	cfg.SessionProfiling.CleanupIntervalSeconds = 600
	cfg.AdaptiveEnforcement.Enabled = true
	cfg.AdaptiveEnforcement.EscalationThreshold = adaptiveTestThreshold
	cfg.RequestBodyScanning.Enabled = true
	cfg.RequestBodyScanning.Action = config.ActionBlock
	cfg.RequestBodyScanning.ScanHeaders = true
	cfg.RequestBodyScanning.HeaderMode = "all"

	var upstreamCalls atomic.Int32
	rp, p, upstreamURL := newReverseParityHarness(t, cfg, func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls.Add(1)
		_, _ = w.Write([]byte("ok"))
	})

	const clientHost = "10.0.0.32"
	apiKey := "AKIA" + "IOSFODNN7EXAMPLE"
	const blocks = 2
	for i := 0; i < blocks; i++ {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://reverse.example/y", http.NoBody)
		req.RemoteAddr = clientHost + ":9100"
		req.Header.Set("X-Secret", apiKey)
		rr := httptest.NewRecorder()
		rp.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("request %d: header DLP must block, got %d: %s", i, rr.Code, rr.Body.String())
		}
		if got := rr.Header().Get(blockreason.HeaderLayer); got != scanner.ScannerDLP {
			t.Fatalf("request %d: block layer = %q, want %q", i, got, scanner.ScannerDLP)
		}
	}
	if got := upstreamCalls.Load(); got != 0 {
		t.Fatalf("header-DLP-blocked requests reached upstream %d times, want 0", got)
	}

	sm := p.SessionMgrPtr().Load()
	if sm == nil {
		t.Fatal("session manager not initialized")
	}
	sess := sm.GetOrCreate(sessionKeyFor("", clientHost))
	scope := adaptiveScopeForHost(upstreamURL.Hostname())
	if score := sess.ScopedThreatScore(scope); score != blocks*session.SignalPoints[session.SignalBlock] {
		t.Fatalf("blocked header DLP requests recorded scoped threat score=%.4f, want %.4f for %d block signals", score, blocks*session.SignalPoints[session.SignalBlock], blocks)
	}
}

// TestReverseDLPBlockAdaptiveSignalHonorsExemptDomain proves the reverse DLP
// block signal honors adaptive_enforcement.exempt_domains exactly as the forward
// proxy does: a DLP block to an exempt upstream still returns the 403 but records
// the activity as ALLOWED (score-neutral), so a run of blocked requests to that
// trusted destination never escalates the scoped adaptive score. The two exempt
// cases are calibrated by their non-exempt siblings in the SAME table: with the
// same DLP trigger and no exemption the score rises above zero, which proves the
// zero score in the exempt case is the exemption at work and not a block path
// that silently stopped recording. Covers both the URL-DLP (~reverse.go:923) and
// header-DLP (~reverse.go:972) block sites, which share recordRequestBlockSignal.
func TestReverseDLPBlockAdaptiveSignalHonorsExemptDomain(t *testing.T) {
	cases := []struct {
		name   string
		header bool
		exempt bool
	}{
		{name: "url_dlp_not_exempt_escalates", header: false, exempt: false},
		{name: "url_dlp_exempt_stays_flat", header: false, exempt: true},
		{name: "header_dlp_not_exempt_escalates", header: true, exempt: false},
		{name: "header_dlp_exempt_stays_flat", header: true, exempt: true},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := reverseParityBaseConfig(t)
			cfg.CrossRequestDetection.Enabled = false
			cfg.Taint.Enabled = false
			cfg.SessionProfiling.Enabled = true
			cfg.SessionProfiling.MaxSessions = 1000
			cfg.SessionProfiling.DomainBurst = 100
			cfg.SessionProfiling.WindowMinutes = 5
			cfg.SessionProfiling.SessionTTLMinutes = 30
			cfg.SessionProfiling.CleanupIntervalSeconds = 600
			cfg.AdaptiveEnforcement.Enabled = true
			cfg.AdaptiveEnforcement.EscalationThreshold = adaptiveTestThreshold
			cfg.RequestBodyScanning.Enabled = true
			cfg.RequestBodyScanning.Action = config.ActionBlock
			if tc.header {
				cfg.RequestBodyScanning.ScanHeaders = true
				cfg.RequestBodyScanning.HeaderMode = "all"
			}
			if tc.exempt {
				cfg.AdaptiveEnforcement.ExemptDomains = []string{"127.0.0.1"}
			}

			rp, p, upstreamURL := newReverseParityHarness(t, cfg, nil)
			if tc.exempt && upstreamURL.Hostname() != "127.0.0.1" {
				t.Fatalf("exemption fixture host = %q, want 127.0.0.1", upstreamURL.Hostname())
			}

			// Distinct client host per subtest so their sessions do not share state.
			clientHost := fmt.Sprintf("10.0.0.%d", 40+i)
			apiKey := "AKIA" + "IOSFODNN7EXAMPLE"
			const blocks = 3
			for b := 0; b < blocks; b++ {
				var rr *httptest.ResponseRecorder
				if tc.header {
					req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://reverse.example/y", http.NoBody)
					req.RemoteAddr = clientHost + ":9200"
					req.Header.Set("X-Secret", apiKey)
					rr = httptest.NewRecorder()
					rp.ServeHTTP(rr, req)
				} else {
					rr = reverseParityRequest(t, rp, http.MethodGet, "http://reverse.example/x?token="+apiKey, clientHost+":9200", nil)
				}
				if rr.Code != http.StatusForbidden {
					t.Fatalf("request %d: DLP must block regardless of exemption, got %d: %s", b, rr.Code, rr.Body.String())
				}
			}

			sm := p.SessionMgrPtr().Load()
			if sm == nil {
				t.Fatal("session manager not initialized")
			}
			sess := sm.GetOrCreate(sessionKeyFor("", clientHost))
			scope := adaptiveScopeForHost(upstreamURL.Hostname())
			score := sess.ScopedThreatScore(scope)
			if tc.exempt {
				if got := sess.BaselineMetrics().Requests; got != blocks {
					t.Fatalf("adaptive-exempt blocked DLP activity recorded %d requests, want %d", got, blocks)
				}
				if score != 0 {
					t.Fatalf("blocked DLP requests to an adaptive-exempt upstream must stay score-neutral, "+
						"got scoped threat score=%.4f (want 0); the exempt block still fed an escalation signal", score)
				}
			} else if score <= 0 {
				t.Fatalf("blocked DLP requests to a non-exempt upstream must escalate, "+
					"got scoped threat score=%.4f (want >0); the block path recorded no adaptive signal", score)
			}
		})
	}
}

func TestReverseDLPWarnRecordsAdaptiveNearMiss(t *testing.T) {
	cases := []struct {
		name   string
		header bool
		exempt bool
	}{
		{name: "url_warn"},
		{name: "url_warn_exempt", exempt: true},
		{name: "header_warn", header: true},
		{name: "header_warn_exempt", header: true, exempt: true},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := reverseParityBaseConfig(t)
			cfg.CrossRequestDetection.Enabled = false
			cfg.Taint.Enabled = false
			cfg.SessionProfiling.Enabled = true
			cfg.SessionProfiling.DomainBurst = 100
			cfg.SessionProfiling.WindowMinutes = 5
			cfg.AdaptiveEnforcement.Enabled = true
			cfg.AdaptiveEnforcement.EscalationThreshold = adaptiveTestThreshold
			cfg.RequestBodyScanning.Enabled = true
			cfg.RequestBodyScanning.Action = config.ActionWarn
			cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{
				Name: "reverse_warn_probe", Regex: `reversewarn-[A-Za-z0-9]{12}`, Severity: config.SeverityMedium,
			})
			if tc.header {
				cfg.RequestBodyScanning.ScanHeaders = true
				cfg.RequestBodyScanning.HeaderMode = "all"
			}
			if tc.exempt {
				cfg.AdaptiveEnforcement.ExemptDomains = []string{"127.0.0.1"}
			}

			rp, p, upstreamURL := newReverseParityHarness(t, cfg, nil)
			if tc.exempt && upstreamURL.Hostname() != "127.0.0.1" {
				t.Fatalf("exemption fixture host = %q, want 127.0.0.1", upstreamURL.Hostname())
			}
			clientHost := fmt.Sprintf("10.0.1.%d", 40+i)
			apiKey := "reversewarn-abcdefghijkl"
			probeScanner := scanner.MustNew(cfg)
			probe := probeScanner.ScanTextForDLP(t.Context(), apiKey)
			probeScanner.Close()
			if probe.Clean {
				t.Fatal("DLP fixture did not independently match the configured warning pattern")
			}
			var rr *httptest.ResponseRecorder
			if tc.header {
				req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://reverse.example/y", http.NoBody)
				req.RemoteAddr = clientHost + ":9200"
				req.Header.Set("X-Secret", apiKey)
				rr = httptest.NewRecorder()
				rp.ServeHTTP(rr, req)
			} else {
				rr = reverseParityRequest(t, rp, http.MethodGet, "http://reverse.example/x?token="+apiKey, clientHost+":9200", nil)
			}
			if rr.Code != http.StatusOK {
				t.Fatalf("warn-mode DLP request = %d, want 200", rr.Code)
			}
			if rr.Body.String() != "ok" {
				t.Fatalf("warn-mode DLP body = %q, want upstream body %q", rr.Body.String(), "ok")
			}

			sess := p.SessionMgrPtr().Load().GetOrCreate(sessionKeyFor("", clientHost))
			score := sess.ScopedThreatScore(adaptiveScopeForHost(upstreamURL.Hostname()))
			if tc.exempt {
				if got := sess.BaselineMetrics().Requests; got != 1 {
					t.Fatalf("adaptive-exempt warn DLP activity recorded %d requests, want 1", got)
				}
				if score != 0 {
					t.Fatalf("adaptive-exempt warn finding score = %.4f, want 0", score)
				}
			} else if want := session.SignalPoints[session.SignalNearMiss]; score != want {
				t.Fatalf("warn finding score = %.4f, want near-miss score %.4f", score, want)
			}
		})
	}
}

// --- Cross-transport: reverse uses the SAME CEE session key as forward --------

// TestReverseSharesCEESessionKeyWithForward proves the reverse path accumulates
// cross-request entropy under the exact transport-independent key a forward
// request from the same bound identity would use. The expected key is built with
// the production ceeSessionKey derivation (not a copy), and the owner's entropy
// tracker is checked for usage under that key after one reverse request.
func TestReverseSharesCEESessionKeyWithForward(t *testing.T) {
	cfg := reverseParityBaseConfig(t)
	cfg.Taint.Enabled = false
	cfg.CrossRequestDetection = config.CrossRequestDetection{
		Enabled: true,
		Action:  config.ActionWarn, // observe: we assert accumulation, not a block
		EntropyBudget: config.CrossRequestEntropyBudget{
			Enabled:       true,
			BitsPerWindow: 1000.0, // high budget so a single request never trips it
			WindowMinutes: 5,
			Action:        config.ActionWarn,
		},
	}
	rp, p, upstreamURL := newReverseParityHarness(t, cfg, nil)

	const clientHost = "203.0.113.7"
	// Derive the identity the reverse path will resolve using the SAME production
	// function reverse.resolveAgentIdentity uses for the no-edition path.
	idReq := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://reverse.example/q?p=abcdefghij0123456789", nil)
	resolved := edition.ResolveAgentIdentity(idReq, nil, cfg.DefaultAgentIdentity, cfg.BindDefaultAgentIdentity)
	expectedKey := ceeSessionKey(resolved.Name, clientHost, resolved.Auth)

	et := p.EntropyTrackerPtr().Load()
	if et == nil {
		t.Fatal("entropy tracker not initialized")
	}
	if before := et.CurrentUsage(expectedKey); before != 0 {
		t.Fatalf("entropy usage under shared key should start at 0, got %.4f", before)
	}

	resp := reverseParityRequest(t, rp, http.MethodGet, "http://reverse.example/q?p=abcdefghij0123456789", clientHost+":4444", nil)
	if resp.Code != http.StatusOK || resp.Body.String() != "ok" {
		t.Fatalf("reverse request = %d %q, want 200 ok", resp.Code, resp.Body.String())
	}

	afterReverse := et.CurrentUsage(expectedKey)
	if afterReverse <= 0 {
		t.Fatalf("reverse request recorded no cross-request entropy under the shared key %q "+
			"(usage=%.4f); the reverse CEE join does not use the transport-independent key", expectedKey, afterReverse)
	}

	forwardURL := *upstreamURL
	forwardURL.Path = "/q"
	forwardURL.RawQuery = "p=zyxwvutsrq9876543210"
	forwardReq := httptest.NewRequestWithContext(t.Context(), http.MethodGet, forwardURL.String(), http.NoBody)
	forwardReq.RemoteAddr = clientHost + ":5555"
	forwardRec := httptest.NewRecorder()
	p.handleForwardHTTP(forwardRec, forwardReq)
	if forwardRec.Code != http.StatusOK || forwardRec.Body.String() != "ok" {
		t.Fatalf("forward request = %d %q, want 200 ok", forwardRec.Code, forwardRec.Body.String())
	}
	if afterForward := et.CurrentUsage(expectedKey); afterForward <= afterReverse {
		t.Fatalf("forward request did not add entropy to reverse key %q: before=%.4f after=%.4f", expectedKey, afterReverse, afterForward)
	}

	const otherClient = "203.0.113.8"
	otherReq := httptest.NewRequestWithContext(t.Context(), http.MethodGet, forwardURL.String(), http.NoBody)
	otherReq.RemoteAddr = otherClient + ":5555"
	otherRec := httptest.NewRecorder()
	p.handleForwardHTTP(otherRec, otherReq)
	if otherRec.Code != http.StatusOK {
		t.Fatalf("distinct-client forward request = %d, want 200: %s", otherRec.Code, otherRec.Body.String())
	}
	otherID := edition.ResolveAgentIdentity(otherReq, nil, cfg.DefaultAgentIdentity, cfg.BindDefaultAgentIdentity)
	otherKey := ceeSessionKey(otherID.Name, otherClient, otherID.Auth)
	if otherKey == expectedKey || et.CurrentUsage(otherKey) <= 0 {
		t.Fatalf("distinct client did not use an isolated CEE key: shared=%q other=%q usage=%.4f", expectedKey, otherKey, et.CurrentUsage(otherKey))
	}
}

// --- Receipt-asserting harness for the per-session control block paths --------

// newReverseParityHarnessWithReceipts wires the parity harness (owner Proxy +
// per-session controls) AND a signed receipt emitter pointed at a temp dir, so a
// test can assert the operator-visible receipt (layer + verdict + transport) a
// block path emits. Returns the handler, owner proxy, upstream URL, the recorder
// dir, a closeRecorder that flushes the recorder before extraction, and the
// verify public key. Mirrors reverseReceiptParitySetup's emitter wiring but on
// the owner-wired handler the control paths need.
func newReverseParityHarnessWithReceipts(t *testing.T, cfg *config.Config, upstreamHandler http.HandlerFunc) (rp *ReverseProxyHandler, owner *Proxy, upstreamURL *url.URL, dir string, closeRecorder func(), pubKey ed25519.PublicKey) {
	t.Helper()
	rp, owner, upstreamURL = newReverseParityHarness(t, cfg, upstreamHandler)
	dir = t.TempDir()
	emitter, rec, key := newCoverageEmitter(t, dir)
	var emPtr atomic.Pointer[receipt.Emitter]
	emPtr.Store(emitter)
	rp.SetReceiptEmitter(&emPtr)
	var once sync.Once
	closeRecorder = func() {
		once.Do(func() {
			if err := rec.Close(); err != nil {
				t.Fatalf("recorder close: %v", err)
			}
		})
	}
	t.Cleanup(closeRecorder)
	return rp, owner, upstreamURL, dir, closeRecorder, key
}

// assertReverseBlockReceipt confirms the block named by the response's recorded-
// receipt header is a signed, verifiable receipt with the expected verdict and
// layer on the reverse transport. headerID is read from the response BEFORE
// closeRecorder is called; extraction happens after the recorder is flushed.
func assertReverseBlockReceipt(t *testing.T, dir, headerID string, pubKey ed25519.PublicKey, wantVerdict, wantLayer string) {
	t.Helper()
	if headerID == "" {
		t.Fatalf("%s header is empty: the block emitted no recorded receipt", blockreason.HeaderRecordedReceipt)
	}
	for _, rcpt := range extractReceiptsFromDir(t, dir) {
		ar := rcpt.ActionRecord
		if ar.ActionID != headerID {
			continue
		}
		if err := receipt.VerifyWithKey(rcpt, hex.EncodeToString(pubKey)); err != nil {
			t.Fatalf("recorded block receipt %q does not verify: %v", headerID, err)
		}
		if ar.Transport != TransportReverse {
			t.Fatalf("receipt transport = %q, want %q", ar.Transport, TransportReverse)
		}
		if ar.Verdict != wantVerdict {
			t.Fatalf("receipt verdict = %q, want %q", ar.Verdict, wantVerdict)
		}
		if ar.Layer != wantLayer {
			t.Fatalf("receipt layer = %q, want %q", ar.Layer, wantLayer)
		}
		return
	}
	t.Fatalf("%s = %q names no recorded receipt in %s", blockreason.HeaderRecordedReceipt, headerID, dir)
}

// --- Control 1 (anomaly block): a session-profiling anomaly denies the request -

// TestReverseSessionProfilingAnomalyBlockEmitsReceipt proves an enforce-mode
// session-profiling anomaly on the reverse path denies the request with the
// session_profiling layer and emits a signed block receipt, the way the
// fetch/forward transports do. With AnomalyAction=block and DomainBurst=1, the
// first reverse request records the upstream host as a domain-burst anomaly and
// is blocked before it reaches upstream. Covers the reverse handler's
// sessionResult.Blocked branch and its receipt.
func TestReverseSessionProfilingAnomalyBlockEmitsReceipt(t *testing.T) {
	cfg := reverseParityBaseConfig(t)
	cfg.CrossRequestDetection.Enabled = false
	cfg.Taint.Enabled = false
	cfg.AdaptiveEnforcement.Enabled = false
	cfg.SessionProfiling.Enabled = true
	cfg.SessionProfiling.MaxSessions = 1000
	cfg.SessionProfiling.DomainBurst = 1 // first recorded domain trips the burst
	cfg.SessionProfiling.WindowMinutes = 5
	cfg.SessionProfiling.SessionTTLMinutes = 30
	cfg.SessionProfiling.CleanupIntervalSeconds = 600
	cfg.SessionProfiling.AnomalyAction = config.ActionBlock

	rp, _, _, dir, closeRecorder, pubKey := newReverseParityHarnessWithReceipts(t, cfg, func(http.ResponseWriter, *http.Request) {
		t.Error("session-profiling-blocked request must not reach upstream")
	})

	const clientHost = "10.0.0.41"
	resp := reverseParityRequest(t, rp, http.MethodGet, "http://reverse.example/x", clientHost+":9200", nil)
	if resp.Code != http.StatusForbidden {
		t.Fatalf("session-profiling anomaly must block, got %d: %s", resp.Code, resp.Body.String())
	}
	if body := resp.Body.String(); !strings.Contains(body, "session") {
		t.Fatalf("block body should name the session-profiling reason, got %q", body)
	}
	headerID := resp.Header().Get(blockreason.HeaderRecordedReceipt)
	closeRecorder()
	assertReverseBlockReceipt(t, dir, headerID, pubKey, config.ActionBlock, "session_profiling")
}

// --- Control 2 (taint ask): an ask with no approver is refused and blocks ------

// TestReverseTaintAskRefusedWithoutApproverBlocks proves the reverse request
// path enforces a taint ASK verdict: a write carried under UNTRUSTED (not
// hostile) external taint resolves to PolicyAsk, and with no HITL approver
// wired the ask is refused, so the request is denied with the taint_policy
// layer. Distinct from TestReverseTaintFromResponseBlocksLaterRequest, which
// exercises the hostile PolicyBlock arm; this covers the PolicyAsk arm and the
// refused-ask block. Untrusted taint is seeded with the same production
// observation helper the response path uses (an external read with no
// injection), then a write from that identity is asked-and-refused.
func TestReverseTaintAskRefusedWithoutApproverBlocks(t *testing.T) {
	cfg := reverseParityBaseConfig(t)
	cfg.CrossRequestDetection.Enabled = false
	cfg.AdaptiveEnforcement.Enabled = false
	if !cfg.Taint.Enabled {
		t.Fatal("precondition: taint must be enabled by default")
	}
	// Taint risk state lives in the session store, so session profiling must be
	// on (anomaly action stays warn so only the taint control produces a block).
	cfg.SessionProfiling.Enabled = true
	cfg.SessionProfiling.MaxSessions = 1000
	cfg.SessionProfiling.DomainBurst = 100
	cfg.SessionProfiling.WindowMinutes = 5
	cfg.SessionProfiling.SessionTTLMinutes = 30
	cfg.SessionProfiling.CleanupIntervalSeconds = 600

	rp, p, _, dir, closeRecorder, pubKey := newReverseParityHarnessWithReceipts(t, cfg, func(http.ResponseWriter, *http.Request) {
		t.Error("taint-asked write must not reach upstream")
	})

	const clientHost = "10.0.0.42"
	idReq := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://reverse.example/x", nil)
	resolved := edition.ResolveAgentIdentity(idReq, nil, cfg.DefaultAgentIdentity, cfg.BindDefaultAgentIdentity)
	sm := p.SessionMgrPtr().Load()
	if sm == nil {
		t.Fatal("session manager not initialized")
	}
	rec := sm.GetOrCreate(responseTaintSessionKey(resolved.Name, clientHost, resolved.Auth))
	// Seed UNTRUSTED (not hostile) external taint: an external read with no
	// injection (promptHit=false), so a later write ASKs rather than BLOCKS.
	observeHTTPResponseTaint(rec, cfg, "https://news.vendor.example/article/42", "text/html", "reverse_response", false)
	if snap := rec.RiskSnapshot(); snap.Level != session.TaintExternalUntrusted {
		t.Fatalf("seed: want untrusted external taint, got level=%v (contaminated=%v)", snap.Level, snap.Contaminated)
	}

	resp := reverseParityRequest(t, rp, http.MethodPost, "http://reverse.example/publish", clientHost+":9300", []byte("payload"))
	if resp.Code != http.StatusForbidden {
		t.Fatalf("write under untrusted taint with the ask refused (no approver) must be denied, got %d: %s", resp.Code, resp.Body.String())
	}
	headerID := resp.Header().Get(blockreason.HeaderRecordedReceipt)
	closeRecorder()
	assertReverseBlockReceipt(t, dir, headerID, pubKey, config.ActionBlock, "taint_policy")
}

// --- Control 3 (CEE block_all): a globally escalated session denies a clean req -

// TestReverseCEEBlockAllDeniesGloballyEscalatedSession proves the reverse CEE
// block_all denial: when the shared folded session sits at a block_all
// escalation level on the GLOBAL (unscoped) lane but NOT on the reverse
// upstream's scope, the earlier session-profiling block_all check (which reads
// the upstream-scoped effective level) does not fire, and a clean reverse
// request that carries no entropy/fragment finding is instead denied by the CEE
// block_all path with the adaptive session-deny layer.
//
// That global-but-not-upstream-scoped state is exactly what a forward request to
// a DIFFERENT destination from the same bound identity leaves on the shared key:
// forward records a destination-scoped signal, which mirrors into the global
// lane without making it authoritative. It is the only state that reaches the
// CEE block_all path, because CEE's own escalation goes through the global
// authoritative lane and would trip the session-profiling block_all first. The
// precondition below asserts the upstream-scoped level is 0 so the test cannot
// silently pass by taking the session-profiling path instead.
func TestReverseCEEBlockAllDeniesGloballyEscalatedSession(t *testing.T) {
	cfg := reverseParityBaseConfig(t)
	cfg.Taint.Enabled = false
	cfg.SessionProfiling.Enabled = true
	cfg.SessionProfiling.MaxSessions = 1000
	cfg.SessionProfiling.DomainBurst = 100
	cfg.SessionProfiling.WindowMinutes = 5
	cfg.SessionProfiling.SessionTTLMinutes = 30
	cfg.SessionProfiling.CleanupIntervalSeconds = 600
	cfg.AdaptiveEnforcement.Enabled = true
	cfg.AdaptiveEnforcement.EscalationThreshold = adaptiveTestThreshold
	cfg.AdaptiveEnforcement.Levels.Elevated.BlockAll = ptrBool(true)
	// CEE active but with a budget high enough that a single clean request never
	// trips entropy or fragment detection: the denial must come from the
	// escalated session, not this request's payload (ceeRes.Blocked must be false
	// so the block_all arm, not the entropy-block arm, is what fires).
	cfg.CrossRequestDetection = config.CrossRequestDetection{
		Enabled: true,
		Action:  config.ActionWarn,
		EntropyBudget: config.CrossRequestEntropyBudget{
			Enabled:       true,
			BitsPerWindow: 100000.0,
			WindowMinutes: 5,
			Action:        config.ActionWarn,
		},
	}
	// A bound identity gives a stable agent name so the folded key is stable and
	// distinct from a bare client IP.
	cfg.DefaultAgentIdentity = "reverse-agent"
	cfg.BindDefaultAgentIdentity = true

	rp, p, upstreamURL, dir, closeRecorder, pubKey := newReverseParityHarnessWithReceipts(t, cfg, func(http.ResponseWriter, *http.Request) {
		t.Error("CEE-block_all-denied request must not reach upstream")
	})

	const clientHost = "203.0.113.9"
	idReq := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://reverse.example/clean", nil)
	resolved := edition.ResolveAgentIdentity(idReq, nil, cfg.DefaultAgentIdentity, cfg.BindDefaultAgentIdentity)
	sm := p.SessionMgrPtr().Load()
	if sm == nil {
		t.Fatal("session manager not initialized")
	}
	sess := sm.GetOrCreate(ceeSessionKey(resolved.Name, clientHost, resolved.Auth))

	// Escalate the GLOBAL lane to block_all via a scope OTHER than the reverse
	// upstream's, using the production scoped-signal API. RecordScopedSignal
	// mirrors into the session-wide escalation level without making it
	// authoritative, so the upstream-scoped effective level stays 0.
	otherScope := adaptiveScopeForHost("other-destination.example")
	upstreamScope := adaptiveScopeForHost(upstreamURL.Hostname())
	if otherScope == upstreamScope {
		t.Fatal("test setup: the seeded scope must differ from the reverse upstream scope")
	}
	for attempts := 0; sess.EscalationLevel() < 1 && attempts < 10; attempts++ {
		sess.RecordScopedSignal(otherScope, session.SignalBlock, adaptiveTestThreshold)
	}
	if got := sess.EscalationLevel(); got < 1 {
		t.Fatalf("global escalation level = %d after 10 signals, want at least 1", got)
	}
	// The shadow guard: if the upstream-scoped effective level were >0 the
	// session-profiling block_all would fire first and this test would not
	// exercise the CEE block_all path at all.
	if lvl := sess.EffectiveEscalationLevel(upstreamScope); lvl != 0 {
		t.Fatalf("precondition: upstream-scoped effective level must be 0 (got %d); "+
			"session-profiling block_all would shadow the CEE block_all path", lvl)
	}

	resp := reverseParityRequest(t, rp, http.MethodGet, "http://reverse.example/clean", clientHost+":9400", nil)
	if resp.Code != http.StatusForbidden {
		t.Fatalf("clean reverse request on a globally block_all session must be CEE-denied, got %d: %s", resp.Code, resp.Body.String())
	}
	if body := resp.Body.String(); !containsReverseAdaptiveDeny(body) {
		t.Fatalf("expected an adaptive session-deny block reason, got %q", body)
	}
	headerID := resp.Header().Get(blockreason.HeaderRecordedReceipt)
	closeRecorder()
	assertReverseBlockReceipt(t, dir, headerID, pubKey, config.ActionBlock, adaptiveSessionDeny)
}
