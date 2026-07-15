// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// This file holds adversarial regression tests for the three named CEE
// bypasses. Each test encodes the SECURE invariant: it fails against the
// pre-fix code (proving the gap is real) and passes after the fix (proving the
// gap is closed).

// ceeFragmentBlockCfg returns a CEE config that blocks on fragment-reassembly
// DLP matches, with the entropy budget disabled so fragment behavior is
// isolated.
func ceeFragmentBlockCfg() config.CrossRequestDetection {
	return config.CrossRequestDetection{
		Enabled: true,
		Action:  config.ActionBlock,
		FragmentReassembly: config.CrossRequestFragments{
			Enabled:        true,
			MaxBufferBytes: 65536,
			WindowMinutes:  5,
		},
	}
}

// --- Bypass #1: session-key partitioning evasion -------------------------

// TestCEEBypass_AgentRotationDoesNotPartition proves that an attacker cannot
// evade fragment reassembly by rotating the self-declared X-Pipelock-Agent
// header per request. The agent identity is attacker-controlled
// (self-declared); only the client IP (RemoteAddr) is a trustworthy anchor.
// Splitting a secret across requests under DIFFERENT agent names must still
// reassemble against the IP-anchored bucket and block the completing request.
//
// Pre-fix: each rotated agent gets its own bucket (agent|ip), so neither
// bucket ever holds 2 fragments and the secret leaks. This test fails.
// Post-fix: self-declared agents fold to the client IP, so both fragments land
// in one bucket and the completing request is blocked.
func TestCEEBypass_AgentRotationDoesNotPartition(t *testing.T) {
	// Each scenario gets its own proxy (and thus its own fragment buffer) so
	// the shared IP-anchored bucket from one scenario cannot leak into the
	// next. After the fix every loopback fetch folds to the same client-IP
	// key, so a single proxy cannot host two independent split-secret runs.

	// Positive control: SAME agent across both requests must block on the
	// completing request. Proves the detector and test wiring work.
	t.Run("same_agent_blocks", func(t *testing.T) {
		ts, target := testCEEProxy(t, ceeFragmentBlockCfg())
		frag1 := target.URL + "/a?x=" + testCEEAWSKeyPrefix
		frag2 := target.URL + "/a?x=" + testCEEAWSKeySuffix

		_, code1 := fetchThroughProxyWithAgent(t, ts.URL, frag1, "agent-a")
		if code1 == http.StatusForbidden {
			t.Fatalf("first fragment should not block, got %d", code1)
		}
		fr2, code2 := fetchThroughProxyWithAgent(t, ts.URL, frag2, "agent-a")
		if code2 != http.StatusForbidden || !fr2.Blocked {
			t.Fatalf("completing fragment under same agent must block, got code=%d blocked=%v", code2, fr2.Blocked)
		}
	})

	// The attack: ROTATE the agent identity per request. The secure invariant
	// is that the completing fragment is still blocked, because keying is
	// anchored to the client IP, not the attacker-controlled agent name.
	t.Run("rotated_agent_still_blocks", func(t *testing.T) {
		ts, target := testCEEProxy(t, ceeFragmentBlockCfg())
		frag1 := target.URL + "/b?x=" + testCEEAWSKeyPrefix
		frag2 := target.URL + "/b?x=" + testCEEAWSKeySuffix

		_, code1 := fetchThroughProxyWithAgent(t, ts.URL, frag1, "rot-agent-1")
		if code1 == http.StatusForbidden {
			t.Fatalf("first fragment should not block, got %d", code1)
		}
		fr2, code2 := fetchThroughProxyWithAgent(t, ts.URL, frag2, "rot-agent-2")
		if code2 != http.StatusForbidden || !fr2.Blocked {
			t.Fatalf("BYPASS: rotating the agent identifier evaded fragment reassembly "+
				"(code=%d blocked=%v): the secret leaked across buckets", code2, fr2.Blocked)
		}
	})
}

// TestCEEBypass_FetchWarnModeBlockAllUsesFoldedKey proves that CEE adaptive
// enforcement follows the same folded key as fragment reassembly. In warn/audit
// mode, a fragment DLP hit records an adaptive signal instead of directly
// blocking. The completing rotated-agent request must still be denied when that
// signal escalates the IP-anchored CEE session to block_all.
func TestCEEBypass_FetchWarnModeBlockAllUsesFoldedKey(t *testing.T) {
	target := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer target.Close()

	cfg := adaptiveConfigBlockAll()
	cfg.AdaptiveEnforcement.EscalationThreshold = 3.0 // one FragmentDLP signal reaches elevated
	cfg.CrossRequestDetection.Enabled = true
	cfg.CrossRequestDetection.Action = config.ActionWarn
	cfg.CrossRequestDetection.EntropyBudget.Enabled = false
	cfg.CrossRequestDetection.FragmentReassembly = config.CrossRequestFragments{
		Enabled:        true,
		MaxBufferBytes: 65536,
		WindowMinutes:  5,
	}

	sc := scanner.MustNew(cfg)
	defer sc.Close()
	p, err := New(cfg, audit.NewNop(), sc, metrics.New())
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	defer p.Close()

	ts := httptest.NewServer(p.Handler())
	defer ts.Close()

	_, code1 := fetchThroughProxyWithAgent(t, ts.URL, target.URL+"/x?p="+testCEEAWSKeyPrefix, "rot-agent-1")
	if code1 == http.StatusForbidden {
		t.Fatalf("first fragment should not block, got %d", code1)
	}

	fr2, code2 := fetchThroughProxyWithAgent(t, ts.URL, target.URL+"/x?p="+testCEEAWSKeySuffix, "rot-agent-2")
	if code2 != http.StatusForbidden || !fr2.Blocked {
		t.Fatalf("BYPASS: warn-mode CEE escalated the folded session but fetch did not enforce block_all "+
			"(code=%d blocked=%v)", code2, fr2.Blocked)
	}
}

// TestCEEKeyAgent_TrustModel pins the trust classification that closes the
// partitioning bypass: only infrastructure-bound and config-default identities
// (which an attacker cannot vary per request) may narrow the CEE bucket below
// the client IP. Header/query-derived identities (matched or self-declared)
// must fold to the empty agent so the bucket key is the IP alone.
func TestCEEKeyAgent_TrustModel(t *testing.T) {
	const name = "agent-x"
	tests := []struct {
		name string
		auth envelope.ActorAuth
		want string
	}{
		{"bound is trusted", envelope.ActorAuthBound, name},
		{"config-default is trusted", envelope.ActorAuthConfigDefault, name},
		{"matched folds (header-supplied)", envelope.ActorAuthMatched, ""},
		{"self-declared folds (header/query-supplied)", envelope.ActorAuthSelfDeclared, ""},
		{"empty auth folds (unknown provenance)", envelope.ActorAuth(""), ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ceeKeyAgent(name, tt.auth); got != tt.want {
				t.Errorf("ceeKeyAgent(%q, %q) = %q, want %q", name, tt.auth, got, tt.want)
			}
		})
	}
}

// TestCEESessionKey_FoldsUntrustedAgent verifies the provenance-aware key
// builder: untrusted identities collapse to the IP-only key, trusted ones keep
// the agent namespace. Rotating untrusted agent names must produce a single,
// stable key so accumulation cannot be partitioned.
func TestCEESessionKey_FoldsUntrustedAgent(t *testing.T) {
	ip := testCEEClientIP

	// Two different self-declared agent names must yield the SAME key.
	k1 := ceeSessionKey("rot-agent-1", ip, envelope.ActorAuthSelfDeclared)
	k2 := ceeSessionKey("rot-agent-2", ip, envelope.ActorAuthSelfDeclared)
	if k1 != ip || k2 != ip {
		t.Fatalf("self-declared agents must fold to IP-only key: k1=%q k2=%q ip=%q", k1, k2, ip)
	}
	if k1 != k2 {
		t.Fatalf("rotating self-declared agents must not partition the bucket: %q != %q", k1, k2)
	}

	// A bound identity keeps its namespace (spoof-proof per-listener binding).
	kb := ceeSessionKey("bound-agent", ip, envelope.ActorAuthBound)
	if kb != "bound-agent|"+ip {
		t.Fatalf("bound agent must keep namespace, got %q", kb)
	}
}

// --- Bypass #2: cross-transport fragment evasion -------------------------

// TestCEEBypass_CrossTransportSharesBuffer proves the fragment buffer is shared
// across transports for one logical session: splitting a secret across two
// DIFFERENT transports (fetch and the forward proxy) does NOT silo the
// fragments per-transport. The entropy tracker and fragment buffer are single
// proxy-wide instances keyed by the transport-independent ceeSessionKey, so a
// secret half-sent over fetch and half over the forward proxy from the same
// client reassembles and the completing request is blocked.
//
// Transport matrix for CEE fragment/entropy accumulation:
//   - fetch (GET /fetch):        query values        - shares buffer
//   - forward proxy (abs-URI):   query values + body - shares buffer
//   - TLS intercept:             query values + body - shares buffer (MITM on)
//   - WebSocket (/ws):           text frame payloads - shares buffer
//   - CONNECT (no MITM):         opaque tunnel       - no payload visibility
//     (documented exception: the hostname is excluded from the entropy budget
//     and the body is encrypted; pre-CONNECT DLP/SSRF still run on the host).
//   - MCP stdio/HTTP:            JSON-RPC payloads    - separate MCP session key
//     (documented exception: not part of HTTP client-IP cross-transport reassembly).
func TestCEEBypass_CrossTransportSharesBuffer(t *testing.T) {
	t.Run("fetch_then_forward", func(t *testing.T) {
		// One proxy instance serving BOTH /fetch and the forward (absolute-URI)
		// path, so the two transports share the proxy-wide fragment buffer.
		target := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("ok"))
		}))
		defer target.Close()

		proxyAddr, _, cleanup := setupForwardProxyWithInstance(t, func(cfg *config.Config) {
			cfg.CrossRequestDetection = ceeFragmentBlockCfg()
		})
		defer cleanup()

		// Fragment 1 over fetch.
		_, code1 := fetchThroughProxy(t, "http://"+proxyAddr, target.URL+"/x?p="+testCEEAWSKeyPrefix)
		if code1 == http.StatusForbidden {
			t.Fatalf("first fragment (fetch) should not block, got %d", code1)
		}

		// Fragment 2 over the forward proxy (absolute-URI GET). Same client IP
		// and anonymous agent use the same IP-anchored key, so reassembly completes.
		client := proxyClient(proxyAddr)
		resp := doGet(t, client, target.URL+"/y?p="+testCEEAWSKeySuffix)
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("SILO: secret split fetch-to-forward was not reassembled "+
				"(forward completing request got %d, want 403): transports siloed CEE state", resp.StatusCode)
		}
	})
}

// --- Boundary: exempt-domain abuse ---------------------------------------

const ceeExemptHost = "api.vendor.example"

// TestCEEBoundary_ExemptDomainIsEntropyOnly proves the entropy-budget
// exemption does NOT open a DLP hole. Routing exfil through an entropy-exempt
// domain skips the entropy budget (the documented false-positive-avoidance
// behavior for high-entropy API traffic) but fragment-reassembly DLP still
// fires, so a split secret to an exempt host is still blocked.
func TestCEEBoundary_ExemptDomainIsEntropyOnly(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	sc := scanner.MustNew(cfg)
	defer sc.Close()

	logger, _ := audit.New("json", "stdout", "", false, false)
	m := metrics.New()
	exemptURL := "https://" + ceeExemptHost + "/path"

	t.Run("entropy_budget_exempt", func(t *testing.T) {
		et := scanner.NewEntropyTracker(1.0, 300) // 1-bit budget: trips instantly unless exempt
		defer et.Close()
		ceeCfg := config.CrossRequestDetection{
			EntropyBudget: config.CrossRequestEntropyBudget{
				Enabled:       true,
				BitsPerWindow: 1.0,
				WindowMinutes: 5,
				Action:        config.ActionBlock,
				ExemptDomains: []string{ceeExemptHost},
			},
		}
		res := ceeAdmit(context.Background(), testCEESessionKey,
			[]byte("x7k9mQ2pR4wL8nJ5vB3cT6yH0"), nil, exemptURL, testCEEAgent,
			testCEEClientIP, testCEERequestID, ceeCfg, et, nil, nil, logger, m)
		if res.Blocked || res.EntropyHit {
			t.Fatalf("entropy budget must be skipped for exempt domain (blocked=%v entropyHit=%v)", res.Blocked, res.EntropyHit)
		}
	})

	t.Run("fragment_dlp_still_fires", func(t *testing.T) {
		et := scanner.NewEntropyTracker(1.0, 300)
		defer et.Close()
		fb := scanner.NewFragmentBuffer(65536, 1000, 300)
		defer fb.Close()
		ceeCfg := config.CrossRequestDetection{
			Action: config.ActionBlock,
			EntropyBudget: config.CrossRequestEntropyBudget{
				Enabled:       true,
				BitsPerWindow: 1.0,
				WindowMinutes: 5,
				Action:        config.ActionBlock,
				ExemptDomains: []string{ceeExemptHost},
			},
			FragmentReassembly: config.CrossRequestFragments{
				Enabled:        true,
				MaxBufferBytes: 65536,
				WindowMinutes:  5,
			},
		}
		// Split a fake AWS key across two requests to the EXEMPT domain.
		r1 := ceeAdmit(context.Background(), testCEESessionKey,
			[]byte(testCEEAWSKeyPrefix), nil, exemptURL, testCEEAgent,
			testCEEClientIP, testCEERequestID, ceeCfg, et, fb, sc, logger, m)
		if r1.Blocked {
			t.Fatal("first fragment should not block")
		}
		r2 := ceeAdmit(context.Background(), testCEESessionKey,
			[]byte(testCEEAWSKeySuffix), nil, exemptURL, testCEEAgent,
			testCEEClientIP, "req-2", ceeCfg, et, fb, sc, logger, m)
		if !r2.Blocked || !r2.FragmentHit {
			t.Fatalf("BYPASS: fragment DLP must still fire on an entropy-exempt domain "+
				"(blocked=%v fragmentHit=%v): exemption widened to skip DLP", r2.Blocked, r2.FragmentHit)
		}
	})
}

// --- Bypass #1 via entropy budget ----------------------------------------

// TestCEEBypass_AgentRotationEntropyBudget proves the same partitioning gap on
// the entropy-budget stream: rotating the agent must not let an attacker stay
// under the per-session entropy budget by spreading high-entropy payloads
// across buckets.
func TestCEEBypass_AgentRotationEntropyBudget(t *testing.T) {
	// Drive the real /fetch request path with a rotating agent identity. One
	// request's query payload stays under the entropy budget; two requests
	// (folded onto the client IP) exceed it. Rotating the agent must not keep
	// each request in its own under-budget bucket.
	//
	// The budget is derived from the fixed payload's entropy so the test is
	// deterministic (ShannonEntropy is pure): set it between one and two
	// payloads' worth of bits.
	const payload = "q7w3e9r1t5y8u2i6o4p0a"
	perReqBits := scanner.ShannonEntropy(payload) * float64(len(payload))

	ceeCfg := config.CrossRequestDetection{
		Enabled: true,
		EntropyBudget: config.CrossRequestEntropyBudget{
			Enabled:       true,
			BitsPerWindow: perReqBits * 1.5, // one request under, two over
			WindowMinutes: 5,
			Action:        config.ActionBlock,
		},
	}
	ts, target := testCEEProxy(t, ceeCfg)

	// First request under a rotating agent: under budget, not blocked.
	_, code1 := fetchThroughProxyWithAgent(t, ts.URL, target.URL+"/a?p="+payload, "ent-rot-1")
	if code1 == http.StatusForbidden {
		t.Fatalf("first request should be under the entropy budget, got %d", code1)
	}

	// Second request under a DIFFERENT agent folds to the same client-IP
	// bucket, so cumulative entropy exceeds the budget and the request blocks.
	fr2, code2 := fetchThroughProxyWithAgent(t, ts.URL, target.URL+"/b?p="+payload, "ent-rot-2")
	if code2 != http.StatusForbidden || !fr2.Blocked {
		t.Fatalf("BYPASS: rotating the agent split entropy across buckets; the budget never tripped (code=%d blocked=%v)", code2, fr2.Blocked)
	}
}
