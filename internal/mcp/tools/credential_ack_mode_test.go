// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package tools

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

const (
	modeTestServer   = "vendor-indexer"
	modeTestRevision = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	modeTestKind     = "verified-local-session-v1"

	// The two published HMAC domains, written out so a typo in the code under
	// test cannot cancel itself.
	modeTestDomainV2  = "pipelock-mcp-ack-binding-v1"
	modeTestDomainVLS = "pipelock-mcp-ack-binding-verified-local-session-v1"
)

var modeTestBinding = ServerBindingDigest(modeTestKind, modeTestServer, modeTestRevision)

// testKeyedBindingDomain recomputes the keyed binding from the published
// construction with an explicit domain, independently of the code under test.
func testKeyedBindingDomain(key []byte, domain, digest string) string {
	id := hmac.New(sha256.New, key)
	_, _ = id.Write([]byte("pipelock-mcp-ack-key-id-v1"))
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(domain + "\x00" + digest))
	return "hmac-sha256-v1:" + hex.EncodeToString(id.Sum(nil)[:8]) + ":" + hex.EncodeToString(mac.Sum(nil))
}

var modeTestVerifiedHMAC = testKeyedBindingDomain(ackTestKey, modeTestDomainVLS, modeTestBinding)

// modeScanConfig is a launch of a registered identity.
func modeScanConfig(mode string, acks ...config.MCPAcknowledgedFinding) *ToolScanConfig {
	cfg := ackScanConfig(acks...)
	return cfg.WithServerMode(modeTestServer, modeTestBinding, mode, modeTestRevision)
}

// verifiedEntry is the acknowledgment an operator would write for a verified
// launch of raw.
func verifiedEntry(t *testing.T, raw string) config.MCPAcknowledgedFinding {
	t.Helper()
	e := ackForTool(t, raw)
	e.Server = modeTestServer
	e.ServerBindingMode = config.MCPAckBindingModeVerifiedLocalSession
	e.ServerBindingHMAC = modeTestVerifiedHMAC
	return e
}

func TestAckBindingDomain(t *testing.T) {
	tests := []struct {
		mode string
		want string
	}{
		{"", modeTestDomainV2},
		{config.MCPAckBindingModeTransportV2, modeTestDomainV2},
		{config.MCPAckBindingModeVerifiedLocalSession, modeTestDomainVLS},
		{"bogus", ""},
		{"Verified-Local-Session", ""},
	}
	for _, tt := range tests {
		t.Run("mode "+tt.mode, func(t *testing.T) {
			if got := ackBindingDomain(tt.mode); got != tt.want {
				t.Fatalf("ackBindingDomain(%q) = %q, want %q", tt.mode, got, tt.want)
			}
		})
	}
}

func TestKeyedBindingDomainSeparation(t *testing.T) {
	set := NewCredentialAckSet(nil, ackTestKey)
	digests := []string{modeTestBinding, ackTestBinding, ServerBindingDigest("subprocess", "/opt/vendor/bin/indexerd")}
	for _, d := range digests {
		v2 := set.keyedBinding(config.MCPAckBindingModeTransportV2, d)
		vls := set.keyedBinding(config.MCPAckBindingModeVerifiedLocalSession, d)
		if v2 == "" || vls == "" {
			t.Fatalf("a keyed set must produce both forms for %s", d)
		}
		if v2 == vls {
			t.Fatalf("the same digest keyed for both modes collides: %s", d)
		}
		if v2 != testKeyedBindingDomain(ackTestKey, modeTestDomainV2, d) {
			t.Fatalf("transport-v2 form diverged from the published construction")
		}
		if vls != testKeyedBindingDomain(ackTestKey, modeTestDomainVLS, d) {
			t.Fatalf("verified-local-session form diverged from the published construction")
		}
		if set.keyedBinding("", d) != v2 {
			t.Fatal("an empty mode must key like transport-v2")
		}
		if set.keyedBinding("bogus", d) != "" {
			t.Fatal("an unknown mode must have no keyed binding")
		}
	}
}

func TestBindingOutcomeDomainSeparationBothWays(t *testing.T) {
	set := NewCredentialAckSet(nil, ackTestKey)
	digest := modeTestBinding
	v2 := set.keyedBinding(config.MCPAckBindingModeTransportV2, digest)
	vls := set.keyedBinding(config.MCPAckBindingModeVerifiedLocalSession, digest)

	tests := []struct {
		name  string
		mode  string
		entry string
		want  string
	}{
		{"v2 entry under v2", config.MCPAckBindingModeTransportV2, v2, ""},
		{"vls entry under vls", config.MCPAckBindingModeVerifiedLocalSession, vls, ""},
		{"vls entry presented under v2", config.MCPAckBindingModeTransportV2, vls, CredentialAckBindingMismatch},
		{"v2 entry presented under vls", config.MCPAckBindingModeVerifiedLocalSession, v2, CredentialAckBindingMismatch},
		{"other key", config.MCPAckBindingModeVerifiedLocalSession, testKeyedBindingDomain([]byte("another-synthetic-acknowledgment-key-9999"), modeTestDomainVLS, digest), CredentialAckBindingKeyChanged},
		{"unknown mode", "bogus", vls, CredentialAckBindingMismatch},
		{"empty entry", config.MCPAckBindingModeVerifiedLocalSession, "", CredentialAckBindingKeyChanged},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := set.bindingOutcome(tt.mode, tt.entry, digest); got != tt.want {
				t.Fatalf("outcome = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRevokeBlanksBothModes(t *testing.T) {
	set := NewCredentialAckSet(nil, ackTestKey)
	for _, mode := range []string{"", config.MCPAckBindingModeTransportV2, config.MCPAckBindingModeVerifiedLocalSession} {
		if set.keyedBinding(mode, modeTestBinding) == "" {
			t.Fatalf("mode %q must key before revocation", mode)
		}
	}
	set.Revoke()
	for _, mode := range []string{"", config.MCPAckBindingModeTransportV2, config.MCPAckBindingModeVerifiedLocalSession} {
		if got := set.keyedBinding(mode, modeTestBinding); got != "" {
			t.Fatalf("revoked set still keys mode %q: %q", mode, got)
		}
	}
	if got := set.bindingOutcome(config.MCPAckBindingModeVerifiedLocalSession, modeTestVerifiedHMAC, modeTestBinding); got != CredentialAckBindingMismatch {
		t.Fatalf("revoked outcome = %q", got)
	}
}

func TestNoKeyKeysNothingInEitherMode(t *testing.T) {
	for name, set := range map[string]*CredentialAckSet{
		"nil set":   nil,
		"short key": NewCredentialAckSet(nil, []byte("short")),
	} {
		t.Run(name, func(t *testing.T) {
			for _, mode := range []string{config.MCPAckBindingModeTransportV2, config.MCPAckBindingModeVerifiedLocalSession} {
				if got := set.keyedBinding(mode, modeTestBinding); got != "" {
					t.Fatalf("mode %q keyed without a key: %q", mode, got)
				}
			}
		})
	}
}

func TestLaunchBindingMode(t *testing.T) {
	var nilCfg *ToolScanConfig
	if got := nilCfg.launchBindingMode(); got != config.MCPAckBindingModeTransportV2 {
		t.Fatalf("nil config mode = %q", got)
	}
	if got := (&ToolScanConfig{}).launchBindingMode(); got != config.MCPAckBindingModeTransportV2 {
		t.Fatalf("empty mode = %q", got)
	}
	if got := modeScanConfig(config.MCPAckBindingModeVerifiedLocalSession).launchBindingMode(); got != config.MCPAckBindingModeVerifiedLocalSession {
		t.Fatalf("verified mode = %q", got)
	}
}

func TestWithServerModeCopiesFields(t *testing.T) {
	base := ackScanConfig()
	got := base.WithServerMode("vendor-indexer", "digest", config.MCPAckBindingModeVerifiedLocalSession, "rev")
	if got == base || got.ServerName != "vendor-indexer" || got.ServerBindingSHA256 != "digest" ||
		got.ServerBindingMode != config.MCPAckBindingModeVerifiedLocalSession || got.ServerRevision != "rev" {
		t.Fatalf("WithServerMode = %+v", got)
	}
	if base.ServerBindingMode != "" || base.ServerRevision != "" {
		t.Fatal("WithServerMode must not mutate its receiver")
	}
	legacy := base.WithServer("plain", "d")
	if legacy.ServerBindingMode != "" || legacy.ServerRevision != "" {
		t.Fatalf("WithServer must be transport-v2: %+v", legacy)
	}
	var nilCfg *ToolScanConfig
	if nilCfg.WithServerMode("a", "b", "c", "d") != nil {
		t.Fatal("nil receiver must stay nil")
	}
}

func TestScanToolsVerifiedModeAcknowledges(t *testing.T) {
	raw := ackTestTool(`{"com.pipelock/provenance":{"sig":"abc"}}`)
	cfg := modeScanConfig(config.MCPAckBindingModeVerifiedLocalSession, verifiedEntry(t, raw))
	r := ScanTools(toolsListLine(raw), testScanner(t), cfg)
	if !r.Clean || !r.CredentialAckApplied() || r.CredentialAckRefused() {
		t.Fatalf("verified entry did not acknowledge under a verified launch: %+v", r)
	}
}

func TestScanToolsBindingModeMismatch(t *testing.T) {
	raw := ackTestTool(`{"com.pipelock/provenance":{"sig":"abc"}}`)
	verified := config.MCPAckBindingModeVerifiedLocalSession
	tests := []struct {
		name    string
		launch  string
		entry   func(*testing.T, string) config.MCPAcknowledgedFinding
		outcome string
	}{
		{"verified entry on a transport-v2 launch", config.MCPAckBindingModeTransportV2, verifiedEntry, CredentialAckBindingModeChanged},
		{"verified entry on a launch with no mode", "", verifiedEntry, CredentialAckBindingModeChanged},
		{"transport-v2 entry on a verified launch", verified, func(t *testing.T, raw string) config.MCPAcknowledgedFinding {
			e := ackForTool(t, raw)
			e.Server = modeTestServer
			e.ServerBindingHMAC = testKeyedBindingDomain(ackTestKey, modeTestDomainV2, modeTestBinding)
			return e
		}, CredentialAckBindingModeChanged},
		{"explicit transport-v2 entry on a verified launch", verified, func(t *testing.T, raw string) config.MCPAcknowledgedFinding {
			e := ackForTool(t, raw)
			e.Server = modeTestServer
			e.ServerBindingMode = config.MCPAckBindingModeTransportV2
			return e
		}, CredentialAckBindingModeChanged},
		{"verified entry bound with the transport-v2 domain", verified, func(t *testing.T, raw string) config.MCPAcknowledgedFinding {
			e := verifiedEntry(t, raw)
			e.ServerBindingHMAC = testKeyedBindingDomain(ackTestKey, modeTestDomainV2, modeTestBinding)
			return e
		}, CredentialAckBindingMismatch},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := modeScanConfig(tt.launch, tt.entry(t, raw))
			r := ScanTools(toolsListLine(raw), testScanner(t), cfg)
			m, ok := credentialMatch(r)
			if r.Clean || !ok || m.CredentialAck != tt.outcome || !r.CredentialAckRefused() || r.CredentialAckApplied() {
				t.Fatalf("outcome = %q (ok=%v clean=%v), want %q", m.CredentialAck, ok, r.Clean, tt.outcome)
			}
		})
	}
}

func TestScanToolsVerifiedEntryRefusesChangedBinding(t *testing.T) {
	raw := ackTestTool(`{"com.pipelock/provenance":{"sig":"abc"}}`)
	cfg := modeScanConfig(config.MCPAckBindingModeVerifiedLocalSession, verifiedEntry(t, raw))
	// Same registered identity, a different binding digest: a changed pin or
	// header is a mismatch rather than a mode change.
	cfg.ServerBindingSHA256 = ServerBindingDigest(modeTestKind, modeTestServer, "another-revision")
	r := ScanTools(toolsListLine(raw), testScanner(t), cfg)
	m, ok := credentialMatch(r)
	if r.Clean || !ok || m.CredentialAck != CredentialAckBindingMismatch {
		t.Fatalf("outcome = %q, want binding_mismatch", m.CredentialAck)
	}
}

func TestVerifiedCandidate(t *testing.T) {
	raw := ackTestTool(`{"com.pipelock/provenance":{"sig":"abc"}}`)
	cfg := modeScanConfig(config.MCPAckBindingModeVerifiedLocalSession)
	cfg.Action = config.ActionBlock
	r := ScanTools(toolsListLine(raw), testScanner(t), cfg)
	m, ok := credentialMatch(r)
	if !ok || m.CredentialAckCandidate == nil {
		t.Fatalf("no candidate offered: %+v", r)
	}
	c := m.CredentialAckCandidate
	if c.Server != modeTestServer || c.ServerBindingMode != config.MCPAckBindingModeVerifiedLocalSession || c.ServerBindingHMAC != modeTestVerifiedHMAC {
		t.Fatalf("candidate = %+v", c)
	}
	if !strings.Contains(c.scope, "every session of verified local service vendor-indexer (revision 0123456789ab)") {
		t.Fatalf("scope = %q", c.scope)
	}
	enc, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(enc), `"server_binding_mode":"verified-local-session"`) {
		t.Fatalf("candidate JSON lacks the mode: %s", enc)
	}
	if strings.Contains(string(enc), modeTestBinding) || strings.Contains(string(enc), "scope") {
		t.Fatalf("candidate JSON carries the exact digest or the display scope: %s", enc)
	}

	var log strings.Builder
	LogToolFindings(&log, 1, r)
	if !strings.Contains(log.String(), "scope: every session of verified local service vendor-indexer (revision 0123456789ab).") {
		t.Fatalf("candidate log line lacks the scope: %s", log.String())
	}

	// With the operator fields added, the candidate acknowledges the tool.
	e := c.entry()
	e.Owner, e.Reason = "platform team", "reviewed"
	// clock-literal-ok: paired with the injected test clock (2026-10-08)
	e.Expires = "2026-12-01"
	cfg.CredentialAcks = NewCredentialAckSet([]config.MCPAcknowledgedFinding{e}, ackTestKey)
	if r2 := ScanTools(toolsListLine(raw), testScanner(t), cfg); !r2.Clean || !r2.CredentialAckApplied() {
		t.Fatalf("candidate did not acknowledge its tool: %+v", r2)
	}
}

func TestLegacyCandidateOmitsModeAndScope(t *testing.T) {
	raw := ackTestTool(`{}`)
	cfg := ackScanConfig()
	cfg.Action = config.ActionBlock
	m, ok := credentialMatch(ScanTools(toolsListLine(raw), testScanner(t), cfg))
	if !ok || m.CredentialAckCandidate == nil {
		t.Fatal("no candidate offered")
	}
	c := m.CredentialAckCandidate
	if c.ServerBindingMode != "" || c.scope != "" {
		t.Fatalf("a transport-v2 candidate must carry neither mode nor scope: %+v", c)
	}
	enc, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(enc), "server_binding_mode") {
		t.Fatalf("transport-v2 candidate JSON must omit the mode: %s", enc)
	}
	var log strings.Builder
	LogToolFindings(&log, 1, ScanTools(toolsListLine(raw), testScanner(t), cfg))
	if strings.Contains(log.String(), "scope:") {
		t.Fatalf("legacy log line gained a scope: %s", log.String())
	}
}

// A candidate with a mode and scope but no bearer value is the only shape a
// verified launch can offer; the scope text must not depend on one.
func TestVerifiedCandidateCarriesNoBearerValue(t *testing.T) {
	raw := ackTestTool(`{}`)
	cfg := modeScanConfig(config.MCPAckBindingModeVerifiedLocalSession)
	cfg.Action = config.ActionBlock
	m, ok := credentialMatch(ScanTools(toolsListLine(raw), testScanner(t), cfg))
	if !ok || m.CredentialAckCandidate == nil {
		t.Fatal("no candidate offered")
	}
	exported, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var log strings.Builder
	LogToolFindings(&log, 1, ScanTools(toolsListLine(raw), testScanner(t), cfg))
	for _, out := range []string{string(exported), log.String()} {
		for _, secret := range []string{"Bearer", "session-token", modeTestBinding, string(ackTestKey)} {
			if strings.Contains(out, secret) {
				t.Fatalf("output carries %q: %s", secret, out)
			}
		}
	}
}

func TestVerifiedCandidateWithheldWithoutKeyOrDigest(t *testing.T) {
	raw := ackTestTool(`{}`)
	tests := []struct {
		name   string
		mutate func(*ToolScanConfig)
	}{
		{"no binding digest", func(c *ToolScanConfig) { c.ServerBindingSHA256 = "" }},
		{"no key", func(c *ToolScanConfig) { c.CredentialAcks = NewCredentialAckSet(nil, []byte("short")) }},
		{"revoked", func(c *ToolScanConfig) { c.CredentialAcks.Revoke() }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := modeScanConfig(config.MCPAckBindingModeVerifiedLocalSession)
			cfg.Action = config.ActionBlock
			tt.mutate(cfg)
			if m, _ := credentialMatch(ScanTools(toolsListLine(raw), testScanner(t), cfg)); m.CredentialAckCandidate != nil {
				t.Fatalf("candidate offered: %+v", m.CredentialAckCandidate)
			}
		})
	}
}

func TestShortRevision(t *testing.T) {
	tests := []struct{ in, want string }{
		{"", ""},
		{"abc", "abc"},
		{"0123456789ab", "0123456789ab"},
		{modeTestRevision, "0123456789ab"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := shortRevision(tt.in); got != tt.want {
				t.Fatalf("shortRevision(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
