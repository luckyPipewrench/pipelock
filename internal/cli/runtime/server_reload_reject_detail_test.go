// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

// TestRejectedDowngradeReloadDetail covers the message-builder unit that names
// the offending edit for a rejected reload, independent of the Server plumbing
// around it. reloadDowngradeRejectReason already decided rejection; this only
// decides what the operator is told about WHY.
func TestRejectedDowngradeReloadDetail(t *testing.T) {
	t.Parallel()

	expires := time.Now().UTC().Add(30 * 24 * time.Hour).Format("2006-01-02")

	baseWithReceipts := func() *config.Config {
		cfg := config.Defaults()
		cfg.Mode = config.ModeBalanced
		cfg.FlightRecorder.Enabled = true
		cfg.FlightRecorder.RequireReceipts = true
		return cfg
	}

	for _, tc := range []struct {
		name   string
		old    func() *config.Config
		mutate func(*config.Config)
		want   string
	}{
		{
			name: "non-advisory downgrade names the triggering field",
			old:  baseWithReceipts,
			mutate: func(cfg *config.Config) {
				cfg.FetchProxy.Monitoring.QueryEntropyParamExclusions = []config.QueryEntropyParamExclusion{{
					Host:    "api.vendor.example",
					Path:    "/v1/search/recent",
					Param:   "query",
					Reason:  "structured query",
					Owner:   "platform-security",
					Expires: expires,
				}}
			},
			want: "fetch_proxy.monitoring.query_entropy_param_exclusions weakens protection and cannot apply at runtime",
		},
		{
			name: "path entropy exclusion names its own field, not the receipts contract",
			old:  baseWithReceipts,
			mutate: func(cfg *config.Config) {
				cfg.FetchProxy.Monitoring.PathEntropyExclusions = []config.PathEntropyExclusion{{
					Host:       "api.vendor.example",
					PathPrefix: "/v1/health",
					Reason:     "health probe",
					Owner:      "platform-security",
					Expires:    expires,
				}}
			},
			want: "fetch_proxy.monitoring.path_entropy_exclusions weakens protection and cannot apply at runtime",
		},
		{
			name: "trust widening gets the widen-specific phrasing, not the generic one",
			old:  baseWithReceipts,
			mutate: func(cfg *config.Config) {
				cfg.TrustedDomains = []string{"internal.example"}
			},
			want: "trusted_domains cannot widen trust at runtime",
		},
		{
			name: "trust widening and a second weakening in one reload are both named",
			old:  baseWithReceipts,
			mutate: func(cfg *config.Config) {
				cfg.TrustedDomains = []string{"internal.example"}
				cfg.FetchProxy.Monitoring.PathEntropyExclusions = []config.PathEntropyExclusion{{
					Host:       "api.vendor.example",
					PathPrefix: "/v1/health",
					Reason:     "health probe",
					Owner:      "platform-security",
					Expires:    expires,
				}}
			},
			want: "trusted_domains cannot widen trust at runtime; fetch_proxy.monitoring.path_entropy_exclusions weakens protection and cannot apply at runtime",
		},
		{
			name: "a required contract torn down directly leaves detail empty: reason already names it",
			old:  baseWithReceipts,
			mutate: func(cfg *config.Config) {
				cfg.FlightRecorder.RequireReceipts = false
			},
			want: "",
		},
		{
			name: "a torn-down contract plus another weakening still names the other edit",
			old:  baseWithReceipts,
			mutate: func(cfg *config.Config) {
				cfg.FlightRecorder.RequireReceipts = false
				cfg.FetchProxy.Monitoring.PathEntropyExclusions = []config.PathEntropyExclusion{{
					Host:       "api.vendor.example",
					PathPrefix: "/v1/health",
					Reason:     "health probe",
					Owner:      "platform-security",
					Expires:    expires,
				}}
			},
			want: "fetch_proxy.monitoring.path_entropy_exclusions weakens protection and cannot apply at runtime",
		},
		{
			name: "advisory-only warnings never appear in the detail",
			old: func() *config.Config {
				cfg := baseWithReceipts()
				// key_id changes warn only while envelope signing is on.
				cfg.MediationEnvelope.Sign = true
				cfg.MediationEnvelope.KeyID = "old-key"
				return cfg
			},
			mutate: func(cfg *config.Config) {
				// mediation_envelope.key_id is advisory ("uses init-time"): it
				// alone must never be named as the trigger.
				cfg.MediationEnvelope.KeyID = "new-key"
			},
			want: "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			oldCfg := tc.old()
			newCfg := oldCfg.Clone()
			tc.mutate(newCfg)
			warnings := config.ValidateReload(oldCfg, newCfg)
			got := rejectedDowngradeReloadDetail(oldCfg, newCfg, warnings)
			if got != tc.want {
				t.Fatalf("rejectedDowngradeReloadDetail = %q, want %q (warnings=%+v)", got, tc.want, warnings)
			}
		})
	}
}

// TestRejectableDowngradeReloadWarningFields covers deduplication and stable
// ordering directly: two warnings on the same field collapse to one entry, in
// the order the warnings were emitted, and advisory warnings are excluded.
func TestRejectableDowngradeReloadWarningFields(t *testing.T) {
	t.Parallel()
	// Warnings come from the real producer, not hand-built literals, so the
	// advisory classification under test is the one ValidateReload assigns.
	expires := time.Now().UTC().Add(30 * 24 * time.Hour).Format("2006-01-02")
	oldCfg := config.Defaults()
	oldCfg.MediationEnvelope.Sign = true
	oldCfg.MediationEnvelope.KeyID = "old-key"
	newCfg := config.Defaults()
	newCfg.MediationEnvelope.Sign = true
	newCfg.MediationEnvelope.KeyID = "new-key"
	newCfg.FetchProxy.Monitoring.QueryEntropyParamExclusions = []config.QueryEntropyParamExclusion{{
		Host: "api.vendor.example", Path: "/v1/search/recent", Param: "query",
		Reason: "structured query", Owner: "platform-security", Expires: expires,
	}}
	newCfg.FetchProxy.Monitoring.PathEntropyExclusions = []config.PathEntropyExclusion{{
		Host: "api.vendor.example", PathPrefix: "/v1/health",
		Reason: "health probe", Owner: "platform-security", Expires: expires,
	}}
	warnings := config.ValidateReload(oldCfg, newCfg)
	var sawKeyID bool
	for _, w := range warnings {
		if w.Field == "mediation_envelope.key_id" {
			sawKeyID = true
		}
	}
	if !sawKeyID {
		t.Fatalf("fixture did not produce the advisory key_id warning: %+v", warnings)
	}
	// Repeat every warning so de-duplication is exercised.
	warnings = append(warnings, warnings...)

	got := rejectableDowngradeReloadWarningFields(warnings)
	// The message joins fields in this order, so order is part of the contract:
	// first appearance of each non-advisory field, in emission order.
	var want []string
	seen := map[string]bool{}
	for _, w := range warnings {
		if w.Field == "mediation_envelope.key_id" || seen[w.Field] {
			continue
		}
		seen[w.Field] = true
		want = append(want, w.Field)
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("fields = %v, want %v in emission order", got, want)
	}
	only := map[string]bool{
		"fetch_proxy.monitoring.query_entropy_param_exclusions": true,
		"fetch_proxy.monitoring.path_entropy_exclusions":        true,
	}
	if len(got) != len(only) {
		t.Fatalf("fields = %v, want exactly the two entropy-exclusion fields", got)
	}
	for _, f := range got {
		if !only[f] {
			t.Fatalf("fields = %v, unexpected %q", got, f)
		}
	}
}

// TestServer_Reload_RejectedDowngradeNamesTriggeringField reproduces the live
// defect: a reload that only ADDS a query-entropy-parameter exclusion while
// flight_recorder.require_receipts stays true is correctly rejected, but the
// message named only the contract in force
// ("required security mode (flight_recorder.require_receipts)"), never the
// edit that actually triggered it. An operator reading the old message had no
// way to tell which line in the diff caused the rejection, and no idea that a
// restart would apply it.
func TestServer_Reload_RejectedDowngradeNamesTriggeringField(t *testing.T) {
	recorderDir := t.TempDir()
	keyPath := filepath.Join(t.TempDir(), "flight-recorder.key")
	_, priv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	if err := signing.SavePrivateKey(priv, keyPath); err != nil {
		t.Fatalf("save signing key: %v", err)
	}
	cfgPath := writeServerTestConfig(t, strings.Join([]string{
		"mode: balanced",
		"flight_recorder:",
		"  enabled: true",
		"  require_receipts: true",
		"  dir: " + strconv.Quote(recorderDir),
		"  signing_key_path: " + strconv.Quote(keyPath),
		"",
	}, "\n"))
	s, err := NewServer(ServerOpts{ConfigFile: cfgPath, Stdout: &syncBuffer{}, Stderr: &syncBuffer{}})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(func() { s.cleanup() })
	if !s.proxy.CurrentConfig().FlightRecorder.RequireReceipts {
		t.Fatal("setup failed: require_receipts not in force before the reload")
	}

	stderr := &syncBuffer{}
	s.opts.Stderr = stderr

	expires := time.Now().UTC().Add(30 * 24 * time.Hour).Format("2006-01-02")
	candidate := s.proxy.CurrentConfig().Clone()
	candidate.FetchProxy.Monitoring.QueryEntropyParamExclusions = []config.QueryEntropyParamExclusion{{
		Host:    "api.vendor.example",
		Path:    "/v1/search/recent",
		Param:   "query",
		Reason:  "structured query",
		Owner:   "platform-security",
		Expires: expires,
	}}
	s.lastReloadAt = time.Time{} // exercise the rejection, not reload dedupe

	reloadErr := s.Reload(candidate)
	if reloadErr == nil {
		t.Fatal("reload silently accepted a query-entropy-parameter exclusion under require_receipts")
	}
	if !strings.Contains(reloadErr.Error(), "flight_recorder.require_receipts") {
		t.Fatalf("rejection = %q, want it to still name the contract in force", reloadErr)
	}
	if !s.proxy.CurrentConfig().FlightRecorder.RequireReceipts {
		t.Fatal("require_receipts was cleared despite the reload being rejected")
	}
	if len(s.proxy.CurrentConfig().FetchProxy.Monitoring.QueryEntropyParamExclusions) != 0 {
		t.Fatal("rejected reload still published its query-entropy-parameter exclusion")
	}

	for _, want := range []string{
		"WARNING: config reload rejected: rejected: security downgrade from required security mode (flight_recorder.require_receipts): " +
			"fetch_proxy.monitoring.query_entropy_param_exclusions weakens protection and cannot apply at runtime",
		"previous configuration remains active",
		"restart Pipelock to apply this change",
	} {
		if !stderr.contains(want) {
			t.Fatalf("stderr missing %q:\n%s", want, stderr.String())
		}
	}
}

// TestServer_Reload_RequiredTeardownRejectionNamesRestartRemedy is the
// companion to TestServer_Reload_RequireReceiptsDowngradeIsRejected in
// server_require_receipts_test.go: that test proves the reload is rejected and
// the field is named; this one proves the message also tells the operator that
// a restart applies the change, which the teardown path previously omitted.
func TestServer_Reload_RequiredTeardownRejectionNamesRestartRemedy(t *testing.T) {
	recorderDir := t.TempDir()
	keyPath := filepath.Join(t.TempDir(), "flight-recorder.key")
	_, priv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	if err := signing.SavePrivateKey(priv, keyPath); err != nil {
		t.Fatalf("save signing key: %v", err)
	}
	cfgPath := writeServerTestConfig(t, strings.Join([]string{
		"mode: balanced",
		"flight_recorder:",
		"  enabled: true",
		"  require_receipts: true",
		"  dir: " + strconv.Quote(recorderDir),
		"  signing_key_path: " + strconv.Quote(keyPath),
		"",
	}, "\n"))
	s, err := NewServer(ServerOpts{ConfigFile: cfgPath, Stdout: &syncBuffer{}, Stderr: &syncBuffer{}})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(func() { s.cleanup() })

	stderr := &syncBuffer{}
	s.opts.Stderr = stderr

	off := s.proxy.CurrentConfig().Clone()
	off.FlightRecorder.Enabled = false
	off.FlightRecorder.RequireReceipts = false
	s.lastReloadAt = time.Time{}

	if err := s.Reload(off); err == nil {
		t.Fatal("reload silently cleared an active fail-closed receipt requirement")
	}
	for _, want := range []string{
		"required security mode (flight_recorder.require_receipts)",
		"previous configuration remains active",
		"restart Pipelock to apply this change",
	} {
		if !stderr.contains(want) {
			t.Fatalf("stderr missing %q:\n%s", want, stderr.String())
		}
	}
}

// TestServer_Reload_TrustWideningWithTeardownNamesBoth pins that a reload which
// both widens trust and tears down a required contract reports BOTH on stderr.
// The trust-only wording prints just the trust field, so an operator who fixed
// only that would hit a second rejection the message never predicted.
func TestServer_Reload_TrustWideningWithTeardownNamesBoth(t *testing.T) {
	recorderDir := t.TempDir()
	keyPath := filepath.Join(t.TempDir(), "flight-recorder.key")
	_, priv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	if err := signing.SavePrivateKey(priv, keyPath); err != nil {
		t.Fatalf("save signing key: %v", err)
	}
	cfgPath := writeServerTestConfig(t, strings.Join([]string{
		"mode: balanced",
		"flight_recorder:",
		"  enabled: true",
		"  require_receipts: true",
		"  dir: " + strconv.Quote(recorderDir),
		"  signing_key_path: " + strconv.Quote(keyPath),
		"",
	}, "\n"))
	s, err := NewServer(ServerOpts{ConfigFile: cfgPath, Stdout: &syncBuffer{}, Stderr: &syncBuffer{}})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(func() { s.cleanup() })

	stderr := &syncBuffer{}
	s.opts.Stderr = stderr

	next := s.proxy.CurrentConfig().Clone()
	next.FlightRecorder.Enabled = false
	next.FlightRecorder.RequireReceipts = false
	next.TrustedDomains = []string{"internal.example"}
	s.lastReloadAt = time.Time{}

	if err := s.Reload(next); err == nil {
		t.Fatal("reload applied a trust widening together with a receipt teardown")
	}
	for _, want := range []string{
		"required security mode (flight_recorder.require_receipts)",
		"trusted_domains cannot widen trust at runtime",
		"restart Pipelock to apply this change",
	} {
		if !stderr.contains(want) {
			t.Fatalf("stderr missing %q:\n%s", want, stderr.String())
		}
	}
}

// TestServer_Reload_StrictModeRejectionNamesTriggeringField exercises the
// third message shape: a strict-mode reload rejected purely because
// oldCfg.Mode == ModeStrict, with no required-contract teardown involved. The
// old message said only "strict mode"; an operator had no way to tell which
// warning caused the rejection.
func TestServer_Reload_StrictModeRejectionNamesTriggeringField(t *testing.T) {
	s, stderr := newTestServer(t, func(o *ServerOpts) {
		o.Mode = config.ModeStrict
		o.ModeChanged = true
	})
	oldCfg := s.proxy.CurrentConfig()
	candidate := oldCfg.Clone()
	expires := time.Now().UTC().Add(30 * 24 * time.Hour).Format("2006-01-02")
	candidate.FetchProxy.Monitoring.PathEntropyExclusions = []config.PathEntropyExclusion{{
		Host:       "api.vendor.example",
		PathPrefix: "/v1/health",
		Reason:     "health probe",
		Owner:      "platform-security",
		Expires:    expires,
	}}
	s.lastReloadAt = time.Time{}

	reloadErr := s.Reload(candidate)
	if reloadErr == nil {
		t.Fatal("strict-mode path-entropy-exclusion reload succeeded")
	}
	if !strings.Contains(reloadErr.Error(), "strict mode") {
		t.Fatalf("rejection = %q, want it to still name strict mode", reloadErr)
	}
	for _, want := range []string{
		"fetch_proxy.monitoring.path_entropy_exclusions weakens protection and cannot apply at runtime",
		"previous configuration remains active",
		"restart Pipelock to apply this change",
	} {
		if !stderr.contains(want) {
			t.Fatalf("stderr missing %q:\n%s", want, stderr.String())
		}
	}
}
