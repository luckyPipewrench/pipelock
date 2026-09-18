// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// TestServer_ReloadCarriesContainmentLoopbackServices proves
// containment.loopback_services participates in the ordinary hot-reload
// path the same way containment.metrics_exposure's owner/reason/expiry
// fields do: NewServer's initial config.Load already runs Validate()
// (config/validate.go, validateContainmentLoopbackServices), and
// Server.Reload does not special-case LoopbackServices back to the old
// value the way it does for MetricsExposure when metrics_listen is
// unchanged (server_reload.go, the "if oldCfg.MetricsListen !=
// newCfg.MetricsListen" block), so a changed declared set on reload takes
// effect, and reloading the identical config again is idempotent.
func TestServer_ReloadCarriesContainmentLoopbackServices(t *testing.T) {
	expiresAt := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
	configWithService := func(port int) string {
		return "mode: balanced\n" +
			"containment:\n" +
			"  loopback_services:\n" +
			"  - host: 127.0.0.1\n" +
			"    port: " + strconv.Itoa(port) + "\n" +
			"    owner: search-team\n" +
			"    reason: local index\n" +
			"    expires_at: " + expiresAt + "\n"
	}

	s, err := NewServer(ServerOpts{
		ConfigFile:                        writeServerTestConfig(t, configWithService(9200)),
		Listen:                            serverTestEphemeralListen,
		ListenChanged:                     true,
		Stdout:                            &syncBuffer{},
		Stderr:                            &syncBuffer{},
		allowEphemeralListenersForTesting: true,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(s.cleanup)

	first := s.proxy.CurrentConfig()
	if len(first.Containment.LoopbackServices) != 1 || first.Containment.LoopbackServices[0].Port != 9200 {
		t.Fatalf("first load Containment.LoopbackServices = %+v, want one entry on port 9200", first.Containment.LoopbackServices)
	}

	// First reload: change the declared port. The new value must take
	// effect, proving the section is not pinned to the old config the way
	// MetricsExposure is when metrics_listen is unchanged.
	changed, err := loadServerTestConfig(t, configWithService(9201))
	if err != nil {
		t.Fatalf("load changed config: %v", err)
	}
	if err := s.Reload(changed); err != nil {
		t.Fatalf("Reload with a changed declared port: %v", err)
	}
	afterChange := s.proxy.CurrentConfig()
	if len(afterChange.Containment.LoopbackServices) != 1 || afterChange.Containment.LoopbackServices[0].Port != 9201 {
		t.Fatalf("after changed reload, Containment.LoopbackServices = %+v, want one entry on port 9201", afterChange.Containment.LoopbackServices)
	}

	// Second reload: same config again (unrelated reload). Idempotent: the
	// declared set is unchanged and Reload does not error.
	unchanged, err := loadServerTestConfig(t, configWithService(9201))
	if err != nil {
		t.Fatalf("load unchanged config: %v", err)
	}
	if err := s.Reload(unchanged); err != nil {
		t.Fatalf("Reload with an unrelated/unchanged declared set: %v", err)
	}
	afterUnchanged := s.proxy.CurrentConfig()
	if len(afterUnchanged.Containment.LoopbackServices) != 1 || afterUnchanged.Containment.LoopbackServices[0].Port != 9201 {
		t.Fatalf("after unrelated reload, Containment.LoopbackServices = %+v, want the port 9201 entry preserved", afterUnchanged.Containment.LoopbackServices)
	}

	// A malformed declared entry is rejected by config.Load's Validate()
	// before it could ever reach Reload -- the same guarantee
	// metrics_exposure relies on for its own owner/reason/expiry fields.
	_, err = loadServerTestConfig(t, strings.Replace(configWithService(9202), "owner: search-team\n", "", 1))
	if err == nil {
		t.Fatal("loading a config with a declared loopback service missing owner should fail closed")
	}
}

func loadServerTestConfig(t *testing.T, body string) (*config.Config, error) {
	t.Helper()
	return config.Load(writeServerTestConfig(t, body))
}

// TestServer_ReloadWarnsOnContainmentLoopbackServicesChangeWithoutRejecting
// covers the runtime-reload half of the HIGH-severity fix: config reload
// only swaps Server's in-memory Config, it never touches kernel nftables
// state, so a changed containment.loopback_services must warn -- naming the
// exact reconciliation command -- and still succeed, and an unrelated
// reload with the SAME declared set must stay silent about it.
func TestServer_ReloadWarnsOnContainmentLoopbackServicesChangeWithoutRejecting(t *testing.T) {
	t.Setenv(config.ContainmentManagedEnvKey, config.ContainmentManagedEnvValue)
	expiresAt := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
	metricsAddr := reserveTCPAddress(t, "127.0.0.1")
	configWithService := func(port int) string {
		return "mode: balanced\n" +
			"metrics_listen: " + metricsAddr + "\n" +
			"containment:\n" +
			"  loopback_services:\n" +
			"  - host: 127.0.0.1\n" +
			"    port: " + strconv.Itoa(port) + "\n" +
			"    owner: search-team\n" +
			"    reason: local index\n" +
			"    expires_at: " + expiresAt + "\n"
	}
	stderr := &syncBuffer{}
	s, err := NewServer(ServerOpts{
		ConfigFile:                        writeServerTestConfig(t, configWithService(9200)),
		Listen:                            serverTestEphemeralListen,
		ListenChanged:                     true,
		Stdout:                            &syncBuffer{},
		Stderr:                            stderr,
		allowEphemeralListenersForTesting: true,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(s.cleanup)

	const wantWarning = "containment.loopback_services changed"
	const wantCommand = "pipelock contain reload-nft-rules"

	// Changed declared set: warn, naming the command, and the reload still
	// succeeds (the config change itself is valid).
	stderr.reset()
	changed, err := loadServerTestConfig(t, configWithService(9201))
	if err != nil {
		t.Fatalf("load changed config: %v", err)
	}
	if err := s.Reload(changed); err != nil {
		t.Fatalf("Reload with a changed declared set must not be rejected: %v", err)
	}
	if !stderr.contains(wantWarning) || !stderr.contains(wantCommand) {
		t.Fatalf("stderr = %q, want a warning naming %q and %q", stderr.String(), wantWarning, wantCommand)
	}

	// Unrelated reload with the SAME declared set: no warning about
	// loopback_services.
	stderr.reset()
	unchanged, err := loadServerTestConfig(t, configWithService(9201))
	if err != nil {
		t.Fatalf("load unchanged config: %v", err)
	}
	if err := s.Reload(unchanged); err != nil {
		t.Fatalf("Reload with an unrelated/unchanged declared set: %v", err)
	}
	if stderr.contains(wantWarning) {
		t.Fatalf("stderr = %q, an unrelated/unchanged reload must not warn about loopback_services", stderr.String())
	}
}

// TestServer_ReloadRejectsInvalidLoopbackServiceCandidate covers the reload
// boundary a file-based reload never exercises. config.Load validates the
// declaration, so a config read from disk cannot carry an invalid one; a
// caller handing Reload an in-memory config skips Load entirely, and the
// whole-config re-validation further down the function collects warnings and
// discards its error. An expired declaration could therefore become the live
// policy, which is a declaration authorizing an extra hole in the agent's
// egress boundary that no validator ever approved.
func TestServer_ReloadRejectsInvalidLoopbackServiceCandidate(t *testing.T) {
	valid := "mode: balanced\n"
	s, err := NewServer(ServerOpts{
		ConfigFile:                        writeServerTestConfig(t, valid),
		Listen:                            serverTestEphemeralListen,
		ListenChanged:                     true,
		Stdout:                            &syncBuffer{},
		Stderr:                            &syncBuffer{},
		allowEphemeralListenersForTesting: true,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(s.cleanup)

	before := s.proxy.CurrentConfig()

	for _, tc := range []struct {
		name    string
		mutate  func(*config.Config)
		wantErr string
	}{
		{
			name: "expired declaration",
			mutate: func(c *config.Config) {
				c.Containment.LoopbackServices = []config.ContainmentLoopbackService{{
					Host: "127.0.0.1", Port: 9200, Owner: "search-team", Reason: "local index",
					ExpiresAt: time.Now().UTC().Add(-time.Hour).Format(time.RFC3339),
				}}
			},
			wantErr: "expired",
		},
		{
			name: "host that is not a loopback literal",
			mutate: func(c *config.Config) {
				c.Containment.LoopbackServices = []config.ContainmentLoopbackService{{
					Host: "10.20.0.20", Port: 9200, Owner: "search-team", Reason: "local index",
					ExpiresAt: time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
				}}
			},
			wantErr: "loopback literal",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate, loadErr := loadServerTestConfig(t, valid)
			if loadErr != nil {
				t.Fatalf("load candidate: %v", loadErr)
			}
			tc.mutate(candidate)

			err := s.Reload(candidate)
			if err == nil {
				t.Fatal("expected the reload to be rejected")
			}
			if !strings.Contains(err.Error(), "rejected: invalid config reload") {
				t.Errorf("error = %v, want the standard reload rejection prefix", err)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %v, want it to name the validation failure %q", err, tc.wantErr)
			}
			if got := s.proxy.CurrentConfig(); len(got.Containment.LoopbackServices) != len(before.Containment.LoopbackServices) {
				t.Errorf("live config changed to %+v; a rejected candidate must not become live", got.Containment.LoopbackServices)
			}
		})
	}
}

// TestServer_ReloadAcceptsValidLoopbackServiceCandidate is the positive
// control: a well-formed declaration handed to Reload directly must still be
// accepted, so the rejection above cannot be satisfied by refusing every
// in-memory candidate.
func TestServer_ReloadAcceptsValidLoopbackServiceCandidate(t *testing.T) {
	valid := "mode: balanced\n"
	s, err := NewServer(ServerOpts{
		ConfigFile:                        writeServerTestConfig(t, valid),
		Listen:                            serverTestEphemeralListen,
		ListenChanged:                     true,
		Stdout:                            &syncBuffer{},
		Stderr:                            &syncBuffer{},
		allowEphemeralListenersForTesting: true,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(s.cleanup)

	candidate, loadErr := loadServerTestConfig(t, valid)
	if loadErr != nil {
		t.Fatalf("load candidate: %v", loadErr)
	}
	candidate.Containment.LoopbackServices = []config.ContainmentLoopbackService{{
		Host: "127.0.0.1", Port: 9200, Owner: "search-team", Reason: "local index",
		ExpiresAt: time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
	}}
	if err := s.Reload(candidate); err != nil {
		t.Fatalf("a valid declaration handed to Reload must be accepted: %v", err)
	}
	if got := s.proxy.CurrentConfig(); len(got.Containment.LoopbackServices) != 1 {
		t.Fatalf("live config = %+v, want the accepted declaration", got.Containment.LoopbackServices)
	}
}

// TestServer_ReloadValidatesLoopbackServicesAgainstTheEffectivePort covers the
// ordering the first version of this rejection got wrong. The declaration is
// validated against the proxy port read from fetch_proxy.listen, and a reload
// cannot rebind the listener: the candidate's value is discarded and the live
// address restored. A check placed before that restore reads a port the
// process will never listen on, which is wrong in both directions. This test
// drives the direction a test server can construct: a declaration that
// collides with the CANDIDATE's requested port but not with the effective one
// must be accepted, because the candidate's port is discarded.
func TestServer_ReloadValidatesLoopbackServicesAgainstTheEffectivePort(t *testing.T) {
	s, err := NewServer(ServerOpts{
		ConfigFile:                        writeServerTestConfig(t, "mode: balanced\n"),
		Listen:                            serverTestEphemeralListen,
		ListenChanged:                     true,
		Stdout:                            &syncBuffer{},
		Stderr:                            &syncBuffer{},
		allowEphemeralListenersForTesting: true,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(s.cleanup)

	const declaredPort = 9200
	candidate, loadErr := loadServerTestConfig(t, "mode: balanced\n")
	if loadErr != nil {
		t.Fatalf("load candidate: %v", loadErr)
	}
	// The candidate asks to move the listener onto the very port it declares
	// as a loopback service. Reload refuses listener changes and restores the
	// live address, so that collision never exists in the published config.
	candidate.FetchProxy.Listen = "127.0.0.1:" + strconv.Itoa(declaredPort)
	// Capture it now: reloadLocked restores the live address INTO this same
	// config object, so reading the field after the call reports the
	// restored value and the comparison below would always hold.
	requestedListen := candidate.FetchProxy.Listen
	candidate.Containment.LoopbackServices = []config.ContainmentLoopbackService{{
		Host: "127.0.0.1", Port: declaredPort, Owner: "search-team", Reason: "local index",
		ExpiresAt: time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
	}}

	if err := s.Reload(candidate); err != nil {
		t.Fatalf("reload rejected a declaration that only collides with the discarded candidate port: %v", err)
	}
	live := s.proxy.CurrentConfig()
	if len(live.Containment.LoopbackServices) != 1 || live.Containment.LoopbackServices[0].Port != declaredPort {
		t.Fatalf("live declaration = %+v, want the accepted entry on port %d", live.Containment.LoopbackServices, declaredPort)
	}
	if live.FetchProxy.Listen == requestedListen {
		t.Fatal("this test is vacuous unless reload discarded the candidate's listener")
	}
}

// TestServer_ReloadDoesNotPromiseReconciliationForARejectedCandidate pins the
// ordering between the reconciliation warning and the checks that can still
// refuse the reload. The warning tells an operator the declared set changed
// and to run the reconciliation command; emitting it before validation meant
// a candidate that was then REJECTED still produced that instruction, naming
// a change that was never published and a reconciliation with nothing to do.
// containmentManagedTestConfig satisfies the containment metrics check that
// s.containmentManaged turns on, so a rejection in the test below comes from
// the loopback declaration under test and not from an unrelated refusal.
const containmentManagedTestConfig = "mode: balanced\nmetrics_listen: 127.0.0.1:9109\n"

func TestServer_ReloadDoesNotPromiseReconciliationForARejectedCandidate(t *testing.T) {
	stderr := &syncBuffer{}
	s, err := NewServer(ServerOpts{
		ConfigFile:                        writeServerTestConfig(t, containmentManagedTestConfig),
		Listen:                            serverTestEphemeralListen,
		ListenChanged:                     true,
		Stdout:                            &syncBuffer{},
		Stderr:                            stderr,
		allowEphemeralListenersForTesting: true,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(s.cleanup)
	s.containmentManaged = true

	rejected, loadErr := loadServerTestConfig(t, containmentManagedTestConfig)
	if loadErr != nil {
		t.Fatalf("load candidate: %v", loadErr)
	}
	rejected.Containment.LoopbackServices = []config.ContainmentLoopbackService{{
		Host: "127.0.0.1", Port: 9200, Owner: "search-team", Reason: "local index",
		ExpiresAt: time.Now().UTC().Add(-time.Hour).Format(time.RFC3339),
	}}
	if err := s.Reload(rejected); err == nil {
		t.Fatal("this test is vacuous unless the candidate is rejected")
	}
	if strings.Contains(stderr.String(), "run `pipelock contain reload-nft-rules`") {
		t.Errorf("a rejected candidate must not instruct the operator to reconcile; stderr = %q", stderr.String())
	}

	// Positive control: an ACCEPTED change must still produce the warning,
	// so suppressing it for a rejection cannot suppress it everywhere.
	accepted, loadErr := loadServerTestConfig(t, containmentManagedTestConfig)
	if loadErr != nil {
		t.Fatalf("load candidate: %v", loadErr)
	}
	accepted.Containment.LoopbackServices = []config.ContainmentLoopbackService{{
		Host: "127.0.0.1", Port: 9200, Owner: "search-team", Reason: "local index",
		ExpiresAt: time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
	}}
	if err := s.Reload(accepted); err != nil {
		t.Fatalf("a valid declaration must be accepted: %v", err)
	}
	if !strings.Contains(stderr.String(), "run `pipelock contain reload-nft-rules`") {
		t.Errorf("an accepted change must still tell the operator to reconcile; stderr = %q", stderr.String())
	}
}
