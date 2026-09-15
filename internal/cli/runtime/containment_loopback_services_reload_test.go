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
