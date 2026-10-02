// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

const expiredLoopbackTestStamp = "2000-01-01T00:00:00Z"

// loopbackEntryYAML renders one containment.loopback_services list item.
func loopbackEntryYAML(host string, port int, expiresAt string) string {
	return "  - host: " + host + "\n    port: " + strconv.Itoa(port) +
		"\n    owner: owner-" + strconv.Itoa(port) + "\n    reason: local index\n    expires_at: \"" + expiresAt + "\"\n"
}

func loopbackConfigYAML(entries ...string) string {
	return "containment:\n  loopback_services:\n" + strings.Join(entries, "")
}

// TestParseContainmentLoopbackServicesPartitionsExpiry pins the lapsed-grant
// contract at the single parser every consumer shares: an expired entry is
// returned separately and never in the effective set, while every malformed
// shape still fails closed whatever its date says.
func TestParseContainmentLoopbackServicesPartitionsExpiry(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	future := "2030-01-01T00:00:00Z"

	t.Run("expired entry is dropped and named, future sibling kept", func(t *testing.T) {
		t.Parallel()
		data := []byte(loopbackConfigYAML(loopbackEntryYAML("127.0.0.1", 9200, future), loopbackEntryYAML("127.0.0.1", 9201, expiredLoopbackTestStamp)))
		active, lapsed, err := parseContainmentLoopbackServicesWithLapsed(data, 8888, now)
		if err != nil {
			t.Fatalf("an expired entry must not be an error: %v", err)
		}
		if len(active) != 1 || active[0].Port != 9200 {
			t.Fatalf("effective set = %+v, want only the unexpired 9200", active)
		}
		if len(lapsed) != 1 || lapsed[0].Name != "127.0.0.1:9201" || lapsed[0].Owner != "owner-9201" || lapsed[0].Kind != config.ContainmentGrantLoopbackService {
			t.Fatalf("lapsed = %+v, want the 9201 entry with its owner", lapsed)
		}
		plain, err := parseContainmentLoopbackServicesFromConfigBytes(data, 8888, now)
		if err != nil || len(plain) != 1 || plain[0].Port != 9200 {
			t.Fatalf("shared parser = (%+v, %v), want the same effective set", plain, err)
		}
	})

	for _, tc := range []struct {
		name string
		body string
		want string
	}{
		{"hostname", loopbackConfigYAML(loopbackEntryYAML("localhost", 9200, future)), "loopback literal"},
		{"proxy port", loopbackConfigYAML(loopbackEntryYAML("127.0.0.1", 8888, future)), "proxy port"},
		{"duplicate", loopbackConfigYAML(loopbackEntryYAML("127.0.0.1", 9200, future), loopbackEntryYAML("127.0.0.1", 9200, future)), "duplicates"},
		{"expired duplicate still fails", loopbackConfigYAML(loopbackEntryYAML("127.0.0.1", 9200, future), loopbackEntryYAML("127.0.0.1", 9200, expiredLoopbackTestStamp)), "duplicates"},
		{"expired with a bad host still fails", loopbackConfigYAML(loopbackEntryYAML("0.0.0.0", 9200, expiredLoopbackTestStamp)), "loopback literal"},
		{"expired on the proxy port still fails", loopbackConfigYAML(loopbackEntryYAML("127.0.0.1", 8888, expiredLoopbackTestStamp)), "proxy port"},
		{"unparseable expiry", loopbackConfigYAML(loopbackEntryYAML("127.0.0.1", 9200, "not-a-date")), "RFC3339"},
		{"missing owner on an expired entry", "containment:\n  loopback_services:\n  - host: 127.0.0.1\n    port: 9200\n    reason: r\n    expires_at: \"" + expiredLoopbackTestStamp + "\"\n", "owner is required"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			active, lapsed, err := parseContainmentLoopbackServicesWithLapsed([]byte(tc.body), 8888, now)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want containing %q", err, tc.want)
			}
			if active != nil || lapsed != nil {
				t.Fatalf("a failing parse must return no entries, got active=%+v lapsed=%+v", active, lapsed)
			}
		})
	}
}

// TestReloadNFTRulesKeepsUnexpiredSiblingOfExpiredLoopbackService is the
// regression for one expired entry taking every declared forwarder with it.
func TestReloadNFTRulesKeepsUnexpiredSiblingOfExpiredLoopbackService(t *testing.T) {
	t.Parallel()
	persisted := RenderNFTRulesWithLoopbackServices(loopbackTestOperatorUID, loopbackTestProxyUID, loopbackTestAgentUID, loopbackTestProxyPort, []config.ContainmentLoopbackService{loopbackTestService(9200), loopbackTestService(9201)})
	body := loopbackConfigYAML(loopbackEntryYAML("127.0.0.1", 9200, "2099-01-01T00:00:00Z"), loopbackEntryYAML("127.0.0.1", 9201, expiredLoopbackTestStamp))
	fx := newNFTReloadTestFixture(t, nftReloadTestLiveWithOneService, body, persisted)
	var forwarded []config.ContainmentLoopbackService
	fx.env.reconcileForwarders = func(_ context.Context, _ int, services []config.ContainmentLoopbackService) error {
		forwarded = append([]config.ContainmentLoopbackService(nil), services...)
		return nil
	}
	if err := reloadNFTRules(context.Background(), fx.env); err != nil {
		t.Fatalf("reloadNFTRules: %v", err)
	}
	if len(forwarded) != 1 || forwarded[0].Port != 9200 {
		t.Fatalf("reconciled forwarders = %+v, want only the unexpired 9200", forwarded)
	}
	for _, svc := range forwarded {
		if svc.Port == 9201 {
			t.Fatalf("expired 127.0.0.1:9201 reached the rendered forwarder set: %+v", forwarded)
		}
	}
	if len(fx.warnings) != 1 || !strings.Contains(fx.warnings[0], "127.0.0.1:9201") || !strings.Contains(fx.warnings[0], "owner-9201") || strings.Contains(fx.warnings[0], "9200") {
		t.Fatalf("warnings = %v, want exactly one naming the expired 9201 entry and not its sibling", fx.warnings)
	}
}

// TestReloadNFTRulesStillDropsEveryForwarderOnMalformedSibling is the
// fail-closed control: expiry is tolerated, but a malformed sibling is not,
// so the reconciler still returns the empty set for a file it cannot read.
func TestReloadNFTRulesStillDropsEveryForwarderOnMalformedSibling(t *testing.T) {
	t.Parallel()
	persisted := RenderNFTRulesWithLoopbackServices(loopbackTestOperatorUID, loopbackTestProxyUID, loopbackTestAgentUID, loopbackTestProxyPort, []config.ContainmentLoopbackService{loopbackTestService(9200)})
	body := loopbackConfigYAML(loopbackEntryYAML("127.0.0.1", 9200, "2099-01-01T00:00:00Z"), loopbackEntryYAML("localhost", 9201, "2099-01-01T00:00:00Z"))
	fx := newNFTReloadTestFixture(t, nftReloadTestLiveWithOneService, body, persisted)
	var forwarded []config.ContainmentLoopbackService
	forwarders := func(_ context.Context, _ int, services []config.ContainmentLoopbackService) error {
		forwarded = append([]config.ContainmentLoopbackService(nil), services...)
		return nil
	}
	fx.env.reconcileForwarders = forwarders
	if err := reloadNFTRules(context.Background(), fx.env); err != nil {
		t.Fatalf("reloadNFTRules: %v", err)
	}
	if len(forwarded) != 0 {
		t.Fatalf("a malformed declaration must reconcile to none, got %+v", forwarded)
	}
	if len(fx.warnings) != 1 || !strings.Contains(fx.warnings[0], "cannot honor") {
		t.Fatalf("warnings = %v, want the malformed-declaration warning", fx.warnings)
	}
}

// TestVerifyLoopbackDeclarationNamesExpiredEntryAndKeepsSibling covers the
// reader behind verify, doctor, and the probes: it reports unusable (so the
// probe FAILS) and names the expired entry, yet still returns the unexpired
// entry so it can be checked.
func TestVerifyLoopbackDeclarationNamesExpiredEntryAndKeepsSibling(t *testing.T) {
	t.Parallel()
	body := loopbackConfigYAML(loopbackEntryYAML("127.0.0.1", 9200, "2099-01-01T00:00:00Z"), loopbackEntryYAML("127.0.0.1", 9201, expiredLoopbackTestStamp))
	env := &probeEnv{
		configPath: "/etc/pipelock/pipelock.yaml",
		readFile:   func(string) ([]byte, error) { return []byte(body), nil },
	}
	decl := readVerifyLoopbackDeclaration(env, 8888)
	if !decl.unusable || !decl.lapsedOnly {
		t.Fatalf("declaration = %+v, want unusable and lapsedOnly", decl)
	}
	if len(decl.services) != 1 || decl.services[0].Port != 9200 {
		t.Fatalf("services = %+v, want the unexpired 9200 kept for checking", decl.services)
	}
	if !strings.Contains(decl.problem, "127.0.0.1:9201") || !strings.Contains(decl.problem, "owner-9201") || strings.Contains(decl.problem, "9200") {
		t.Fatalf("problem = %q, want it to name only the expired 9201 entry", decl.problem)
	}
	services, problem, unusable := declaredContainmentLoopbackServicesForVerify(env, 8888)
	if !unusable || problem != decl.problem || len(services) != 1 {
		t.Fatalf("legacy reader = (%+v, %q, %v), want it to agree with the detailed reader", services, problem, unusable)
	}
}

// writeLoopbackProbeUnits writes the three managed unit files verify expects
// for one declared service, beside the base fixture's namespace units.
func writeLoopbackProbeUnits(t *testing.T, env *probeEnv, service config.ContainmentLoopbackService) {
	t.Helper()
	unitDir := filepath.Dir(env.proxyForwarderSocketPath)
	unit := loopbackForwarderUnitBase(service.Host, service.Port)
	for path, body := range map[string]string{
		filepath.Join(unitDir, unit+".socket"):        renderDeclaredLoopbackSocketUnit(env.agentUserName, service),
		filepath.Join(unitDir, unit+".service"):       renderDeclaredLoopbackForwarderUnit(env.pipelockTarget, env.proxyUserName, service),
		filepath.Join(unitDir, unit+"-netns.service"): renderDeclaredLoopbackNamespaceForwarderUnit(env.pipelockTarget, env.agentUserName, service),
	} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// TestProbeAgentNetworkNamespaceFailsNamingExpiredEntryWhileCheckingSibling
// is the verify contract: probe 21 FAILS naming the expired entry, and the
// unexpired sibling is still checked (a drifted sibling unit is reported too).
func TestProbeAgentNetworkNamespaceFailsNamingExpiredEntryWhileCheckingSibling(t *testing.T) {
	sibling := config.ContainmentLoopbackService{Host: "127.0.0.1", Port: 9200, Owner: "owner-9200", Reason: "local index", ExpiresAt: "2099-01-01T00:00:00Z"}
	body := loopbackConfigYAML(loopbackEntryYAML("127.0.0.1", 9200, sibling.ExpiresAt), loopbackEntryYAML("127.0.0.1", 9201, expiredLoopbackTestStamp))

	setup := func(t *testing.T, withExpired bool) *probeEnv {
		t.Helper()
		env := covNSProbeBase(t)
		cfg := body
		if !withExpired {
			cfg = loopbackConfigYAML(loopbackEntryYAML("127.0.0.1", 9200, sibling.ExpiresAt))
		}
		if err := os.WriteFile(env.configPath, []byte(cfg), 0o600); err != nil {
			t.Fatal(err)
		}
		inv, err := json.MarshalIndent(desiredLoopbackForwarders([]config.ContainmentLoopbackService{sibling}), "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(env.loopbackForwarderInvPath, append(inv, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
		writeLoopbackProbeUnits(t, env, sibling)
		return env
	}

	t.Run("positive control: the unexpired sibling alone passes", func(t *testing.T) {
		status, detail := probeAgentNetworkNamespace(context.Background(), setup(t, false))
		if status != statusPass {
			t.Fatalf("probe = (%q, %q), want pass: the fixture must be valid or the failures below prove nothing", status, detail)
		}
	})

	t.Run("expired entry fails the probe and is named", func(t *testing.T) {
		status, detail := probeAgentNetworkNamespace(context.Background(), setup(t, true))
		if status != statusFail {
			t.Fatalf("probe = (%q, %q), want fail while an expired entry is declared", status, detail)
		}
		if !strings.Contains(detail, "127.0.0.1:9201") || !strings.Contains(detail, "owner-9201") || !strings.Contains(detail, "expired") {
			t.Fatalf("detail = %q, want it to name the expired entry", detail)
		}
	})

	t.Run("a drifted sibling is still reported next to the expired entry", func(t *testing.T) {
		env := setup(t, true)
		unit := loopbackForwarderUnitBase(sibling.Host, sibling.Port)
		if err := os.Remove(filepath.Join(filepath.Dir(env.proxyForwarderSocketPath), unit+".socket")); err != nil {
			t.Fatal(err)
		}
		status, detail := probeAgentNetworkNamespace(context.Background(), env)
		if status != statusFail || !strings.Contains(detail, "is missing or drifted") {
			t.Fatalf("probe = (%q, %q), want the unexpired sibling's drift reported", status, detail)
		}
		if !strings.Contains(detail, "127.0.0.1:9201") {
			t.Fatalf("detail = %q, want the expired entry named alongside the drift", detail)
		}
	})
}

// fakeSystemd models the one systemd behavior this defect hangs on: a socket
// unit refuses to listen while a service of the same name is already active,
// even when that service's unit file is gone.
type fakeSystemd struct {
	mu      sync.Mutex
	active  map[string]bool
	enabled map[string]bool
	stopped []string
}

func newFakeSystemd() *fakeSystemd {
	return &fakeSystemd{active: map[string]bool{}, enabled: map[string]bool{}}
}

func (f *fakeSystemd) run(_ context.Context, name string, args ...string) (string, int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if name != "systemctl" || len(args) == 0 {
		return "", 0, nil
	}
	verb, units := args[0], args[1:]
	switch verb {
	case "is-enabled":
		if f.enabled[units[0]] {
			return systemctlEnabled + "\n", 0, nil
		}
		return "disabled\n", 1, nil
	case "is-active":
		if f.active[units[0]] {
			return systemctlActive + "\n", 0, nil
		}
		return "inactive\n", 3, nil
	case "stop":
		for _, unit := range units {
			f.stopped = append(f.stopped, unit)
			delete(f.active, unit)
		}
	case "disable":
		for _, unit := range units {
			if unit == "--now" {
				continue
			}
			delete(f.enabled, unit)
			if len(args) > 1 && args[1] == "--now" {
				delete(f.active, unit)
			}
		}
	case "enable":
		for _, unit := range units {
			if unit == "--now" {
				continue
			}
			if base, ok := strings.CutSuffix(unit, ".socket"); ok && !f.active[unit] && f.active[base+".service"] {
				return fmt.Sprintf("%s: Socket service %s.service already active, refusing.\n", unit, base), 1, nil
			}
			f.enabled[unit] = true
			if len(args) > 1 && args[1] == "--now" {
				f.active[unit] = true
			}
		}
	}
	return "", 0, nil
}

func relayUnit(port int) string {
	return loopbackForwarderUnitBase("127.0.0.1", port)
}

func TestRetirementPreservesForeignPrefixedUnit(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	systemd := newFakeSystemd()
	env.runCmd = systemd.run
	unitDir := filepath.Dir(env.proxyForwarderSocketPath)
	if err := os.MkdirAll(unitDir, 0o750); err != nil {
		t.Fatal(err)
	}
	foreign := relayUnit(9300) + ".service"
	body := []byte("[Service]\nExecStart=/usr/bin/true\n")
	path := filepath.Join(unitDir, foreign)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	systemd.active[foreign] = true
	services := []config.ContainmentLoopbackService{}
	if _, err := stepInstallNetworkNamespaceWithServices(&services).apply(context.Background(), env); err != nil {
		t.Fatal(err)
	}
	if !systemd.active[foreign] {
		t.Error("retirement stopped an unrecorded foreign relay")
	}
	got, err := os.ReadFile(filepath.Clean(path))
	if err != nil || string(got) != string(body) {
		t.Errorf("retirement changed the foreign unit: %q, %v", got, err)
	}
}

// TestRetiredLoopbackRelayIsStoppedSoThePortCanBeReAdded is the regression
// for the orphaned host relay: retiring a declaration must stop the relay
// service its socket activated, or re-adding the port is refused by systemd.
func TestRetiredLoopbackRelayIsStoppedSoThePortCanBeReAdded(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	systemd := newFakeSystemd()
	env.runCmd = systemd.run
	unitDir := filepath.Dir(env.proxyForwarderSocketPath)
	if err := os.MkdirAll(unitDir, 0o750); err != nil {
		t.Fatal(err)
	}
	svc := func(port int) config.ContainmentLoopbackService {
		return config.ContainmentLoopbackService{Host: "127.0.0.1", Port: port, Owner: "o", Reason: "r", ExpiresAt: "2099-01-01T00:00:00Z"}
	}
	apply := func(services ...config.ContainmentLoopbackService) error {
		_, err := stepInstallNetworkNamespaceWithServices(&services).apply(context.Background(), env)
		return err
	}
	// A connection to the doorway is what starts the host relay.
	connect := func(port int) {
		systemd.mu.Lock()
		defer systemd.mu.Unlock()
		systemd.active[relayUnit(port)+".service"] = true
	}

	if err := apply(svc(9200), svc(9201)); err != nil {
		t.Fatalf("first install: %v", err)
	}
	connect(9200)
	connect(9201)

	// The expiry reconciler keeps 9200 and retires 9201.
	if err := apply(svc(9200)); err != nil {
		t.Fatalf("reconcile after expiry: %v", err)
	}
	if systemd.active[relayUnit(9201)+".service"] {
		t.Fatal("retired 9201 relay service is still running with its unit file removed")
	}
	if !systemd.active[relayUnit(9200)+".service"] {
		t.Fatal("the unexpired 9200 relay must keep running")
	}
	if _, err := os.Stat(filepath.Join(unitDir, relayUnit(9201)+".service")); !os.IsNotExist(err) {
		t.Fatalf("retired 9201 unit file still present: %v", err)
	}

	// Re-adding the port must work.
	if err := apply(svc(9200), svc(9201)); err != nil {
		t.Fatalf("re-adding the retired port: %v", err)
	}
}

// TestForeignActiveRelayIsStillRefused is the negative control: a service
// Pipelock does not own is never stopped, so systemd's refusal stands.
func TestForeignActiveRelayIsStillRefused(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	systemd := newFakeSystemd()
	env.runCmd = systemd.run
	if err := os.MkdirAll(filepath.Dir(env.proxyForwarderSocketPath), 0o750); err != nil {
		t.Fatal(err)
	}
	foreign := relayUnit(9300) + ".service"
	systemd.active[foreign] = true
	services := []config.ContainmentLoopbackService{{Host: "127.0.0.1", Port: 9300, Owner: "o", Reason: "r", ExpiresAt: "2099-01-01T00:00:00Z"}}
	_, err := stepInstallNetworkNamespaceWithServices(&services).apply(context.Background(), env)
	if err == nil || !strings.Contains(err.Error(), "enable contained namespace socket") {
		t.Fatalf("err = %v, want the refused socket enable to surface", err)
	}
	if !systemd.active[foreign] {
		t.Fatal("a foreign active service was stopped")
	}
	for _, unit := range systemd.stopped {
		if unit == foreign {
			t.Fatalf("stop was issued for the foreign service: %v", systemd.stopped)
		}
	}
}

// TestInstallNamespaceStepDropsExpiredEntryAndWarns proves install no longer
// refuses at the managed-config read: the expired entry is dropped and named,
// the unexpired sibling is rendered, and a malformed entry still fails.
func TestInstallNamespaceStepDropsExpiredEntryAndWarns(t *testing.T) {
	env, _, out := newFakeEnv(t)
	systemd := newFakeSystemd()
	env.runCmd = systemd.run
	if err := os.MkdirAll(filepath.Dir(env.proxyForwarderSocketPath), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(env.configDir, 0o750); err != nil {
		t.Fatal(err)
	}
	cfg := loopbackConfigYAML(loopbackEntryYAML("127.0.0.1", 9200, "2099-01-01T00:00:00Z"), loopbackEntryYAML("127.0.0.1", 9201, expiredLoopbackTestStamp))
	if err := os.WriteFile(managedPipelockConfigPath(env), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := stepInstallNetworkNamespace().apply(context.Background(), env); err != nil {
		t.Fatalf("an expired entry must not fail install: %v", err)
	}
	unitDir := filepath.Dir(env.proxyForwarderSocketPath)
	if _, err := os.Stat(filepath.Join(unitDir, relayUnit(9200)+".socket")); err != nil {
		t.Fatalf("unexpired sibling was not rendered: %v", err)
	}
	if _, err := os.Stat(filepath.Join(unitDir, relayUnit(9201)+".socket")); !os.IsNotExist(err) {
		t.Fatalf("expired entry was rendered: %v", err)
	}
	if !strings.Contains(out.String(), "127.0.0.1:9201") || !strings.Contains(out.String(), "expired") {
		t.Fatalf("install output = %q, want a warning naming the expired entry", out.String())
	}

	bad := loopbackConfigYAML(loopbackEntryYAML("localhost", 9202, expiredLoopbackTestStamp))
	if err := os.WriteFile(managedPipelockConfigPath(env), []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := stepInstallNetworkNamespace().apply(context.Background(), env); err == nil || !strings.Contains(err.Error(), "loopback literal") {
		t.Fatalf("a malformed expired entry must still fail install, got %v", err)
	}
}

// TestProbePublishedServicesFailsNamingExpiredEntryWhileCheckingSibling is the
// published-service twin of the loopback verify contract: an expired
// publication fails the probe by name, while the unexpired one is still
// checked.
func TestProbePublishedServicesFailsNamingExpiredEntryWhileCheckingSibling(t *testing.T) {
	expired := publishedTestConfig +
		"    - name: console\n      agent_port: 5901\n      operator_user: operator\n" +
		"      owner: owner-console\n      reason: second\n      expires_at: \"" + expiredLoopbackTestStamp + "\"\n"

	t.Run("positive control: the unexpired publication alone passes", func(t *testing.T) {
		fx := newPublishedProbeFixture(t)
		if status, detail := fx.probe(); status != statusPass {
			t.Fatalf("probe = (%q, %q), want pass: the fixture must be valid or the failures below prove nothing", status, detail)
		}
	})

	t.Run("expired publication fails the probe and is named", func(t *testing.T) {
		fx := newPublishedProbeFixture(t)
		fx.files[fx.env.configPath] = expired
		status, detail := fx.probe()
		if status != statusFail || !strings.Contains(detail, "published service console") || !strings.Contains(detail, "owner-console") || !strings.Contains(detail, "expired") {
			t.Fatalf("probe = (%q, %q), want a failure naming the expired console publication", status, detail)
		}
		if strings.Contains(detail, "published service viewer") {
			t.Fatalf("detail = %q, must not name the unexpired viewer publication", detail)
		}
	})

	t.Run("a drifted sibling is still reported next to the expired entry", func(t *testing.T) {
		fx := newPublishedProbeFixture(t)
		fx.files[fx.env.configPath] = expired
		fx.states["is-active pipelock-published-viewer.socket"] = "inactive"
		status, detail := fx.probe()
		if status != statusFail || !strings.Contains(detail, "bridge failed") || !strings.Contains(detail, "published service console") {
			t.Fatalf("probe = (%q, %q), want the unexpired publication's failure plus the expired entry", status, detail)
		}
	})

	t.Run("legacy reader agrees", func(t *testing.T) {
		fx := newPublishedProbeFixture(t)
		fx.files[fx.env.configPath] = expired
		services, problem, unusable := declaredContainmentPublishedServicesForVerify(fx.env, 8888)
		if !unusable || len(services) != 1 || services[0].Name != "viewer" || !strings.Contains(problem, "console") {
			t.Fatalf("legacy reader = (%+v, %q, %v)", services, problem, unusable)
		}
	})
}
