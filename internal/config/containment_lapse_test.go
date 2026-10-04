// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var lapseNow = time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

const (
	lapseFuture = "2030-01-01T00:00:00Z"
	lapsePast   = "2020-01-01T00:00:00Z"
)

func lapseLoopback(port int, expiresAt string) ContainmentLoopbackService {
	return ContainmentLoopbackService{Host: "127.0.0.1", Port: port, Owner: "owner", Reason: "reason", ExpiresAt: expiresAt}
}

func lapsePublished(name string, agentPort int, expiresAt string) ContainmentPublishedService {
	return ContainmentPublishedService{Name: name, AgentPort: agentPort, OperatorUser: "operator", Owner: "owner", Reason: "reason", ExpiresAt: expiresAt}
}

func TestResolveContainmentLoopbackServicesPartitionsExpiry(t *testing.T) {
	t.Parallel()
	active, lapsed, err := ResolveContainmentLoopbackServices([]ContainmentLoopbackService{
		lapseLoopback(9200, lapseFuture), lapseLoopback(9201, lapsePast), lapseLoopback(9202, lapseFuture),
	}, 8888, lapseNow)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(active) != 2 || active[0].Port != 9200 || active[1].Port != 9202 {
		t.Fatalf("active = %+v, want 9200 and 9202 in declared order", active)
	}
	if len(lapsed) != 1 || lapsed[0].Name != "127.0.0.1:9201" || lapsed[0].Kind != ContainmentGrantLoopbackService || lapsed[0].ExpiresAt != lapsePast {
		t.Fatalf("lapsed = %+v, want the 9201 entry", lapsed)
	}
	if want := "127.0.0.1:9201 (owner=owner): containment.loopback_services[1] expired at " + lapsePast; lapsed[0].Message != want {
		t.Fatalf("message = %q, want %q", lapsed[0].Message, want)
	}

	// The strict form still reports the same entry as an error, in the
	// historical wording callers and tests match on.
	err = ValidateContainmentLoopbackServices([]ContainmentLoopbackService{lapseLoopback(9201, lapsePast)}, 8888, lapseNow)
	if err == nil || !strings.Contains(err.Error(), "expired at "+lapsePast) {
		t.Fatalf("strict validate err = %v, want the expiry", err)
	}
	// An expiry equal to now is expired: After is strict.
	_, lapsed, err = ResolveContainmentLoopbackServices([]ContainmentLoopbackService{lapseLoopback(9200, lapseNow.Format(time.RFC3339))}, 8888, lapseNow)
	if err != nil || len(lapsed) != 1 {
		t.Fatalf("expiry at the boundary: lapsed=%+v err=%v, want lapsed", lapsed, err)
	}
}

func TestResolveContainmentLoopbackServicesMalformedStillErrorsWhenExpired(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		svc  []ContainmentLoopbackService
		want string
	}{
		{"expired wildcard host", []ContainmentLoopbackService{{Host: "0.0.0.0", Port: 9200, Owner: "o", Reason: "r", ExpiresAt: lapsePast}}, "loopback literal"},
		{"expired padded host", []ContainmentLoopbackService{{Host: " ::1", Port: 9200, Owner: "o", Reason: "r", ExpiresAt: lapsePast}}, "no surrounding whitespace"},
		{"expired proxy port", []ContainmentLoopbackService{lapseLoopback(8888, lapsePast)}, "proxy port"},
		{"expired out-of-range port", []ContainmentLoopbackService{lapseLoopback(70000, lapsePast)}, "between 1 and 65535"},
		{"expired duplicate of a live entry", []ContainmentLoopbackService{lapseLoopback(9200, lapseFuture), lapseLoopback(9200, lapsePast)}, "duplicates"},
		{"expired without owner", []ContainmentLoopbackService{{Host: "127.0.0.1", Port: 9200, Reason: "r", ExpiresAt: lapsePast}}, "owner is required"},
		{"expired without reason", []ContainmentLoopbackService{{Host: "127.0.0.1", Port: 9200, Owner: "o", ExpiresAt: lapsePast}}, "reason is required"},
		{"unparseable expiry", []ContainmentLoopbackService{lapseLoopback(9200, "soon")}, "RFC3339"},
		{"empty expiry", []ContainmentLoopbackService{lapseLoopback(9200, "")}, "RFC3339"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			active, lapsed, err := ResolveContainmentLoopbackServices(tc.svc, 8888, lapseNow)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want containing %q", err, tc.want)
			}
			if active != nil || lapsed != nil {
				t.Fatalf("an error must not return entries: active=%+v lapsed=%+v", active, lapsed)
			}
		})
	}
}

func TestResolveContainmentPublishedServicesPartitionsExpiry(t *testing.T) {
	t.Parallel()
	active, lapsed, err := ResolveContainmentPublishedServices([]ContainmentPublishedService{
		lapsePublished("viewer", 5900, lapsePast), lapsePublished("console", 5901, lapseFuture),
	}, nil, 8888, lapseNow)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(active) != 1 || active[0].Name != "console" {
		t.Fatalf("active = %+v, want only console", active)
	}
	if len(lapsed) != 1 || lapsed[0].Name != "viewer" || lapsed[0].Kind != ContainmentGrantPublishedService {
		t.Fatalf("lapsed = %+v, want viewer", lapsed)
	}
	if err := ValidateContainmentPublishedServices([]ContainmentPublishedService{lapsePublished("viewer", 5900, lapsePast)}, nil, 8888, lapseNow); err == nil || !strings.Contains(err.Error(), "expired at") {
		t.Fatalf("strict validate err = %v, want the expiry", err)
	}
}

func TestResolveContainmentPublishedServicesMalformedStillErrorsWhenExpired(t *testing.T) {
	t.Parallel()
	badOperator := lapsePublished("viewer", 5900, lapsePast)
	badOperator.OperatorUser = "Not A User"
	badName := lapsePublished("Viewer!", 5900, lapsePast)
	for _, tc := range []struct {
		name string
		svc  []ContainmentPublishedService
		want string
	}{
		{"bad operator", []ContainmentPublishedService{badOperator}, "operator_user"},
		{"bad name", []ContainmentPublishedService{badName}, "name"},
		{"duplicate name", []ContainmentPublishedService{lapsePublished("viewer", 5900, lapseFuture), lapsePublished("viewer", 5901, lapsePast)}, "more than once"},
		{"duplicate agent port", []ContainmentPublishedService{lapsePublished("a", 5900, lapseFuture), lapsePublished("b", 5900, lapsePast)}, "already published"},
		{"expired on the proxy port", []ContainmentPublishedService{lapsePublished("a", 8888, lapsePast)}, "proxy port"},
		{"unparseable expiry", []ContainmentPublishedService{lapsePublished("a", 5900, "soon")}, "RFC3339"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, _, err := ResolveContainmentPublishedServices(tc.svc, nil, 8888, lapseNow); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want containing %q", err, tc.want)
			}
		})
	}
}

// TestPublishedServicesReservedPortsIgnoreLapsedLoopback: a lapsed loopback
// declaration reserves nothing, so it cannot wedge startup through a port
// collision, while a live (or unreadable) one still reserves its port.
func TestPublishedServicesReservedPortsIgnoreLapsedLoopback(t *testing.T) {
	t.Parallel()
	published := []ContainmentPublishedService{lapsePublished("viewer", 9200, lapseFuture)}
	if _, _, err := ResolveContainmentPublishedServices(published, []ContainmentLoopbackService{lapseLoopback(9200, lapsePast)}, 8888, lapseNow); err != nil {
		t.Fatalf("a lapsed loopback port must not collide: %v", err)
	}
	if _, _, err := ResolveContainmentPublishedServices(published, []ContainmentLoopbackService{lapseLoopback(9200, lapseFuture)}, 8888, lapseNow); err == nil || !strings.Contains(err.Error(), "collides") {
		t.Fatalf("a live loopback port must still collide, err = %v", err)
	}
	malformed := lapseLoopback(9200, "soon")
	if _, _, err := ResolveContainmentPublishedServices(published, []ContainmentLoopbackService{malformed}, 8888, lapseNow); err == nil || !strings.Contains(err.Error(), "collides") {
		t.Fatalf("an unreadable loopback entry must keep reserving its port, err = %v", err)
	}
}

func TestLapseExpiredContainmentGrants(t *testing.T) {
	t.Parallel()
	cfg := Defaults()
	cfg.Containment.LoopbackServices = []ContainmentLoopbackService{lapseLoopback(9200, lapseFuture), lapseLoopback(9201, lapsePast)}
	cfg.Containment.PublishedServices = []ContainmentPublishedService{lapsePublished("viewer", 5900, lapsePast), lapsePublished("console", 5901, lapseFuture)}

	lapsed, err := cfg.LapseExpiredContainmentGrants(lapseNow)
	if err != nil {
		t.Fatalf("Lapse: %v", err)
	}
	if len(lapsed) != 2 {
		t.Fatalf("lapsed = %+v, want two", lapsed)
	}
	if len(cfg.Containment.LoopbackServices) != 1 || cfg.Containment.LoopbackServices[0].Port != 9200 {
		t.Fatalf("loopback_services = %+v", cfg.Containment.LoopbackServices)
	}
	if len(cfg.Containment.PublishedServices) != 1 || cfg.Containment.PublishedServices[0].Name != "console" {
		t.Fatalf("published_services = %+v", cfg.Containment.PublishedServices)
	}

	// Idempotent: a second call finds nothing new and returns the same record.
	again, err := cfg.LapseExpiredContainmentGrants(lapseNow)
	if err != nil || len(again) != 2 {
		t.Fatalf("second Lapse = (%+v, %v), want the same two grants and no duplicates", again, err)
	}

	// Warnings still name both grants after they were dropped, so a second
	// validation pass (startup and reload run one after Load) stays loud.
	warnings, err := cfg.ValidateWithWarnings()
	if err != nil {
		t.Fatalf("ValidateWithWarnings: %v", err)
	}
	var joined []string
	for _, w := range warnings {
		joined = append(joined, w.Field+": "+w.Message)
	}
	text := strings.Join(joined, "\n")
	for _, want := range []string{"127.0.0.1:9201", "published service viewer"} {
		if !strings.Contains(text, want) {
			t.Fatalf("warnings do not name %q:\n%s", want, text)
		}
	}
	if strings.Count(text, "127.0.0.1:9201") != 1 {
		t.Fatalf("a lapsed grant must warn once per validation:\n%s", text)
	}

	// The returned slice is a copy.
	again[0].Name = "mutated"
	if cfg.LapsedContainmentGrants()[0].Name == "mutated" {
		t.Fatal("LapsedContainmentGrants exposes the internal record")
	}
}

func TestLapseExpiredContainmentGrantsLeavesConfigUntouchedOnError(t *testing.T) {
	t.Parallel()
	cfg := Defaults()
	cfg.Containment.LoopbackServices = []ContainmentLoopbackService{lapseLoopback(9200, lapsePast), lapseLoopback(9200, lapseFuture)}
	if _, err := cfg.LapseExpiredContainmentGrants(lapseNow); err == nil || !strings.Contains(err.Error(), "duplicates") {
		t.Fatalf("err = %v, want the duplicate", err)
	}
	if len(cfg.Containment.LoopbackServices) != 2 || len(cfg.LapsedContainmentGrants()) != 0 {
		t.Fatalf("a failed Lapse changed the config: %+v lapsed=%+v", cfg.Containment.LoopbackServices, cfg.LapsedContainmentGrants())
	}

	cfg = Defaults()
	cfg.FetchProxy.Listen = "no-port"
	cfg.Containment.LoopbackServices = []ContainmentLoopbackService{lapseLoopback(9200, lapsePast)}
	if _, err := cfg.LapseExpiredContainmentGrants(lapseNow); err == nil || !strings.Contains(err.Error(), "fetch_proxy.listen") {
		t.Fatalf("err = %v, want the unusable proxy listen", err)
	}

	// Nothing declared never parses the listener.
	cfg = Defaults()
	cfg.FetchProxy.Listen = "no-port"
	if lapsed, err := cfg.LapseExpiredContainmentGrants(lapseNow); err != nil || len(lapsed) != 0 {
		t.Fatalf("empty declaration: (%+v, %v)", lapsed, err)
	}
}

// TestLoadDropsExpiredContainmentGrants drives the real loader: the file that
// used to be refused at startup now loads, with the lapsed entries out of the
// effective set and the policy hash.
func TestLoadDropsExpiredContainmentGrants(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	write := func(name, body string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	entry := func(port, expiresAt string) string {
		return "    - host: 127.0.0.1\n      port: " + port + "\n      owner: o\n      reason: r\n      expires_at: \"" + expiresAt + "\"\n"
	}
	withExpired := write("expired.yaml", "containment:\n  loopback_services:\n"+entry("9200", "2099-01-01T00:00:00Z")+entry("9201", lapsePast))
	cfg, err := Load(withExpired)
	if err != nil {
		t.Fatalf("an expired loopback entry must not fail load: %v", err)
	}
	if len(cfg.Containment.LoopbackServices) != 1 || cfg.Containment.LoopbackServices[0].Port != 9200 {
		t.Fatalf("effective set = %+v", cfg.Containment.LoopbackServices)
	}
	if got := cfg.LapsedContainmentGrants(); len(got) != 1 || got[0].Name != "127.0.0.1:9201" {
		t.Fatalf("lapsed = %+v", got)
	}
	// The lapsed entry is not part of the policy: the same file without it
	// hashes the same.
	clean, err := Load(write("clean.yaml", "containment:\n  loopback_services:\n"+entry("9200", "2099-01-01T00:00:00Z")))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CanonicalPolicyHash() != clean.CanonicalPolicyHash() {
		t.Fatal("a lapsed entry changed the policy hash; it must not be part of the effective policy")
	}

	// Malformed siblings still refuse the whole file.
	for name, body := range map[string]string{
		"hostname.yaml":  "containment:\n  loopback_services:\n" + strings.Replace(entry("9200", lapsePast), "127.0.0.1", "localhost", 1),
		"proxyport.yaml": "containment:\n  loopback_services:\n" + entry("8888", lapsePast),
		"dup.yaml":       "containment:\n  loopback_services:\n" + entry("9200", lapseFuture) + entry("9200", lapsePast),
	} {
		if _, err := Load(write(name, body)); err == nil {
			t.Fatalf("%s: a malformed declaration must still fail load", name)
		}
	}

	// Clone keeps the record so a cloned live config keeps reporting it.
	if got := cfg.Clone().LapsedContainmentGrants(); len(got) != 1 {
		t.Fatalf("clone lost the lapsed record: %+v", got)
	}
}

func TestContainmentProxyPortRejectsUnusableListen(t *testing.T) {
	t.Parallel()
	for _, listen := range []string{"no-port", "127.0.0.1:notaport"} {
		cfg := Defaults()
		cfg.FetchProxy.Listen = listen
		if _, err := cfg.containmentProxyPort(); err == nil {
			t.Fatalf("listen %q: want an error", listen)
		}
	}
	// A declared published service with an unusable listen surfaces through
	// the validator too, not only through Lapse.
	cfg := Defaults()
	cfg.FetchProxy.Listen = "no-port"
	cfg.Containment.PublishedServices = []ContainmentPublishedService{lapsePublished("viewer", 5900, lapseFuture)}
	if err := cfg.validateContainmentPublishedServices(nil); err == nil {
		t.Fatal("published validator accepted an unusable fetch_proxy.listen")
	}
	// A malformed published entry fails the validator, expired or not.
	cfg = Defaults()
	cfg.Containment.PublishedServices = []ContainmentPublishedService{lapsePublished("Bad Name", 5900, lapsePast)}
	if err := cfg.validateContainmentPublishedServices(nil); err == nil {
		t.Fatal("published validator accepted a malformed expired entry")
	}
}
