// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

const (
	lapseFutureStamp = "2099-01-01T00:00:00Z"
	lapsePastStamp   = "2000-01-01T00:00:00Z"
)

func lapseLoopbackYAML(port int, expiresAt string) string {
	return fmt.Sprintf("    - host: 127.0.0.1\n      port: %d\n      owner: owner-%d\n      reason: local index\n      expires_at: %q\n", port, port, expiresAt)
}

func lapsePublishedYAML(name string, agentPort int, expiresAt string) string {
	return fmt.Sprintf("    - name: %s\n      agent_port: %d\n      operator_user: operator\n      owner: owner-%s\n      reason: watch the display\n      expires_at: %q\n", name, agentPort, name, expiresAt)
}

func lapseConfig(webhookURL string, loopback, published []string) string {
	body := "mode: balanced\n"
	if webhookURL != "" {
		body += "emit:\n  webhook:\n    url: " + fmt.Sprintf("%q", webhookURL) + "\n    min_severity: warn\n    timeout_seconds: 1\n    queue_size: 16\n"
	}
	body += "containment:\n"
	if len(loopback) > 0 {
		body += "  loopback_services:\n" + strings.Join(loopback, "")
	}
	if len(published) > 0 {
		body += "  published_services:\n" + strings.Join(published, "")
	}
	return body
}

func newLapseTestServer(t *testing.T, body string) (*Server, *syncBuffer, error) {
	t.Helper()
	buf := &syncBuffer{}
	s, err := NewServer(ServerOpts{
		ConfigFile:                        writeServerTestConfig(t, body),
		Listen:                            reserveTCPAddress(t, "127.0.0.1"),
		ListenChanged:                     true,
		Stdout:                            buf,
		Stderr:                            buf,
		allowEphemeralListenersForTesting: true,
	})
	if err == nil {
		t.Cleanup(s.cleanup)
	}
	return s, buf, err
}

// waitForLapseEvents collects containment_grant_lapsed webhook events keyed by
// entry until want have arrived or the deadline passes.
func waitForLapseEvents(t *testing.T, events <-chan serverTestWebhookEvent, want int) map[string]serverTestWebhookEvent {
	t.Helper()
	got := map[string]serverTestWebhookEvent{}
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	for len(got) < want {
		select {
		case event := <-events:
			if event.Type != containmentGrantLapsedEvent {
				continue
			}
			entry, _ := event.Fields["entry"].(string)
			got[entry] = event
		case <-timer.C:
			t.Fatalf("timed out with %d of %d lapse events: %v", len(got), want, got)
		}
	}
	return got
}

// TestNewServer_ExpiredContainmentGrantsAreDroppedNotFatal is the startup
// outage regression: an expired loopback or published entry used to make
// config load fail, so pipelock.service refused to start and every contained
// agent lost egress. Only the expired entries must leave the effective set.
func TestNewServer_ExpiredContainmentGrantsAreDroppedNotFatal(t *testing.T) {
	webhookURL, events := newServerTestWebhook(t)
	body := lapseConfig(webhookURL,
		[]string{lapseLoopbackYAML(9200, lapseFutureStamp), lapseLoopbackYAML(9201, lapsePastStamp)},
		[]string{lapsePublishedYAML("viewer", 5900, lapsePastStamp), lapsePublishedYAML("console", 5901, lapseFutureStamp)})
	s, stderr, err := newLapseTestServer(t, body)
	if err != nil {
		t.Fatalf("an expired grant must not stop the proxy from starting: %v", err)
	}

	live := s.proxy.CurrentConfig()
	if len(live.Containment.LoopbackServices) != 1 || live.Containment.LoopbackServices[0].Port != 9200 {
		t.Fatalf("effective loopback_services = %+v, want only the unexpired 9200", live.Containment.LoopbackServices)
	}
	if len(live.Containment.PublishedServices) != 1 || live.Containment.PublishedServices[0].Name != "console" {
		t.Fatalf("effective published_services = %+v, want only the unexpired console", live.Containment.PublishedServices)
	}
	for _, want := range []string{"127.0.0.1:9201", "owner-9201", "published service viewer", "owner-viewer"} {
		if !stderr.contains(want) {
			t.Fatalf("stderr does not name %q:\n%s", want, stderr.String())
		}
	}
	if stderr.contains("127.0.0.1:9200 (owner") || stderr.contains("published service console") {
		t.Fatalf("stderr warned about an unexpired entry:\n%s", stderr.String())
	}

	got := waitForLapseEvents(t, events, 2)
	if ev := got["127.0.0.1:9201"]; ev.Fields["field"] != "containment.loopback_services" || ev.Fields["phase"] != "startup" {
		t.Fatalf("loopback lapse event = %+v", ev)
	}
	if ev := got["viewer"]; ev.Fields["field"] != "containment.published_services" || ev.Fields["owner"] != "owner-viewer" {
		t.Fatalf("published lapse event = %+v", ev)
	}
}

// TestNewServer_MalformedContainmentGrantsStillFailClosed is the control for
// the test above: lapse tolerance covers expiry and nothing else.
func TestNewServer_MalformedContainmentGrantsStillFailClosed(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want string
	}{
		{"hostname loopback host", lapseConfig("", []string{strings.Replace(lapseLoopbackYAML(9200, lapseFutureStamp), "127.0.0.1", "localhost", 1)}, nil), "loopback literal"},
		{"expired with a hostname still fails", lapseConfig("", []string{strings.Replace(lapseLoopbackYAML(9200, lapsePastStamp), "127.0.0.1", "localhost", 1)}, nil), "loopback literal"},
		{"duplicate loopback entries", lapseConfig("", []string{lapseLoopbackYAML(9200, lapseFutureStamp), lapseLoopbackYAML(9200, lapsePastStamp)}, nil), "duplicates"},
		{"proxy port loopback entry", lapseConfig("", []string{lapseLoopbackYAML(8888, lapsePastStamp)}, nil), "proxy port"},
		{"expired published entry with a bad operator", lapseConfig("", nil, []string{strings.Replace(lapsePublishedYAML("viewer", 5900, lapsePastStamp), "operator_user: operator", "operator_user: Bad User", 1)}), "operator_user"},
		{"duplicate published names", lapseConfig("", nil, []string{lapsePublishedYAML("viewer", 5900, lapseFutureStamp), lapsePublishedYAML("viewer", 5901, lapsePastStamp)}), "more than once"},
		{"unparseable expiry", lapseConfig("", []string{lapseLoopbackYAML(9200, "tomorrow")}, nil), "RFC3339"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := newLapseTestServer(t, tc.body)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("NewServer err = %v, want containing %q", err, tc.want)
			}
		})
	}
}

// TestServer_ReloadAppliesContainmentGrantPartition covers both reload
// entries: a file candidate (config.Load already partitions it) and an
// in-memory candidate that never passed through Load.
func TestServer_ReloadAppliesContainmentGrantPartition(t *testing.T) {
	webhookURL, events := newServerTestWebhook(t)
	s, stderr, err := newLapseTestServer(t, lapseConfig(webhookURL, []string{lapseLoopbackYAML(9200, lapseFutureStamp)}, nil))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	t.Run("candidate loaded from a file", func(t *testing.T) {
		candidate, loadErr := loadServerTestConfig(t, lapseConfig(webhookURL,
			[]string{lapseLoopbackYAML(9200, lapseFutureStamp), lapseLoopbackYAML(9202, lapsePastStamp)}, nil))
		if loadErr != nil {
			t.Fatalf("load candidate: %v", loadErr)
		}
		if reloadErr := s.Reload(candidate); reloadErr != nil {
			t.Fatalf("Reload: %v", reloadErr)
		}
		live := s.proxy.CurrentConfig()
		if len(live.Containment.LoopbackServices) != 1 || live.Containment.LoopbackServices[0].Port != 9200 {
			t.Fatalf("effective loopback_services after reload = %+v, want only 9200", live.Containment.LoopbackServices)
		}
		if !stderr.contains("127.0.0.1:9202") {
			t.Fatalf("reload did not warn about the expired entry:\n%s", stderr.String())
		}
		ev := waitForLapseEvents(t, events, 1)["127.0.0.1:9202"]
		if ev.Fields["phase"] != "reload" {
			t.Fatalf("reload lapse event = %+v, want phase reload", ev)
		}
	})

	t.Run("in-memory candidate that never passed through Load", func(t *testing.T) {
		candidate := s.proxy.CurrentConfig().Clone()
		candidate.Containment.LoopbackServices = []config.ContainmentLoopbackService{
			{Host: "127.0.0.1", Port: 9200, Owner: "o", Reason: "r", ExpiresAt: lapseFutureStamp},
			{Host: "127.0.0.1", Port: 9203, Owner: "o", Reason: "r", ExpiresAt: lapsePastStamp},
		}
		if reloadErr := s.Reload(candidate); reloadErr != nil {
			t.Fatalf("an expired entry must not reject an in-memory reload: %v", reloadErr)
		}
		live := s.proxy.CurrentConfig()
		for _, svc := range live.Containment.LoopbackServices {
			if svc.Port == 9203 {
				t.Fatalf("expired 9203 reached the live effective set: %+v", live.Containment.LoopbackServices)
			}
		}
		if len(live.Containment.LoopbackServices) != 1 {
			t.Fatalf("effective loopback_services = %+v, want only 9200", live.Containment.LoopbackServices)
		}
	})

	t.Run("in-memory malformed candidate is still rejected", func(t *testing.T) {
		candidate := s.proxy.CurrentConfig().Clone()
		candidate.Containment.LoopbackServices = []config.ContainmentLoopbackService{
			{Host: "127.0.0.1", Port: 9200, Owner: "o", Reason: "r", ExpiresAt: lapseFutureStamp},
			{Host: "127.0.0.1", Port: 9200, Owner: "o", Reason: "r", ExpiresAt: lapsePastStamp},
		}
		reloadErr := s.Reload(candidate)
		if reloadErr == nil || !strings.Contains(reloadErr.Error(), "duplicates") {
			t.Fatalf("Reload err = %v, want the duplicate rejected", reloadErr)
		}
		if live := s.proxy.CurrentConfig(); len(live.Containment.LoopbackServices) != 1 {
			t.Fatalf("a rejected reload changed the live set: %+v", live.Containment.LoopbackServices)
		}
	})
}

func TestReportLapsedContainmentGrantsIsSilentWithoutLapsedGrants(t *testing.T) {
	s := &Server{}
	// Neither a nil config nor a config with nothing lapsed may report or panic
	// on a server that has no logger or emitter yet.
	s.reportLapsedContainmentGrants(nil, "startup")
	s.reportLapsedContainmentGrants(config.Defaults(), "startup")
}
