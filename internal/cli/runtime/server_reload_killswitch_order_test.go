// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"os"
	"path/filepath"
	"testing"
)

func TestServerReloadActivatesSentinelKillSwitchBeforeProxyPublication(t *testing.T) {
	s, _ := newTestServer(t, nil)
	if s.killswitch.IsActive() {
		t.Fatal("kill switch active before reload")
	}
	sentinel := filepath.Join(t.TempDir(), "kill")
	if err := os.WriteFile(sentinel, nil, 0o600); err != nil {
		t.Fatalf("write sentinel: %v", err)
	}
	next := *s.proxy.CurrentConfig()
	next.KillSwitch.Enabled = false
	next.KillSwitch.SentinelFile = sentinel
	seen := false
	restore := setReloadAfterProxySwapHookForTest(func(server *Server) {
		if server != s {
			return
		}
		seen = true
		if server.proxy.CurrentConfig().KillSwitch.SentinelFile != sentinel {
			t.Error("new proxy policy was not published")
		}
		if !server.killswitch.IsActive() {
			t.Error("new proxy policy visible before sentinel kill switch activated")
		}
	})
	t.Cleanup(restore)
	if err := s.Reload(&next); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !seen {
		t.Fatal("publication hook did not run")
	}
	if !s.killswitch.IsActive() {
		t.Fatal("sentinel reload did not activate the kill switch")
	}
}

// TestServerReloadSentinelCreatedDuringPublicationWindowDenies creates the new
// sentinel after the controller learns the candidate's sources and before the
// proxy publishes the candidate. The new policy must never be live unguarded.
func TestServerReloadSentinelCreatedDuringPublicationWindowDenies(t *testing.T) {
	s, _ := newTestServer(t, nil)
	sentinel := filepath.Join(t.TempDir(), "kill")
	next := *s.proxy.CurrentConfig()
	next.KillSwitch.Enabled = false
	next.KillSwitch.SentinelFile = sentinel
	t.Cleanup(setReloadBeforeProxySwapHookForTest(func(server *Server) {
		if server != s {
			return
		}
		if err := os.WriteFile(sentinel, nil, 0o600); err != nil {
			t.Errorf("write sentinel: %v", err)
		}
	}))
	seen := false
	t.Cleanup(setReloadAfterProxySwapHookForTest(func(server *Server) {
		if server != s {
			return
		}
		seen = true
		if server.proxy.CurrentConfig().KillSwitch.SentinelFile != sentinel {
			t.Error("new proxy policy was not published")
		}
		if !server.killswitch.IsActive() {
			t.Error("new policy live while its sentinel was ignored")
		}
	}))
	if err := s.Reload(&next); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !seen || !s.killswitch.IsActive() {
		t.Fatalf("seen=%v active=%v, want both", seen, s.killswitch.IsActive())
	}
}

// TestServerReloadHonorsActiveOldSentinelThroughSwap keeps an active old
// sentinel in force until the candidate that drops it is live.
func TestServerReloadHonorsActiveOldSentinelThroughSwap(t *testing.T) {
	s, _ := newTestServer(t, nil)
	oldSentinel := filepath.Join(t.TempDir(), "old")
	if err := os.WriteFile(oldSentinel, nil, 0o600); err != nil {
		t.Fatalf("write sentinel: %v", err)
	}
	first := *s.proxy.CurrentConfig()
	first.KillSwitch.Enabled = false
	first.KillSwitch.SentinelFile = oldSentinel
	if err := s.Reload(&first); err != nil {
		t.Fatalf("first reload: %v", err)
	}
	if !s.killswitch.IsActive() {
		t.Fatal("old sentinel not active")
	}
	next := first
	next.KillSwitch.SentinelFile = filepath.Join(t.TempDir(), "absent")
	check := func(stage string) func(*Server) {
		return func(server *Server) {
			if server == s && !server.killswitch.IsActive() {
				t.Errorf("active old sentinel lapsed %s", stage)
			}
		}
	}
	t.Cleanup(setReloadBeforeProxySwapHookForTest(check("before publication")))
	t.Cleanup(setReloadAfterProxySwapHookForTest(check("at publication")))
	if err := s.Reload(&next); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if s.killswitch.IsActive() {
		t.Fatal("old sentinel still honored after the candidate went live")
	}
}

func TestServerReloadActivatesKillSwitchBeforeProxyPublication(t *testing.T) {
	s, _ := newTestServer(t, nil)
	if s.killswitch.IsActive() {
		t.Fatal("kill switch active before reload")
	}
	next := *s.proxy.CurrentConfig()
	next.KillSwitch.Enabled = true
	seen := false
	restore := setReloadAfterProxySwapHookForTest(func(server *Server) {
		if server != s {
			return
		}
		seen = true
		if !server.proxy.CurrentConfig().KillSwitch.Enabled {
			t.Error("new proxy policy was not published")
		}
		if !server.killswitch.IsActive() {
			t.Error("new proxy policy visible before configured kill switch activated")
		}
	})
	t.Cleanup(restore)
	if err := s.Reload(&next); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !seen {
		t.Fatal("publication hook did not run")
	}
	if !s.killswitch.IsActive() || s.proxy.CurrentConfig().KillSwitch.Enabled != true {
		t.Fatal("enabling reload did not publish both policies")
	}
}
