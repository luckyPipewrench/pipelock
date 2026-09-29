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

func TestConfigActivatesKillSwitch(t *testing.T) {
	present := filepath.Join(t.TempDir(), "present")
	if err := os.WriteFile(present, nil, 0o600); err != nil {
		t.Fatalf("write sentinel: %v", err)
	}
	s, _ := newTestServer(t, nil)
	for _, tc := range []struct {
		name     string
		enabled  bool
		sentinel string
		want     bool
	}{
		{"off", false, "", false},
		{"enabled", true, "", true},
		{"sentinel_present", false, present, true},
		{"sentinel_absent", false, filepath.Join(t.TempDir(), "absent"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := *s.proxy.CurrentConfig()
			cfg.KillSwitch.Enabled = tc.enabled
			cfg.KillSwitch.SentinelFile = tc.sentinel
			if got := configActivatesKillSwitch(&cfg); got != tc.want {
				t.Fatalf("configActivatesKillSwitch = %v, want %v", got, tc.want)
			}
		})
	}
	if configActivatesKillSwitch(nil) {
		t.Fatal("nil config activated kill switch")
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
