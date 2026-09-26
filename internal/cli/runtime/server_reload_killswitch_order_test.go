// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"testing"
)

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
