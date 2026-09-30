// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package killswitch

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestKillSwitchActivationNotBlockedByStalledDeferredSend proves a claimed
// deferred send that never completes (a stalled journal, receipt writer, or
// upstream/stdout send) cannot hold the controller lock: ClaimDeferredSendAt
// releases deferredMu before returning, so every activation path completes.
func TestKillSwitchActivationNotBlockedByStalledDeferredSend(t *testing.T) {
	for name, activate := range map[string]func(t *testing.T, c *Controller){
		"api":           func(_ *testing.T, c *Controller) { c.SetAPI(true) },
		"signal":        func(_ *testing.T, c *Controller) { c.ToggleSignal() },
		"remote":        func(_ *testing.T, c *Controller) { c.SetConductorRemote(true, "") },
		"stale":         func(_ *testing.T, c *Controller) { c.SetConductorStale(true, "") },
		"apply_failure": func(_ *testing.T, c *Controller) { c.SetConductorApplyFailure(true, "") },
		"reload": func(_ *testing.T, c *Controller) {
			cfg := testConfig()
			cfg.KillSwitch.Enabled = true
			c.Reload(cfg)
		},
		"sentinel": func(t *testing.T, c *Controller) {
			path := filepath.Join(t.TempDir(), "kill")
			cfg := testConfig()
			cfg.KillSwitch.SentinelFile = path
			c.Reload(cfg)
			if err := os.WriteFile(path, nil, 0o600); err != nil {
				t.Errorf("write sentinel: %v", err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			c := New(testConfig())
			release, ok := c.ClaimDeferredSend()
			if !ok {
				t.Fatal("initial claim refused")
			}
			// Deliberately never released until cleanup: the stalled send.
			t.Cleanup(release)
			done := make(chan struct{})
			go func() {
				activate(t, c)
				close(done)
			}()
			timer := time.NewTimer(2 * time.Second)
			defer timer.Stop()
			select {
			case <-done:
			case <-timer.C:
				t.Fatal("activation blocked behind a stalled deferred send")
			}
			if !c.IsActive() {
				t.Fatal("controller not active after activation")
			}
			if got := c.DeferredInFlight(); got != 1 {
				t.Fatalf("DeferredInFlight = %d, want 1", got)
			}
			if _, ok := c.ClaimDeferredSend(); ok {
				t.Fatal("new deferred send claimed while active")
			}
		})
	}
}
