// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestContainedRelayTargetFollowsAgentListener proves the doorway relay
// delivers to the contained agent's own listener when the managed config names
// one, so the proxy attributes the traffic to the profile bound there, and
// keeps the shared listener otherwise.
func TestContainedRelayTargetFollowsAgentListener(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	write := func(name, body string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	withListener := write("with.yaml", "agents:\n  contained:\n    listeners: [\"127.0.0.1:8889\"]\ncontainment:\n  agent_listener: 127.0.0.1:8889\n")
	without := write("without.yaml", "mode: balanced\n")

	if got := containedRelayTarget(withListener, 8888); got != "127.0.0.1:8889" {
		t.Fatalf("relay target with agent_listener = %q, want 127.0.0.1:8889", got)
	}
	if got := containedRelayTarget(without, 8888); got != "127.0.0.1:8888" {
		t.Fatalf("relay target without agent_listener = %q, want the shared listener", got)
	}
	if got := containedRelayTarget(filepath.Join(dir, "absent.yaml"), 8888); got != "127.0.0.1:8888" {
		t.Fatalf("relay target with no config = %q, want the shared listener", got)
	}

	unit := renderContainedProxyForwarderUnitTo("/usr/local/bin/pipelock", "pipelock-proxy", containedRelayTarget(withListener, 8888))
	if !strings.Contains(unit, "--target-tcp 127.0.0.1:8889\n") {
		t.Fatalf("relay unit does not target the agent listener:\n%s", unit)
	}
	if strings.Contains(unit, "127.0.0.1:8888") {
		t.Fatalf("relay unit still targets the shared listener:\n%s", unit)
	}
}
