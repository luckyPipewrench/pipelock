// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

func TestReservedControlActorName(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"exact pipelock", "pipelock", "pipelock"},
		{"exact anonymous", "anonymous", "anonymous"},
		{"mixed case", "Pipelock", "pipelock"},
		{"upper with spaces", "  ANONYMOUS  ", "anonymous"},
		{"normal agent", "agent-a", ""},
		{"superstring not reserved", "pipelocks", ""},
		{"empty", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := reservedControlActorName(tc.in); got != tc.want {
				t.Fatalf("reservedControlActorName(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestValidateAgents_RejectsReservedControlActorNames(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"pipelock", "anonymous", "Pipelock", " anonymous "} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			c := &Config{Agents: map[string]AgentProfile{name: {}}}
			err := c.validateAgents()
			if err == nil {
				t.Fatalf("validateAgents accepted reserved agent name %q; want rejection", name)
			}
			if !strings.Contains(err.Error(), "reserved control-actor") {
				t.Fatalf("validateAgents(%q) error = %v, want a reserved-control-actor rejection", name, err)
			}
		})
	}
}

func TestValidateAgents_AcceptsOrdinaryAgentName(t *testing.T) {
	t.Parallel()
	c := &Config{Agents: map[string]AgentProfile{"agent-a": {}}}
	if err := c.validateAgents(); err != nil {
		t.Fatalf("validateAgents rejected ordinary agent name: %v", err)
	}
}

func TestValidateDefaultAgentIdentity_RejectsReservedControlActorNames(t *testing.T) {
	t.Parallel()
	for _, id := range []string{"pipelock", "anonymous", "Pipelock"} {
		t.Run(id, func(t *testing.T) {
			t.Parallel()
			c := &Config{DefaultAgentIdentity: id}
			err := c.validateDefaultAgentIdentity()
			if err == nil {
				t.Fatalf("validateDefaultAgentIdentity accepted reserved default identity %q; want rejection", id)
			}
			if !strings.Contains(err.Error(), "reserved control-actor") {
				t.Fatalf("validateDefaultAgentIdentity(%q) error = %v, want a reserved-control-actor rejection", id, err)
			}
		})
	}
}

func TestValidateDefaultAgentIdentity_AcceptsOrdinaryIdentity(t *testing.T) {
	t.Parallel()
	c := &Config{DefaultAgentIdentity: "agent-a"}
	if err := c.validateDefaultAgentIdentity(); err != nil {
		t.Fatalf("validateDefaultAgentIdentity rejected ordinary identity: %v", err)
	}
}

func TestReservedControlActorName_Exported(t *testing.T) {
	if got := ReservedControlActorName("PIPELOCK"); got != "pipelock" {
		t.Errorf("ReservedControlActorName(PIPELOCK) = %q, want pipelock", got)
	}
	if got := ReservedControlActorName("anonymous"); got != "anonymous" {
		t.Errorf("ReservedControlActorName(anonymous) = %q, want anonymous", got)
	}
	if got := ReservedControlActorName("agent-a"); got != "" {
		t.Errorf("ReservedControlActorName(agent-a) = %q, want empty", got)
	}
}
