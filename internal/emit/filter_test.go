// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package emit

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestFilterAllows(t *testing.T) {
	event := Event{
		Severity:   SeverityWarn,
		Type:       EventBodyDLP,
		Timestamp:  time.Now(),
		InstanceID: testInstanceName,
		Fields: map[string]any{
			"action":        conventionActionBlock,
			"decision_type": EventBodyDLP,
			"agent":         "agent-a",
		},
	}

	tests := []struct {
		name   string
		filter Filter
		event  Event
		want   bool
	}{
		{name: "empty filter allows", filter: Filter{}, event: event, want: true},
		{name: "all criteria match", filter: Filter{Actions: []string{"block"}, DecisionTypes: []string{EventBodyDLP}, Agents: []string{"agent-a"}}, event: event, want: true},
		{name: "case insensitive match", filter: Filter{Actions: []string{"BLOCK"}, Agents: []string{"AGENT-A"}}, event: event, want: true},
		{name: "action mismatch drops", filter: Filter{Actions: []string{"warn"}}, event: event, want: false},
		{name: "decision type mismatch drops", filter: Filter{DecisionTypes: []string{EventHeaderDLP}}, event: event, want: false},
		{name: "agent mismatch drops", filter: Filter{Agents: []string{"agent-b"}}, event: event, want: false},
		{name: "missing action drops when action filter configured", filter: Filter{Actions: []string{"block"}}, event: Event{Type: EventStartup, Fields: map[string]any{}}, want: false},
		{name: "legacy blocked event infers block", filter: Filter{Actions: []string{"block"}}, event: Event{Type: EventBlocked, Fields: map[string]any{"scanner": "ssrf"}}, want: true},
		{name: "identity alias matches agent filter", filter: Filter{Agents: []string{"identity-a"}}, event: Event{Type: EventBodyDLP, Fields: map[string]any{"identity": "identity-a"}}, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.filter.Allows(tt.event); got != tt.want {
				t.Fatalf("Allows() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFilteringSink(t *testing.T) {
	inner := &mockSink{}
	sink := NewFilteringSink(inner, Filter{Actions: []string{conventionActionBlock}, Agents: []string{"agent-a"}})

	matching := Event{
		Type:   EventBodyDLP,
		Fields: map[string]any{"action": conventionActionBlock, "agent": "agent-a"},
	}
	dropped := Event{
		Type:   EventBodyDLP,
		Fields: map[string]any{"action": conventionActionWarn, "agent": "agent-a"},
	}

	if err := sink.Emit(context.Background(), matching); err != nil {
		t.Fatalf("matching Emit: %v", err)
	}
	if err := sink.Emit(context.Background(), dropped); err != nil {
		t.Fatalf("dropped Emit: %v", err)
	}

	events := inner.getEvents()
	if len(events) != 1 {
		t.Fatalf("inner sink events = %d, want 1", len(events))
	}
	if events[0].Fields["action"] != conventionActionBlock {
		t.Fatalf("forwarded action = %v, want block", events[0].Fields["action"])
	}
}

func TestValidateFilterValues(t *testing.T) {
	tests := []struct {
		name    string
		values  []string
		wantErr string
	}{
		{name: "empty list", values: nil},
		{name: "valid values", values: []string{"block", "warn"}},
		{name: "blank value", values: []string{"block", " "}, wantErr: "emit.filter.actions[1] is empty"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateFilterValues("emit.filter.actions", tt.values)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("ValidateFilterValues() unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want contains %q", err, tt.wantErr)
			}
		})
	}
}
