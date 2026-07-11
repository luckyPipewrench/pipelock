// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package emit

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
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
		{name: "known allow event drops from block filter", filter: Filter{Actions: []string{"block"}}, event: Event{Type: EventStartup, Fields: map[string]any{}}, want: false},
		{name: "unknown action passes block-inclusive filter", filter: Filter{Actions: []string{"block"}}, event: Event{Type: "future_event", Fields: map[string]any{}}, want: true},
		{name: "unknown action drops from non-block filter", filter: Filter{Actions: []string{"warn"}}, event: Event{Type: "future_event", Fields: map[string]any{}}, want: false},
		{name: "legacy blocked event infers block", filter: Filter{Actions: []string{"block"}}, event: Event{Type: EventBlocked, Fields: map[string]any{"scanner": "ssrf"}}, want: true},
		{name: "kill switch deny infers block", filter: Filter{Actions: []string{"block"}}, event: Event{Type: EventKillSwitchDeny, Fields: map[string]any{"source": "config"}}, want: true},
		{name: "airlock deny infers block", filter: Filter{Actions: []string{"block"}}, event: Event{Type: EventAirlockDeny, Fields: map[string]any{"tier": "hard"}}, want: true},
		{name: "SNI mismatch infers block", filter: Filter{Actions: []string{"block"}}, event: Event{Type: EventSNIMismatch, Fields: map[string]any{"category": "mismatch"}}, want: true},
		{name: "blocked boolean infers block", filter: Filter{Actions: []string{"block"}}, event: Event{Type: EventMediaExposure, Fields: map[string]any{"blocked": true}}, want: true},
		{name: "deny decision normalizes to block", filter: Filter{Actions: []string{"block"}}, event: Event{Type: EventTaintDecision, Fields: map[string]any{"decision": "deny"}}, want: true},
		{name: "adaptive escalation to block infers block", filter: Filter{Actions: []string{"block"}}, event: Event{Type: EventAdaptiveEscalation, Fields: map[string]any{"to": "block"}}, want: true},
		{name: "blocked redirect result infers block", filter: Filter{Actions: []string{"block"}}, event: Event{Type: EventToolRedirect, Fields: map[string]any{"result": "blocked"}}, want: true},
		{name: "redirected result normalizes to redirect", filter: Filter{Actions: []string{"redirect"}}, event: Event{Type: EventToolRedirect, Fields: map[string]any{"result": "redirected"}}, want: true},
		{name: "identity alias matches agent filter", filter: Filter{Agents: []string{"identity-a"}}, event: Event{Type: EventBodyDLP, Fields: map[string]any{"identity": "identity-a"}}, want: true},
		{name: "blocked event ignores downgraded field action", filter: Filter{Actions: []string{"block"}}, event: Event{Type: EventBlocked, Fields: map[string]any{"action": "allow"}}, want: true},
		{name: "deny decision overrides downgraded field action", filter: Filter{Actions: []string{"block"}}, event: Event{Type: EventTaintDecision, Fields: map[string]any{"action": "allow", "decision": "deny"}}, want: true},
		{name: "blocked boolean overrides downgraded field action", filter: Filter{Actions: []string{"block"}}, event: Event{Type: EventMediaExposure, Fields: map[string]any{"action": "allow", "blocked": true}}, want: true},
		{name: "warn event ignores downgraded field action", filter: Filter{Actions: []string{"warn"}}, event: Event{Type: EventBodyDLP, Fields: map[string]any{"action": "allow"}}, want: true},
		{name: "field action can upgrade warn event to block", filter: Filter{Actions: []string{"block"}}, event: Event{Type: EventBodyDLP, Fields: map[string]any{"action": "block"}}, want: true},
		{name: "known event ignores spoofed decision type", filter: Filter{DecisionTypes: []string{"spoofed"}}, event: Event{Type: EventBodyDLP, Fields: map[string]any{"decision_type": "spoofed"}}, want: false},
		{name: "unknown event can use field decision type", filter: Filter{DecisionTypes: []string{"custom_decision"}}, event: Event{Type: "future_event", Fields: map[string]any{"decision_type": "custom_decision"}}, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.filter.Allows(tt.event); got != tt.want {
				t.Fatalf("Allows() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEventActionCoversEveryEventConstant(t *testing.T) {
	knownActions := map[string]bool{
		conventionActionAllow: true,
		conventionActionBlock: true,
		conventionActionWarn:  true,
		conventionActionAsk:   true,
		EventRedirect:         true,
		eventActionDefer:      true,
		eventActionForward:    true,
		eventActionStrip:      true,
	}

	constants := eventConstantsFromSource(t)
	for constName, eventType := range constants {
		t.Run(constName, func(t *testing.T) {
			typeAction := eventTypeAction(eventType)
			if typeAction == "" {
				t.Fatalf("eventTypeAction(%q) returned empty action", eventType)
			}
			if !knownActions[typeAction] {
				t.Fatalf("eventTypeAction(%q) = %q, want known action", eventType, typeAction)
			}

			action := eventAction(Event{Type: eventType, Fields: map[string]any{}})
			if action == "" {
				t.Fatalf("eventAction(%q) returned empty action", eventType)
			}
			if !knownActions[action] {
				t.Fatalf("eventAction(%q) = %q, want known action", eventType, action)
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
	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !inner.isClosed() {
		t.Fatal("inner sink was not closed")
	}
}

func TestNewFilteringSinkDisabledOrNil(t *testing.T) {
	inner := &mockSink{}
	if got := NewFilteringSink(inner, Filter{}); got != inner {
		t.Fatal("disabled filter should return original sink")
	}
	if got := NewFilteringSink(nil, Filter{Actions: []string{conventionActionBlock}}); got != nil {
		t.Fatal("nil sink should remain nil")
	}
}

type startableMockSink struct {
	mockSink
	started bool
}

func (s *startableMockSink) Start() { s.started = true }

func TestFilteringSinkStartsWrappedSink(t *testing.T) {
	inner := &startableMockSink{}
	sink := NewFilteringSink(inner, Filter{Actions: []string{conventionActionBlock}})
	starter, ok := sink.(interface{ Start() })
	if !ok {
		t.Fatal("filtered sink does not expose deferred startup")
	}
	starter.Start()
	if !inner.started {
		t.Fatal("wrapped sink was not started")
	}
}

func TestNormalizeEventActionAliases(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{name: "allowed event", value: EventAllowed, want: conventionActionAllow},
		{name: "allow convention", value: conventionActionAllow, want: conventionActionAllow},
		{name: "blocked event", value: EventBlocked, want: conventionActionBlock},
		{name: "websocket blocked event", value: EventWSBlocked, want: conventionActionBlock},
		{name: "deny", value: "deny", want: conventionActionBlock},
		{name: "denied", value: "denied", want: conventionActionBlock},
		{name: "warn", value: conventionActionWarn, want: conventionActionWarn},
		{name: "ask", value: conventionActionAsk, want: conventionActionAsk},
		{name: "redirect event", value: EventRedirect, want: EventRedirect},
		{name: "redirected", value: "redirected", want: EventRedirect},
		{name: "forward event", value: EventForwardHTTP, want: eventActionForward},
		{name: "forward", value: eventActionForward, want: eventActionForward},
		{name: "forwarded", value: "forwarded", want: eventActionForward},
		{name: "strip", value: eventActionStrip, want: eventActionStrip},
		{name: "stripped", value: "stripped", want: eventActionStrip},
		{name: "defer", value: eventActionDefer, want: eventActionDefer},
		{name: "deferred", value: "deferred", want: eventActionDefer},
		{name: "custom preserves trim", value: " custom ", want: "custom"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeEventAction(tt.value); got != tt.want {
				t.Fatalf("normalizeEventAction(%q) = %q, want %q", tt.value, got, tt.want)
			}
		})
	}
}

func TestStrongestEventAction(t *testing.T) {
	tests := []struct {
		name        string
		typeAction  string
		fieldAction string
		want        string
	}{
		{name: "empty field keeps type", typeAction: conventionActionWarn, want: conventionActionWarn},
		{name: "empty type uses field", fieldAction: eventActionForward, want: eventActionForward},
		{name: "block beats warn", typeAction: conventionActionWarn, fieldAction: conventionActionBlock, want: conventionActionBlock},
		{name: "warn beats allow", typeAction: conventionActionWarn, fieldAction: conventionActionAllow, want: conventionActionWarn},
		{name: "ask beats redirect", typeAction: EventRedirect, fieldAction: conventionActionAsk, want: conventionActionAsk},
		{name: "strip beats forward", typeAction: eventActionForward, fieldAction: eventActionStrip, want: eventActionStrip},
		{name: "defer beats forward", typeAction: eventActionForward, fieldAction: eventActionDefer, want: eventActionDefer},
		{name: "custom loses to known action", typeAction: conventionActionWarn, fieldAction: "custom", want: conventionActionWarn},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := strongestEventAction(tt.typeAction, tt.fieldAction); got != tt.want {
				t.Fatalf("strongestEventAction(%q, %q) = %q, want %q", tt.typeAction, tt.fieldAction, got, tt.want)
			}
		})
	}
}

func eventConstantsFromSource(t *testing.T) map[string]string {
	t.Helper()

	file, err := parser.ParseFile(token.NewFileSet(), "event.go", nil, 0)
	if err != nil {
		t.Fatalf("parse event.go: %v", err)
	}

	constants := make(map[string]string)
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			valueSpec, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range valueSpec.Names {
				if !strings.HasPrefix(name.Name, "Event") {
					continue
				}
				if i >= len(valueSpec.Values) {
					t.Fatalf("%s must use an explicit string value", name.Name)
				}
				lit, ok := valueSpec.Values[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					t.Fatalf("%s must be a string literal event type", name.Name)
				}
				value, err := strconv.Unquote(lit.Value)
				if err != nil {
					t.Fatalf("unquote %s: %v", name.Name, err)
				}
				constants[name.Name] = value
			}
		}
	}
	if len(constants) == 0 {
		t.Fatal("no Event* constants found in event.go")
	}
	return constants
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
