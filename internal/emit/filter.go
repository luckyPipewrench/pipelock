// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package emit

import (
	"context"
	"fmt"
	"strings"
)

const (
	eventActionDefer   = "defer"
	eventActionForward = "forward"
	eventActionStrip   = "strip"
)

// Filter controls which events are exported to configured sinks.
type Filter struct {
	Actions       []string
	DecisionTypes []string
	Agents        []string
}

// Enabled reports whether the filter has any active criteria.
func (f Filter) Enabled() bool {
	return len(f.Actions) > 0 || len(f.DecisionTypes) > 0 || len(f.Agents) > 0
}

// Allows reports whether event matches every configured criterion. As a
// fail-safe, when an Actions filter includes "block" and an event's action
// cannot be classified, the event is still allowed through rather than
// silently dropped.
func (f Filter) Allows(event Event) bool {
	if len(f.Actions) > 0 {
		action := eventAction(event)
		if !containsFold(f.Actions, action) {
			if action != "" || !containsFold(f.Actions, conventionActionBlock) {
				return false
			}
		}
	}
	if len(f.DecisionTypes) > 0 && !containsFold(f.DecisionTypes, eventDecisionType(event)) {
		return false
	}
	if len(f.Agents) > 0 && !containsFold(f.Agents, eventAgent(event)) {
		return false
	}
	return true
}

// ValidateFilterValues rejects empty configured values before a filter can
// silently narrow exports in a way the operator did not intend.
func ValidateFilterValues(name string, values []string) error {
	for i, value := range values {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s[%d] is empty", name, i)
		}
	}
	return nil
}

// FilteringSink applies a Filter before forwarding matching events to a sink.
type FilteringSink struct {
	filter Filter
	sink   Sink
}

// NewFilteringSink wraps sink with filter. A disabled filter returns sink as-is.
func NewFilteringSink(sink Sink, filter Filter) Sink {
	if sink == nil || !filter.Enabled() {
		return sink
	}
	return &FilteringSink{filter: filter, sink: sink}
}

func (s *FilteringSink) Emit(ctx context.Context, event Event) error {
	if !s.filter.Allows(event) {
		return nil
	}
	return s.sink.Emit(ctx, event)
}

func (s *FilteringSink) Close() error {
	return s.sink.Close()
}

func (s *FilteringSink) Start() {
	if starter, ok := s.sink.(interface{ Start() }); ok {
		starter.Start()
	}
}

func containsFold(values []string, candidate string) bool {
	candidate = strings.TrimSpace(candidate)
	if candidate == "" {
		return false
	}
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), candidate) {
			return true
		}
	}
	return false
}

func eventAction(event Event) string {
	typeAction := eventTypeAction(event.Type)
	fieldAction := eventFieldAction(event)
	return strongestEventAction(typeAction, fieldAction)
}

func eventFieldAction(event Event) string {
	action := ""
	if blocked, ok := event.Fields["blocked"].(bool); ok && blocked {
		action = strongestEventAction(action, conventionActionBlock)
	}
	for _, key := range []string{"action", "effective_action", "to_action", "verdict", "decision"} {
		if value, ok := event.Fields[key].(string); ok && value != "" {
			action = strongestEventAction(action, normalizeEventAction(value))
		}
	}
	if event.Type == EventAdaptiveEscalation {
		if value, ok := event.Fields["to"].(string); ok && value != "" {
			action = strongestEventAction(action, normalizeEventAction(value))
		}
	}
	if event.Type == EventToolRedirect {
		if value, ok := event.Fields["result"].(string); ok && value != "" {
			action = strongestEventAction(action, normalizeEventAction(value))
		}
	}
	return action
}

func strongestEventAction(typeAction, fieldAction string) string {
	if fieldAction == "" {
		return typeAction
	}
	if typeAction == "" {
		return fieldAction
	}
	if actionRank(fieldAction) > actionRank(typeAction) {
		return fieldAction
	}
	return typeAction
}

func actionRank(action string) int {
	switch action {
	case conventionActionBlock:
		return 5
	case conventionActionWarn:
		return 4
	case conventionActionAsk:
		return 3
	case EventRedirect, eventActionStrip, eventActionDefer:
		return 2
	case eventActionForward:
		return 1
	default:
		return 0
	}
}

func normalizeEventAction(value string) string {
	trimmed := strings.TrimSpace(value)
	switch strings.ToLower(trimmed) {
	case EventAllowed, conventionActionAllow:
		return conventionActionAllow
	case EventBlocked, EventWSBlocked, conventionActionBlock, "deny", "denied":
		return conventionActionBlock
	case conventionActionWarn:
		return conventionActionWarn
	case conventionActionAsk:
		return conventionActionAsk
	case EventRedirect, "redirected":
		return EventRedirect
	case EventForwardHTTP, eventActionForward, "forwarded":
		return eventActionForward
	case eventActionStrip, "stripped":
		return eventActionStrip
	case eventActionDefer, "deferred":
		return eventActionDefer
	default:
		return trimmed
	}
}

func eventTypeAction(eventType string) string {
	switch eventType {
	case EventAllowed:
		return conventionActionAllow
	case EventBlocked, EventWSBlocked, EventKillSwitchDeny, EventAirlockDeny, EventSNIMismatch:
		return conventionActionBlock
	case EventDLPWarn,
		EventAddressProtection,
		EventBodyDLP,
		EventBodyPromptInjection,
		EventHeaderDLP,
		EventTaintDecision,
		EventAirlockEnter,
		EventSessionAnomaly,
		EventMCPUnknownTool,
		EventResponseScan,
		EventError,
		EventResponseScanExempt,
		EventWSScan,
		EventAdaptiveEscalation,
		EventAdaptiveUpgrade,
		EventAnomaly,
		EventTextStego,
		EventLicenseExpiry:
		return conventionActionWarn
	case EventRedirect, EventToolRedirect:
		return EventRedirect
	case EventForwardHTTP:
		return eventActionForward
	case EventStartup,
		EventShutdown,
		EventAgentListener,
		EventTunnelClose,
		EventTunnelOpen,
		EventWSOpen,
		EventWSClose,
		EventAdaptiveRecovery,
		EventAirlockDeescalate,
		EventSessionAdmin,
		EventShieldRewrite,
		EventConfigReload,
		EventMediaExposure:
		return conventionActionAllow
	default:
		return ""
	}
}

// eventDecisionType derives the decision type for filtering. For events that
// eventTypeAction recognizes, the event type itself wins so spoofed
// decision_type/type/event_type field values cannot evade filters.
func eventDecisionType(event Event) string {
	if eventTypeAction(event.Type) != "" {
		return event.Type
	}
	for _, key := range []string{"decision_type", "type", "event_type"} {
		if value, ok := event.Fields[key].(string); ok && value != "" {
			return value
		}
	}
	return event.Type
}

func eventAgent(event Event) string {
	for _, key := range []string{"agent", "identity", "actor", "principal"} {
		if value, ok := event.Fields[key].(string); ok && value != "" {
			return value
		}
	}
	return ""
}
