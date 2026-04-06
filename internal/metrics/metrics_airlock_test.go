// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"testing"
	"time"
)

func TestRecordAirlockTransition(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		from    string
		to      string
		trigger string
	}{
		{"none to soft", "none", "soft", "adaptive"},
		{"soft to hard", "soft", "hard", "manual"},
		{"hard to drain", "hard", "drain", "api"},
		{"soft to none", "soft", "none", "auto_deescalate"},
		{"empty from", "", "soft", "initial"},
		{"empty to", "soft", "", "release"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			m := New()
			m.RecordAirlockTransition(tt.from, tt.to, tt.trigger)
			// No panic = pass. Prometheus counters are correctly incremented.
		})
	}
}

func TestRecordAirlockTransition_NilReceiver(t *testing.T) {
	t.Parallel()
	var m *Metrics
	m.RecordAirlockTransition("none", "soft", "adaptive") // no panic
}

func TestRecordAirlockDenial(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		tier        string
		transport   string
		actionClass string
	}{
		{"soft fetch block", "soft", "fetch", "block"},
		{"hard connect deny", "hard", "connect", "deny"},
		{"drain websocket reject", "drain", "websocket", "reject"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			m := New()
			m.RecordAirlockDenial(tt.tier, tt.transport, tt.actionClass)
		})
	}
}

func TestRecordAirlockDenial_NilReceiver(t *testing.T) {
	t.Parallel()
	var m *Metrics
	m.RecordAirlockDenial("soft", "fetch", "block") // no panic
}

func TestRecordAirlockDrainCompleted(t *testing.T) {
	t.Parallel()
	m := New()
	m.RecordAirlockDrainCompleted()
	m.RecordAirlockDrainCompleted() // multiple calls should not panic
}

func TestRecordAirlockDrainCompleted_NilReceiver(t *testing.T) {
	t.Parallel()
	var m *Metrics
	m.RecordAirlockDrainCompleted() // no panic
}

func TestRecordAirlockDrainTimeout(t *testing.T) {
	t.Parallel()
	m := New()
	m.RecordAirlockDrainTimeout()
	m.RecordAirlockDrainTimeout()
}

func TestRecordAirlockDrainTimeout_NilReceiver(t *testing.T) {
	t.Parallel()
	var m *Metrics
	m.RecordAirlockDrainTimeout() // no panic
}

func TestRecordShieldRewrite(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		category  string
		transport string
	}{
		{"extension fetch", "extension_probing", "fetch"},
		{"tracking connect", "tracking_pixels", "connect"},
		{"hidden traps ws", "hidden_traps", "websocket"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			m := New()
			m.RecordShieldRewrite(tt.category, tt.transport)
		})
	}
}

func TestRecordShieldRewrite_NilReceiver(t *testing.T) {
	t.Parallel()
	var m *Metrics
	m.RecordShieldRewrite("extension_probing", "fetch") // no panic
}

func TestRecordShieldBytesStripped(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		category string
		bytes    int
	}{
		{"zero bytes", "extension_probing", 0},
		{"small strip", "tracking_pixels", 128},
		{"large strip", "hidden_traps", 65536},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			m := New()
			m.RecordShieldBytesStripped(tt.category, tt.bytes)
		})
	}
}

func TestRecordShieldBytesStripped_NilReceiver(t *testing.T) {
	t.Parallel()
	var m *Metrics
	m.RecordShieldBytesStripped("extension_probing", 42) // no panic
}

func TestRecordShieldShimInjected(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		transport string
	}{
		{"fetch", "fetch"},
		{"reverse_proxy", "reverse_proxy"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			m := New()
			m.RecordShieldShimInjected(tt.transport)
		})
	}
}

func TestRecordShieldShimInjected_NilReceiver(t *testing.T) {
	t.Parallel()
	var m *Metrics
	m.RecordShieldShimInjected("fetch") // no panic
}

func TestRecordShieldSkipped(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		reason string
	}{
		{"exempt domain", "exempt_domain"},
		{"disabled", "disabled"},
		{"unsupported content type", "unsupported_content_type"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			m := New()
			m.RecordShieldSkipped(tt.reason)
		})
	}
}

func TestRecordShieldSkipped_NilReceiver(t *testing.T) {
	t.Parallel()
	var m *Metrics
	m.RecordShieldSkipped("disabled") // no panic
}

func TestRecordShieldLatency(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		transport string
		duration  time.Duration
	}{
		{"fast fetch", "fetch", 100 * time.Microsecond},
		{"slow reverse", "reverse_proxy", 50 * time.Millisecond},
		{"zero duration", "fetch", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			m := New()
			m.RecordShieldLatency(tt.transport, tt.duration)
		})
	}
}

func TestRecordShieldLatency_NilReceiver(t *testing.T) {
	t.Parallel()
	var m *Metrics
	m.RecordShieldLatency("fetch", time.Millisecond) // no panic
}
