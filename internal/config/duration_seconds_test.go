// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strconv"
	"strings"
	"testing"
)

func TestValidateRejectsIntegerDurationOverflow(t *testing.T) {
	if strconv.IntSize < 64 {
		t.Skip("overflowing whole-second value is not representable as int on 32-bit hosts")
	}

	overflow := int(maxConfigDurationSeconds + 1)
	tests := []struct {
		name  string
		field string
		mut   func(*Config)
	}{
		{
			name: "conductor created skew", field: "conductor.created_skew_seconds",
			mut: func(cfg *Config) { cfg.Conductor.CreatedSkewSeconds = overflow },
		},
		{
			name: "MCP input response timeout", field: "mcp_input_scanning.response_timeout_seconds",
			mut: func(cfg *Config) { cfg.MCPInputScanning.ResponseTimeoutSeconds = overflow },
		},
		{
			name: "fetch timeout", field: "fetch_proxy.timeout_seconds",
			mut: func(cfg *Config) { cfg.FetchProxy.TimeoutSeconds = overflow },
		},
		{
			name: "response ask timeout", field: "response_scanning.ask_timeout_seconds",
			mut: func(cfg *Config) { cfg.ResponseScanning.AskTimeoutSeconds = overflow },
		},
		{
			name:  "forward maximum tunnel",
			field: "forward_proxy.max_tunnel_seconds",
			mut: func(cfg *Config) {
				cfg.ForwardProxy.Enabled = true
				cfg.ForwardProxy.MaxTunnelSeconds = overflow
			},
		},
		{
			name:  "forward idle timeout",
			field: "forward_proxy.idle_timeout_seconds",
			mut: func(cfg *Config) {
				cfg.ForwardProxy.Enabled = true
				cfg.ForwardProxy.IdleTimeoutSeconds = overflow
			},
		},
		{
			name:  "websocket maximum connection",
			field: "websocket_proxy.max_connection_seconds",
			mut: func(cfg *Config) {
				cfg.WebSocketProxy.Enabled = true
				cfg.WebSocketProxy.MaxConnectionSeconds = overflow
			},
		},
		{
			name:  "websocket idle timeout",
			field: "websocket_proxy.idle_timeout_seconds",
			mut: func(cfg *Config) {
				cfg.WebSocketProxy.Enabled = true
				cfg.WebSocketProxy.IdleTimeoutSeconds = overflow
			},
		},
		{
			name:  "tool chain window",
			field: "tool_chain_detection.window_seconds",
			mut: func(cfg *Config) {
				cfg.ToolChainDetection.Enabled = true
				cfg.ToolChainDetection.Action = ActionBlock
				cfg.ToolChainDetection.WindowSize = 4
				cfg.ToolChainDetection.WindowSeconds = overflow
			},
		},
		{
			name: "reverse request timeout", field: "reverse_proxy.request_timeout_seconds",
			mut: func(cfg *Config) { cfg.ReverseProxy.RequestTimeoutSeconds = overflow },
		},
		{
			name: "defer timeout", field: "defer.timeout_seconds",
			mut: func(cfg *Config) { cfg.Defer.TimeoutSeconds = overflow },
		},
		{
			name: "session cleanup interval", field: "session_profiling.cleanup_interval_seconds",
			mut: func(cfg *Config) { cfg.SessionProfiling.CleanupIntervalSeconds = overflow },
		},
		{
			name: "adaptive level duration", field: "adaptive_enforcement.level_duration_seconds",
			mut: func(cfg *Config) { cfg.AdaptiveEnforcement.LevelDurationSeconds = overflow },
		},
		{
			name: "adaptive deescalation check", field: "adaptive_enforcement.deescalation_check_seconds",
			mut: func(cfg *Config) { cfg.AdaptiveEnforcement.DeescalationCheckSeconds = overflow },
		},
		{
			name: "health watchdog interval", field: "health_watchdog.interval_seconds",
			mut: func(cfg *Config) { cfg.HealthWatchdog.IntervalSeconds = overflow },
		},
		{
			name: "OTLP timeout", field: "emit.otlp.timeout_seconds",
			mut: func(cfg *Config) { cfg.Emit.OTLP.TimeoutSeconds = overflow },
		},
		{
			name: "forwarder timeout", field: "emit.forwarder.timeout_seconds",
			mut: func(cfg *Config) { cfg.Emit.Forwarder.TimeoutSeconds = overflow },
		},
		{
			name: "webhook timeout", field: "emit.webhook.timeout_seconds",
			mut: func(cfg *Config) { cfg.Emit.Webhook.TimeoutSecs = overflow },
		},
		{
			name: "mediation envelope created skew", field: "mediation_envelope.created_skew_seconds",
			mut: func(cfg *Config) { cfg.MediationEnvelope.CreatedSkewSeconds = overflow },
		},
		{
			name: "airlock drain timeout", field: "airlock.timers.drain_timeout_seconds",
			mut: func(cfg *Config) { cfg.Airlock.Timers.DrainTimeoutSeconds = overflow },
		},
		{
			name: "session profiling window", field: "session_profiling.window_minutes",
			mut: func(cfg *Config) { cfg.SessionProfiling.WindowMinutes = int(maxConfigDurationMinutes + 1) },
		},
		{
			name: "session profiling TTL", field: "session_profiling.session_ttl_minutes",
			mut: func(cfg *Config) { cfg.SessionProfiling.SessionTTLMinutes = int(maxConfigDurationMinutes + 1) },
		},
		{
			name: "cross-request entropy window", field: "cross_request_detection.entropy_budget.window_minutes",
			mut: func(cfg *Config) {
				cfg.CrossRequestDetection.EntropyBudget.WindowMinutes = int(maxConfigDurationMinutes + 1)
			},
		},
		{
			name: "cross-request fragment window", field: "cross_request_detection.fragment_reassembly.window_minutes",
			mut: func(cfg *Config) {
				cfg.CrossRequestDetection.FragmentReassembly.WindowMinutes = int(maxConfigDurationMinutes + 1)
			},
		},
		{
			name: "airlock soft timer", field: "airlock.timers.soft_minutes",
			mut: func(cfg *Config) { cfg.Airlock.Timers.SoftMinutes = int(maxConfigDurationMinutes + 1) },
		},
		{
			name: "airlock hard timer", field: "airlock.timers.hard_minutes",
			mut: func(cfg *Config) { cfg.Airlock.Timers.HardMinutes = int(maxConfigDurationMinutes + 1) },
		},
		{
			name: "airlock drain timer", field: "airlock.timers.drain_minutes",
			mut: func(cfg *Config) { cfg.Airlock.Timers.DrainMinutes = int(maxConfigDurationMinutes + 1) },
		},
		{
			name: "flight recorder retention", field: "flight_recorder.retention_days",
			mut: func(cfg *Config) { cfg.FlightRecorder.RetentionDays = int(maxConfigDurationDays + 1) },
		},
		{
			name: "agent budget window", field: "agents.worker.budget.window_minutes",
			mut: func(cfg *Config) {
				cfg.Agents = make(map[string]AgentProfile)
				cfg.Agents["worker"] = AgentProfile{Budget: BudgetConfig{WindowMinutes: int(maxConfigDurationMinutes + 1)}}
			},
		},
		{
			name: "agent wall clock", field: "agents.worker.budget.max_wall_clock_minutes",
			mut: func(cfg *Config) {
				cfg.Agents = make(map[string]AgentProfile)
				cfg.Agents["worker"] = AgentProfile{Budget: BudgetConfig{MaxWallClockMinutes: int(maxConfigDurationMinutes + 1)}}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Defaults()
			tt.mut(cfg)
			err := cfg.Validate()
			if err == nil {
				t.Fatalf("expected %s overflow to be rejected", tt.field)
			}
			if !strings.Contains(err.Error(), tt.field) || !strings.Contains(err.Error(), "too large") {
				t.Fatalf("error = %q, want field-specific upper-bound rejection", err)
			}
		})
	}
}

func TestValidateIntegerDurationAcceptsLargestSafeValues(t *testing.T) {
	if strconv.IntSize < 64 {
		t.Skip("largest duration-second value is not representable as int on 32-bit hosts")
	}
	cfg := Defaults()
	cfg.ForwardProxy.IdleTimeoutSeconds = int(maxConfigDurationSeconds)
	cfg.Airlock.Timers.HardMinutes = int(maxConfigDurationMinutes)
	cfg.FlightRecorder.RetentionDays = int(maxConfigDurationDays)
	if err := cfg.validateIntegerDurationBounds(); err != nil {
		t.Fatalf("largest safe duration rejected: %v", err)
	}
}
