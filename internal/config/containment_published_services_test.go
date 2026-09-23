// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func validPublishedService() ContainmentPublishedService {
	return ContainmentPublishedService{
		Name:         "viewer",
		AgentPort:    5900,
		OperatorUser: "operator",
		Owner:        "ops",
		Reason:       "watch the agent display",
		ExpiresAt:    "2099-01-01T00:00:00Z",
	}
}

func TestValidateContainmentPublishedServices(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	loopback := []ContainmentLoopbackService{{Host: "127.0.0.1", Port: 9119}}
	tests := []struct {
		name   string
		mutate func(*ContainmentPublishedService)
		extra  bool
		want   string
	}{
		{name: "valid default", mutate: func(*ContainmentPublishedService) {}},
		{name: "valid v6 agent host and tcp opt-in", mutate: func(s *ContainmentPublishedService) {
			s.AgentHost = "::1"
			s.HostListen = "127.0.0.1:15900"
		}},
		{name: "valid custom socket", mutate: func(s *ContainmentPublishedService) { s.HostSocket = "/run/operator-view/viewer.sock" }},
		{name: "bad name uppercase", mutate: func(s *ContainmentPublishedService) { s.Name = "Viewer" }, want: ".name"},
		{name: "bad name unit escape", mutate: func(s *ContainmentPublishedService) { s.Name = "a@b" }, want: ".name"},
		{name: "bad name empty", mutate: func(s *ContainmentPublishedService) { s.Name = "" }, want: ".name"},
		{name: "non-loopback agent host", mutate: func(s *ContainmentPublishedService) { s.AgentHost = "0.0.0.0" }, want: "agent_host"},
		{name: "padded agent host", mutate: func(s *ContainmentPublishedService) { s.AgentHost = " 127.0.0.1" }, want: "agent_host"},
		{name: "agent port zero", mutate: func(s *ContainmentPublishedService) { s.AgentPort = 0 }, want: "agent_port"},
		{name: "agent port proxy collision", mutate: func(s *ContainmentPublishedService) { s.AgentPort = 8888 }, want: "proxy port"},
		{name: "agent port loopback collision", mutate: func(s *ContainmentPublishedService) { s.AgentPort = 9119 }, want: "loopback_services"},
		{name: "host listen proxy collision", mutate: func(s *ContainmentPublishedService) { s.HostListen = "127.0.0.1:8888" }, want: "proxy port"},
		{name: "host listen loopback collision", mutate: func(s *ContainmentPublishedService) { s.HostListen = "127.0.0.1:9119" }, want: "loopback_services"},
		{name: "host listen wildcard", mutate: func(s *ContainmentPublishedService) { s.HostListen = "0.0.0.0:15900" }, want: "host_listen"},
		{name: "host listen hostname", mutate: func(s *ContainmentPublishedService) { s.HostListen = "localhost:15900" }, want: "host_listen"},
		{name: "host listen leading zero port", mutate: func(s *ContainmentPublishedService) { s.HostListen = "127.0.0.1:015900" }, want: "invalid port"},
		{name: "socket outside run", mutate: func(s *ContainmentPublishedService) { s.HostSocket = "/tmp/viewer.sock" }, want: "host_socket"},
		{name: "socket traversal", mutate: func(s *ContainmentPublishedService) { s.HostSocket = "/run/x/../viewer.sock" }, want: "host_socket"},
		{name: "socket holder runtime dir", mutate: func(s *ContainmentPublishedService) { s.HostSocket = "/run/pipelock-contain/viewer.sock" }, want: "reserved"},
		{name: "socket proxy doorway", mutate: func(s *ContainmentPublishedService) { s.HostSocket = "/run/pipelock-agent-proxy.sock" }, want: "reserved"},
		{name: "missing operator", mutate: func(s *ContainmentPublishedService) { s.OperatorUser = "" }, want: "operator_user"},
		{name: "missing owner", mutate: func(s *ContainmentPublishedService) { s.Owner = "" }, want: "owner is required"},
		{name: "expired", mutate: func(s *ContainmentPublishedService) { s.ExpiresAt = "2025-01-01T00:00:00Z" }, want: "expired"},
		{name: "malformed expiry", mutate: func(s *ContainmentPublishedService) { s.ExpiresAt = "tomorrow" }, want: "RFC3339"},
		{name: "duplicate name", mutate: func(*ContainmentPublishedService) {}, extra: true, want: "declared more than once"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := validPublishedService()
			tt.mutate(&svc)
			services := []ContainmentPublishedService{svc}
			if tt.extra {
				dup := validPublishedService()
				dup.AgentPort = 5901
				services = append(services, dup)
			}
			err := ValidateContainmentPublishedServices(services, loopback, 8888, now)
			if tt.want == "" {
				if err != nil {
					t.Fatalf("want valid, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("want error containing %q, got %v", tt.want, err)
			}
		})
	}
}

func TestValidateContainmentPublishedServicesUniqueness(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	a := validPublishedService()
	b := validPublishedService()
	b.Name = "other"
	if err := ValidateContainmentPublishedServices([]ContainmentPublishedService{a, b}, nil, 8888, now); err == nil || !strings.Contains(err.Error(), "already published") {
		t.Fatalf("duplicate agent_port: got %v", err)
	}
	b.AgentPort = 5901
	b.HostSocket = a.EffectiveHostSocket()
	if err := ValidateContainmentPublishedServices([]ContainmentPublishedService{a, b}, nil, 8888, now); err == nil || !strings.Contains(err.Error(), "already used") {
		t.Fatalf("duplicate host_socket: got %v", err)
	}
	b.HostSocket = ""
	a.HostListen = "127.0.0.1:15900"
	b.HostListen = "[::1]:15900"
	if err := ValidateContainmentPublishedServices([]ContainmentPublishedService{a, b}, nil, 8888, now); err == nil || !strings.Contains(err.Error(), "already used") {
		t.Fatalf("duplicate host_listen port: got %v", err)
	}
}

func TestContainmentPublishedServiceDefaults(t *testing.T) {
	svc := validPublishedService()
	if got := svc.EffectiveAgentHost(); got != "127.0.0.1" {
		t.Fatalf("agent host default = %q", got)
	}
	if got := svc.EffectiveHostSocket(); got != "/run/pipelock-contain-published/viewer.sock" {
		t.Fatalf("host socket default = %q", got)
	}
}

// TestLoadContainmentPublishedServices drives the whole-config loader so the
// YAML keys, the Validate wiring, and the clone all agree.
func TestLoadContainmentPublishedServices(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pipelock.yaml")
	body := "containment:\n  published_services:\n" +
		"    - name: viewer\n      agent_port: 5900\n      operator_user: operator\n" +
		"      owner: ops\n      reason: watch the display\n      expires_at: \"2099-01-01T00:00:00Z\"\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(cfg.Containment.PublishedServices) != 1 || cfg.Containment.PublishedServices[0].AgentPort != 5900 {
		t.Fatalf("published services not loaded: %+v", cfg.Containment.PublishedServices)
	}
	clone := cfg.Clone()
	clone.Containment.PublishedServices[0].AgentPort = 1
	if cfg.Containment.PublishedServices[0].AgentPort != 5900 {
		t.Fatal("clone shares the published services slice")
	}

	expired := strings.Replace(body, "2099", "2001", 1)
	if err := os.WriteFile(path, []byte(expired), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired publication must fail load, got %v", err)
	}
}
