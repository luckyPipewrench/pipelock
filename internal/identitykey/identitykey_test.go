// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package identitykey

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/envelope"
)

func TestCEESafeKey_OnlyTrustedAgentAuthNamespacesBucket(t *testing.T) {
	tests := []struct {
		name string
		auth envelope.ActorAuth
		want string
	}{
		{name: "bound", auth: envelope.ActorAuthBound, want: "agent-a|203.0.113.10"},
		{name: "config default", auth: envelope.ActorAuthConfigDefault, want: "agent-a|203.0.113.10"},
		{name: "matched", auth: envelope.ActorAuthMatched, want: "203.0.113.10"},
		{name: "self declared", auth: envelope.ActorAuthSelfDeclared, want: "203.0.113.10"},
		{name: "unset", auth: "", want: "203.0.113.10"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CEESafeKey("agent-a", "203.0.113.10", tt.auth); got != tt.want {
				t.Fatalf("CEESafeKey() = %q, want %q", got, tt.want)
			}
		})
	}
}
