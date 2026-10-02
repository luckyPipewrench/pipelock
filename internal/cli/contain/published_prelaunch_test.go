// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"os/user"
	"strings"
	"testing"
)

const publishedTestAgentUID = "987"

// prelaunchFixture is the published-service fixture seen before the agent has
// started: the preflight of `contain run` and `service-posture`.
func prelaunchFixture(t *testing.T) *publishedProbeFixture {
	t.Helper()
	fx := newPublishedProbeFixture(t)
	fx.env.agentUserName = "pipelock-agent"
	fx.env.prelaunch = true
	lookup := fx.env.lookupUser
	fx.env.lookupUser = func(name string) (*user.User, error) {
		if name == "pipelock-agent" {
			return &user.User{Uid: publishedTestAgentUID, Gid: publishedTestAgentUID, Username: name}, nil
		}
		return lookup(name)
	}
	return fx
}

func TestProbePublishedServicesBeforeLaunch(t *testing.T) {
	tests := []struct {
		name       string
		tcp        string
		prelaunch  bool
		wantStatus string
		wantDetail string
	}{
		{"pending listener passes before launch", publishedTestTCPHeader, true, statusPass, "pending until the agent starts: viewer"},
		{"agent-owned listener passes before launch", publishedTestTCPHeader + publishedTestListen, true, statusPass, "reach their agent listener"},
		{"foreign occupant fails before launch", publishedTestTCPHeader + strings.Replace(publishedTestListen, "   987 ", "     0 ", 1), true, statusFail, "foreign occupant"},
		{"foreign occupant on the wildcard fails before launch", publishedTestTCPHeader + strings.Replace(strings.Replace(publishedTestListen, "0100007F", "00000000", 1), "   987 ", "  1234 ", 1), true, statusFail, "foreign occupant"},
		{"unreadable owner fails before launch", publishedTestTCPHeader + strings.Replace(publishedTestListen, "   987 ", "   xyz ", 1), true, statusFail, "foreign occupant"},
		{"absent listener still fails for verify", publishedTestTCPHeader, false, statusFail, "absent listener"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fx := prelaunchFixture(t)
			fx.env.prelaunch = tc.prelaunch
			fx.tcp = tc.tcp
			status, detail := fx.probe()
			if status != tc.wantStatus || !strings.Contains(detail, tc.wantDetail) {
				t.Fatalf("probe = %s %q, want %s containing %q", status, detail, tc.wantStatus, tc.wantDetail)
			}
		})
	}
}

func TestProbePublishedServicesBeforeLaunchFailsClosedWithoutAgentIdentity(t *testing.T) {
	fx := prelaunchFixture(t)
	fx.env.agentUserName = "missing-agent"
	status, detail := fx.probe()
	if status != statusFail || !strings.Contains(detail, "agent listener state unknown") {
		t.Fatalf("probe = %s %q, want fail on unresolvable agent", status, detail)
	}
}

func TestAgentUIDStringNilLookup(t *testing.T) {
	if _, err := agentUIDString(&probeEnv{}); err == nil {
		t.Fatal("agentUIDString with no lookup succeeded")
	}
}

// agentNamespaceListens reports whether any matching listener exists.
func agentNamespaceListens(env *probeEnv, holderPID int, host string, port int) (bool, error) {
	owners, err := agentNamespaceListeners(env, "/proc", holderPID, host, port)
	return len(owners) > 0, err
}
