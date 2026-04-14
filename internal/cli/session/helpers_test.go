// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/proxy"
)

// Test-local constants shared across subcommand tests. Keeps goconst
// quiet on repeated literals.
const (
	testToken       = "stub-admin-token"
	testKeyIdent    = "agent-z|10.0.0.42"
	testKeyInvoc    = "mcp-stdio-7"
	sessionListURL  = "/api/v1/sessions"
	contentTypeJSON = "application/json"
	tierHard        = "hard"
	tierSoft        = "soft"
	tierNone        = "none"
)

// stubServer starts an httptest.Server using the given handler. Returns
// a rootFlags configured to point at it with the test bearer token.
// The server is closed via t.Cleanup so callers do not need to hold on
// to the server handle.
func stubServer(t *testing.T, handler http.Handler) *rootFlags {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return &rootFlags{
		apiURL:   srv.URL,
		apiToken: testToken,
	}
}

// overrideClientFactory swaps newClientFn to build a *Client pointing at
// the given base URL using a shared http.Client. Restores the original
// factory on test cleanup.
func overrideClientFactory(t *testing.T, flags *rootFlags) {
	t.Helper()
	orig := newClientFn
	t.Cleanup(func() { newClientFn = orig })
	newClientFn = func(actual *rootFlags) (*Client, error) {
		// Prefer the actual flag values from the caller — this lets a
		// subcommand test pass a doctored rootFlags through addCommonFlags
		// while still using the httptest base URL when no override came in.
		if actual.apiURL == "" {
			actual.apiURL = flags.apiURL
		}
		if actual.apiToken == "" {
			actual.apiToken = flags.apiToken
		}
		return newClient(endpoint{URL: actual.apiURL, Token: actual.apiToken}), nil
	}
}

// runCommand executes a cobra command with captured stdout/stderr. The
// caller provides pre-bound args. Returns the stdout bytes and any
// error the command surfaced.
func runCommand(cmd *cobra.Command, args ...string) (string, error) {
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return buf.String(), err
}

// writeJSONResponse encodes v as JSON and writes it with the given
// status code. Used by mock handlers to return canned responses.
func writeJSONResponse(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", contentTypeJSON)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// testFixedTime returns a stable non-zero timestamp used in test fixtures.
// Picking a fixed value keeps rendered output deterministic.
func testFixedTime() time.Time {
	return time.Date(2026, time.April, 13, 12, 0, 0, 0, time.UTC)
}

// makeDetail builds a populated SessionDetail for handler/render tests.
func makeDetail() proxy.SessionDetail {
	now := testFixedTime()
	return proxy.SessionDetail{
		SessionSnapshot: proxy.SessionSnapshot{
			Key:             testKeyIdent,
			Agent:           "agent-z",
			ClientIP:        "10.0.0.42",
			Kind:            "identity",
			ThreatScore:     0.75,
			EscalationLevel: "critical",
			AirlockTier:     "hard",
			LastActivity:    now,
		},
		AirlockEnteredAt:   now,
		InFlight:           3,
		EscalationLevelInt: 3,
		RecentEvents: []proxy.SessionEvent{
			{At: now, Kind: "block", Target: "evil.example.com", Detail: "dlp secret", Severity: "critical", Score: 0.9},
		},
	}
}

// makeExplanation builds a populated SessionExplanation for tests.
func makeExplanation() proxy.SessionExplanation {
	now := testFixedTime()
	return proxy.SessionExplanation{
		Key:                  testKeyIdent,
		Tier:                 "hard",
		Reason:               "session quarantined at airlock tier hard",
		Trigger:              "on_critical",
		TriggerSource:        "airlock_triggers",
		EnteredAt:            now,
		EscalationLevel:      "critical",
		EscalationLevelInt:   3,
		ThreatScore:          0.9,
		EvidenceKind:         "block",
		EvidenceTarget:       "evil.example.com",
		EvidenceDetail:       "dlp secret",
		EvidenceAt:           now,
		NextDeescalationTier: "soft",
		NextDeescalationAt:   now.Add(time.Hour),
	}
}

// makeSnapshot builds a populated SessionSnapshot slice for list tests.
func makeSnapshotList() []proxy.SessionSnapshot {
	now := testFixedTime()
	return []proxy.SessionSnapshot{
		{
			Key: testKeyIdent, Agent: "agent-z", ClientIP: "10.0.0.42",
			Kind: "identity", AirlockTier: "hard",
			EscalationLevel: "critical", ThreatScore: 0.9,
			LastActivity: now,
		},
	}
}

// stubRecoverDispatcher is the recoverDispatcher used by recover_test.go
// to assert which downstream method was called without hitting the wire.
type stubRecoverDispatcher struct {
	inspectCalls   int
	explainCalls   int
	releaseCalls   int
	terminateCalls int
	lastReleaseTo  string
	lastKey        string
	returnErr      error
}

func (s *stubRecoverDispatcher) Inspect(_ context.Context, _ *Client, key string, _ io.Writer) error {
	s.inspectCalls++
	s.lastKey = key
	return s.returnErr
}

func (s *stubRecoverDispatcher) Explain(_ context.Context, _ *Client, key string, _ io.Writer) error {
	s.explainCalls++
	s.lastKey = key
	return s.returnErr
}

func (s *stubRecoverDispatcher) Release(_ context.Context, _ *Client, key, tier string, _ io.Writer) error {
	s.releaseCalls++
	s.lastKey = key
	s.lastReleaseTo = tier
	return s.returnErr
}

func (s *stubRecoverDispatcher) Terminate(_ context.Context, _ *Client, key string, _ io.Writer) error {
	s.terminateCalls++
	s.lastKey = key
	return s.returnErr
}
