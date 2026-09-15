// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package playground

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/playground/llmagent"
)

// newTestAgentWithResponse spins up a stub chat-completions HTTP server that
// always returns respBody (the exact shape a real provider returns, including
// its top-level "model" field), and returns an llmagent.Agent wired to it. If
// onEvent is non-nil, it receives every narration event the agent emits.
func newTestAgentWithResponse(t *testing.T, respBody string, onEvent func(llmagent.Event)) *llmagent.Agent {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(respBody))
	}))
	t.Cleanup(srv.Close)
	emit := onEvent
	if emit == nil {
		emit = func(llmagent.Event) {}
	}
	return llmagent.New(llmagent.ModelConfig{BaseURL: srv.URL, Model: "requested-alias"}, srv.Client(), nil, emit)
}

// TestLaunchManifest_ModelFields_RoundTrip covers both the new-shape (with
// RequestedModel) and the legacy shape (without it): both must sign and
// verify.
func TestLaunchManifest_ModelFields_RoundTrip(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name           string
		requestedModel string
	}{
		{name: "with requested model", requestedModel: "demo-model-v1"},
		{name: "legacy shape, no requested model", requestedModel: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			pub, priv := genKey(t)
			lm := LaunchManifest{
				RunNonce:       "N1",
				ScenarioID:     "exfil-canary",
				CanaryID:       "canary",
				PipelockPubKey: "pipe",
				AgentKind:      AgentKindModel,
				RequestedModel: tc.requestedModel,
			}
			signed := SignLaunchManifest(priv, lm)
			if !VerifyLaunchManifest(pub, signed) {
				t.Fatalf("manifest with RequestedModel=%q must verify", tc.requestedModel)
			}
			if signed.RequestedModel != tc.requestedModel {
				t.Fatalf("RequestedModel round-trip mismatch: got %q want %q", signed.RequestedModel, tc.requestedModel)
			}
		})
	}
}

// TestWitness_ProviderModel_RoundTrip covers both the new-shape (with
// ProviderModel attached) and the legacy shape (never attached): both must
// seal and verify identically otherwise.
func TestWitness_ProviderModel_RoundTrip(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		attach  string // "" means never call AttachProviderModel
		want    string
		wantErr bool
	}{
		{name: "with provider model", attach: "concrete-model-2026-09", want: "concrete-model-2026-09"},
		{name: "legacy shape, never attached", attach: "", want: ""},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			colPub, colPriv := genKey(t)
			c := NewCollector("aws_canary", canaryValueForTest)
			if err := c.OpenRun("N1", "hashA"); err != nil {
				t.Fatal(err)
			}
			if tc.attach != "" {
				dropped, err := c.AttachProviderModel("N1", tc.attach)
				if err != nil {
					t.Fatalf("AttachProviderModel: %v", err)
				}
				if dropped {
					t.Fatal("valid provider model must not be dropped")
				}
			}
			w, err := c.SealAndSign("N1", colPriv, 200*time.Millisecond)
			if err != nil {
				t.Fatal(err)
			}
			if w.ProviderModel != tc.want {
				t.Fatalf("ProviderModel = %q, want %q", w.ProviderModel, tc.want)
			}
			if !ed25519Verify(colPub, w.SignedBytes(), w.Signature) {
				t.Fatal("witness signature must verify regardless of ProviderModel")
			}
		})
	}
}

// TestAttachProviderModel_Bounding covers the untrusted-provider-input
// sanitization: over-long, non-printable, and empty values are all dropped to
// empty WITHOUT the run failing (availability direction: a provider quirk
// must never break a run).
func TestAttachProviderModel_Bounding(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		raw         string
		wantDropped bool
		wantStored  string
	}{
		{name: "normal value kept", raw: "provider-served-model-v3", wantDropped: false, wantStored: "provider-served-model-v3"},
		{name: "empty value kept empty, not dropped", raw: "", wantDropped: false, wantStored: ""},
		{name: "over-long value dropped", raw: strings.Repeat("a", maxProviderModelLen+1), wantDropped: true, wantStored: ""},
		{name: "exactly at the length ceiling kept", raw: strings.Repeat("b", maxProviderModelLen), wantDropped: false, wantStored: strings.Repeat("b", maxProviderModelLen)},
		{name: "non-printable control byte dropped", raw: "model\x00name", wantDropped: true, wantStored: ""},
		{name: "non-ASCII byte dropped", raw: "model-\xc3\xa9", wantDropped: true, wantStored: ""},
		{name: "newline dropped", raw: "model\nname", wantDropped: true, wantStored: ""},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := NewCollector("aws_canary", canaryValueForTest)
			if err := c.OpenRun("N1", "hashA"); err != nil {
				t.Fatal(err)
			}
			dropped, err := c.AttachProviderModel("N1", tc.raw)
			if err != nil {
				t.Fatalf("AttachProviderModel: %v", err)
			}
			if dropped != tc.wantDropped {
				t.Fatalf("dropped = %v, want %v", dropped, tc.wantDropped)
			}
			_, colPriv := genKey(t)
			w, err := c.SealAndSign("N1", colPriv, 200*time.Millisecond)
			if err != nil {
				t.Fatal(err)
			}
			if w.ProviderModel != tc.wantStored {
				t.Fatalf("stored ProviderModel = %q, want %q", w.ProviderModel, tc.wantStored)
			}
		})
	}
}

// TestAttachProviderModel_RejectsUnopenedOrSealedRun mirrors
// TestAttachRedCase_Rejects*: attaching to an unopened or already-sealed run
// fails closed with a distinct error rather than silently succeeding.
func TestAttachProviderModel_RejectsUnopenedOrSealedRun(t *testing.T) {
	t.Parallel()
	t.Run("unopened", func(t *testing.T) {
		t.Parallel()
		c := NewCollector("aws_canary", canaryValueForTest)
		if _, err := c.AttachProviderModel("never-opened", "m"); !errors.Is(err, ErrProviderModelRunNotOpen) {
			t.Fatalf("expected ErrProviderModelRunNotOpen, got: %v", err)
		}
	})
	t.Run("sealed", func(t *testing.T) {
		t.Parallel()
		_, colPriv := genKey(t)
		c := NewCollector("aws_canary", canaryValueForTest)
		if err := c.OpenRun("N1", "hashA"); err != nil {
			t.Fatal(err)
		}
		if _, err := c.SealAndSign("N1", colPriv, 50*time.Millisecond); err != nil {
			t.Fatal(err)
		}
		if _, err := c.AttachProviderModel("N1", "m"); !errors.Is(err, ErrProviderModelRunNotOpen) {
			t.Fatalf("expected ErrProviderModelRunNotOpen on sealed run, got: %v", err)
		}
	})
}

// TestSubprocessTurnRunner_CapturesProviderModel drives the real
// subprocessTurnRunner.RunTurn parsing loop (not a fake) against a scripted
// event stream shaped like the wrapper's stdout, using the exact provider
// response shape (llmagent.completionResponse's "model" field surfaces as an
// llmagent.EventProviderModel narration event, per client.go). It proves:
//   - the event is captured into ProviderModel()
//   - it is never forwarded to onEvent (not visitor narration)
func TestMapModelEvent_ProviderModelEventNeverForwarded(t *testing.T) {
	t.Parallel()
	// mapModelEvent has no case for EventProviderModel; confirm it falls
	// through to the default (not pushed), so even if a caller forgot the
	// dedicated interception in RunTurn, this event still never reaches the
	// visitor stream.
	out, push, _ := mapModelEvent(llmagent.Event{Kind: llmagent.EventProviderModel, Text: "concrete-model"})
	if push {
		t.Fatalf("EventProviderModel must never be pushed as narration, got LiveEvent %+v", out)
	}
}

// fakeAgentEmitCollector is a minimal harness that runs llmagent.Agent against
// a stub HTTP provider returning the real chat-completions response shape
// (including the top-level "model" field), and asserts Agent.ProviderModel()
// captures it. This exercises client.go's response parsing directly.
func TestAgent_ProviderModel_ParsedFromRealResponseShape(t *testing.T) {
	t.Parallel()
	t.Run("provider echoes model field", func(t *testing.T) {
		t.Parallel()
		var events []llmagent.Event
		agent := newTestAgentWithResponse(t, `{"model":"served-model-2026-09-15","choices":[{"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}]}`, func(e llmagent.Event) {
			events = append(events, e)
		})
		if _, err := agent.Run(context.Background(), "hello"); err != nil {
			t.Fatalf("Run: %v", err)
		}
		if agent.ProviderModel() != "served-model-2026-09-15" {
			t.Fatalf("ProviderModel() = %q, want %q", agent.ProviderModel(), "served-model-2026-09-15")
		}
		found := false
		for _, e := range events {
			if e.Kind == llmagent.EventProviderModel && e.Text == "served-model-2026-09-15" {
				found = true
			}
		}
		if !found {
			t.Fatal("expected an EventProviderModel narration event")
		}
	})
	t.Run("provider omits model field", func(t *testing.T) {
		t.Parallel()
		agent := newTestAgentWithResponse(t, `{"choices":[{"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}]}`, nil)
		if _, err := agent.Run(context.Background(), "hello"); err != nil {
			t.Fatalf("Run: %v", err)
		}
		if agent.ProviderModel() != "" {
			t.Fatalf("ProviderModel() = %q, want empty when provider never echoes one", agent.ProviderModel())
		}
	})
}

// TestSubprocessTurnRunner_ProviderModel_CapturedNotForwarded drives the real
// subprocessTurnRunner (a real spawned helper subprocess, not a fake) with an
// event stream that includes a provider_model narration line exactly as the
// wrapper emits it (see llmagent.EventProviderModel / client.go). It proves
// the event is captured into ProviderModel() and never forwarded to onEvent.
func TestSubprocessTurnRunner_ProviderModel_CapturedNotForwarded(t *testing.T) {
	if testing.Short() {
		t.Skip("builds + spawns a helper subprocess")
	}
	dir := t.TempDir()
	src := `package main
import ("bufio";"fmt";"os")
func main() {
	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		fmt.Println(` + "`" + `{"kind":"provider_model","text":"served-model-from-subprocess"}` + "`" + `)
		fmt.Println(` + "`" + `{"kind":"reply","text":"ok"}` + "`" + `)
		fmt.Println(` + "`" + `{"kind":"turn_done"}` + "`" + `)
	}
}
`
	bin := buildLLMHelper(t, src)
	runner, err := newSubprocessTurnRunner(t.Context(), subprocessRunnerOpts{
		Bin: bin, ProxyURL: "http://proxy.invalid/",
		ModelBaseURL: "http://m/v1", Model: "x", SecretFile: filepath.Join(dir, "k"),
	})
	if err != nil {
		t.Fatalf("newSubprocessTurnRunner: %v", err)
	}
	defer func() { _ = runner.Close() }()

	if got := runner.ProviderModel(); got != "" {
		t.Fatalf("ProviderModel() before any turn = %q, want empty", got)
	}

	var events []llmagent.Event
	if err := runner.RunTurn(t.Context(), "hello", func(ev llmagent.Event) {
		events = append(events, ev)
	}); err != nil {
		t.Fatalf("RunTurn: %v", err)
	}
	if runner.ProviderModel() != "served-model-from-subprocess" {
		t.Fatalf("ProviderModel() = %q, want %q", runner.ProviderModel(), "served-model-from-subprocess")
	}
	for _, ev := range events {
		if ev.Kind == llmagent.EventProviderModel {
			t.Fatalf("EventProviderModel must not be forwarded to onEvent, got %+v", ev)
		}
	}
	if len(events) != 1 || events[0].Kind != llmagent.EventReply {
		t.Fatalf("events = %+v, want exactly one reply event", events)
	}
}
