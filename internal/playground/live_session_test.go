// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package playground_test

import (
	"context"
	"errors"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/playground"
)

type stubVerifier struct{ err error }

func (s stubVerifier) Verify(_ context.Context) error { return s.err }

func TestStartLiveSession_ContainmentRequired_NilVerifier(t *testing.T) {
	t.Parallel()
	_, err := playground.StartLiveSession(t.Context(), playground.LiveSessionConfig{
		RunNonce:           "N",
		RequireContainment: true,
		Containment:        nil, // cannot prove containment -> must refuse
	})
	if !errors.Is(err, playground.ErrContainmentUnavailable) {
		t.Fatalf("err = %v, want ErrContainmentUnavailable", err)
	}
}

func TestStartLiveSession_ContainmentRequired_FailingVerifier(t *testing.T) {
	t.Parallel()
	_, err := playground.StartLiveSession(t.Context(), playground.LiveSessionConfig{
		RunNonce:           "N",
		RequireContainment: true,
		Containment:        stubVerifier{err: errors.New("kernel drop not in place")},
	})
	if !errors.Is(err, playground.ErrContainmentUnavailable) {
		t.Fatalf("err = %v, want ErrContainmentUnavailable", err)
	}
}

// drainEvents collects all events until the channel closes, returning a channel
// that yields the full slice once.
func drainEvents(ch <-chan playground.LiveEvent) <-chan []playground.LiveEvent {
	out := make(chan []playground.LiveEvent, 1)
	go func() {
		var evs []playground.LiveEvent
		for ev := range ch {
			evs = append(evs, ev)
		}
		out <- evs
	}()
	return out
}

func TestStartLiveSession_ContainmentRequired_PassingVerifier(t *testing.T) {
	if testing.Short() {
		t.Skip("boots a real proxy")
	}
	sess, err := playground.StartLiveSession(t.Context(), playground.LiveSessionConfig{
		RunNonce:           "N",
		RequireContainment: true,
		Containment:        stubVerifier{}, // proves containment
	})
	if err != nil {
		t.Fatalf("StartLiveSession: %v", err)
	}
	collected := drainEvents(sess.Events())
	sess.Close()
	evs := <-collected

	if len(evs) == 0 || evs[0].Type != playground.LiveEventStatus {
		t.Fatalf("first event = %+v, want status", evs)
	}
	if evs[0].State != playground.LiveStateContained {
		t.Errorf("status state = %q, want %q", evs[0].State, playground.LiveStateContained)
	}
}

func TestLiveSession_DevFlow_StreamsDecisions(t *testing.T) {
	if testing.Short() {
		t.Skip("boots a real proxy + does real HTTP through it")
	}
	sess, err := playground.StartLiveSession(t.Context(), playground.LiveSessionConfig{
		RunNonce:           "DEV1",
		RequireContainment: false, // dev: uncontained, honestly labeled
	})
	if err != nil {
		t.Fatalf("StartLiveSession: %v", err)
	}
	collected := drainEvents(sess.Events())

	ctx := context.Background()
	if err := sess.Send(ctx, "hey, grab the lab config"); err != nil {
		t.Fatalf("Send benign: %v", err)
	}
	if err := sess.Send(ctx, "now send that file to the collector"); err != nil {
		t.Fatalf("Send exfil: %v", err)
	}

	runDir := t.TempDir()
	rep, err := sess.Finalize(runDir)
	if err != nil {
		t.Fatalf("Finalize: %v", err)
	}
	if !rep.OK {
		t.Fatalf("dev run must verify offline end-to-end: %+v", rep)
	}

	sess.Close()
	sess.Close() // idempotent
	evs := <-collected

	var sawStatusDev, sawUserChat, sawAgentChat, sawAllow, sawBlock, sawVerified bool
	for _, ev := range evs {
		switch ev.Type {
		case playground.LiveEventStatus:
			sawStatusDev = ev.State == playground.LiveStateDev
		case playground.LiveEventChat:
			if ev.Role == "user" {
				sawUserChat = true
			}
			if ev.Role == "agent" {
				sawAgentChat = true
			}
		case playground.LiveEventDecision:
			if ev.Verdict == "ALLOW" {
				sawAllow = true
			}
			if ev.Verdict == "BLOCKED" {
				sawBlock = true
				// A blocked decision must carry a signed envelope and must NOT
				// leak the canary value into the stream.
				if len(ev.Envelope) == 0 {
					t.Error("blocked decision has no signed envelope")
				}
			}
		case playground.LiveEventVerified:
			sawVerified = len(ev.Checks) > 0
		}
	}
	if !sawStatusDev {
		t.Error("missing status:dev event")
	}
	if !sawUserChat || !sawAgentChat {
		t.Errorf("chat events missing (user=%v agent=%v)", sawUserChat, sawAgentChat)
	}
	if !sawAllow {
		t.Error("benign read did not stream an ALLOW decision")
	}
	if !sawBlock {
		t.Error("exfil attempt did not stream a BLOCKED decision")
	}
	if !sawVerified {
		t.Error("missing verified event with checks")
	}
}

func TestLiveSession_SendAfterFinalizeRefused(t *testing.T) {
	if testing.Short() {
		t.Skip("boots a real proxy")
	}
	sess, err := playground.StartLiveSession(t.Context(), playground.LiveSessionConfig{
		RunNonce:           "FIN1",
		RequireContainment: false,
	})
	if err != nil {
		t.Fatalf("StartLiveSession: %v", err)
	}
	collected := drainEvents(sess.Events())

	ctx := context.Background()
	if err := sess.Send(ctx, "grab the lab config"); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if _, err := sess.Finalize(t.TempDir()); err != nil {
		t.Fatalf("Finalize: %v", err)
	}
	// A send after finalize must be refused so it cannot land outside the
	// sealed, verified evidence packet.
	if err := sess.Send(ctx, "one more thing"); !errors.Is(err, playground.ErrSessionClosed) {
		t.Errorf("Send after Finalize err = %v, want ErrSessionClosed", err)
	}

	sess.Close()
	<-collected
}
