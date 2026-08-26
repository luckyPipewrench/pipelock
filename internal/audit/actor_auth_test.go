// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"strings"
	"testing"

	"github.com/rs/zerolog"

	"github.com/luckyPipewrench/pipelock/internal/envelope"
)

// newTestLogEntry builds a log entry whose output is discarded, so these tests
// assert on the fields map the external emitter reads rather than on log text.
func newTestLogEntry() *logEntry {
	nop := zerolog.Nop()
	return newLogEntryRaw(nop.Info(), "test")
}

// TestWithActorAuthCarriesGrade covers the carrier itself. The grade rides on
// the context so a downstream emitter can tell an infrastructure-bound identity
// from a caller-supplied one.
func TestWithActorAuthCarriesGrade(t *testing.T) {
	t.Parallel()
	ctx := NewMethodLogContext("GET").WithActorAuth(string(envelope.ActorAuthBound))
	if got := ctx.AgentAuth(); got != string(envelope.ActorAuthBound) {
		t.Fatalf("AgentAuth() = %q, want %q", got, envelope.ActorAuthBound)
	}
}

// TestAgentAuthUnrecordedIsUnknown pins the fail-closed default at the audit
// layer: a context that never recorded a grade reports unknown rather than an
// empty string, so an emitter cannot read "absent" as "fine".
func TestAgentAuthUnrecordedIsUnknown(t *testing.T) {
	t.Parallel()
	ctx := NewMethodLogContext("GET")
	if got := ctx.AgentAuth(); got != "" {
		t.Fatalf("an ungraded context should hold no grade, got %q", got)
	}
	if got := ctx.agentAuthOrUnknown(); got != string(envelope.ActorAuthUnknown) {
		t.Fatalf("agentAuthOrUnknown() = %q, want %q", got, envelope.ActorAuthUnknown)
	}

	graded := ctx.WithActorAuth(string(envelope.ActorAuthSelfDeclared))
	if got := graded.agentAuthOrUnknown(); got != string(envelope.ActorAuthSelfDeclared) {
		t.Fatalf("a recorded grade must survive, got %q", got)
	}
}

// TestAgentFieldEmitsNameAndGradeTogether is the invariant the helper exists
// for. An agent name reaching an external consumer without its grade is
// indistinguishable from a caller-controlled label, so the two are written as
// one operation or not at all.
func TestAgentFieldEmitsNameAndGradeTogether(t *testing.T) {
	t.Parallel()

	withName := newTestLogEntry().agentField("agent-a", string(envelope.ActorAuthBound))
	if got := withName.fields["agent"]; got != "agent-a" {
		t.Fatalf("agent field = %v, want agent-a", got)
	}
	if got := withName.fields["agent_auth"]; got != string(envelope.ActorAuthBound) {
		t.Fatalf("agent_auth field = %v, want %q", got, envelope.ActorAuthBound)
	}

	ungraded := newTestLogEntry().agentField("agent-a", "")
	if got := ungraded.fields["agent_auth"]; got != string(envelope.ActorAuthUnknown) {
		t.Fatalf("a missing grade must be written as unknown, got %v", got)
	}

	empty := newTestLogEntry().agentField("", string(envelope.ActorAuthBound))
	if _, present := empty.fields["agent"]; present {
		t.Fatal("no agent name means no agent field")
	}
	if _, present := empty.fields["agent_auth"]; present {
		t.Fatal("a grade must never be emitted without the label it grades")
	}
}

func TestAgentAuthGradeIsNotFreeText(t *testing.T) {
	t.Parallel()
	ctx := NewMethodLogContext("GET").WithActorAuth("whatever-the-caller-said")
	if !strings.EqualFold(ctx.AgentAuth(), "whatever-the-caller-said") {
		t.Fatal("the audit layer stores the grade verbatim; normalization belongs to the consumer")
	}
	if envelope.NormalizeActorAuth(ctx.AgentAuth()).TrustedForIdentity() {
		t.Fatal("an unrecognized grade must not survive normalization as trusted")
	}
}
