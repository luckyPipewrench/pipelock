// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"crypto/ed25519"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/evidenceview"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

// proxyLifecycleActor is the identity the proxy opens every session under,
// which is what made a lifecycle-counting guard misread an ordinary
// single-agent session as two agents.
const proxyLifecycleActor = "pipelock"

// emitLifecycleThenActions reproduces the PRODUCTION shape the previous fixture
// could not: the session is opened under the proxy's own identity while the
// mediated actions carry the resolved request agent.
//
// The old fixture gave one emitter a single Actor for both, so the session-open
// record and the action records always agreed and the collision below could not
// occur. That is why a guard counting lifecycle records as distinct agents
// survived review: the test that would have caught it agreed with the code by
// construction.
func emitLifecycleThenActions(t *testing.T, dir string, key ed25519.PrivateKey, actionActors ...string) {
	t.Helper()
	rec := newTestRecorder(t, dir, key)

	opener := receipt.NewEmitter(receipt.EmitterConfig{
		Recorder: rec, PrivKey: key, ConfigHash: testPolicyHash,
		Principal: testPrincipal, Actor: proxyLifecycleActor,
	})
	if err := opener.EmitSessionOpen(); err != nil {
		t.Fatalf("EmitSessionOpen: %v", err)
	}

	for _, actor := range actionActors {
		em := receipt.NewEmitter(receipt.EmitterConfig{
			Recorder: rec, PrivKey: key, ConfigHash: testPolicyHash,
			Principal: testPrincipal, Actor: actor,
		})
		if err := em.Emit(receipt.EmitOpts{
			ActionID:  receipt.NewActionID(),
			Target:    testTarget,
			Verdict:   config.ActionAllow,
			Transport: testTransport,
		}); err != nil {
			t.Fatalf("Emit for actor %q: %v", actor, err)
		}
	}
}

// readSessionReceipts loads the receipts the emitters above wrote. The recorder
// hard-codes the evidence session ID to "proxy", so a temp dir holds exactly
// one session.
func readSessionReceipts(t *testing.T, dir string) []receipt.Receipt {
	t.Helper()
	location := resolveTestEvidenceLocation(t, dir)
	receipts, _, err := receipt.ExtractReceiptsFromResolvedSessionDirBounded(
		location, "proxy", evidenceview.DashboardReceiptReadLimit,
	)
	if err != nil {
		t.Fatalf("reading receipts from %q: %v", dir, err)
	}
	return receipts
}

// renderForTest drives the real render path so the assertions below cover the
// template an operator actually sees, not a hand-built struct.
func renderForTest(t *testing.T, dir string) string {
	t.Helper()
	html, err := renderSessionHTML(resolveTestEvidenceLocation(t, dir), "proxy", nil, "Pipelock Evidence Report")
	if err != nil {
		t.Fatalf("renderSessionHTML: %v", err)
	}
	return string(html)
}

// TestRecordedActorLabels_ExcludesLifecycleRecord guards the normal-operation
// bug: the proxy opens every session under its own identity, so counting that
// record made an ordinary single-agent session look like two agents and denied
// the operator the report with no attacker involved.
func TestRecordedActorLabels_ExcludesLifecycleRecord(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	_, key := genKey(t)
	emitLifecycleThenActions(t, dir, key, "agent-alpha", "agent-alpha")

	labels := evidenceview.RecordedActorLabels(readSessionReceipts(t, dir))
	if len(labels) != 1 || labels[0] != "agent-alpha" {
		t.Fatalf("ordinary session should report exactly its agent, got %v", labels)
	}
}

// TestOrdinarySessionRendersAndClaimsNoIdentity is the payoff of the lifecycle
// fix. An ordinary single-agent session (proxy-opened, one named agent) must
// render, and its header must NOT present the recorded label as an established
// identity: a v1 receipt stores the label without any record of how it was
// established, and on a listener without a bound identity the caller supplies
// it. The signature proves Pipelock recorded the label, not that anyone proved
// it.
func TestOrdinarySessionRendersAndClaimsNoIdentity(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	_, key := genKey(t)
	emitLifecycleThenActions(t, dir, key, "agent-alpha", "agent-alpha")

	html := renderForTest(t, dir)

	if strings.Contains(html, "<b>Agent</b> agent-alpha") {
		t.Fatal("a v1 label is still presented as an established identity")
	}
	if !strings.Contains(html, "not established by v1 receipts") {
		t.Fatal("report must state that identity is not established by v1 receipts")
	}
	if !strings.Contains(html, "agent-alpha") {
		t.Fatal("the recorded label should still be disclosed to the operator")
	}
}

// TestTwoNamedLabelsStillRefusedAndDoNotLeak pins the confidentiality control
// that survived this change.
//
// Refusing here is NOT a tier gate. One agent's report would disclose the
// other's target URLs, which can carry capability tokens, so the refusal is
// load-bearing and the error must not echo a target either. The accepted cost
// is stated on validateSingleActorReceipts: a caller who can inject a distinct
// named label can still deny this view, and closing that needs
// receipt-carried provenance a v1 receipt cannot express.
func TestTwoNamedLabelsStillRefusedAndDoNotLeak(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	_, key := genKey(t)
	emitLifecycleThenActions(t, dir, key, "agent-alpha", "agent-bravo")

	_, err := renderSessionHTML(resolveTestEvidenceLocation(t, dir), "proxy", nil, "Pipelock Evidence Report")
	if err == nil {
		t.Fatal("a genuinely two-agent session must not render in the single-agent view")
	}
	if strings.Contains(err.Error(), testTarget) {
		t.Fatalf("refusal echoed a target URL: %v", err)
	}
	if !strings.Contains(err.Error(), "bind_default_agent_identity") {
		t.Fatalf("refusal should name the binding that makes the label trustworthy: %v", err)
	}
}

// TestAnonymousPlusNamedStillRenders pins that the anonymous label is not a
// second agent. A session where some actions resolved to a named agent and
// others fell back to "anonymous" is one agent's session, and refusing it would
// deny the operator the view with no confidentiality gain.
func TestAnonymousPlusNamedStillRenders(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	_, key := genKey(t)
	emitLifecycleThenActions(t, dir, key, anonymousActor, "agent-alpha")

	if _, err := renderSessionHTML(
		resolveTestEvidenceLocation(t, dir), "proxy", nil, "Pipelock Evidence Report",
	); err != nil {
		t.Fatalf("anonymous plus one named agent is a single-agent session: %v", err)
	}
}

// TestEmptyActorStillCountsAsAnAgent guards the fallback the guard has always
// had. A receipt with an empty Actor does not mean "no agent": it falls back to
// the receipt's own session ID, then the session being rendered. Dropping that
// fallback would let a receipt with an empty Actor go uncounted, so a session
// mixing two agents could render and disclose the other agent's target URLs.
func TestEmptyActorStillCountsAsAnAgent(t *testing.T) {
	t.Parallel()
	receipts := []receipt.Receipt{
		{ActionRecord: receipt.ActionRecord{Actor: "agent-alpha", SessionID: "s-alpha"}},
		{ActionRecord: receipt.ActionRecord{Actor: "", SessionID: "s-bravo"}},
	}
	keys := evidenceview.DistinctActorKeys("proxy", receipts)
	if len(keys) != 2 {
		t.Fatalf("empty Actor must fall back to its session ID, got %v", keys)
	}
	if err := validateSingleActorReceipts("proxy", receipts); err == nil {
		t.Fatal("two distinct actor keys must refuse the single-agent view")
	}
}

// TestCaseVariantAnonymousStillRenders pins the sentinel comparison. The guard
// used to skip only the exact lowercase "anonymous", so a label that differed
// only in case counted as a second agent and denied the operator an ordinary
// single-agent report.
func TestCaseVariantAnonymousStillRenders(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	_, key := genKey(t)
	emitLifecycleThenActions(t, dir, key, "Anonymous", "agent-alpha")

	if _, err := renderSessionHTML(
		resolveTestEvidenceLocation(t, dir), "proxy", nil, "Pipelock Evidence Report",
	); err != nil {
		t.Fatalf("a case-variant anonymous label is not a second agent: %v", err)
	}
}

// TestCaseVariantNamedLabelsStillRefused proves the loosened comparison did not
// loosen the confidentiality control itself: two genuinely different named
// agents are still refused.
func TestCaseVariantNamedLabelsStillRefused(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	_, key := genKey(t)
	emitLifecycleThenActions(t, dir, key, "agent-alpha", "agent-bravo")

	if _, err := renderSessionHTML(
		resolveTestEvidenceLocation(t, dir), "proxy", nil, "Pipelock Evidence Report",
	); err == nil {
		t.Fatal("two distinct named agents must still be refused")
	}
}
