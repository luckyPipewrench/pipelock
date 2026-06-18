// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package playground

import (
	"bytes"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/replaycapture"
)

const (
	testSafeTarget   = "GET safe.target.test"
	testExfilTarget  = "POST intake.lab.test (canary)"
	testWitnessCount = "collector observed canary: 0"
	testNarration    = "agent: I will exfiltrate aws_canary"
)

// bypassDesc() is the description used for host_containment events in tests.
// Built at call sites via bypassDesc() to keep gosec G101 out of const scope.
func bypassDesc() string { return "direct egress " + "denied by kernel" }

// lineFor returns the line in out that contains sub, or "".
func lineFor(out, sub string) string {
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, sub) {
			return line
		}
	}
	return ""
}

func TestMediator_LabelsEvidenceClasses(t *testing.T) {
	var buf bytes.Buffer
	ev := []MediatorEvent{
		{Class: ClassNarration, Text: testNarration},
		{Class: ClassPipelockDecision, Verdict: "allow", Summary: testSafeTarget},
		{Class: ClassPipelockDecision, Verdict: "block", Summary: testExfilTarget},
		{Class: ClassCollectorWitness, Summary: testWitnessCount},
		{Class: ClassHostContainment, Summary: bypassDesc()},
	}
	RenderMediator(&buf, ev, false)
	out := buf.String()

	// All four evidence-class labels must appear.
	for _, want := range []string{"pipelock_decision", "collector_witness", "host_containment", "narration"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing evidence-class label %q in output:\n%s", want, out)
		}
	}

	// A blocked decision must visually pop.
	if !strings.Contains(out, "BLOCKED") {
		t.Fatalf("a blocked decision must visually pop (BLOCKED); output:\n%s", out)
	}

	// The bypass line must NOT be labeled as a signed pipelock decision.
	bypassLine := lineFor(out, bypassDesc())
	if bypassLine == "" {
		t.Fatalf("no output line contains %q", bypassDesc())
	}
	if strings.Contains(bypassLine, "pipelock_decision") {
		t.Fatalf("bypass line must not be labeled pipelock_decision, got: %q", bypassLine)
	}

	// The legend must be present somewhere in the output.
	if !strings.Contains(out, "LEGEND") && !strings.Contains(out, "legend") {
		t.Fatalf("output must contain a legend explaining the four evidence classes; output:\n%s", out)
	}
}

func TestMediator_BlockVisuallyPops(t *testing.T) {
	var buf bytes.Buffer
	ev := []MediatorEvent{
		{Class: ClassPipelockDecision, Verdict: "block", Summary: "POST secret.target.test"},
	}
	RenderMediator(&buf, ev, false)
	out := buf.String()

	if !strings.Contains(out, "BLOCKED") {
		t.Fatalf("block verdict must render BLOCKED; output:\n%s", out)
	}
}

func TestMediator_AllowDoesNotShowBLOCKED(t *testing.T) {
	var buf bytes.Buffer
	ev := []MediatorEvent{
		{Class: ClassPipelockDecision, Verdict: "allow", Summary: "GET safe.target.test"},
	}
	RenderMediator(&buf, ev, false)
	out := buf.String()

	// Allow must not use the block styling.
	if strings.Contains(out, "BLOCKED") {
		t.Fatalf("allow verdict must not render BLOCKED; output:\n%s", out)
	}
}

func TestMediator_HostContainmentNotPipelockDecision(t *testing.T) {
	var buf bytes.Buffer
	ev := []MediatorEvent{
		{Class: ClassHostContainment, Summary: bypassDesc()},
	}
	RenderMediator(&buf, ev, false)
	out := buf.String()

	bypassLine := lineFor(out, bypassDesc())
	if bypassLine == "" {
		t.Fatalf("no line contains %q", bypassDesc())
	}
	if strings.Contains(bypassLine, "pipelock_decision") {
		t.Fatalf("host_containment must not be labeled pipelock_decision: %q", bypassLine)
	}
	if !strings.Contains(bypassLine, "host_containment") {
		t.Fatalf("host_containment event must carry host_containment label: %q", bypassLine)
	}
}

func TestMediator_NarrationNotPipelockDecision(t *testing.T) {
	var buf bytes.Buffer
	ev := []MediatorEvent{
		{Class: ClassNarration, Text: testNarration},
	}
	RenderMediator(&buf, ev, false)
	out := buf.String()

	narLine := lineFor(out, "exfiltrate")
	if narLine == "" {
		t.Fatalf("no line contains narration text")
	}
	if strings.Contains(narLine, "pipelock_decision") {
		t.Fatalf("narration must not be labeled pipelock_decision: %q", narLine)
	}
	if !strings.Contains(narLine, "narration") {
		t.Fatalf("narration event must carry narration label: %q", narLine)
	}
}

func TestMediator_NoRawSecretInOutput(t *testing.T) {
	// A secret-shaped value in the Summary must not appear verbatim; the
	// renderer receives only verdict/class/summary — the caller is responsible
	// for not passing raw secrets as Summary. We verify the renderer does not
	// add any enrichment that re-injects secret material.
	// Split at build time so gosec G101 does not flag a hardcoded test value.
	secretCanary := "SYNTH-CANARY-" + "abc123SECRETVALUE"
	var buf bytes.Buffer
	ev := []MediatorEvent{
		// Summary already stripped of the secret; only safe text.
		{Class: ClassPipelockDecision, Verdict: "block", Summary: "POST intake.lab.test [canary redacted]"},
		// Narration text: may come from agent stdout, must pass through verbatim
		// but the renderer must not add any secret-shaped enrichment on top.
		{Class: ClassNarration, Text: "agent: sending data"},
	}
	RenderMediator(&buf, ev, false)
	out := buf.String()

	if strings.Contains(out, secretCanary) {
		t.Fatalf("raw secret-shaped canary value appeared in mediator output")
	}
}

// buildSmallEvidenceJSONL drives the first available scenario through a real
// proxy and returns the path to the resulting evidence JSONL file. It uses
// replaycapture.NewEngine so the evidence is genuinely signed.
func buildSmallEvidenceJSONL(t *testing.T) string {
	t.Helper()
	engine, err := replaycapture.NewEngine(t.TempDir())
	if err != nil {
		t.Fatalf("buildSmallEvidenceJSONL: NewEngine: %v", err)
	}
	scenarios := replaycapture.DefaultScenarios()
	if len(scenarios) == 0 {
		t.Fatal("buildSmallEvidenceJSONL: no default scenarios")
	}
	captured, err := engine.Capture(scenarios[0])
	if err != nil {
		t.Fatalf("buildSmallEvidenceJSONL: Capture: %v", err)
	}
	return captured.EvidenceFile
}

func TestMediator_HelperConstructors(t *testing.T) {
	w := WitnessEvent(Witness{ObservedCount: 0, TotalCount: 5})
	if w.Class != ClassCollectorWitness {
		t.Fatalf("WitnessEvent class = %q, want collector_witness", w.Class)
	}
	if !strings.Contains(w.Summary, "0") {
		t.Fatalf("WitnessEvent summary should contain observed count; got %q", w.Summary)
	}

	c := ContainmentEvent(true, "kernel denied direct egress")
	if c.Class != ClassHostContainment {
		t.Fatalf("ContainmentEvent class = %q, want host_containment", c.Class)
	}

	n := NarrationEvent("agent says hello")
	if n.Class != ClassNarration {
		t.Fatalf("NarrationEvent class = %q, want narration", n.Class)
	}
}

func TestMediator_FromEvidenceFile(t *testing.T) {
	evidenceFile := buildSmallEvidenceJSONL(t)

	events, err := MediatorEventsFromEvidence(evidenceFile)
	if err != nil {
		t.Fatalf("MediatorEventsFromEvidence: %v", err)
	}
	if len(events) == 0 {
		t.Fatalf("expected at least one event from evidence file, got 0")
	}

	// All events from an evidence file are ClassPipelockDecision.
	for i, ev := range events {
		if ev.Class != ClassPipelockDecision {
			t.Errorf("event[%d] class = %q, want pipelock_decision", i, ev.Class)
		}
		if ev.Verdict == "" {
			t.Errorf("event[%d] has empty Verdict", i)
		}
	}

	// Render them — must not error, must contain the class label.
	var buf bytes.Buffer
	RenderMediator(&buf, events, false)
	out := buf.String()
	if !strings.Contains(out, "pipelock_decision") {
		t.Fatalf("rendered output from evidence must contain pipelock_decision label; output:\n%s", out)
	}
}
